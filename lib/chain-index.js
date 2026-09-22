/**
 * @file Worker-backed wallet index facade. Mutations run in a dedicated SQLite worker.
 * Persisted hash strings use display order; checkpoint Buffers use P2P wire order.
 */
// chain-index.js
import path from 'node:path';
import fs from 'node:fs';
import { Worker } from 'node:worker_threads';
import { fileURLToPath } from 'node:url';
import Database from './sqlite.js';

// Resolve the real directory of THIS file, not process.cwd()
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ABSOLUTE, PERSISTENT DATABASE LOCATION
// Change this if you want, but DO NOT use relative paths.
const DEFAULT_DB_DIR = path.resolve('/var/lib/pepecoin');

/**
 * Quarantine a database with impossible adjacent repeated hashes and recover watch identities.
 * This narrow repair is not a general corruption check or chain-reorganization rollback.
 * @private
 * @param {string} dir - Index directory.
 * @returns {string[]} Recovered hex identities, or an empty array if no repair was performed.
 */
function recoverCorruptIndex(dir) {
  const dbPath = path.join(dir, 'chainindex.db');
  if (!fs.existsSync(dbPath)) return [];

  let db;
  try {
    db = new Database(dbPath, { readonly: true });
    const repeated = db.prepare(`
      SELECT blocks.height
      FROM blocks
      JOIN blocks AS previous ON previous.height = blocks.height - 1
      WHERE blocks.hash = previous.hash
      ORDER BY blocks.height ASC
      LIMIT 1
    `).get();
    if (!repeated) return [];
    const identities = db.prepare(`SELECT identity FROM wallets`).all()
      .map(row => row.identity);
    db.close();
    db = null;

    const suffix = `.corrupt-${new Date().toISOString().replace(/[:.]/g, '-')}`;
    for (const extension of ['', '-wal', '-shm']) {
      const source = `${dbPath}${extension}`;
      if (fs.existsSync(source)) fs.renameSync(source, `${source}${suffix}`);
    }
    return identities;
  } catch {
    return [];
  } finally {
    db?.close();
  }
}

/**
 * Manage requests to the chain-index worker and expose a synchronous startup checkpoint.
 * The owner must close the worker and hold the surrounding data-directory lock.
 */
export class ChainIndex {
  /**
   * Resolve the database directory, quarantine a recognized corrupt tail, and start a worker.
   * @param {string} [dir] - Index directory; defaults to the resolved /var/lib/pepecoin path.
   */
  constructor(dir = DEFAULT_DB_DIR) {
    // Always absolute, always persistent
    this.dir = path.resolve(dir);
    const recoveredWatchIdentities = recoverCorruptIndex(this.dir);

    // Worker path anchored to THIS file's directory
    const workerPath = path.join(__dirname, 'chain-index-worker.js');

    const workerOptions = {
      workerData: { dir: this.dir, recoveredWatchIdentities }
    };
    if (process.execArgv.some(arg => arg.startsWith('--input-type')))
      workerOptions.execArgv = [];
    this.worker = new Worker(workerPath, workerOptions);
    this.worker.unref();

    this._reqId = 0;
    this._pending = new Map();
    this.closing = false;

    this.worker.on('message', msg => {
      const { id, result, error } = msg;
      const pending = this._pending.get(id);
      if (!pending) return;
      this._pending.delete(id);
      if (error) pending.reject(new Error(error));
      else pending.resolve(result);
    });

    this.worker.on('error', err => {
      for (const { reject } of this._pending.values()) reject(err);
      this._pending.clear();
      console.error('ChainIndex worker crashed:', err);
    });

    this.worker.on('exit', code => {
      const wasClosing = this.closing;
      this.closing = true;
      for (const { reject } of this._pending.values()) reject(new Error('Chain index worker stopped.'));
      this._pending.clear();
      if (code !== 0 && !wasClosing) {
        console.error('ChainIndex worker exited with code', code);
      }
    });
  }

  /**
   * Send a correlated worker request and reject it if the worker fails or closes.
   * @private
   * @param {string} method - Worker operation name.
   * @param {Object} payload - Structured-cloneable request data.
   * @returns {Promise<*>} Structured-cloned result from the worker.
   */
  _call(method, payload) {
    if (this.closing) return Promise.reject(new Error('Chain index is closed.'));
    return new Promise((resolve, reject) => {
      const id = ++this._reqId;
      this._pending.set(id, { resolve, reject });
      this.worker.postMessage({ id, method, payload });
    });
  }

  /**
   * Wait for the worker to initialize its schema and statement cache.
   * @returns {Promise<boolean>} True once initialization is acknowledged.
   */
  init() {
    return this._call('init', {});
  }

  /**
   * Parse and index one block atomically, validating its transaction Merkle root.
   * The sync layer must supply a requested block at the correct linked height.
   * @param {Buffer|Uint8Array} rawBlock - Serialized mainnet block.
   * @param {number} height - Expected indexed height.
   * @returns {Promise<{height: number, blockHash: string}>} Height and display-order block hash.
   * @throws {Error} Rejects on malformed data, a Merkle mismatch or a conflicting saved block.
   */
  ingest(rawBlock, height) {
    return this._call('ingest', { rawBlock, height });
  }

  /**
   * Index an ordered non-empty block batch in one SQLite transaction.
   * @param {Array<{rawBlock: Buffer|Uint8Array, height: number}>} blocks - Requested blocks in chain order.
   * @returns {Promise<Array<{height: number, blockHash: string}>>} Results in input order; any failure rolls back the batch.
   */
  ingestBatch(blocks) {
    return this._call('ingestBatch', { blocks });
  }

  /**
   * Persist a public-key identity for future indexing; existing history is not rescanned.
   * @param {string} identity - Hex-encoded 20-byte HASH160.
   * @returns {Promise<boolean>} True after the watch is registered.
   */
  watchIdentity(identity) {
    return this._call('watchIdentity', { identity });
  }

  /**
   * Read a consistent index snapshot for the requested public-key identities.
   * @param {string[]} identities - Hex HASH160 values belonging to the authorized wallet.
   * @returns {Promise<{height: number, utxos: Object[], transactions: Object[], legacyPending: Object[]}>} Index rows; *Koinu values are integer ribbit strings.
   */
  walletSnapshot(identities) { return this._call('walletSnapshot', { identities }); }

  /**
   * Terminate the worker and reject remaining requests when it exits.
   * The runtime drains ingestion before calling this method.
   * @returns {Promise<number>} Worker exit code.
   */
  close() {
    this.closing = true;
    return this.worker.terminate();
  }

  // IMPORTANT: make syncCheckpoint truly synchronous so PepecoinSync
  // can safely read it in the constructor without async/await.
  /**
   * Synchronously read the highest committed block for constructing a sync attempt.
   * Failures and empty indexes return height -1 with a zero hash rather than throwing.
   * @returns {{height: number, hash: Buffer}} Height and 32-byte wire-order hash.
   */
  syncCheckpoint() {
    const dbPath = path.join(this.dir, 'chainindex.db');

    let height = -1;
    let hash = Buffer.alloc(32);

    try {
      const db = new Database(dbPath, { fileMustExist: false });
      const row = db
        .prepare(`SELECT height, hash FROM blocks ORDER BY height DESC LIMIT 1`)
        .get();

      if (row) {
        height = row.height;
        hash = Buffer.from(row.hash, 'hex').reverse();
      }

      db.close();
    } catch {
      // if anything goes wrong, fall back to "no checkpoint"
    }

    return { height, hash };
  }
}
