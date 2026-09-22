/**
 * @file Internal worker entry point; do not import it on the main thread.
 * workerData supplies dir and optional recoveredWatchIdentities. Requests use
 * {id, method, payload}; replies use {id, result} or {id, error}. No wallet secrets are indexed.
 */
// chain-index-worker.js
import fs from 'node:fs';
import path from 'node:path';
import Database from './sqlite.js';
import { parentPort, workerData } from 'node:worker_threads';

import { parseBlock, verifyBlockMerkle } from './pepenet-wire.js';

const dir = workerData.dir;
fs.mkdirSync(dir, { recursive: true });
const dbPath = path.join(dir, 'chainindex.db');

let db = null;
let statementCache = null;
const watchedIdentities = new Set();

/**
 * Open the index, initialize schema and cached statements, and recover watch identities.
 * Legacy coins with unknown origin are conservatively marked as coinbase outputs.
 * @private
 * @returns {void}
 */
function init() {
  db = new Database(dbPath, { fileMustExist: false });
  statementCache = new Map();
  const prepare = db.prepare.bind(db);
  db.prepare = sql => {
    let statement = statementCache.get(sql);
    if (!statement) {
      statement = prepare(sql);
      statementCache.set(sql, statement);
    }
    return statement;
  };

  db.exec(`
    PRAGMA journal_mode = WAL;

    CREATE TABLE IF NOT EXISTS blocks (
      height INTEGER PRIMARY KEY,
      hash TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS headers (
      height INTEGER PRIMARY KEY,
      time INTEGER,
      blockBytes TEXT,
      coinbaseTotal TEXT
    );

    CREATE TABLE IF NOT EXISTS wallets (
      identity TEXT PRIMARY KEY
    );

    CREATE TABLE IF NOT EXISTS wallet_utxos (
      identity TEXT,
      key TEXT,
      txid TEXT,
      vout INTEGER,
      valueKoinu TEXT,
      height INTEGER,
      PRIMARY KEY (identity, key)
    );

    CREATE TABLE IF NOT EXISTS wallet_transactions (
      identity TEXT,
      txid TEXT,
      height INTEGER,
      time INTEGER,
      receivedKoinu TEXT,
      spentKoinu TEXT,
      PRIMARY KEY (identity, txid)
    );

    CREATE TABLE IF NOT EXISTS pending_withdrawals (
      identity TEXT,
      txid TEXT PRIMARY KEY,
      inputKoinu TEXT NOT NULL,
      amountKoinu TEXT NOT NULL,
      changeKoinu TEXT NOT NULL,
      createdHeight INTEGER,
      createdAt INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS pending_withdrawal_inputs (
      txid TEXT,
      inputTxid TEXT,
      vout INTEGER,
      valueKoinu TEXT NOT NULL,
      PRIMARY KEY (txid, inputTxid, vout)
    );

  `);
  if (!db.prepare('PRAGMA table_info(headers)').all().some(c => c.name === 'bits')) {
    // Compact difficulty targets let a restarted sync keep validating DigiShield retargets.
    // Rows indexed before this column existed stay NULL; no rescan is required.
    db.exec('ALTER TABLE headers ADD COLUMN bits INTEGER');
  }
  if (!db.prepare('PRAGMA table_info(wallet_utxos)').all().some(c => c.name === 'coinbase')) {
    // Unknown legacy coins are conservatively treated as mining rewards.
    db.exec('ALTER TABLE wallet_utxos ADD COLUMN coinbase INTEGER NOT NULL DEFAULT 1');
  }
  for (const row of db.prepare(`SELECT identity FROM wallets`).all())
    watchedIdentities.add(row.identity);
  for (const identity of workerData.recoveredWatchIdentities || []) {
    db.prepare(`INSERT OR IGNORE INTO wallets(identity) VALUES (?)`).run(identity);
    watchedIdentities.add(identity);
  }
}

init();

/**
 * Convert a serialized previous-output reference to a display-order outpoint identifier.
 * @private
 * @param {Buffer} previousOutput - 32-byte wire-order transaction hash followed by uint32 output index.
 * @returns {string} txid:vout identifier.
 */
function outpointKey(previousOutput) {
  return `${Buffer.from(previousOutput.subarray(0, 32)).reverse().toString('hex')}:${previousOutput.readUInt32LE(32)}`;
}

/**
 * Extract HASH160 from a standard 25-byte P2PKH locking script.
 * @private
 * @param {Buffer} script - Output locking script.
 * @returns {string|null} Hex public-key identity, or null for other script forms.
 */
function p2pkhIdentity(script) {
  return Buffer.isBuffer(script) &&
    script.length === 25 &&
    script[0] === 0x76 &&
    script[1] === 0xa9 &&
    script[2] === 0x14 &&
    script[23] === 0x88 &&
    script[24] === 0xac
    ? script.subarray(3, 23).toString('hex')
    : null;
}

/**
 * Validate a block Merkle root and apply watched-wallet UTXO/history changes.
 * Already-indexed matching hashes are idempotent; conflicting hashes require recovery.
 * This does not validate proof of work, scripts, difficulty or all consensus rules.
 * @private
 * @param {Buffer|Uint8Array} rawBlock - Serialized block.
 * @param {number} height - Height established by the sync layer.
 * @param {boolean} [commit=true] - Create a transaction; false requires an enclosing batch transaction.
 * @returns {{height: number, blockHash: string}} Indexed height and display-order hash.
 * @throws {Error} If parsing, Merkle verification, conflict checks or persistence fails.
 */
function ingestOne(rawBlock, height, commit = true) {
  const block = parseBlock(rawBlock);
  verifyBlockMerkle(block);
  const blockHash = Buffer.from(block.hash).reverse().toString('hex');

  const known = db.prepare(`SELECT hash FROM blocks WHERE height=?`).get(height);
  if (known && known.hash !== blockHash)
    throw new Error(`Chain reorg rollback is required at height ${height}.`);
  if (known) return { height, blockHash };

  const insertBlock = db.prepare(`
    INSERT INTO blocks (height, hash)
    VALUES (?, ?)
    ON CONFLICT(height) DO UPDATE SET hash=excluded.hash
  `);

  const insertHeader = db.prepare(`
    INSERT INTO headers (height, time, blockBytes, coinbaseTotal, bits)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(height) DO UPDATE SET
      time=excluded.time,
      bits=excluded.bits,
      blockBytes=excluded.blockBytes,
      coinbaseTotal=excluded.coinbaseTotal
  `);

  const selectUtxoByKey = db.prepare(`
    SELECT identity, valueKoinu FROM wallet_utxos WHERE key=?
  `);
  const deleteUtxoByKey = db.prepare(`
    DELETE FROM wallet_utxos WHERE key=?
  `);
  const insertUtxo = db.prepare(`
    INSERT INTO wallet_utxos (identity, key, txid, vout, valueKoinu, height, coinbase)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(identity, key) DO UPDATE SET
      txid=excluded.txid,
      vout=excluded.vout,
      valueKoinu=excluded.valueKoinu,
      height=excluded.height,
      coinbase=excluded.coinbase
  `);
  const insertTx = db.prepare(`
    INSERT INTO wallet_transactions (
      identity, txid, height, time, receivedKoinu, spentKoinu
    ) VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(identity, txid) DO UPDATE SET
      height=excluded.height,
      time=excluded.time,
      receivedKoinu=excluded.receivedKoinu,
      spentKoinu=excluded.spentKoinu
  `);

  const process = () => {
    for (const tx of block.transactions) {
      const txid = Buffer.from(tx.txid).reverse().toString('hex');
      const changes = new Map();
      db.prepare(`DELETE FROM pending_withdrawal_inputs WHERE txid=?`).run(txid);
      db.prepare(`DELETE FROM pending_withdrawals WHERE txid=?`).run(txid);

      for (const input of tx.inputs) {
        const key = outpointKey(input.previousOutput);
        if (!watchedIdentities.size) continue;
        const rows = selectUtxoByKey.all(key);
        for (const row of rows) {
          deleteUtxoByKey.run(key);
          const identity = row.identity;
          const ch = changes.get(identity) || { received: 0n, spent: 0n };
          ch.spent += BigInt(row.valueKoinu);
          changes.set(identity, ch);
        }
      }

      tx.outputs.forEach((output, vout) => {
        const identity = p2pkhIdentity(output.scriptPubKey);
        if (!identity || output.value < 0n) return;

        if (!watchedIdentities.has(identity)) return;

        const key = `${txid}:${vout}`;
        insertUtxo.run(
          identity,
          key,
          txid,
          vout,
          output.value.toString(),
          height,
          tx.inputs.length === 1 && tx.inputs[0].previousOutput.subarray(0, 32).equals(Buffer.alloc(32)) ? 1 : 0
        );

        const ch = changes.get(identity) || { received: 0n, spent: 0n };
        ch.received += output.value;
        changes.set(identity, ch);
      });

      for (const [identity, ch] of changes) {
        insertTx.run(
          identity,
          txid,
          height,
          block.time,
          ch.received.toString(),
          ch.spent.toString()
        );

        // Retain complete indexed wallet history, not only the last 100 rows.
      }
    }

    insertBlock.run(height, blockHash);
    insertHeader.run(
      height,
      block.time,
      block.blockBytes.toString(),
      block.coinbaseTotal.toString(),
      block.header.readUInt32LE(72)
    );
  };
  const batch = commit ? db.transaction(process) : process;

  if (commit) batch();
  else process();

  return { height, blockHash };
}

/**
 * Apply every block in an ordered batch in one atomic database transaction.
 * @private
 * @param {Array<{rawBlock: Buffer|Uint8Array, height: number}>} blocks - Non-empty block batch.
 * @returns {Array<{height: number, blockHash: string}>} Results in input order.
 * @throws {Error} If any block fails; all changes in the batch roll back.
 */
function ingestBatch(blocks) {
  if (!Array.isArray(blocks) || !blocks.length)
    throw new Error('A non-empty block batch is required.');
  const results = [];
  const commit = db.transaction(() => {
    for (const block of blocks)
      results.push(ingestOne(block.rawBlock, block.height, false));
  });
  commit();
  return results;
}

/**
 * Read the highest indexed height from this worker connection.
 * @private
 * @returns {{height: number, hash: Buffer}} Wire-order hash; height -1 and zero hash for an empty index.
 */
function syncCheckpoint() {
  const row = db.prepare(`SELECT height, hash FROM blocks ORDER BY height DESC LIMIT 1`).get();
  if (!row) return { height: -1, hash: Buffer.alloc(32) };
  return { height: row.height, hash: Buffer.from(row.hash, 'hex').reverse() };
}

parentPort.on('message', ({ id, method, payload }) => {
  try {
    let result;
    switch (method) {
      case 'init': result = true; break;
      case 'ingest': result = ingestOne(payload.rawBlock, payload.height); break;
      case 'ingestBatch': result = ingestBatch(payload.blocks); break;
      case 'watchIdentity':
        db.prepare(`INSERT OR IGNORE INTO wallets(identity) VALUES (?)`).run(payload.identity);
        watchedIdentities.add(payload.identity);
        result = true;
        break;
      case 'walletSnapshot': result = db.transaction(() => {
        const height = db.prepare('SELECT MAX(height) AS h FROM blocks').get()?.h ?? -1;
        const utxos = [], transactions = [], legacyPending = [];
        for (const identity of payload.identities) {
          utxos.push(...db.prepare('SELECT identity,txid,vout,valueKoinu,height,coinbase FROM wallet_utxos WHERE identity=?').all(identity));
          transactions.push(...db.prepare('SELECT identity,txid,height,time,receivedKoinu,spentKoinu FROM wallet_transactions WHERE identity=? ORDER BY height DESC').all(identity));
          legacyPending.push(...db.prepare('SELECT p.inputTxid,p.vout FROM pending_withdrawal_inputs p JOIN pending_withdrawals w ON w.txid=p.txid WHERE w.identity=?').all(identity));
        }
        return { height, utxos, transactions, legacyPending };
      })(); break;
      case 'syncCheckpoint': result = syncCheckpoint(); break;
      default: throw new Error('Unknown method');
    }
    parentPort.postMessage({ id, result });
  } catch (err) {
    parentPort.postMessage({ id, error: err.message });
  }
});
