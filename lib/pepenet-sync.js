/**
 * @file Ordered headers-first public-peer catch-up with bounded block requests and ingestion.
 * Header linkage and requested hashes are checked; full consensus and fork rollback are not implemented.
 */
// pepecoin-sync-fast.js
import { EventEmitter } from 'node:events';
import { hash256d } from './pepenet-wire.js';
import { parseHeaders } from './pepenet-p2p.js';

const INVENTORY_TYPE_BLOCK = 2;
// Pepecoin archive peers commonly cap a getdata response well below a full
// 2,000-header page. Requesting 500 bodies at a time is reliable and keeps a
// stalled peer from abandoning an otherwise valid page halfway through.
const MAX_BLOCKS_PER_REQUEST = 500;
const DEFAULT_INGEST_BATCH_SIZE = 512;
const MAX_INGEST_BATCH_SIZE = 2_000;
const MAX_PENDING_BLOCK_BYTES = 256 * 1024 * 1024;
const REQUEST_TIMEOUT_MS = 30_000;
const configuredBatchSize = Number.parseInt(
  process.env.PEPE_INGEST_BATCH_SIZE || '',
  10
);
const INGEST_BATCH_SIZE =
  Number.isSafeInteger(configuredBatchSize) &&
  configuredBatchSize > 0 &&
  configuredBatchSize <= MAX_INGEST_BATCH_SIZE
    ? configuredBatchSize
    : DEFAULT_INGEST_BATCH_SIZE;
const GENESIS_HASH = Buffer.from(
  '37981c0c48b8d48965376c8a42ece9a0838daadb93ff975cb091f57f8c2a5faa',
  'hex'
).reverse();

/**
 * Download and index linked pages from a selected peer using the committed checkpoint.
 * Emits headers {count, targetHeight}, block {height, hash}, synced {height, hash},
 * error Error, reorg {conflictHeight, conflictHash}, and close events.
 * The supervisor must compare completion height with network height before permitting spending.
 * @extends EventEmitter
 */
export class PepecoinSync extends EventEmitter {
  /**
   * Read a synchronous checkpoint and attach peer message handlers without starting requests.
   * @param {Object} options - Dependencies.
   * @param {import("./pepenet-p2p.js").PepecoinPeer|import("./pepenet-p2p.js").MultiPeerManager} options.peer - Event-emitting request transport.
   * @param {import("./chain-index.js").ChainIndex} options.index - Initialized persistent index.
   * @throws {Error} If required transport or index methods are missing.
   */
  constructor({ peer, index }) {
    super();

    if (!peer || typeof peer.requestHeaders !== 'function' ||
        typeof peer.requestData !== 'function')
      throw new Error('A Pepecoin peer is required.');

    if (!index || typeof index.ingest !== 'function' || typeof index.ingestBatch !== 'function' || typeof index.syncCheckpoint !== 'function')
      throw new Error('A chain index with syncCheckpoint() is required.');

    this.peer = peer;
    this.index = index;
    // Pepecoin's archive peers support the normal headers path used by the
    // original client. Keep that simple, ordered path; AuxPoW framing is
    // handled by parseHeaders() once the chain reaches its activation height.

    const checkpoint = { height: -1, hash: Buffer.alloc(32) };
    try {
      const cp = this.index.syncCheckpoint();
      if (cp && Number.isSafeInteger(cp.height) && Buffer.isBuffer(cp.hash) && cp.hash.length === 32) {
        checkpoint.height = cp.height;
        checkpoint.hash = Buffer.from(cp.hash);
      }
    } catch {}

    this.height = checkpoint.height < 0 ? 0 : checkpoint.height;
    this.announcedHeight = this.height;
    this.tipHash = checkpoint.height < 0
      ? Buffer.from(GENESIS_HASH)
      : checkpoint.hash;

    this.pendingBlocks = new Map();
    this.pendingBytes = 0;
    this.ingestQueue = Promise.resolve();
    this.ingesting = false;
    this.waitingForEmptyHeaders = false;
    this.headerRequestInFlight = false;
    this.headerTimer = null;
    this.blockTimer = null;
    this.started = false;


    peer.on('message', m => this.#onMessage(m));
    peer.on('error', () => {});
    peer.on('close', () => this.emit('close'));
  }

  /**
   * Begin the first header request now, or when the peer becomes ready.
   * @returns {void}
   * @throws {Error} If the same attempt is already running.
   */
  start() {
    if (this.started) throw new Error('Sync is already running.');
    this.started = true;

    if (this.peer.ready) this.#requestHeaders();
    else this.peer.once('ready', () => {
      if (this.started) this.#requestHeaders();
    });
  }

  /**
   * Stop requests, cancel watchdogs and discard uncommitted pending blocks.
   * Already queued ingestion is not cancelled; the owner must await ingestQueue before closing the index.
   * @returns {void}
   */
  stop() {
    this.started = false;
    this.headerRequestInFlight = false;
    this.waitingForEmptyHeaders = false;
    if (this.headerTimer) clearTimeout(this.headerTimer);
    if (this.blockTimer) clearTimeout(this.blockTimer);
    this.headerTimer = null;
    this.blockTimer = null;
    this.pendingBlocks.clear();
    this.pendingBytes = 0;
  }

  /**
   * Request the next page from the current wire-order locator, with one request in flight.
   * @private
   * @returns {void}
   */
  #requestHeaders() {
    if (this.headerRequestInFlight) return;
    this.headerRequestInFlight = true;
    this.peer.requestHeaders([this.tipHash]);
    this.#armRequestTimeout('headers');
  }

  /**
   * Reset the response watchdog for a header page or requested block stream.
   * @private
   * @param {"headers"|"block"} kind - Response type being awaited.
   * @returns {void}
   */
  #armRequestTimeout(kind) {
    const property = kind === 'headers' ? 'headerTimer' : 'blockTimer';
    if (this[property]) clearTimeout(this[property]);
    this[property] = setTimeout(() => {
      this[property] = null;
      if (!this.started) return;
      this.emit(
        'error',
        new Error(`Timed out waiting for Pepecoin ${kind} response.`)
      );
    }, REQUEST_TIMEOUT_MS);
    this[property].unref();
  }

  /**
   * Cancel the watchdog for a completed response type.
   * @private
   * @param {"headers"|"block"} kind - Timer selector.
   * @returns {void}
   */
  #clearRequestTimeout(kind) {
    const property = kind === 'headers' ? 'headerTimer' : 'blockTimer';
    if (this[property]) clearTimeout(this[property]);
    this[property] = null;
  }

  /**
   * Dispatch relevant peer messages only while the attempt is running.
   * @private
   * @param {{command: string, payload: Buffer}} message - Decoded P2P message.
   * @returns {void}
   */
  #onMessage(message) {
    if (!this.started) return;

    if (message.command === 'headers') this.#onHeaders(message.payload);
    else if (message.command === 'block') this.#onBlock(message.payload);
  }

  /**
   * Validate header linkage, stage the next bounded page, and request its block bodies.
   * Unsolicited responses cannot complete a page while download/ingestion is active.
   * @private
   * @param {Buffer} payload - Serialized headers message payload.
   * @returns {void} Errors are emitted on this sync instance.
   */
  #onHeaders(payload) {
    try {
      if (!this.headerRequestInFlight || this.pendingBlocks.size || this.ingesting) return;
      const headers = parseHeaders(payload).slice(0, MAX_BLOCKS_PER_REQUEST);
      this.headerRequestInFlight = false;
      this.#clearRequestTimeout('headers');

      const targetHeight =
        headers.length > 0 ? (this.height + headers.length) : this.height;

      this.emit('headers', {
        count: headers.length,
        targetHeight
      });

      if (!headers.length) {
        this.waitingForEmptyHeaders = true;
        this.#finishIfSynced();
        return;
      }

      let previous = this.tipHash;
      let baseHeight = this.announcedHeight;

      for (let i = 0; i < headers.length; i++) {
        const h = headers[i];

        if (!h.previousHash.equals(previous))
          throw new Error('Peer returned a header chain that does not link to the current tip.');

        const key = h.hash.toString('hex');
        const height = baseHeight + i + 1;

        this.pendingBlocks.set(key, {
          height,
          header: h.header,
          raw: null,
          parsed: null
        });

        previous = h.hash;
      }

      this.tipHash = previous;
      this.announcedHeight = baseHeight + headers.length;

      const inventory = headers.map(h => ({
        type: INVENTORY_TYPE_BLOCK,
        hash: h.hash
      }));

      this.peer.requestData(inventory);
      this.#armRequestTimeout('block');

    } catch (err) {
      this.emit('error', err);
    }
  }

  /**
   * Accept a requested block only when its base header matches the staged announcement.
   * @private
   * @param {Buffer} raw - Full serialized block.
   * @returns {void} Unrequested or duplicate bodies are ignored.
   */
  #onBlock(raw) {
    if (!this.started) return;

    if (!Buffer.isBuffer(raw) || raw.length < 80) return;
    const header = raw.subarray(0, 80);
    const key = hash256d(header).toString('hex');
    const pending = this.pendingBlocks.get(key);

    if (!pending) return;
    if (pending.header && !header.equals(pending.header)) return;
    if (pending.hash && !hash256d(header).equals(pending.hash)) return;
    if (pending.previousHash && !header.subarray(4, 36).equals(pending.previousHash)) {
      this.stop();
      this.emit('error', new Error('Peer returned a block that does not link to the indexed tip.'));
      return;
    }
    if (pending.raw) return;

    pending.raw = raw;
    this.pendingBytes += raw.length;
    if ([...this.pendingBlocks.values()].some(block => !block.raw))
      this.#armRequestTimeout('block');
    else
      this.#clearRequestTimeout('block');

    this.#drainPending();
  }

  /**
   * Queue a contiguous batch for atomic index ingestion and emit committed block results.
   * @private
   * @param {Array<{key: string, pending: Object}>} batch - Staged blocks with raw bytes and assigned heights.
   * @returns {Promise<void>} Completion of queued ingestion; failures reject or emit reorg.
   */
  #parseAndIngest(batch) {
    this.ingestQueue = this.ingestQueue.then(async () => {
      try {
        const results = await this.index.ingestBatch(batch.map(({ key, pending }) => ({
          rawBlock: pending.raw,
          height: pending.height
        })));
        for (let index = 0; index < batch.length; index++) {
          const { key, pending } = batch[index];
          this.pendingBlocks.delete(key);
          this.pendingBytes -= pending.raw.length;
          this.height = pending.height;
          this.tipHash = hash256d(pending.raw.subarray(0, 80));
          this.emit('block', {
            height: pending.height,
            hash: Buffer.from(results[index].blockHash, 'hex')
          });
        }

        this.#drainPending();
      } catch (err) {
        const msg = String(err.message || '');
        if (msg.includes('reorg rollback is required')) {
          this.pendingBlocks.clear();
          this.pendingBytes = 0;
          this.started = false;

          this.emit('reorg', {
            conflictHeight: batch[0].pending.height,
            conflictHash: Buffer.from(batch[0].key, 'hex')
          });

          return;
        }

        throw err;
      }
    });

    return this.ingestQueue;
  }

  /**
   * Ingest available contiguous blocks before requesting another header page.
   * @private
   * @returns {void}
   */
  #drainPending() {
    if (!this.started || this.ingesting) return;
    const batch = [];
    let nextHeight = this.height + 1;
    for (const [key, pending] of this.pendingBlocks) {
      if (pending.height !== nextHeight || !pending.raw) break;
      batch.push({ key, pending });
      nextHeight++;
      if (batch.length === INGEST_BATCH_SIZE) break;
    }
    if (batch.length) {
      this.ingesting = true;
      this.#parseAndIngest(batch)
        .catch(err => this.emit('error', err))
        .finally(() => { this.ingesting = false; this.#drainPending(); });
      return;
    }

    // Do not advance the locator while this page still has unreceived block
    // bodies. Advancing early mixes pages and causes the next request to race
    // a peer's getdata response.
    if (this.pendingBlocks.size) return;

    if (this.waitingForEmptyHeaders) this.#finishIfSynced();
    else if (this.pendingBytes < MAX_PENDING_BLOCK_BYTES)
      this.#requestHeaders();
  }

  /**
   * Emit local catch-up completion only after an empty requested page and no pending bodies.
   * @private
   * @returns {void}
   */
  #finishIfSynced() {
    if (!this.started ||
        !this.waitingForEmptyHeaders ||
        this.pendingBlocks.size)
      return;
    this.started = false;
    this.emit('synced', {
      height: this.height,
      hash: Buffer.from(this.tipHash)
    });
  }
}
