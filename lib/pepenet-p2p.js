/**
 * @file Outbound Pepecoin P2P framing, discovery, peer management and transaction relay.
 * Wire hashes are raw 32-byte digests; reverse them only when displaying conventional hex IDs.
 * A peer receipt verifies relay, not mining, confirmation or full consensus validity.
 *
 * @typedef {{type: number, hash: Buffer}} InventoryItem
 *
 * @typedef {{command: string, payload: Buffer}} PeerMessage
 *
 * @typedef {{host: string, port: number, services: bigint}} PeerAddress
 */
import { createHash, randomBytes } from 'node:crypto';
import { EventEmitter } from 'node:events';
import net from 'node:net';
import { lookup } from 'node:dns/promises';
import { skipAuxPow } from './pepenet-wire.js';

/**
 * Mainnet magic bytes, default TCP port and advertised wire protocol version.
 * @type {Readonly<{magic: Buffer, port: number, protocolVersion: number}>}
 */
export const PEP_NETWORK = Object.freeze({
  magic: Buffer.from([0xc0, 0xa0, 0xf0, 0xe0]),
  port: 33874,
  // Pepecoin's namespace indexer pins 70015 for wire compatibility with
  // publicly reachable Pepecoin Core peers.
  protocolVersion: 70015
});

// The PepeNet desktop reference lists its two public archive peers first.  The
// Core DNS seeds remain fallbacks; a single vSeed is not a reliable source of
// archive peers.  All entries are remote public peers, never localhost.
/**
 * Public DNS seed names used to discover remote peers; availability is not guaranteed.
 * @type {ReadonlyArray<string>}
 */
export const PEP_DNS_SEEDS = Object.freeze([
  'pepenet.shibpost.com',
  'net.pepecoin.services',
  'seeds.pepecoin.org',
  'seeds.pepeblocks.com'
]);

// Public NODE_NETWORK peers learned from the PepeNet seed's address book and
// verified by an outbound handshake.  They are direct fallbacks so a seed that
// only serves recent history cannot prevent a deep sync while its addr reply is
// still being processed.  None is a local/private address.
/**
 * Fallback remote peer candidates; their current service flags are checked after handshake.
 * @type {ReadonlyArray<{host: string, port: number}>}
 */
export const PEP_ARCHIVE_PEERS = Object.freeze([
  { host: '98.80.234.184', port: 33874 },
  { host: '209.74.87.138', port: 33874 },
  { host: '162.55.243.24', port: 33874 },
  { host: '39.109.12.163', port: 33874 },
  { host: '5.161.85.224', port: 33874 },
  { host: '157.90.88.178', port: 9152 }
]);

const MAX_MESSAGE_BYTES = 32 * 1024 * 1024;
const MAX_HEADERS = 2000000;
const MAX_INVENTORY = 2000000;

/**
 * Compute double-SHA256 without reversing digest bytes.
 * @param {Buffer|Uint8Array} bytes - Input bytes.
 * @returns {Buffer} 32-byte digest.
 */
const hash256 = bytes =>
  createHash('sha256')
    .update(createHash('sha256').update(bytes).digest())
    .digest();

/**
 * Compute the double-SHA-256 digest used by P2P checksums and transaction IDs.
 * @param {Buffer} bytes - Input bytes.
 * @returns {Buffer} Raw 32-byte digest.
 */
export const hash256d = hash256;

/**
 * Encode a non-negative safe integer as CompactSize.
 * @param {number} value - Count to serialize.
 * @returns {Buffer} One-, three-, five- or nine-byte encoding.
 * @throws {Error} If the value is negative or not a safe integer.
 */
export const varInt = value => {
  if (!Number.isSafeInteger(value) || value < 0)
    throw new Error('Invalid P2P count.');
  if (value < 0xfd) return Buffer.from([value]);
  if (value <= 0xffff) {
    const out = Buffer.alloc(3);
    out[0] = 0xfd;
    out.writeUInt16LE(value, 1);
    return out;
  }
  if (value <= 0xffffffff) {
    const out = Buffer.alloc(5);
    out[0] = 0xfe;
    out.writeUInt32LE(value, 1);
    return out;
  }
  const out = Buffer.alloc(9);
  out[0] = 0xff;
  out.writeBigUInt64LE(BigInt(value), 1);
  return out;
};

/**
 * Decode a CompactSize count, clamping oversized values to MAX_INVENTORY.
 * @private
 * @param {Buffer} payload - Serialized message bytes.
 * @param {number} [offset=0] - Start offset.
 * @returns {{value: number, offset: number}} Decoded/clamped value and next unread offset.
 * @throws {Error} If the count is truncated.
 */
function readVarInt(payload, offset = 0) {
  if (!Buffer.isBuffer(payload) || offset >= payload.length)
    throw new Error('Truncated P2P varint.');
  const lead = payload[offset++];
  if (lead < 0xfd) return { value: lead, offset };
  const length = lead === 0xfd ? 2 : lead === 0xfe ? 4 : 8;
  if (offset + length > payload.length)
    throw new Error('Truncated P2P varint.');
  const raw =
    length === 2
      ? BigInt(payload.readUInt16LE(offset))
      : length === 4
      ? BigInt(payload.readUInt32LE(offset))
      : payload.readBigUInt64LE(offset);

  if (raw > BigInt(MAX_INVENTORY))
    return { value: MAX_INVENTORY, offset: offset + length };

  return { value: Number(raw), offset: offset + length };
}

/**
 * Extract advertised starting height from a peer version payload.
 * @private
 * @param {Buffer} payload - Version message payload.
 * @returns {number|null} Advertised height, or null for unsupported/truncated framing.
 */
function peerStartHeight(payload) {
  if (!Buffer.isBuffer(payload) || payload.length < 85) return null;
  try {
    const agent = readVarInt(payload, 80);
    return agent.offset + agent.value + 4 <= payload.length
      ? payload.readInt32LE(agent.offset + agent.value)
      : null;
  } catch {
    return null;
  }
}

/**
 * Frame a P2P command with network magic, payload length and checksum.
 * @param {string} command - One to twelve lowercase ASCII letters.
 * @param {Buffer} [payload] - Message body; defaults to empty.
 * @returns {Buffer} Complete 24-byte header followed by payload.
 * @throws {Error} If the command is invalid.
 */
export function encodeMessage(command, payload = Buffer.alloc(0)) {
  if (!/^[a-z]{1,12}$/.test(command))
    throw new Error('Invalid P2P command.');
  const header = Buffer.alloc(24);
  PEP_NETWORK.magic.copy(header, 0);
  header.write(command, 4, 'ascii');
  header.writeUInt32LE(payload.length, 16);
  hash256(payload).copy(header, 20, 0, 4);
  return Buffer.concat([header, payload]);
}

/**
 * Incrementally collect framed messages from arbitrary TCP chunks.
 */
export class MessageDecoder {
  /**
   * Initialize an empty receive buffer.
   */
  constructor() {
    this.buffer = Buffer.alloc(0);
  }
  /**
   * Append bytes and return complete checksum-valid messages, retaining partial frames.
   * Bad-checksum frames are discarded; oversized messages clear the buffer and throw.
   * @param {Buffer} chunk - Next TCP chunk.
   * @returns {PeerMessage[]} Complete decoded messages.
   * @throws {Error} If a framed payload exceeds the configured byte limit.
   */
  push(chunk) {
    this.buffer = Buffer.concat([this.buffer, chunk]);
    const messages = [];
    while (this.buffer.length >= 24) {
      if (!this.buffer.subarray(0, 4).equals(PEP_NETWORK.magic))
        return [];
      const commandBytes = this.buffer.subarray(4, 16);
      const nul = commandBytes.indexOf(0);
      const command = commandBytes
        .subarray(0, nul < 0 ? 12 : nul)
        .toString('ascii');
      const length = this.buffer.readUInt32LE(16);
      if (length > MAX_MESSAGE_BYTES) {
        this.buffer = Buffer.alloc(0);
        throw new Error('Pepecoin message exceeds the permitted size.');
      }
      if (this.buffer.length < 24 + length) break;
      const payload = this.buffer.subarray(24, 24 + length);
      const checksum = this.buffer.subarray(20, 24);
      if (!hash256(payload).subarray(0, 4).equals(checksum)) {
        this.buffer = this.buffer.subarray(24 + length);
        continue;
      }
      messages.push({ command, payload: Buffer.from(payload) });
      this.buffer = this.buffer.subarray(24 + length);
    }
    return messages;
  }
}

/**
 * Write a signed 64-bit value to an existing buffer.
 * @private
 * @param {Buffer} buffer - Destination.
 * @param {bigint|number} value - Integer to serialize.
 * @param {number} offset - Destination byte offset.
 * @returns {void}
 */
function writeInt64LE(buffer, value, offset) {
  buffer.writeBigInt64LE(BigInt(value), offset);
}

/**
 * Serialize a legacy P2P network address with little-endian services and big-endian port.
 * @private
 * @param {string} host - IPv4 text; unsupported forms leave the IP bytes unspecified.
 * @param {number} port - TCP port.
 * @param {bigint|number} services - Advertised service bitfield.
 * @returns {Buffer} 26-byte network address.
 */
function networkAddress(host, port, services) {
  const address = Buffer.alloc(26);
  address.writeBigUInt64LE(BigInt(services), 0);
  // P2P addresses are IPv6. IPv4 peers use the IPv4-mapped IPv6 form.
  const octets = String(host).split('.').map(Number);
  if (octets.length === 4 && octets.every(value => Number.isInteger(value) && value >= 0 && value <= 255)) {
    address[18] = 0xff;
    address[19] = 0xff;
    Buffer.from(octets).copy(address, 20);
  }
  address.writeUInt16BE(port, 24);
  return address;
}

/**
 * Construct an outbound version handshake with nonce, client identifier and starting height.
 * @param {number} [startHeight=0] - Local indexed height.
 * @param {string} [receiverHost] - Optional receiver IPv4 address.
 * @param {number} [receiverPort] - Optional receiver port, defaulting to mainnet when address fields are supplied.
 * @returns {Buffer} Serialized version payload.
 * @throws {Error} If the starting height is not a safe integer.
 */
export function versionPayload(startHeight = 0, receiverHost, receiverPort) {
  if (!Number.isSafeInteger(startHeight)) throw new Error('Invalid Pepecoin start height.');
  const agent = Buffer.from('/pepecoin-js-wallet:0.2/');
  const payload = Buffer.alloc(80);

  payload.writeInt32LE(PEP_NETWORK.protocolVersion, 0);
  writeInt64LE(payload, 0n, 4);
  writeInt64LE(payload, BigInt(Math.floor(Date.now() / 1000)), 12);
  // Pepecoin Core has historically accepted this confirmation-only client
  // when both legacy address fields are unspecified.  Do not advertise a
  // guessed local address or service while connecting outbound.
  if (receiverHost !== undefined || receiverPort !== undefined) {
    networkAddress(receiverHost || '0.0.0.0', receiverPort || PEP_NETWORK.port, 0n).copy(payload, 20);
    networkAddress('0.0.0.0', 0, 1n).copy(payload, 46);
  }
  randomBytes(8).copy(payload, 72);
  const tail = Buffer.alloc(5);
  tail.writeInt32LE(startHeight, 0);
  tail[4] = 1;
  return Buffer.concat([payload, varInt(agent.length), agent, tail]);
}

/**
 * Serialize a getheaders/getblocks locator and stop hash.
 * @private
 * @param {Buffer[]} locatorHashes - Non-empty array of 32-byte wire-order hashes.
 * @param {Buffer} stopHash - 32-byte wire-order stop hash.
 * @returns {Buffer} Version-prefixed locator payload.
 * @throws {Error} If any hash length or input shape is invalid.
 */
function locatorPayload(locatorHashes, stopHash) {
  if (!Array.isArray(locatorHashes) || !locatorHashes.length ||
      locatorHashes.some(hash => !Buffer.isBuffer(hash) || hash.length !== 32) ||
      !Buffer.isBuffer(stopHash) || stopHash.length !== 32)
    throw new Error('Invalid Pepecoin block locator.');
  const version = Buffer.alloc(4);
  version.writeInt32LE(PEP_NETWORK.protocolVersion);
  return Buffer.concat([
    version,
    varInt(locatorHashes.length),
    ...locatorHashes,
    stopHash
  ]);
}

/**
 * Serialize typed inventory entries for inv/getdata messages.
 * @param {InventoryItem[]} items - Typed 32-byte wire-order hashes.
 * @returns {Buffer} CompactSize count and serialized entries.
 * @throws {Error} If item counts, types or hash buffers are invalid.
 */
export function inventoryPayload(items) {
  if (!Array.isArray(items) || items.length > MAX_INVENTORY)
    throw new Error('Invalid P2P inventory.');
  const entries = items.map(item => {
    if (!item || !Number.isSafeInteger(item.type) || !Buffer.isBuffer(item.hash) || item.hash.length !== 32)
      throw new Error('Invalid P2P inventory item.');
    const entry = Buffer.alloc(36);
    entry.writeUInt32LE(item.type);
    item.hash.copy(entry, 4);
    return entry;
  });
  return Buffer.concat([varInt(items.length), ...entries]);
}

/**
 * Decode an exactly framed inventory message.
 * @param {Buffer} payload - inv/getdata/notfound payload.
 * @returns {InventoryItem[]} Typed wire-order hashes.
 * @throws {Error} If counts or payload size are invalid.
 */
export function parseInventory(payload) {
  const count = readVarInt(payload);
  if (count.value > MAX_INVENTORY || payload.length !== count.offset + count.value * 36)
    throw new Error('Invalid inventory payload.');
  const inventory = [];
  let offset = count.offset;
  for (let i = 0; i < count.value; i++, offset += 36) {
    inventory.push({
      type: payload.readUInt32LE(offset),
      hash: Buffer.from(payload.subarray(offset + 4, offset + 36))
    });
  }
  return inventory;
}

/**
 * Decode legacy addr entries, retaining IPv4-mapped candidates after local/private-range filtering.
 * @param {Buffer} payload - addr message payload, at most 1000 entries.
 * @returns {PeerAddress[]} Candidate hosts, ports and service flags.
 * @throws {Error} If entry counts or framing are invalid.
 */
export function parseAddresses(payload) {
  const count = readVarInt(payload);
  const entryBytes = 30; // time + services + 16-byte IP + big-endian port
  if (count.value > 1_000 || payload.length !== count.offset + count.value * entryBytes)
    throw new Error('Invalid Pepecoin address payload.');

  const addresses = [];
  for (let offset = count.offset; offset < payload.length; offset += entryBytes) {
    const services = payload.readBigUInt64LE(offset + 4);
    const ip = payload.subarray(offset + 12, offset + 28);
    // Keep only public IPv4-mapped addresses. They are usable by Node's TCP
    // client and cannot accidentally route this application to localhost.
    if (!ip.subarray(0, 12).equals(Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])))
      continue;
    const [a, b, c, d] = ip.subarray(12);
    if (a === 0 || a === 10 || a === 127 || a >= 224 ||
        (a === 169 && b === 254) ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168)) continue;
    const port = payload.readUInt16BE(offset + 28);
    if (!port) continue;
    addresses.push({ host: `${a}.${b}.${c}.${d}`, port, services });
  }
  return addresses;
}

/**
 * Decode base headers and skip attached AuxPoW records without validating their proofs.
 * Header linkage, requested-body matching and consensus checks belong to higher layers.
 * @param {Buffer} payload - headers message payload.
 * @returns {Array<{header: Buffer, hash: Buffer, previousHash: Buffer, time: number, bits: number}>} Header metadata with wire-order hashes.
 * @throws {Error} For truncated headers/AuxPoW or trailing payload bytes.
 */
export function parseHeaders(payload) {
  const count = readVarInt(payload);
  const headers = [];
  let offset = count.offset;
  if (count.value > MAX_HEADERS) throw new Error('Too many headers in Pepecoin response.');

  for (let i = 0; i < count.value; i++) {
    if (offset + 80 > payload.length) throw new Error('Truncated Pepecoin headers response.');
    const header = Buffer.from(payload.subarray(offset, offset + 80));
    offset += 80;
    if (header.readUInt32LE(0) & 0x100) offset = skipAuxPow(payload, offset);
    const txCount = readVarInt(payload, offset);
    offset = txCount.offset;
    headers.push({
      header,
      hash: hash256(header),
      previousHash: Buffer.from(header.subarray(4, 36)),
      time: header.readUInt32LE(68),
      bits: header.readUInt32LE(72)
    });
  }
  if (offset !== payload.length) throw new Error('Trailing data in Pepecoin headers response.');
  return headers;
}

/**
 * Own one outbound TCP peer and version/verack handshake state.
 * Emits ready, message (PeerMessage), error (Error) and close events.
 * @extends EventEmitter
 */
export class PepecoinPeer extends EventEmitter {
  /**
   * Configure a peer without opening a connection.
   * @param {Object} options - Connection settings.
   * @param {string} options.host - Remote peer hostname or address.
   * @param {number} [options.port=33874] - Remote TCP port.
   * @param {number} [options.startHeight=0] - Local height advertised in the handshake.
   * @param {number} [options.timeoutMs=10000] - Handshake deadline in milliseconds.
   */
  constructor({ host, port = PEP_NETWORK.port, startHeight = 0, timeoutMs = 10000 }) {
    super();
    this.host = host;
    this.port = port;
    this.startHeight = startHeight;
    this.timeoutMs = timeoutMs;
    this.socket = null;
    this.decoder = new MessageDecoder();
    this.gotVersion = false;
    this.gotVerack = false;
    this.ready = false;
    this.remoteStartHeight = null;
    this.remoteServices = 0n;
  }

  /**
   * Connect and await both version and verack before reporting readiness.
   * @returns {Promise<PepecoinPeer>} This ready peer.
   * @throws {Error} Rejects if already connected, timed out, disconnected or the dial fails.
   */
  async connect() {
    if (this.socket) throw new Error('Peer is already connected.');
    await new Promise((resolve, reject) => {
      const socket = (this.socket = net.createConnection({
        host: this.host,
        port: this.port
      }));
      let settled = false;

      const complete = () => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          resolve();
        }
      };

      const fail = error => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          this.socket = null;
          socket.destroy();
          reject(error);
        }
      };

      const timer = setTimeout(() => fail(new Error('Pepecoin peer connection timed out.')), this.timeoutMs);

      socket.once('error', fail);
      socket.once('connect', () => {
        socket.off('error', fail);
        socket.on('data', data => {
          try {
            this.#receive(data);
          } catch {
            socket.end();
          }
        });
        socket.on('error', error => (this.ready ? this.emit('error', error) : fail(error)));
        socket.on('close', () => {
          if (!this.ready) fail(new Error('Pepecoin peer closed during handshake.'));
          this.emit('close');
        });

        this.once('ready', complete);
        this.send('version', versionPayload(this.startHeight));
      });
    });
    return this;
  }

  /**
   * Write a framed message if a usable socket exists; a write is not a peer acknowledgment.
   * @param {string} command - P2P command name.
   * @param {Buffer} payload - Serialized command body.
   * @returns {void}
   */
  send(command, payload) {
    if (!this.socket || this.socket.destroyed) return;
    this.socket.write(encodeMessage(command, payload));
  }

  /**
   * Request headers following a known locator.
   * @param {Buffer[]} locatorHashes - Known 32-byte block hashes in wire order.
   * @param {Buffer} [stopHash] - Wire-order stop hash; defaults to all zero bytes.
   * @returns {void}
   */
  requestHeaders(locatorHashes, stopHash = Buffer.alloc(32)) {
    this.send('getheaders', locatorPayload(locatorHashes, stopHash));
  }

  /**
   * Request block inventory following a known locator.
   * @param {Buffer[]} locatorHashes - Known 32-byte block hashes in wire order.
   * @param {Buffer} [stopHash] - Wire-order stop hash; defaults to all zero bytes.
   * @returns {void}
   */
  requestBlocks(locatorHashes, stopHash = Buffer.alloc(32)) {
    this.send('getblocks', locatorPayload(locatorHashes, stopHash));
  }

  /**
   * Request full objects by typed inventory identifiers.
   * @param {InventoryItem[]} items - Block or transaction identifiers.
   * @returns {void}
   */
  requestData(items) {
    this.send('getdata', inventoryPayload(items));
  }

  /**
   * Send a signed transaction, then require the peer to serve the exact bytes back.
   * Rejects/timeouts leave confirmation uncertain: callers must retain input reservations.
   * @param {Buffer} rawTransaction - Exact signed transaction bytes.
   * @param {{timeoutMs?: number}} [options={}] - Receipt deadline, default 8000 milliseconds.
   * @returns {Promise<void>} Resolves on byte-for-byte peer receipt, not block confirmation.
   * @throws {Error} Rejects on matching peer rejection, notfound, disconnect or timeout.
   */
  broadcastTransaction(rawTransaction, { timeoutMs = 8000 } = {}) {
    if (!Buffer.isBuffer(rawTransaction) || !rawTransaction.length)
      return Promise.reject(new Error('A serialized Pepecoin transaction is required.'));
    if (!this.socket || this.socket.destroyed)
      return Promise.reject(new Error('Pepecoin peer is not connected.'));
    const txHash = hash256(rawTransaction);
    const nonce = randomBytes(8);
    return new Promise((resolve, reject) => {
      let settled = false;
      const finish = error => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.off('message', onMessage);
        this.off('close', onClose);
        this.off('error', onError);
        error ? reject(error) : resolve();
      };
      const onClose = () => finish(new Error('Peer disconnected before transaction relay could be verified.'));
      const onError = error => finish(error);
      const onMessage = message => {
        try {
          if (message.command === 'reject') {
            const command = readVarInt(message.payload);
            const end = command.offset + command.value;
            if (message.payload.subarray(command.offset, end).toString() !== 'tx') return;
            const reason = readVarInt(message.payload, end + 1);
            const reasonEnd = reason.offset + reason.value;
            if (reasonEnd + 32 > message.payload.length) return;
            if (!message.payload.subarray(reasonEnd, reasonEnd + 32).equals(txHash)) return;
            finish(new Error(`Pepecoin peer rejected transaction: ${message.payload.subarray(reason.offset, reasonEnd).toString()}`));
          } else if (message.command === 'pong' && message.payload.equals(nonce)) {
            // A write callback proves only that bytes reached the local socket.
            // Ask for the transaction after the peer has processed our messages.
            this.requestData([{ type: 1, hash: txHash }]);
          } else if (message.command === 'tx' && message.payload.equals(rawTransaction)) {
            finish();
          } else if (message.command === 'notfound' &&
              parseInventory(message.payload).some(item => item.type === 1 && item.hash.equals(txHash))) {
            finish(new Error('Pepecoin peer did not retain the transaction; relay could not be verified.'));
          }
        } catch (error) { finish(error); }
      };
      const timer = setTimeout(() => finish(new Error('Timed out verifying transaction relay; confirmation is unknown.')), timeoutMs);
      this.on('message', onMessage);
      this.once('close', onClose);
      this.on('error', onError);
      this.socket.write(encodeMessage('tx', rawTransaction), error => {
        if (settled) return;
        if (error) finish(error);
        else this.send('ping', nonce);
      });
    });
  }

  /**
   * Observe the next reject message during a short window.
   * This legacy helper does not correlate a transaction; silence is not relay verification.
   * @param {number} [timeoutMs=1000] - Observation window in milliseconds.
   * @returns {Promise<void>} Resolves on silence; rejects on a reject message.
   */
  waitForReject(timeoutMs = 1_000) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.off('message', onMessage);
        resolve();
      }, timeoutMs);
      timer.unref?.();
      const onMessage = message => {
        if (message.command !== 'reject') return;
        clearTimeout(timer);
        this.off('message', onMessage);
        const payload = message.payload;
        try {
          const command = readVarInt(payload, 0);
          const commandEnd = command.offset + command.value;
          const codeOffset = commandEnd + 1;
          const reason = readVarInt(payload, codeOffset);
          const reasonEnd = reason.offset + reason.value;
          if (reasonEnd > payload.length) throw new Error('Truncated reject message.');
          reject(new Error(payload.subarray(reason.offset, reasonEnd).toString('utf8') || 'Pepecoin peer rejected the transaction.'));
        } catch (error) {
          reject(error);
        }
      };
      this.on('message', onMessage);
    });
  }

  /**
   * Destroy this peer’s socket without opening a replacement connection.
   * @returns {void}
   */
  close() {
    this.socket?.destroy();
    this.socket = null;
  }

  /**
   * Decode incoming frames, handle handshake/ping messages and forward peer events.
   * @private
   * @param {Buffer} data - Next TCP chunk.
   * @returns {void}
   */
  #receive(data) {
    for (const message of this.decoder.push(data)) {
      if (message.command === 'version') {
        this.gotVersion = true;
        if (message.payload.length >= 12)
          this.remoteServices = message.payload.readBigUInt64LE(4);
        this.remoteStartHeight = peerStartHeight(message.payload);
        this.send('verack');
      }
      if (message.command === 'verack') this.gotVerack = true;
      if (message.command === 'ping') this.send('pong', message.payload);

      this.emit('message', message);

      if (this.gotVersion && this.gotVerack && !this.ready) {
        this.ready = true;
        this.emit('ready');
        // Learn public peers from the connected peer as a supplementary
        // discovery channel; this does not rely on a local node.
        this.send('getaddr');
      }
    }
  }
}

/**
 * Resolve DNS seeds concurrently and deduplicate discovered addresses.
 * @param {ReadonlyArray<string>} [seeds=PEP_DNS_SEEDS] - DNS seed names.
 * @returns {Promise<string[]>} Resolved host addresses; individual seed failures are tolerated.
 * @throws {Error} Rejects if no seed yields an address.
 */
export async function discoverPeers(seeds = PEP_DNS_SEEDS) {
  const results = await Promise.allSettled(
    seeds.map(seed => lookup(seed, { all: true, verbatim: true }))
  );
  const hosts = [
    ...new Set(
      results.flatMap(result =>
        result.status === 'fulfilled'
          ? result.value.map(row => row.address)
          : []
      )
    )
  ];
  if (!hosts.length) throw new Error('Could not discover a Pepecoin peer from the DNS seeds.');
  return hosts;
}

/**
 * Try discovered peers sequentially until one completes a handshake.
 * @param {Object} [options={}] - Discovery and dialing settings.
 * @param {ReadonlyArray<string>} [options.seeds=PEP_DNS_SEEDS] - DNS seed names.
 * @param {number} [options.port=33874] - Peer port.
 * @param {number} [options.startHeight=0] - Advertised local height.
 * @param {number} [options.timeoutMs=10000] - Per-peer handshake deadline.
 * @returns {Promise<PepecoinPeer>} Ready peer owned by the caller, which must close it.
 * @throws {Error} Rejects if discovery or every dial fails.
 */
export async function connectDiscoveredPeer({
  seeds = PEP_DNS_SEEDS,
  port = PEP_NETWORK.port,
  startHeight = 0,
  timeoutMs = 10000
} = {}) {
  const hosts = await discoverPeers(seeds);
  const errors = [];
  for (const host of hosts) {
    const peer = new PepecoinPeer({ host, port, startHeight, timeoutMs });
    try {
      await peer.connect();
      return peer;
    } catch (error) {
      errors.push(`${host}: ${error.message}`);
      peer.close();
    }
  }
  throw new Error(`Unable to connect to a discovered Pepecoin peer. ${errors.join(' | ')}`);
}

/**
 * Attempt verified relay through bounded concurrent public-peer candidates.
 * Closes every temporary connection. Success does not establish chain confirmation.
 * @param {Buffer} rawTransaction - Exact signed transaction bytes to relay.
 * @param {Object} [options={}] - Discovery and concurrency settings.
 * @param {ReadonlyArray<string>} [options.seeds=PEP_DNS_SEEDS] - Supplementary DNS seeds.
 * @param {number} [options.port=33874] - Port for DNS-discovered peers.
 * @param {number} [options.timeoutMs=4000] - Per-peer handshake deadline.
 * @param {number} [options.maxPeers=3] - Maximum concurrent relay attempts.
 * @returns {Promise<number>} Number of peers that verified receipt.
 * @throws {Error} Rejects if no peer receipt can be verified; the transaction may still confirm.
 */
export async function broadcastDiscoveredTransaction(
  rawTransaction,
  { seeds = PEP_DNS_SEEDS, port = PEP_NETWORK.port, timeoutMs = 4000, maxPeers = 3 } = {}
) {
  const hosts = await discoverPeers(seeds).catch(() => []);
  const candidates = [...PEP_ARCHIVE_PEERS, ...hosts.map(host => ({ host, port }))]
    .filter((peer, i, all) => all.findIndex(other => other.host === peer.host && other.port === peer.port) === i)
    .slice(0, 12);
  const errors = [];
  let sent = 0;
  let next = 0;
  await Promise.all(Array.from({ length: Math.min(maxPeers, candidates.length) }, async () => {
    while (next < candidates.length && !sent) {
      const address = candidates[next++];
      const peer = new PepecoinPeer({ ...address, timeoutMs });
      peer.on('error', () => {});
      try {
        await peer.connect();
        await peer.broadcastTransaction(rawTransaction);
        sent++;
      } catch (err) {
        errors.push(`${address.host}: ${err.message}`);
      } finally {
        peer.close();
      }
    }
  }));

  if (!sent) throw new Error(`Transaction relay could not be verified. ${errors.join(' | ')}`);
  return sent;
}

/**
 * Manage candidate peers and route chain responses only from the selected sync peer.
 * Emits ready/archiveReady ({peer}), message (PeerMessage), and peerError ({peer, error}).
 * Service flags and remote heights are peer claims, not consensus proofs.
 * @extends EventEmitter
 */
export class MultiPeerManager extends EventEmitter {
  /**
   * Configure a peer pool without dialing.
   * @param {Object} [options={}] - Pool configuration.
   * @param {number} [options.maxPeers=12] - Concurrent peer connection limit.
   * @param {number} [options.startHeight=0] - Advertised local height.
   * @param {number} [options.timeoutMs=10000] - Handshake deadline per candidate.
   * @param {ReadonlyArray<string>} [options.seeds=PEP_DNS_SEEDS] - DNS seed names.
   * @param {ReadonlyArray<{host: string, port: number}>} [options.archivePeers=PEP_ARCHIVE_PEERS] - Preferred fallback candidates.
   * @param {number} [options.port=33874] - Default discovered-peer port.
   */
  constructor({
    maxPeers = 12,
    startHeight = 0,
    timeoutMs = 10000,
    seeds = PEP_DNS_SEEDS,
    archivePeers = PEP_ARCHIVE_PEERS,
    port = PEP_NETWORK.port
  } = {}) {
    super();
    this.maxPeers = maxPeers;
    this.startHeight = startHeight;
    this.timeoutMs = timeoutMs;
    this.seeds = seeds;
    this.archivePeers = archivePeers;
    this.port = port;
    this.peers = new Set();
    this.readyPeers = new Set();
    this.syncPeer = null;
    this.candidates = [];
    this.candidateKeys = new Set();
    this.closed = false;
  }

  /**
   * Track an existing peer or begin its handshake, forwarding readiness and failures.
   * @param {PepecoinPeer} peer - Peer instance transferred to pool ownership.
   * @returns {void}
   */
  connectTo(peer) {
    if (this.closed) return;
    this.#wirePeer(peer);
    if (peer.ready) {
      this.readyPeers.add(peer);
      this.emit('ready', { peer });
      if (((peer.remoteServices ?? 0n) & 1n) === 1n) this.emit('archiveReady', { peer });
    } else {
      peer.connect().catch(error => {
        this.emit('peerError', { peer, error });
        this.#dropPeer(peer);
      });
    }
  }

  /**
   * Queue fallback and DNS candidates, then begin filling connection slots.
   * @returns {Promise<void>} Discovery/setup completion, not readiness of all peers.
   * @throws {Error} Rejects if DNS discovery yields no addresses.
   */
  async connect() {
    for (const peer of this.archivePeers)
      this.#queueCandidate(peer.host, peer.port, 1n);
    const hosts = await discoverPeers(this.seeds);
    if (this.closed) return;
    for (const host of hosts) this.#queueCandidate(host, this.port, 0n);
    this.#fillConnections();
  }

  /**
   * Attach readiness/discovery handlers and isolate chain messages to the selected peer.
   * @private
   * @param {PepecoinPeer} peer - Pool-owned peer.
   * @returns {void}
   */
  #wirePeer(peer) {
    this.peers.add(peer);
    peer.on('ready', () => {
      if (this.closed) { peer.close(); return; }
      this.readyPeers.add(peer);
      this.emit('ready', { peer });
      if ((peer.remoteServices & 1n) === 1n)
        this.emit('archiveReady', { peer });
    });
    peer.on('message', message => {
      if (message.command === 'addr') {
        try {
          for (const address of parseAddresses(message.payload))
            this.#queueCandidate(address.host, address.port, address.services);
          this.#fillConnections();
        } catch {}
      }
      // Chain responses belong to the selected sync peer. An unrelated
      // peer's empty headers must not terminate another peer's download.
      if (['headers', 'block', 'inv', 'notfound'].includes(message.command) && peer !== this.syncPeer) return;
      this.emit('message', message);
    });
    peer.on('error', () => this.#dropPeer(peer));
    peer.on('close', () => this.#dropPeer(peer));
  }

  /**
   * Remove and close a failed peer, then fill a free slot unless the pool is closed.
   * @private
   * @param {PepecoinPeer} peer - Peer to remove.
   * @returns {void}
   */
  #dropPeer(peer) {
    if (!this.peers.has(peer)) return;
    this.readyPeers.delete(peer);
    this.peers.delete(peer);
    if (this.syncPeer === peer) this.syncPeer = null;
    peer.close();
    this.#fillConnections();
  }

  /**
   * Deduplicate host/port pairs and prioritize candidates advertising full block service.
   * @private
   * @param {string} host - Candidate host.
   * @param {number} port - Candidate TCP port.
   * @param {bigint} services - Advertised service flags.
   * @returns {void}
   */
  #queueCandidate(host, port, services) {
    const key = `${host}:${port}`;
    if (this.candidateKeys.has(key)) return;
    this.candidateKeys.add(key);
    const candidate = { host, port, services };
    // Full NODE_NETWORK peers can supply a deep catch-up. Prefer them over
    // NODE_NETWORK_LIMITED mesh peers learned from addr gossip.
    if ((services & 1n) === 1n) this.candidates.unshift(candidate);
    else this.candidates.push(candidate);
  }

  /**
   * Start queued dials until the pool reaches its configured connection limit.
   * @private
   * @returns {void}
   */
  #fillConnections() {
    if (this.closed) return;
    while (this.peers.size < this.maxPeers && this.candidates.length) {
      const candidate = this.candidates.shift();
      const peer = new PepecoinPeer({
        host: candidate.host,
        port: candidate.port,
        startHeight: this.startHeight,
        timeoutMs: this.timeoutMs
      });
      this.connectTo(peer);
    }
  }

  /**
   * Send a framed command to every ready peer.
   * @param {string} command - P2P command name.
   * @param {Buffer} payload - Serialized body.
   * @returns {void}
   */
  send(command, payload) {
    for (const peer of this.readyPeers) peer.send(command, payload);
  }

  /**
   * Select or retain a full-service sync peer and request its next header page.
   * Returns without sending when no suitable peer is ready.
   * @param {Buffer[]} locatorHashes - Known 32-byte block hashes in wire order.
   * @param {Buffer} [stopHash] - Wire-order stop hash; defaults to all zero bytes.
   * @returns {void}
   */
  requestHeaders(locatorHashes, stopHash = Buffer.alloc(32)) {
    const archivePeers = [...this.readyPeers]
      .filter(candidate => (candidate.remoteServices & 1n) === 1n);
    const peer = this.syncPeer && this.readyPeers.has(this.syncPeer) &&
      (this.syncPeer.remoteServices & 1n) === 1n
      ? this.syncPeer
      : archivePeers.sort((a, b) => (b.remoteStartHeight || 0) - (a.remoteStartHeight || 0))[0];
    if (!peer) return;
    this.syncPeer = peer;
    peer.requestHeaders(locatorHashes, stopHash);
  }

  /**
   * Select or retain a full-service sync peer and request block inventory.
   * @param {Buffer[]} locatorHashes - Known 32-byte block hashes in wire order.
   * @param {Buffer} [stopHash] - Wire-order stop hash; defaults to all zero bytes.
   * @returns {void}
   */
  requestBlocks(locatorHashes, stopHash = Buffer.alloc(32)) {
    const archivePeers = [...this.readyPeers]
      .filter(candidate => (candidate.remoteServices & 1n) === 1n);
    const peer = this.syncPeer && this.readyPeers.has(this.syncPeer) &&
      (this.syncPeer.remoteServices & 1n) === 1n
      ? this.syncPeer
      : archivePeers.sort((a, b) => (b.remoteStartHeight || 0) - (a.remoteStartHeight || 0))[0];
    if (!peer) return;
    this.syncPeer = peer;
    peer.requestBlocks(locatorHashes, stopHash);
  }

  /**
   * Request inventory from the current sync peer, falling back to an available ready peer.
   * @param {InventoryItem[]} items - Wire-order block or transaction identifiers.
   * @returns {void}
   */
  requestData(items) {
    const peer = this.syncPeer && this.readyPeers.has(this.syncPeer)
      ? this.syncPeer
      : this.getBestPeer() || this.readyPeers.values().next().value;
    peer?.requestData(items);
  }

  /**
   * Attempt exact-byte verified relay through every currently ready peer.
   * @param {Buffer} rawTransaction - Persisted signed transaction bytes.
   * @returns {Promise<number>} Number of peers verifying receipt; not a confirmation count.
   * @throws {Error} Rejects if no peer is ready or none verifies receipt.
   */
  async broadcastTransaction(rawTransaction) {
    const peers = [...this.readyPeers];
    if (!peers.length) throw new Error('No connected Pepecoin peers are available for transaction relay.');
    const results = await Promise.allSettled(
      peers.map(peer => peer.broadcastTransaction(rawTransaction))
    );
    const sent = results.filter(result => result.status === 'fulfilled').length;
    if (!sent) {
      const errors = results
        .filter(result => result.status === 'rejected')
        .map(result => result.reason?.message || String(result.reason));
      throw new Error(`No Pepecoin peer accepted the transaction. ${errors.join(' | ')}`);
    }
    return sent;
  }

  /**
   * Permanently close the pool, destroy peer sockets and clear candidate state.
   * @returns {void}
   */
  close() {
    this.closed = true;
    for (const peer of this.peers) peer.close();
    this.peers.clear();
    this.readyPeers.clear();
    this.syncPeer = null;
    this.candidates = [];
    this.candidateKeys.clear();
  }

  /**
   * Read the maximum height advertised by ready peers.
   * @returns {number|null} Claimed network height, or null if unknown.
   */
  get remoteStartHeight() {
    let max = null;
    for (const peer of this.readyPeers) {
      if (peer.remoteStartHeight != null) {
        if (max == null || peer.remoteStartHeight > max) max = peer.remoteStartHeight;
      }
    }
    return max;
  }

  /**
   * Check whether at least one peer completed its handshake.
   * @returns {boolean} Readiness, independent of archive capability.
   */
  get ready() {
    return this.readyPeers.size > 0;
  }

  /**
   * Check whether any handshaken peer is available.
   * @returns {boolean}
   */
  hasReadyPeers() {
    return this.ready;
  }

  /**
   * Check for a ready peer advertising the NODE_NETWORK service bit.
   * @returns {boolean} True based on advertised capabilities, not a guarantee of retained history.
   */
  hasArchivePeers() {
    return [...this.readyPeers].some(peer => (peer.remoteServices & 1n) === 1n);
  }

  /**
   * Choose the ready peer advertising the highest known starting height.
   * @returns {PepecoinPeer|null} Best known-height peer, or null if none advertises a height.
   */
  getBestPeer() {
    let best = null;
    for (const peer of this.readyPeers) {
      if (peer.remoteStartHeight != null) {
        if (!best || peer.remoteStartHeight > best.remoteStartHeight) {
          best = peer;
        }
      }
    }
    return best;
  }
}
