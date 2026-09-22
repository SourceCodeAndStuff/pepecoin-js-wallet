/**
 * @file Bounds-checked transaction/block wire parsing and Merkle verification.
 * AuxPoW records are parsed here and verified by pepenet-pow.js. Hash Buffers are wire order.
 *
 * @typedef {Object} ParsedTransaction
 * @property {Buffer} raw - Original serialized transaction bytes.
 * @property {Buffer} txid - Computed 32-byte transaction digest.
 * @property {number} version - Transaction version.
 * @property {number} lockTime - Transaction lock time.
 * @property {Array<{previousOutput: Buffer, scriptSig: Buffer, sequence: number}>} inputs - Serialized input references and scripts.
 * @property {Array<{vout: number, value: bigint, scriptPubKey: Buffer}>} outputs - Output values in ribbits.
 *
 * @typedef {Object} ParsedBlock
 * @property {Buffer} hash - Double-SHA-256 of the base header.
 * @property {Buffer} header - The 80-byte base header.
 * @property {number} version - Block version and flags.
 * @property {AuxPow|null} auxpow - Merged-mining proof when the AuxPoW version flag is set.
 * @property {number} time - Header Unix timestamp in seconds.
 * @property {ParsedTransaction[]} transactions - Parsed block transactions.
 * @property {bigint} blockBytes - Sum of transaction sizes, excluding block/AuxPoW framing.
 * @property {bigint} coinbaseTotal - Sum of the first transaction outputs in ribbits.
 */
import { createHash } from 'node:crypto';

const MAX_ITEMS = 100_000;
/**
 * Compute double-SHA256 without reversing digest bytes.
 * @param {Buffer|Uint8Array} bytes - Input bytes.
 * @returns {Buffer} 32-byte digest.
 */
const hash256 = bytes => createHash('sha256').update(createHash('sha256').update(bytes).digest()).digest();
/**
 * Compute SHA-256 twice without reversing the digest bytes.
 * @param {Buffer|Uint8Array} bytes - Input bytes.
 * @returns {Buffer} 32-byte digest.
 */
export const hash256d = hash256;

/**
 * Advance through serialized chain bytes with bounds checks.
 * @private
 */
class Cursor {
  /**
   * Create a cursor at offset zero.
   * @param {Buffer} bytes - Serialized payload.
   */
  constructor(bytes) { this.bytes = bytes; this.offset = 0; }
  /**
   * Read a slice and advance the cursor.
   * @param {number} length - Non-negative integer byte count.
   * @returns {Buffer} View into the input buffer.
   * @throws {Error} If the requested length is invalid or exceeds remaining bytes.
   */
  take(length) { if (!Number.isSafeInteger(length) || length < 0 || length > this.bytes.length - this.offset) throw new Error('Truncated chain message.'); const value = this.bytes.subarray(this.offset, this.offset + length); this.offset += length; return value; }
  /**
   * Read an unsigned byte.
   * @returns {number} Unsigned 8-bit value.
   */
  u8() { return this.take(1)[0]; }
  /**
   * Read an unsigned little-endian 32-bit integer.
   * @returns {number} Unsigned integer.
   */
  u32() { return this.take(4).readUInt32LE(); }
  /**
   * Read a signed little-endian 64-bit amount.
   * @returns {bigint} Signed atomic value.
   */
  i64() { return this.take(8).readBigInt64LE(); }
  /**
   * Read a CompactSize integer representable as a JavaScript safe integer.
   * @returns {number} Decoded count.
   * @throws {Error} If bytes are truncated or the value exceeds the local numeric limit.
   */
  varInt() { const lead = this.u8(); if (lead < 0xfd) return lead; if (lead === 0xfd) return this.take(2).readUInt16LE(); if (lead === 0xfe) return this.u32(); const value = this.take(8).readBigUInt64LE(); if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('Chain count exceeds local limit.'); return Number(value); }
}

/**
 * Parse transaction fields, skipping witness stacks when present.
 * This parser does not execute scripts or establish consensus validity.
 * @private
 * @param {Cursor} cursor - Cursor positioned at a transaction version field.
 * @returns {ParsedTransaction} Parsed transaction, with amounts represented as bigint ribbits.
 */
function parseTx(cursor) {
  const start = cursor.offset;
  const version = cursor.u32();
  const marker = cursor.bytes[cursor.offset];
  const flag = cursor.bytes[cursor.offset + 1];
  const segwit = marker === 0 && flag !== 0;
  if (segwit) cursor.take(2);
  const inputCount = cursor.varInt();
  if (inputCount < 1 || inputCount > MAX_ITEMS) throw new Error('Invalid transaction input count.');
  const inputs = Array.from({ length: inputCount }, () => ({ previousOutput: Buffer.from(cursor.take(36)), scriptSig: Buffer.from(cursor.take(cursor.varInt())), sequence: cursor.u32() }));
  const outputCount = cursor.varInt();
  if (outputCount > MAX_ITEMS) throw new Error('Invalid transaction output count.');
  const outputs = Array.from({ length: outputCount }, (_, vout) => ({ vout, value: cursor.i64(), scriptPubKey: Buffer.from(cursor.take(cursor.varInt())) }));
  if (segwit) {
    for (let index = 0; index < inputCount; index++) {
      const itemCount = cursor.varInt();
      if (itemCount > MAX_ITEMS) throw new Error('Invalid witness item count.');
      for (let item = 0; item < itemCount; item++) cursor.take(cursor.varInt());
    }
  }
  const lockTime = cursor.u32();
  const raw = Buffer.from(cursor.bytes.subarray(start, cursor.offset));
  const txidRaw = segwit
    ? Buffer.concat([
        cursor.bytes.subarray(start, start + 4),
        cursor.bytes.subarray(start + 6, cursor.offset - 4),
        cursor.bytes.subarray(cursor.offset - 4, cursor.offset)
      ])
    : raw;
  return { raw, txid: hash256(txidRaw), version, lockTime, inputs, outputs };
}

/**
 * @typedef {Object} AuxPow
 * @property {Buffer} coinbaseTxid - Wire-order txid of the parent coinbase.
 * @property {Buffer} coinbaseScript - scriptSig of the parent coinbase's first input.
 * @property {Buffer[]} coinbaseBranch - Merkle branch linking the coinbase to the parent header.
 * @property {number} coinbaseIndex - Coinbase position (must be 0).
 * @property {Buffer[]} chainBranch - Merged-mining chain Merkle branch.
 * @property {number} chainIndex - Slot of this chain in the merged-mining tree.
 * @property {Buffer} parentHeader - The parent chain's 80-byte header that carries the work.
 */
/**
 * Read parent coinbase, hash branches and parent header.
 * @private
 * @param {Cursor} cursor - Cursor positioned after the child base header.
 * @returns {AuxPow} Parsed merged-mining proof (not yet verified).
 * @throws {Error} If framing is truncated or a branch exceeds 64 hashes.
 */
function readAuxPowData(cursor) {
  const coinbase = parseTx(cursor); cursor.take(32);
  const coinbaseBranchLength = cursor.varInt(); if (coinbaseBranchLength > 64) throw new Error('Invalid AuxPoW branch.');
  const coinbaseBranch = Array.from({ length: coinbaseBranchLength }, () => Buffer.from(cursor.take(32)));
  const coinbaseIndex = cursor.take(4).readInt32LE();
  const chainBranchLength = cursor.varInt(); if (chainBranchLength > 64) throw new Error('Invalid AuxPoW branch.');
  const chainBranch = Array.from({ length: chainBranchLength }, () => Buffer.from(cursor.take(32)));
  const chainIndex = cursor.take(4).readInt32LE();
  const parentHeader = Buffer.from(cursor.take(80));
  return { coinbaseTxid: coinbase.txid, coinbaseScript: coinbase.inputs[0].scriptSig, coinbaseBranch, coinbaseIndex, chainBranch, chainIndex, parentHeader };
}

/**
 * Parse an AuxPoW record in place, without copying the surrounding payload.
 * @param {Buffer|Uint8Array} payload - Message containing AuxPoW data.
 * @param {number} [offset=0] - Start byte offset of the AuxPoW record.
 * @returns {{auxpow: AuxPow, offset: number}} Parsed proof and the first byte offset after it.
 */
export function parseAuxPow(payload, offset = 0) {
  // Buffer.from(Buffer) copies; a copy per header made large pages quadratic.
  const cursor = new Cursor(Buffer.isBuffer(payload) ? payload : Buffer.from(payload));
  cursor.offset = offset;
  const auxpow = readAuxPowData(cursor);
  return { auxpow, offset: cursor.offset };
}

/**
 * Find the end of a structurally valid AuxPoW record.
 * @param {Buffer|Uint8Array} payload - Message containing AuxPoW data.
 * @param {number} [offset=0] - Start byte offset of the AuxPoW record.
 * @returns {number} First byte offset after the record; use parseAuxPow() plus pepenet-pow.js to verify it.
 */
export function skipAuxPow(payload, offset = 0) { return parseAuxPow(payload, offset).offset; }

/**
 * Parse one complete serialized block, including optional AuxPoW framing.
 * @param {Buffer|Uint8Array} rawBlock - Serialized block bytes.
 * @returns {ParsedBlock} Header, transactions and size/value metadata.
 * @throws {Error} If framing/counts are invalid, truncated or followed by trailing bytes.
 */
export function parseBlock(rawBlock) {
  const cursor = new Cursor(Buffer.from(rawBlock));
  const header = Buffer.from(cursor.take(80));
  const version = header.readUInt32LE();
  const auxpow = version & 0x100 ? readAuxPowData(cursor) : null;
  const count = cursor.varInt();
  if (count < 1 || count > 1_000_000) throw new Error('Invalid block transaction count.');
  const transactions = Array.from({ length: count }, () => parseTx(cursor));
  if (cursor.offset !== cursor.bytes.length) throw new Error('Trailing data after block.');
  return { hash: hash256(header), header, version, auxpow, time: header.readUInt32LE(68), transactions, blockBytes: transactions.reduce((total, transaction) => total + BigInt(transaction.raw.length), 0n), coinbaseTotal: transactions[0].outputs.reduce((total, output) => total + output.value, 0n) };
}

/**
 * Recompute the transaction Merkle root and reject detected duplicate-pair mutations.
 * @param {ParsedBlock} block - Parsed block with transaction digests.
 * @returns {boolean} True on a matching root.
 * @throws {Error} For empty blocks, mutated trees or a root mismatch.
 */
export function verifyBlockMerkle(block) {
  let level = block.transactions.map(tx => tx.txid);
  if (!level.length) throw new Error('Empty block.');
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length && level[i].equals(level[i + 1])) throw new Error('Mutated transaction Merkle tree.');
      next.push(hash256(Buffer.concat([level[i], level[i + 1] || level[i]])));
    }
    level = next;
  }
  if (!level[0].equals(block.header.subarray(36, 68))) throw new Error('Block transactions do not match the header Merkle root.');
  return true;
}
