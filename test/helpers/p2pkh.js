/**
 * Independent P2PKH serialization and verification helpers for signing regression tests.
 * These deliberately avoid the production signing implementation.
 */
import { createHash, createPublicKey, ECDH, verify } from 'node:crypto';

/**
 * Double-SHA256 a fixture byte sequence.
 * @param {Buffer} value - Bytes to hash.
 * @returns {Buffer} 32-byte digest.
 */
const sha256d = value => createHash('sha256').update(createHash('sha256').update(value).digest()).digest();
/**
 * Compute RIPEMD160(SHA256(bytes)) for a public key.
 * @param {Buffer} value - Public-key bytes.
 * @returns {Buffer} 20-byte identity.
 */
const hash160 = value => createHash('ripemd160').update(createHash('sha256').update(value).digest()).digest();
/**
 * Encode a nonnegative fixture count as CompactSize, supporting up to uint32.
 * @param {number} value - Integer from 0 through 0xffffffff.
 * @returns {Buffer} Encoded count.
 */
const varInt = value => value < 0xfd ? Buffer.from([value]) : (() => { if (value <= 0xffff) { const out = Buffer.alloc(3); out[0] = 0xfd; out.writeUInt16LE(value, 1); return out; } const out = Buffer.alloc(5); out[0] = 0xfe; out.writeUInt32LE(value, 1); return out; })();
/**
 * Encode an unsigned 32-bit fixture integer in little-endian order.
 * @param {number} value - Integer to encode.
 * @returns {Buffer} Four bytes.
 */
const u32 = value => { const out = Buffer.alloc(4); out.writeUInt32LE(value); return out; };
/**
 * Encode an unsigned 64-bit ribbit amount in little-endian order.
 * @param {bigint} value - Integer to encode.
 * @returns {Buffer} Eight bytes.
 */
const u64 = value => { const out = Buffer.alloc(8); out.writeBigUInt64LE(value); return out; };

/**
 * Read direct pushes and minimally encoded PUSHDATA1 from a fixture script.
 * @param {Buffer} script - Unlocking script.
 * @returns {Buffer[]|null} Pushed values, or null for unsupported or malformed encoding.
 */
function pushes(script) {
  const values = []; let offset = 0;
  while (offset < script.length) {
    const op = script[offset++]; let length;
    if (op >= 1 && op <= 75) length = op;
    else if (op === 0x4c && offset < script.length) { length = script[offset++]; if (length < 76) return null; }
    else return null;
    if (length > script.length - offset) return null;
    values.push(script.subarray(offset, offset + length)); offset += length;
  }
  return values;
}
/**
 * Build a standard P2PKH locking script for a 20-byte identity.
 * @param {Buffer} identity - Public-key hash.
 * @returns {Buffer} Locking script.
 */
function p2pkhScript(identity) { return Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), identity, Buffer.from([0x88, 0xac])]); }
/**
 * Serialize a legacy SIGHASH_ALL preimage with only the signing input’s script populated.
 * @param {object} tx - Parsed transaction with inputs and outputs.
 * @param {number} signingIndex - Input receiving scriptCode.
 * @param {Buffer} scriptCode - Previous output’s locking script.
 * @returns {Buffer} Preimage including the four-byte hash type.
 */
export function legacySighashPreimage(tx, signingIndex, scriptCode) {
  const fields = [u32(tx.version), varInt(tx.inputs.length)];
  for (let index = 0; index < tx.inputs.length; index++) {
    const input = tx.inputs[index], code = index === signingIndex ? scriptCode : Buffer.alloc(0);
    fields.push(input.previousOutput, varInt(code.length), code, u32(input.sequence));
  }
  fields.push(varInt(tx.outputs.length));
  for (const output of tx.outputs) fields.push(u64(output.value), varInt(output.scriptPubKey.length), output.scriptPubKey);
  fields.push(u32(tx.lockTime), u32(1));
  return Buffer.concat(fields);
}
/**
 * Wrap a SEC public key as an SPKI key for Node crypto verification.
 * @param {Buffer} key - Compressed or uncompressed public key.
 * @returns {import("node:crypto").KeyObject|null} Public key, or null for invalid encoding.
 */
function publicKeyObject(key) {
  try {
    const uncompressed = key.length === 33 ? Buffer.from(ECDH.convertKey(key, 'secp256k1', undefined, undefined, 'uncompressed')) : key;
    if (uncompressed.length !== 65 || uncompressed[0] !== 4) return null;
    const prefix = Buffer.from('3056301006072a8648ce3d020106052b8104000a034200', 'hex');
    return createPublicKey({ key: Buffer.concat([prefix, uncompressed]), format: 'der', type: 'spki' });
  } catch { return null; }
}

/**
 * Verify one fixture input using Node crypto and legacy SIGHASH_ALL serialization.
 * This checks its signature against the supplied public key, not ownership of an external UTXO.
 * @param {object} tx - Parsed legacy transaction.
 * @param {number} [index=0] - Input to verify.
 * @returns {{identity: Buffer, sighash: Buffer}|null} Verified identity/digest or null.
 */
export function verifyP2pkhInput(tx, index = 0) {
  const input = tx.inputs[index]; if (!input) return null;
  const items = pushes(input.scriptSig);
  if (!items || items.length !== 2) return null;
  const [signatureWithType, publicKey] = items;
  if (signatureWithType.length < 10 || signatureWithType.at(-1) !== 1 || ![33, 65].includes(publicKey.length)) return null;
  const key = publicKeyObject(publicKey); if (!key) return null;
  const identity = hash160(publicKey), signature = signatureWithType.subarray(0, -1), preimage = legacySighashPreimage(tx, index, p2pkhScript(identity));
  try { return verify('sha256', createHash('sha256').update(preimage).digest(), key, signature) ? { identity, sighash: sha256d(preimage) } : null; } catch { return null; }
}
