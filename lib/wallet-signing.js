/**
 * @file Amount conversion, legacy P2PKH transaction signing and compact message signatures.
 * One PEPE equals 100000000 ribbits. Legacy *Koinu property names store ribbits.
 */
import { createHash } from 'node:crypto';
import { secp256k1 } from '@noble/curves/secp256k1';
import { base58Check, destinationScript, walletFromPrivateKey } from './wallet.js';
import { varInt } from './pepenet-p2p.js';

/**
 * Compute one SHA-256 digest.
 * @param {Buffer|Uint8Array} b - Input bytes.
 * @returns {Buffer} 32-byte digest.
 */
const hash = b => createHash('sha256').update(b).digest();
/**
 * Compute the double-SHA256 digest used by transaction signing.
 * @param {Buffer|Uint8Array} b - Input bytes.
 * @returns {Buffer} 32-byte digest.
 */
const doubleHash = b => hash(hash(b));
/**
 * Encode an unsigned 32-bit integer in little-endian order.
 * @param {number} n - Integer to encode.
 * @returns {Buffer} Four bytes.
 */
const u32 = n => { const b = Buffer.alloc(4); b.writeUInt32LE(n); return b; };
/**
 * Encode an unsigned 64-bit ribbit amount in little-endian order.
 * @param {bigint} n - Integer to encode.
 * @returns {Buffer} Eight bytes.
 */
const u64 = n => { const b = Buffer.alloc(8); b.writeBigUInt64LE(n); return b; };
/**
 * Encode a direct script push for a short signature or public key.
 * @param {Buffer} b - Between 1 and 75 bytes; larger pushes are unsupported here.
 * @returns {Buffer} Length opcode followed by payload.
 */
const push = b => Buffer.concat([Buffer.from([b.length]), b]);
/**
 * Convert a non-negative decimal PEPE amount to integer ribbits without floating point.
 * @param {string} value - Up to 12 whole digits and 8 fractional digits.
 * @returns {bigint} Atomic amount; 0.00000001 PEPE is one ribbit.
 * @throws {Error} If input is not a supported decimal string.
 */
export function ribbit(value) {
  if (typeof value !== 'string' || !/^\d{1,12}(\.\d{1,8})?$/.test(value)) throw new Error('Use a decimal amount with at most 8 places.');
  const [w, f = ''] = value.split('.');
  return BigInt(w) * 100000000n + BigInt(f.padEnd(8, '0'));
}
/**
 * Format an integer atomic amount as PEPE with exactly eight fractional digits.
 * @param {bigint|string|number} n - Integer ribbits; prefer bigint or strings to avoid precision loss.
 * @returns {string} Signed decimal PEPE amount.
 */
export function pepe(n) {
  n = BigInt(n);
  return `${n < 0n ? '-' : ''}${(n < 0n ? -n : n) / 100000000n}.${((n < 0n ? -n : n) % 100000000n).toString().padStart(8, '0')}`;
}
/**
 * Serialize a version-1, non-witness transaction with final input sequences.
 * @private
 * @param {Array<{txid: string, vout: number}>} inputs - Inputs with display-order transaction hashes.
 * @param {Array<{value: bigint, script: Buffer}>} outputs - Atomic values and locking scripts.
 * @param {Buffer[]} [scripts=[]] - Input scripts; omitted entries serialize as empty.
 * @returns {Buffer} Raw transaction bytes.
 */
function serialize(inputs, outputs, scripts = []) {
  return Buffer.concat([u32(1), varInt(inputs.length), ...inputs.flatMap((i, n) => [
    Buffer.from(i.txid, 'hex').reverse(), u32(i.vout), varInt(scripts[n]?.length || 0), scripts[n] || Buffer.alloc(0), u32(0xffffffff)
  ]), varInt(outputs.length), ...outputs.flatMap(o => [u64(o.value), varInt(o.script.length), o.script]), u32(0)]);
}

/**
 * Select inputs and sign a legacy P2PKH payment without persisting or relaying it.
 * Supports multiple input keys and P2PKH/P2SH destinations. The caller must enforce
 * ownership, confirmation policy, reservations and sync freshness before supplying UTXOs.
 * @param {Object} options - Payment construction settings.
 * @param {Array<{identity: string, txid: string, vout: number, valueKoinu: string}>} options.utxos - Spendable coins, in ribbits.
 * @param {Array<{address: string, amount: string}>} options.recipients - Decimal PEPE destinations; 1–50 entries.
 * @param {string} options.changeAddress - Mainnet change destination.
 * @param {function(string): ({privateKey: Buffer, compressed?: boolean}|null)} options.keyFor - Resolve an input identity to its signing key.
 * @param {string} [options.feeRate="1000"] - Integer ribbits per byte, minimum 1000.
 * @param {boolean} [options.sendAll=false] - Spend selected available coins to one recipient, less fees.
 * @param {string[]} [options.selected=[]] - Optional explicit txid:vout selection.
 * @returns {import("../index.d.ts").Quote & {raw: Buffer}} Signed transaction and review metadata.
 * @throws {Error} If recipients, keys, selected coins, fee policy or available funds are invalid.
 */
export function buildPayment({ utxos, recipients, changeAddress, keyFor, feeRate = '1000', sendAll = false, selected = [] }) {
  if (!Array.isArray(recipients) || !recipients.length || recipients.length > 50) throw new Error('Provide 1–50 recipients.');
  if (!/^\d{1,9}$/.test(String(feeRate)) || BigInt(feeRate) < 1000n) throw new Error('Fee must be at least 1000 ribbits per byte.');
  const rate = BigInt(feeRate);
  const targets = recipients.map(r => ({ address: r.address, value: sendAll ? 0n : ribbit(r.amount), script: destinationScript(r.address) }));
  if (sendAll && targets.length !== 1) throw new Error('Send all requires one recipient.');
  if (!sendAll && targets.some(r => r.value < 1000000n)) throw new Error('Each recipient must receive at least 0.01 PEPE.');
  const ids = new Set(selected);
  const available = utxos.filter(u => !ids.size || ids.has(`${u.txid}:${u.vout}`)).sort((a, b) => BigInt(a.valueKoinu) > BigInt(b.valueKoinu) ? -1 : 1);
  if (ids.size && available.length !== ids.size) throw new Error('A selected coin is no longer spendable.');
  const inputs = [], keys = [];
  let total = 0n, requested = targets.reduce((n, r) => n + r.value, 0n);
  // Worst-case size also covers uncompressed imported public keys.
  const estimate = n => rate * BigInt(10 + n * 180 + (targets.length + 1) * 34);
  for (const u of available) {
    if (!/^[0-9a-f]{64}$/.test(u.txid) || !Number.isInteger(u.vout) || u.vout < 0) throw new Error('Invalid spendable coin.');
    const key = keyFor(u.identity);
    if (!key) throw new Error('Private key unavailable for a selected input.');
    const wallet = walletFromPrivateKey(key.privateKey, key.compressed !== false);
    if (wallet.identity.toString('hex') !== u.identity) throw new Error('Input signing key does not match its address.');
    inputs.push(u); keys.push(wallet); total += BigInt(u.valueKoinu);
    if (!sendAll && !ids.size && total >= requested + estimate(inputs.length)) break;
  }
  if (!inputs.length || inputs.length > 400) throw new Error('Select between 1 and 400 spendable coins.');
  let fee = estimate(inputs.length);
  if (sendAll) targets[0].value = total - fee;
  requested = targets.reduce((n, r) => n + r.value, 0n);
  if (total < requested + fee || targets.some(r => r.value < 1000000n)) throw new Error('Insufficient spendable balance including the network fee.');
  let change = total - requested - fee;
  if (change < 1000000n) { fee += change; change = 0n; }
  const outputs = [...targets];
  if (change) outputs.push({ address: changeAddress, value: change, script: destinationScript(changeAddress) });
  const scripts = inputs.map((u, i) => {
    const codes = inputs.map((_, j) => i === j ? destinationScript(keys[i].address) : Buffer.alloc(0));
    const digest = doubleHash(Buffer.concat([serialize(inputs, outputs, codes), u32(1)]));
    const signature = secp256k1.sign(digest, keys[i].privateKey, { lowS: true, prehash: false });
    if (!secp256k1.verify(signature, digest, keys[i].publicKey, { prehash: false })) throw new Error('Signature verification failed.');
    return Buffer.concat([push(Buffer.concat([Buffer.from(signature.toDERRawBytes()), Buffer.from([1])])), push(keys[i].publicKey)]);
  });
  const raw = serialize(inputs, outputs, scripts);
  if (fee < rate * BigInt(raw.length)) throw new Error('Fee is below the signed transaction size requirement.');
  return {
    raw, txid: Buffer.from(doubleHash(raw)).reverse().toString('hex'), bytes: raw.length,
    feeKoinu: fee.toString(), amountKoinu: requested.toString(), totalKoinu: total.toString(), changeKoinu: change.toString(),
    inputs: inputs.map(({ identity, txid, vout, valueKoinu }) => ({ identity, txid, vout, valueKoinu })),
    recipients: targets.map(r => ({ address: r.address, amount: pepe(r.value) })), changeAddress
  };
}

/**
 * Hash a length-prefixed Pepecoin Signed Message payload twice with SHA-256.
 * @private
 * @param {string} message - UTF-8 text, at most 10000 bytes.
 * @returns {Buffer} 32-byte signing digest.
 * @throws {Error} If the message is invalid or exceeds the byte limit.
 */
function messageHash(message) {
  if (typeof message !== 'string' || Buffer.byteLength(message) > 10000) throw new Error('Message must be at most 10 KB.');
  const magic = Buffer.from('Pepecoin Signed Message:\n'), text = Buffer.from(message);
  return doubleHash(Buffer.concat([varInt(magic.length), magic, varInt(text.length), text]));
}
/**
 * Sign text with a recoverable, compact secp256k1 signature.
 * @param {Buffer} privateKey - Sensitive private scalar.
 * @param {string} message - Exact UTF-8 text to sign.
 * @param {boolean} [compressed=true] - Encode the corresponding public-key compression flag.
 * @returns {string} Base64 representation of a 65-byte compact signature.
 */
export function signMessage(privateKey, message, compressed = true) {
  const sig = secp256k1.sign(messageHash(message), privateKey, { prehash: false });
  return Buffer.concat([Buffer.from([27 + sig.recovery + (compressed ? 4 : 0)]), Buffer.from(sig.toCompactRawBytes())]).toString('base64');
}
/**
 * Recover the signer and compare its mainnet P2PKH address with the claimed address.
 * @param {string} address - Claimed signer address.
 * @param {string} message - Exact original message.
 * @param {string} signature - Base64 compact signature.
 * @returns {boolean} False for mismatches, malformed signatures or invalid messages.
 */
export function verifyMessage(address, message, signature) {
  try {
    const bytes = Buffer.from(signature, 'base64');
    if (bytes.length !== 65 || bytes[0] < 27 || bytes[0] > 34) return false;
    const flag = bytes[0] - 27;
    const point = secp256k1.Signature.fromCompact(bytes.subarray(1)).addRecoveryBit(flag & 3).recoverPublicKey(messageHash(message));
    const id = createHash('ripemd160').update(hash(Buffer.from(point.toRawBytes(Boolean(flag & 4))))).digest();
    return base58Check(Buffer.concat([Buffer.from([56]), id])) === address;
  } catch { return false; }
}
