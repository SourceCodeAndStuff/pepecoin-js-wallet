/**
 * Independent secp256k1 verification of withdrawal signatures against the chain digest.
 * The arithmetic below is a test oracle, not production signing code.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, ECDH } from 'node:crypto';
import { createWallet } from '../lib/wallet.js';
import { buildPayment } from '../lib/wallet-signing.js';
import { parseBlock } from '../lib/pepenet-wire.js';
import { legacySighashPreimage } from './helpers/p2pkh.js';

// Independent ECDSA verification over a prehashed digest. This test never calls
// Node's sign/verify APIs, which shared the extra-hash bug in the old tests.
const field = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const order = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const generator = [
  0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n,
  0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n
];
/**
 * Normalize an integer modulo a positive modulus.
 * @param {bigint} x - Integer.
 * @param {bigint} [m=field] - Modulus.
 * @returns {bigint} Nonnegative residue.
 */
const mod = (x, m = field) => (x % m + m) % m;
/**
 * Compute a nonzero scalar’s inverse using Fermat exponentiation.
 * @param {bigint} x - Nonzero value modulo m.
 * @param {bigint} m - Prime modulus.
 * @returns {bigint} Multiplicative inverse.
 */
function inverse(x, m) {
  let result = 1n, power = m - 2n;
  for (x = mod(x, m); power; power >>= 1n, x = x * x % m)
    if (power & 1n) result = result * x % m;
  return result;
}
/**
 * Add secp256k1 points; null represents the point at infinity.
 * @param {bigint[]|null} a - First affine point.
 * @param {bigint[]|null} b - Second affine point.
 * @returns {bigint[]|null} Sum.
 */
function add(a, b) {
  if (!a) return b;
  if (!b) return a;
  if (a[0] === b[0] && mod(a[1] + b[1]) === 0n) return null;
  const slope = a[0] === b[0]
    ? mod(3n * a[0] * a[0] * inverse(2n * a[1], field))
    : mod((b[1] - a[1]) * inverse(b[0] - a[0], field));
  const x = mod(slope * slope - a[0] - b[0]);
  return [x, mod(slope * (a[0] - x) - a[1])];
}
/**
 * Multiply a test point by a nonnegative scalar using double-and-add.
 * @param {bigint} k - Nonnegative scalar.
 * @param {bigint[]|null} point - Affine point or infinity.
 * @returns {bigint[]|null} Product.
 */
function multiply(k, point) {
  let result = null;
  for (; k; k >>= 1n, point = add(point, point))
    if (k & 1n) result = add(result, point);
  return result;
}
/**
 * Read nonempty big-endian bytes as an unsigned integer.
 * @param {Buffer} bytes - Scalar bytes.
 * @returns {bigint} Unsigned value.
 */
const scalar = bytes => BigInt(`0x${bytes.toString('hex')}`);
/**
 * Verify a fixture DER signature against an already-hashed digest, with no extra hashing.
 * Assumes structurally valid fixture encodings; malformed input may throw.
 * @param {Buffer} digest - Double-SHA256 transaction digest.
 * @param {Buffer} signature - DER ECDSA signature without sighash byte.
 * @param {Buffer} publicKey - SEC-encoded secp256k1 public key.
 * @returns {boolean} Whether the ECDSA equation holds.
 */
function verifiesDigest(digest, signature, publicKey) {
  const rlen = signature[3], r = scalar(signature.subarray(4, 4 + rlen));
  const slen = signature[5 + rlen], s = scalar(signature.subarray(6 + rlen, 6 + rlen + slen));
  if (r <= 0n || r >= order || s <= 0n || s >= order) return false;
  const key = ECDH.convertKey(publicKey, 'secp256k1', undefined, undefined, 'uncompressed');
  const point = [scalar(key.subarray(1, 33)), scalar(key.subarray(33))];
  const w = inverse(s, order);
  const checked = add(multiply(scalar(digest) * w % order, generator), multiply(r * w % order, point));
  return checked !== null && checked[0] % order === r;
}

test('withdrawal signatures satisfy ECDSA for the double-hashed chain digest', () => {
  const wallet = createWallet();
  const withdrawal = buildPayment({
    utxos: [
      { identity: wallet.identity.toString('hex'), txid: '11'.repeat(32), vout: 0, valueKoinu: '100000000' },
      { identity: wallet.identity.toString('hex'), txid: '22'.repeat(32), vout: 1, valueKoinu: '100000000' }
    ], recipients: [{ address: wallet.address, amount: '1' }], feeRate: '1000',
    changeAddress: wallet.address, keyFor: () => wallet
  });
  const tx = parseBlock(Buffer.concat([Buffer.alloc(80), Buffer.from([1]), withdrawal.raw])).transactions[0];
  const sha = bytes => createHash('sha256').update(bytes).digest();
  for (let i = 0; i < tx.inputs.length; i++) {
    const script = tx.inputs[i].scriptSig;
    const signature = script.subarray(1, script[0]);
    const publicKey = script.subarray(script[0] + 2);
    const code = Buffer.concat([Buffer.from('76a914', 'hex'), wallet.identity, Buffer.from('88ac', 'hex')]);
    const digest = sha(sha(legacySighashPreimage(tx, i, code)));
    assert.ok(verifiesDigest(digest, signature, publicKey));
    assert.equal(verifiesDigest(sha(digest), signature, publicKey), false);
  }
  const actualFee = 200000000n - tx.outputs.reduce((sum, out) => sum + out.value, 0n);
  assert.equal(actualFee.toString(), withdrawal.feeKoinu);
  assert.ok(actualFee >= BigInt(withdrawal.raw.length) * 1000n);
});
