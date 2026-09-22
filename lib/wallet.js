/**
 * @file Mainnet addresses, private keys and authenticated encryption primitives.
 * Private-key Buffers and WIF strings are secrets; callers own their lifetime.
 *
 * @typedef {Object} KeyMaterial
 * @property {Buffer} privateKey - Sensitive secp256k1 scalar.
 * @property {Buffer} publicKey - Serialized secp256k1 public key.
 * @property {Buffer} identity - 20-byte HASH160 of the public key.
 * @property {string} address - Mainnet P2PKH receiving address.
 * @property {boolean} [compressed=true] - Public-key serialization mode.
 */
import { createCipheriv, createDecipheriv, createHash, createECDH, generateKeyPairSync, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const PEP_PUBKEY_PREFIX = 0x38; // Pepecoin mainnet P2PKH addresses begin with P.
const PEP_SECRET_PREFIX = 0x9e; // Dogecoin-compatible private-key prefix adopted by Pepecoin.

/**
 * Compute a single SHA-256 digest.
 * @private
 * @param {Buffer|string} value - Bytes or UTF-8 text.
 * @returns {Buffer} 32-byte digest.
 */
function sha256(value) { return createHash('sha256').update(value).digest(); }
/**
 * Compute RIPEMD-160(SHA-256(value)).
 * @private
 * @param {Buffer} value - Serialized public key.
 * @returns {Buffer} 20-byte public-key identity.
 */
function hash160(value) { return createHash('ripemd160').update(sha256(value)).digest(); }
/**
 * Encode bytes using the Bitcoin Base58 alphabet, preserving leading zero bytes.
 * @private
 * @param {Buffer} value - Bytes to encode.
 * @returns {string} Base58 text.
 */
function base58(value) {
  let n = BigInt(`0x${value.toString('hex') || '0'}`), out = '';
  while (n > 0n) { out = ALPHABET[Number(n % 58n)] + out; n /= 58n; }
  for (const byte of value) { if (byte !== 0) break; out = '1' + out; }
  return out || '1';
}
/**
 * Append a four-byte double-SHA-256 checksum and Base58-encode a payload.
 * @param {Buffer} payload - Version prefix and data, without a checksum.
 * @returns {string} Base58Check representation.
 */
export function base58Check(payload) { return base58(Buffer.concat([payload, sha256(sha256(payload)).subarray(0, 4)])); }
/**
 * Decode a Base58Check string and verify its checksum.
 * @param {string} text - Encoded address or WIF, at most 120 characters.
 * @returns {Buffer} Version-prefixed payload without checksum bytes.
 * @throws {Error} If the alphabet, length or checksum is invalid.
 */
export function decodeBase58Check(text) {
  if (typeof text !== 'string' || !text.length || text.length > 120) throw new Error('Invalid Base58 value.');
  let n = 0n;
  for (const c of text) {
    const digit = ALPHABET.indexOf(c);
    if (digit < 0) throw new Error('Invalid Base58 value.');
    n = n * 58n + BigInt(digit);
  }
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  const leading = text.match(/^1*/)[0].length;
  const raw = Buffer.concat([Buffer.alloc(leading), n ? Buffer.from(hex, 'hex') : Buffer.alloc(0)]);
  const payload = raw.subarray(0, -4);
  if (raw.length < 5 || !sha256(sha256(payload)).subarray(0, 4).equals(raw.subarray(-4))) throw new Error('Invalid checksum.');
  return payload;
}
/**
 * Build a standard mainnet P2PKH or P2SH locking script.
 * @param {string} address - Mainnet destination with prefix 56 or 22.
 * @returns {Buffer} Serialized scriptPubKey.
 * @throws {Error} If the address checksum, payload length or network prefix is invalid.
 */
export function destinationScript(address) {
  const payload = decodeBase58Check(address);
  if (payload.length !== 21 || ![56, 22].includes(payload[0])) throw new Error('A Pepecoin mainnet address is required.');
  return payload[0] === 56
    ? Buffer.concat([Buffer.from('76a914', 'hex'), payload.subarray(1), Buffer.from('88ac', 'hex')])
    : Buffer.concat([Buffer.from('a914', 'hex'), payload.subarray(1), Buffer.from('87', 'hex')]);
}
/**
 * Derive key metadata and an address without storing the key.
 * @param {Buffer} privateKey - Valid secp256k1 private scalar; copied into the result.
 * @param {boolean} [compressed=true] - Whether to serialize a compressed public key.
 * @returns {KeyMaterial} Sensitive key material and public address.
 * @throws {Error} If the private scalar is invalid.
 */
export function walletFromPrivateKey(privateKey, compressed = true) {
  const curve = createECDH('secp256k1');
  curve.setPrivateKey(privateKey);
  const publicKey = curve.getPublicKey(undefined, compressed ? 'compressed' : 'uncompressed');
  const identity = hash160(publicKey);
  return { privateKey: Buffer.from(privateKey), publicKey, compressed, identity, address: base58Check(Buffer.concat([Buffer.from([56]), identity])) };
}
/**
 * Decode a mainnet WIF key and preserve its compression flag.
 * @param {string} value - Sensitive WIF string with prefix 0x9e.
 * @returns {KeyMaterial} Decrypted key material, not a persisted wallet.
 * @throws {Error} If the WIF is invalid or belongs to another network.
 */
export function importWif(value) {
  const payload = decodeBase58Check(value);
  if (payload[0] !== PEP_SECRET_PREFIX || ![33, 34].includes(payload.length) ||
      (payload.length === 34 && payload[33] !== 1)) throw new Error('Invalid Pepecoin WIF private key.');
  return walletFromPrivateKey(payload.subarray(1, 33), payload.length === 34);
}
/**
 * Normalize and validate a local operator account name.
 * @param {*} value - Value converted to trimmed lowercase text.
 * @returns {string} A 3–32 character name containing letters, digits, underscores or hyphens.
 * @throws {Error} If the resulting name is invalid.
 */
export function normalizeAccountName(value) {
  const accountName = String(value || '').trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9_-]{2,31}$/.test(accountName)) throw new Error('Account name must be 3–32 lowercase letters, numbers, underscores, or hyphens.');
  return accountName;
}
/**
 * Derive a 32-byte key with scrypt for local credentials or backup encryption.
 * @param {string} password - At least 12 characters.
 * @param {Buffer} salt - Random per-password salt; persist it with the encrypted record.
 * @returns {Buffer} Sensitive derived key; clear it after use.
 * @throws {Error} If the password is too short or derivation fails.
 */
export function passwordKey(password, salt) {
  if (typeof password !== 'string' || password.length < 12) throw new Error('Password must be at least 12 characters.');
  return scryptSync(password, salt, 32);
}
/**
 * Hash a derived password key for storage as a login verifier.
 * @param {Buffer} key - Output from passwordKey(), not the plaintext password.
 * @returns {Buffer} SHA-256 verifier.
 */
export function passwordHash(key) { return sha256(key); }
/**
 * Compare equal-length verifier buffers with timingSafeEqual.
 * @param {Buffer} key - Candidate verifier, normally passwordHash(passwordKey(...)).
 * @param {Buffer} expected - Persisted verifier.
 * @returns {boolean} Whether both buffers match; unequal lengths return false.
 */
export function passwordMatches(key, expected) { return expected.length === key.length && timingSafeEqual(key, expected); }
/**
 * Encrypt arbitrary bytes with AES-256-GCM using a new 12-byte IV.
 * Also used for backup payloads and the vault key-check marker.
 * @param {Buffer} privateKey - Plaintext bytes; not cleared by this function.
 * @param {Buffer} key - 32-byte encryption key.
 * @returns {string} Base64url envelope containing IV, authentication tag and ciphertext.
 */
export function encryptPrivateKey(privateKey, key) {
  const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(privateKey), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString('base64url');
}
/**
 * Authenticate and decrypt an AES-256-GCM envelope.
 * @param {string} encrypted - Base64url IV, tag and ciphertext envelope.
 * @param {Buffer} key - 32-byte decryption key.
 * @returns {Buffer} Sensitive plaintext; the caller must protect and clear it.
 * @throws {Error} If authentication fails or the envelope is malformed.
 */
export function decryptPrivateKey(encrypted, key) {
  const raw = Buffer.from(encrypted, 'base64url'), decipher = createDecipheriv('aes-256-gcm', key, raw.subarray(0, 12));
  decipher.setAuthTag(raw.subarray(12, 28));
  return Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]);
}
/**
 * Generate a random compressed secp256k1 keypair and mainnet address.
 * This does not persist the key, register it for indexing or require network access.
 * @returns {KeyMaterial} Sensitive private key with public metadata.
 */
export function createWallet() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
  const priv = Buffer.from(privateKey.export({ format: 'jwk' }).d, 'base64url');
  const jwk = publicKey.export({ format: 'jwk' });
  const x = Buffer.from(jwk.x, 'base64url'), y = Buffer.from(jwk.y, 'base64url');
  const publicKeyBytes = Buffer.concat([Buffer.from([(y[y.length - 1] & 1) ? 0x03 : 0x02]), x]);
  const identity = hash160(publicKeyBytes);
  return { privateKey: priv, publicKey: publicKeyBytes, identity, address: base58Check(Buffer.concat([Buffer.from([PEP_PUBKEY_PREFIX]), identity])) };
}
/**
 * Encode a private scalar in Pepecoin mainnet Wallet Import Format.
 * @param {Buffer} privateKey - Sensitive private scalar.
 * @param {boolean} [compressed=true] - Include the compressed-public-key marker.
 * @returns {string} Sensitive WIF text; anyone holding it can spend the corresponding funds.
 */
export function wif(privateKey, compressed = true) { return base58Check(Buffer.concat([Buffer.from([PEP_SECRET_PREFIX]), privateKey, compressed ? Buffer.from([1]) : Buffer.alloc(0)])); }
