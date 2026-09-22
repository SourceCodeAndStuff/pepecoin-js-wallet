/**
 * @file Encrypted SQLite vault for namespace-owned wallets, keys and durable reservations.
 * Low-level methods assume a trusted caller and an exclusive data-directory lock.
 * Legacy *Koinu fields represent integer ribbits; private keys never belong in public responses.
 */
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes, randomUUID } from 'node:crypto';
import Database from './sqlite.js';
import { createWallet, encryptPrivateKey, decryptPrivateKey, passwordKey, importWif, wif } from './wallet.js';

/**
 * Capture the current UTC timestamp for persisted vault records.
 * @returns {string} ISO 8601 timestamp.
 */
const now = () => new Date().toISOString();
/**
 * Trim and validate a required bounded text label.
 * @param {string} value - Untrusted label or identifier.
 * @param {number} [max=120] - Maximum original string length.
 * @returns {string} Non-empty trimmed value.
 * @throws {Error} If value is not a string or violates the length policy.
 */
export function label(value, max = 120) {
  if (typeof value !== 'string' || !value.trim() || value.length > max) throw new Error(`A non-empty value of at most ${max} characters is required.`);
  return value.trim();
}

// Only encrypted private keys are stored in SQLite. The host secret must be
// protected separately by OS permissions; this is an online custodial wallet.
/**
 * Own the master key and synchronous SQLite storage for all namespaces.
 * Callers must enforce authorization before using methods that accept only wallet IDs.
 */
export class WalletVault {
  /**
   * Open/create the vault and migrate legacy account columns without changing keys.
   * @param {string} dir - Directory containing wallets.db and its separate wallet.key.
   * @throws {Error} If the master key is missing, invalid, mismatched or storage cannot be opened.
   */
  constructor(dir) {
    fs.mkdirSync(dir, { recursive: true });
    const keyPath = path.join(dir, 'wallet.key'), dbPath = path.join(dir, 'wallets.db');
    if (!fs.existsSync(keyPath)) {
      if (fs.existsSync(dbPath)) throw new Error('wallet.key is missing. Restore it from backup; refusing to replace an existing vault key.');
      fs.writeFileSync(keyPath, randomBytes(32), { flag: 'wx', mode: 0o600 });
    }
    this.key = fs.readFileSync(keyPath);
    if (this.key.length !== 32) throw new Error('Invalid wallet.key.');
    this.db = new Database(dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('foreign_keys = ON');
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS settings (name TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS wallets (id TEXT PRIMARY KEY, owner TEXT NOT NULL, accountId TEXT NOT NULL, label TEXT NOT NULL, createdAt TEXT NOT NULL, UNIQUE(owner, accountId));
      CREATE TABLE IF NOT EXISTS addresses (address TEXT PRIMARY KEY, walletId TEXT NOT NULL REFERENCES wallets(id), identity TEXT NOT NULL UNIQUE, secret TEXT NOT NULL, compressed INTEGER NOT NULL, label TEXT NOT NULL, needsRescan INTEGER NOT NULL DEFAULT 0, createdAt TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS outgoing (id TEXT PRIMARY KEY, walletId TEXT NOT NULL REFERENCES wallets(id), requestId TEXT NOT NULL, fingerprint TEXT NOT NULL, txid TEXT NOT NULL, raw TEXT NOT NULL, details TEXT NOT NULL, state TEXT NOT NULL, error TEXT, createdAt TEXT NOT NULL, UNIQUE(walletId,requestId));
      CREATE TABLE IF NOT EXISTS reservations (outpoint TEXT PRIMARY KEY, outgoingId TEXT NOT NULL REFERENCES outgoing(id));
      CREATE TABLE IF NOT EXISTS coin_locks (walletId TEXT NOT NULL REFERENCES wallets(id), outpoint TEXT NOT NULL, PRIMARY KEY(walletId,outpoint));
      CREATE TABLE IF NOT EXISTS contacts (id TEXT PRIMARY KEY, owner TEXT NOT NULL, label TEXT NOT NULL, address TEXT NOT NULL);
    `);
    const check = this.db.prepare('SELECT value FROM settings WHERE name=?').get('key-check');
    if (check) {
      try { if (decryptPrivateKey(check.value, this.key).toString() !== 'pepecoin-wallet-v1') throw new Error(); }
      catch { this.db.close(); throw new Error('wallet.key does not match the encrypted vault.'); }
    } else this.db.prepare('INSERT INTO settings VALUES (?,?)').run('key-check', encryptPrivateKey(Buffer.from('pepecoin-wallet-v1'), this.key));
    // Preserve existing account identifiers when upgrading older vaults.
    try {
      const columns = this.db.prepare('PRAGMA table_info(wallets)').all();
      if (!columns.some(c => c.name === 'accountId') && columns.some(c => c.name === 'playerId')) {
        this.db.transaction(() => this.db.exec('ALTER TABLE wallets RENAME COLUMN playerId TO accountId'))();
      }
    } catch (error) { this.close(); throw error; }
  }
  /**
   * Resolve and persist a default namespace without silently hiding existing wallets.
   * @returns {string} Saved namespace, sole existing owner, or default for an empty vault.
   * @throws {Error} If multiple owners exist and no default has been saved.
   */
  defaultNamespace() {
    return this.db.transaction(() => {
      const saved = this.db.prepare("SELECT value FROM settings WHERE name='default-namespace'").get();
      if (saved) return saved.value;
      const owners = this.db.prepare('SELECT DISTINCT owner FROM wallets').all();
      if (owners.length > 1) throw new Error('Specify namespace when opening a vault containing multiple namespaces.');
      const value = owners[0]?.owner ?? 'default';
      this.db.prepare('INSERT INTO settings VALUES (?,?)').run('default-namespace', value);
      return value;
    })();
  }
  /**
   * Close SQLite and overwrite the in-memory master-key buffer.
   * @returns {void}
   */
  close() { this.db.close(); this.key.fill(0); }
  /**
   * List one namespace's wallets with public address metadata.
   * @param {string} owner - Namespace identifier.
   * @returns {Array<import('../index.d.ts').AccountWallet>} Wallets ordered by creation time and ID.
   */
  list(owner) { return this.db.prepare('SELECT * FROM wallets WHERE owner=? ORDER BY createdAt,id').all(owner).map(w => ({ ...w, addresses: this.addresses(w.id) })); }
  /**
   * Require that a wallet belongs to the requested namespace.
   * @param {string} owner - Namespace identifier.
   * @param {string} id - Wallet UUID.
   * @returns {Omit<import('../index.d.ts').AccountWallet, 'addresses'>} Wallet row without secrets.
   * @throws {Error} With status 404 if the wallet is not owned by this namespace.
   */
  get(owner, id) { const w = this.db.prepare('SELECT * FROM wallets WHERE owner=? AND id=?').get(owner, id); if (!w) throw Object.assign(new Error('Wallet not found.'), { status: 404 }); return w; }
  /**
   * Atomically create a wallet and primary address, or return the existing account wallet.
   * @param {string} owner - Namespace identifier.
   * @param {string} accountId - Stable account ID, unique within the namespace.
   * @param {string} name - Display label; defaults to accountId if empty.
   * @param {import('./wallet.js').KeyMaterial|null} [key=null] - Optional imported primary key; otherwise generate one.
   * @returns {import('../index.d.ts').AccountWallet} Existing or newly persisted wallet. This method does not start indexing.
   */
  create(owner, accountId, name, key = null) {
    accountId = label(accountId); name = label(name || accountId);
    return this.db.transaction(() => {
      let w = this.db.prepare('SELECT * FROM wallets WHERE owner=? AND accountId=?').get(owner, accountId);
      if (!w) {
        w = { id: randomUUID(), owner, accountId, label: name, createdAt: now() };
        this.db.prepare('INSERT INTO wallets VALUES (@id,@owner,@accountId,@label,@createdAt)').run(w);
        this.addAddress(w.id, key || createWallet(), 'Primary address', false);
      }
      return { ...w, addresses: this.addresses(w.id) };
    })();
  }
  /**
   * Read public address metadata without encrypted or plaintext secrets.
   * @param {string} walletId - Wallet UUID; ownership must already be checked.
   * @returns {Array<import('../index.d.ts').Address>} Addresses ordered by creation time and address.
   */
  addresses(walletId) { return this.db.prepare('SELECT address,identity,compressed,label,needsRescan,createdAt FROM addresses WHERE walletId=? ORDER BY createdAt,address').all(walletId); }
  /**
   * List public-key identities across all namespaces for the shared chain index.
   * @returns {string[]} Hex-encoded HASH160 values.
   */
  allIdentities() { return this.db.prepare('SELECT identity FROM addresses').all().map(a => a.identity); }
  /**
   * Encrypt and attach a key to a wallet; an address cannot belong to two wallets.
   * @param {string} walletId - Authorized wallet UUID.
   * @param {import('./wallet.js').KeyMaterial} [wallet] - Key material; a new key is generated when omitted.
   * @param {string} [name='Receive address'] - Public label.
   * @param {boolean} [needsRescan=false] - Mark historical imports as unsafe to spend until rescanned.
   * @returns {import('../index.d.ts').Address} Public address metadata; existing addresses retain their metadata.
   */
  addAddress(walletId, wallet = createWallet(), name = 'Receive address', needsRescan = false) {
    const existing = this.db.prepare('SELECT walletId FROM addresses WHERE address=?').get(wallet.address);
    if (existing) { if (existing.walletId !== walletId) throw new Error('This address already belongs to another wallet.'); return this.addresses(walletId).find(a => a.address === wallet.address); }
    this.db.prepare('INSERT INTO addresses VALUES (?,?,?,?,?,?,?,?)').run(wallet.address, walletId, wallet.identity.toString('hex'), encryptPrivateKey(wallet.privateKey, this.key), wallet.compressed === false ? 0 : 1, label(name), needsRescan ? 1 : 0, now());
    return this.addresses(walletId).find(a => a.address === wallet.address);
  }
  /**
   * Decrypt a key for a previously authorized wallet and identity.
   * @param {string} walletId - Wallet UUID.
   * @param {string} identity - Hex HASH160 of the requested public key.
   * @returns {{privateKey: Buffer, compressed: boolean}|null} Sensitive key or null; caller must clear its buffer.
   */
  signingKey(walletId, identity) {
    const row = this.db.prepare('SELECT secret,compressed FROM addresses WHERE walletId=? AND identity=?').get(walletId, identity);
    return row ? { privateKey: decryptPrivateKey(row.secret, this.key), compressed: Boolean(row.compressed) } : null;
  }
  /**
   * Read a wallet's saved withdrawals without their raw signed bytes.
   * @param {string} walletId - Authorized wallet UUID.
   * @returns {Array<import('../index.d.ts').Withdrawal>} Public requests, newest first.
   */
  outgoing(walletId) { return this.db.prepare('SELECT * FROM outgoing WHERE walletId=? ORDER BY createdAt DESC').all(walletId).map(r => this.publicPayment(r)); }
  /**
   * Project a stored outgoing row into reviewable public metadata.
   * @param {Object|null|undefined} r - Internal outgoing row with JSON details and raw transaction bytes.
   * @returns {import('../index.d.ts').Withdrawal|null} Public fields without raw signed transaction bytes, or null.
   */
  publicPayment(r) { if (!r) return null; return { id: r.id, requestId: r.requestId, txid: r.txid, state: r.state, error: r.error, createdAt: r.createdAt, ...JSON.parse(r.details) }; }
  /**
   * Find a request by idempotency key and reject reuse with different normalized payment fields.
   * @param {string} walletId - Wallet UUID.
   * @param {string} requestId - Durable caller-owned idempotency key.
   * @param {string} fingerprint - SHA-256 of normalized payment fields.
   * @returns {Object|undefined} Internal outgoing row, including raw signed bytes, if present.
   * @throws {Error} With status 409 if the fingerprint differs.
   */
  existing(walletId, requestId, fingerprint) {
    const row = this.db.prepare('SELECT * FROM outgoing WHERE walletId=? AND requestId=?').get(walletId, requestId);
    if (row && row.fingerprint !== fingerprint) throw Object.assign(new Error('Idempotency key was already used for a different withdrawal.'), { status: 409 });
    return row;
  }
  /**
   * Atomically persist a signed outgoing transaction and reserve every consumed outpoint.
   * Unique outpoint constraints prevent a second request from reserving the same input.
   * @param {string} walletId - Authorized wallet UUID.
   * @param {string} requestId - Durable caller-owned idempotency key.
   * @param {string} fingerprint - Hash of normalized payment fields.
   * @param {import("../index.d.ts").Quote & {raw: Buffer}} payment - Signed payment returned by buildPayment().
   * @returns {Object} Internal outgoing row; never send it directly to a client.
   * @throws {Error} If idempotency conflicts, an input is already reserved, or persistence fails.
   */
  reserve(walletId, requestId, fingerprint, payment) {
    return this.db.transaction(() => {
      const old = this.existing(walletId, requestId, fingerprint); if (old) return old;
      const { raw, ...details } = payment;
      const row = { id: randomUUID(), walletId, requestId, fingerprint, txid: payment.txid, raw: raw.toString('hex'), details: JSON.stringify(details), state: 'queued', error: null, createdAt: now() };
      this.db.prepare('INSERT INTO outgoing VALUES (@id,@walletId,@requestId,@fingerprint,@txid,@raw,@details,@state,@error,@createdAt)').run(row);
      for (const input of payment.inputs) this.db.prepare('INSERT INTO reservations VALUES (?,?)').run(`${input.txid}:${input.vout}`, row.id);
      return row;
    })();
  }
  /**
   * Combine all outstanding withdrawal reservations with this wallet’s manual coin locks.
   * @param {string} walletId - Wallet UUID for manual locks.
   * @returns {Set<string>} Reserved or locked txid:vout identifiers.
   */
  blocked(walletId) { return new Set([...this.db.prepare('SELECT outpoint FROM reservations').all(), ...this.db.prepare('SELECT outpoint FROM coin_locks WHERE walletId=?').all(walletId)].map(r => r.outpoint)); }
  /**
   * Persist relay/confirmation state without releasing any input reservations.
   * @param {string} id - Outgoing request UUID.
   * @param {string} state - queued, relayed, unverified or confirmed.
   * @param {string|null} [error=null] - Optional relay diagnostic.
   * @returns {void}
   */
  setPayment(id, state, error = null) { this.db.prepare('UPDATE outgoing SET state=?,error=? WHERE id=?').run(state, error, id); }
  /**
   * Encrypt one namespace's keys, contacts, outgoing requests, reservations and coin locks.
   * Chain data and operator login credentials are not included.
   * @param {string} owner - Authorized namespace.
   * @param {string} passphrase - Backup passphrase, at least 12 characters.
   * @returns {import('../index.d.ts').EncryptedBackup} Version 2 authenticated encrypted envelope.
   */
  backup(owner, passphrase) {
    const salt = randomBytes(16), key = passwordKey(passphrase, salt);
    const wallets = this.list(owner).map(w => ({ accountId: w.accountId, label: w.label, addresses: w.addresses.map(a => { const k = this.signingKey(w.id, a.identity); return { label: a.label, wif: wif(k.privateKey, k.compressed) }; }) }));
    const payload = { wallets, contacts: this.contacts(owner) };
    // Restores retain outgoing reservations, so a copied vault cannot reuse pending inputs.
    payload.outgoing = this.db.prepare('SELECT o.*,w.accountId FROM outgoing o JOIN wallets w ON w.id=o.walletId WHERE w.owner=?').all(owner);
    payload.reservations = this.db.prepare('SELECT r.* FROM reservations r JOIN outgoing o ON o.id=r.outgoingId JOIN wallets w ON w.id=o.walletId WHERE w.owner=?').all(owner);
    payload.coinLocks = this.db.prepare('SELECT c.outpoint,w.accountId FROM coin_locks c JOIN wallets w ON w.id=c.walletId WHERE w.owner=?').all(owner);
    return { format: 'pepecoin-js-wallet', version: 2, salt: salt.toString('base64url'), ciphertext: encryptPrivateKey(Buffer.from(JSON.stringify(payload)), key) };
  }
  /**
   * Decrypt and atomically import a version 1 or 2 backup into a namespace.
   * Matching account IDs reject rather than merging funds. Restored keys require a rescan;
   * reservations are preserved so pending inputs cannot be reused after restoration.
   * @param {string} owner - Destination namespace.
   * @param {import("../index.d.ts").EncryptedBackup} backup - Authenticated encrypted envelope.
   * @param {string} passphrase - Original encryption passphrase.
   * @returns {{wallets: number, needsRescan: boolean}} Restored count and historical-rescan requirement.
   * @throws {Error} If authentication, format, uniqueness constraints or persistence fails.
   */
  restore(owner, backup, passphrase) {
    const legacy = backup?.version === 1 && /^pepecoin-[a-z]+-wallet$/.test(backup.format);
    if (!legacy && !(backup?.format === 'pepecoin-js-wallet' && backup.version === 2)) throw new Error('Unsupported backup.');
    const data = JSON.parse(decryptPrivateKey(backup.ciphertext, passwordKey(passphrase, Buffer.from(backup.salt, 'base64url'))));
    if (!Array.isArray(data.wallets) || data.wallets.length > 10000) throw new Error('Invalid backup.');
    // Version 1 used a different account identifier field; ciphertext remains authenticated.
    if (legacy) for (const row of [...data.wallets, ...(data.outgoing || []), ...(data.coinLocks || [])]) row.accountId ??= row.playerId;
    return this.db.transaction(() => {
      const mapped = new Map();
      for (const w of data.wallets) {
        if (!Array.isArray(w.addresses) || !w.addresses.length) throw new Error('Invalid backup wallet.');
        const existing = this.db.prepare('SELECT id FROM wallets WHERE owner=? AND accountId=?').get(owner, w.accountId);
        if (existing) throw new Error(`Account ${w.accountId} already exists. Restore into a fresh operator account to prevent merging unrelated balances.`);
        const wallet = this.create(owner, w.accountId, w.label, importWif(w.addresses[0].wif));
        mapped.set(w.accountId, wallet.id);
        for (const a of w.addresses) {
          this.addAddress(wallet.id, importWif(a.wif), a.label, true);
          this.db.prepare('UPDATE addresses SET needsRescan=1 WHERE address=?').run(importWif(a.wif).address);
        }
      }
      for (const r of data.outgoing || []) this.db.prepare('INSERT INTO outgoing VALUES (?,?,?,?,?,?,?,?,?,?)').run(r.id, mapped.get(r.accountId), r.requestId, r.fingerprint, r.txid, r.raw, r.details, r.state, r.error, r.createdAt);
      for (const r of data.reservations || []) this.db.prepare('INSERT INTO reservations VALUES (?,?)').run(r.outpoint, r.outgoingId);
      for (const r of data.coinLocks || []) this.db.prepare('INSERT INTO coin_locks VALUES (?,?)').run(mapped.get(r.accountId), r.outpoint);
      for (const c of data.contacts || []) this.saveContact(owner, c.label, c.address);
      return { wallets: data.wallets.length, needsRescan: true };
    })();
  }
  /**
   * Read one namespace’s public address book.
   * @param {string} owner - Namespace identifier.
   * @returns {Array<{id: string, label: string, address: string}>} Contacts ordered by label.
   */
  contacts(owner) { return this.db.prepare('SELECT id,label,address FROM contacts WHERE owner=? ORDER BY label').all(owner); }
  /**
   * Store a contact after the caller validates its destination address.
   * @param {string} owner - Namespace identifier.
   * @param {string} name - Required display label.
   * @param {string} address - Prevalidated mainnet destination.
   * @returns {{id: string}} New contact UUID.
   */
  saveContact(owner, name, address) { const id = randomUUID(); this.db.prepare('INSERT INTO contacts VALUES (?,?,?,?)').run(id, owner, label(name), address); return { id }; }
}
