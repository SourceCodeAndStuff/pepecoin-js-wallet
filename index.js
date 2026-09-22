/**
 * @file Public, in-process wallet API. No HTTP listeners or process handlers are installed.
 * Amounts use decimal PEPE strings; legacy *Koinu fields contain integer ribbits.
 */
import { EventEmitter } from 'node:events';
import { openWalletRuntime } from './lib/wallet-runtime.js';
import { label } from './lib/wallet-vault.js';
import { createWallet, importWif, wif, destinationScript } from './lib/wallet.js';
import { signMessage, verifyMessage } from './lib/wallet-signing.js';

// Your trusted application code is the spending authority. No HTTP server, login,
// API token, or separately running daemon is involved in this package entry.
/**
 * Namespace-scoped custodial wallet. The embedding application authorizes spending.
 * Use open() rather than constructing instances, and always await close().
 * @extends EventEmitter
 * @fires PepecoinWallet#sync
 * @fires PepecoinWallet#block
 */
export class PepecoinWallet extends EventEmitter {
  #runtime; #namespace; #closing = false; #pending = new Set(); #closePromise;
  /**
   * Wrap an initialized runtime and forward its sync and block events.
   * @private
   * @param {Awaited<ReturnType<typeof import('./lib/wallet-runtime.js').openWalletRuntime>>} runtime - Owned runtime.
   * @param {string} namespace - Wallet ownership namespace.
   */
  constructor(runtime, namespace) {
    super(); this.#runtime = runtime; this.#namespace = namespace;
    runtime.events.on('sync', state => this.emit('sync', state));
    runtime.events.on('block', block => this.emit('block', block));
  }
  /**
   * Open a vault, acquire its exclusive data-directory lock, and optionally start sync.
   * An omitted namespace preserves the sole existing namespace; ambiguous vaults reject.
   * @param {import('./index.d.ts').WalletOptions} options - Explicit dataDir and optional namespace, autoSync and rescan settings.
   * @returns {Promise<PepecoinWallet>} An owned instance that must be closed.
   * @throws {Error} Rejects if storage is locked, keys are invalid, or namespace selection is ambiguous.
   * @example
   * const wallet = await PepecoinWallet.open({ dataDir: './wallet-data' });
   * try { await wallet.createWallet('account-123'); } finally { await wallet.close(); }
   */
  static async open({ namespace, ...options } = {}) {
    if (namespace !== undefined) namespace = label(namespace);
    const runtime = await openWalletRuntime(options);
    try { return new PepecoinWallet(runtime, namespace ?? runtime.vault.defaultNamespace()); }
    catch (error) { await runtime.close(); throw error; }
  }
  /**
   * Track an asynchronous operation so shutdown can drain outstanding work.
   * @private
   * @template T
   * @param {function(): (T|Promise<T>)} action - Operation to execute.
   * @returns {Promise<T>} Operation result, or rejection after shutdown begins.
   */
  #run(action) {
    if (this.#closing) return Promise.reject(new Error('Wallet library is closed.'));
    const pending = Promise.resolve().then(action); this.#pending.add(pending);
    pending.then(() => this.#pending.delete(pending), () => this.#pending.delete(pending));
    return pending;
  }
  /**
   * Read a detached copy of the current synchronization status.
   * @returns {import('./index.d.ts').SyncStatus} Current status; peer height is not proof of consensus validity.
   */
  get status() { return { ...this.#runtime.status }; }
  /**
   * Start public-peer synchronization unless an attempt is already running.
   * @returns {void}
   * @throws {Error} If this instance is closing or closed.
   */
  startSync() { if (this.#closing) throw new Error('Wallet library is closed.'); this.#runtime.startSync(); }
  /**
   * Create an account wallet, or return the existing wallet for this namespace/account ID.
   * @param {string} accountId - Stable caller-owned account identifier.
   * @param {string} [name=accountId] - Display label used only for a new wallet.
   * @returns {Promise<import('./index.d.ts').AccountWallet>} Wallet metadata and public receiving addresses.
   */
  createWallet(accountId, name = accountId) { return this.#run(() => this.#runtime.service.create(this.#namespace, accountId, name)); }
  /**
   * List wallets in this namespace without exposing private keys.
   * @returns {Promise<Array<import('./index.d.ts').AccountWallet>>} Wallets ordered by creation time and ID.
   */
  listWallets() { return this.#run(() => this.#runtime.vault.list(this.#namespace)); }
  /**
   * Read indexed balances, coins and history, and reconcile saved withdrawal states.
   * @param {string} walletId - Wallet UUID belonging to this namespace.
   * @param {{confirmations?: number}} [options={}] - Minimum confirmations (default 6; range 1–10000).
   * @returns {Promise<import('./index.d.ts').WalletSnapshot>} Indexed state, not an unconfirmed mempool balance.
   */
  getWallet(walletId, { confirmations = 6 } = {}) { return this.#run(() => this.#runtime.service.snapshot(this.#namespace, walletId, confirmations)); }
  /**
   * Read PEPE balances and rescan status from the current wallet snapshot.
   * @param {string} walletId - Wallet UUID.
   * @param {{confirmations?: number}} [options] - Confirmation policy.
   * @returns {Promise<import('./index.d.ts').Balance>} Decimal-string balances; availability alone does not authorize spending.
   */
  async getBalance(walletId, options) { const w = await this.getWallet(walletId, options); return { balance: w.balance, available: w.available, reserved: w.reserved, immature: w.immature, indexedHeight: w.indexedHeight, needsRescan: w.needsRescan }; }
  /**
   * Read wallet transactions retained by the local index.
   * @param {string} walletId - Wallet UUID.
   * @param {{confirmations?: number}} [options] - Snapshot confirmation policy.
   * @returns {Promise<Array<import('./index.d.ts').Transaction>>} Newest indexed transactions first.
   */
  async getTransactions(walletId, options) { return (await this.getWallet(walletId, options)).transactions; }
  /**
   * Read positive net wallet increases, excluding outgoing change as a separate deposit.
   * Persist deposit IDs in the caller's ledger to avoid duplicate crediting.
   * @param {string} walletId - Wallet UUID.
   * @param {{confirmations?: number}} [options] - Deposit confirmation policy.
   * @returns {Promise<Array<import('./index.d.ts').Deposit>>} Indexed deposits with local eligibility flags.
   */
  async getDeposits(walletId, options) { return (await this.getWallet(walletId, options)).deposits; }
  /**
   * Read saved withdrawal requests with chain-derived confirmation state.
   * @param {string} walletId - Wallet UUID.
   * @returns {Promise<Array<import('./index.d.ts').Withdrawal>>} Requests; a relayed transaction is not yet confirmed.
   */
  async getWithdrawals(walletId) { return (await this.getWallet(walletId)).withdrawals; }
  /**
   * Generate, encrypt, and watch an additional receiving key for this wallet.
   * @param {string} walletId - Wallet UUID.
   * @param {string} [name='Receive address'] - Address label.
   * @returns {Promise<import('./index.d.ts').Address>} Public address metadata.
   */
  newAddress(walletId, name = 'Receive address') { return this.#run(async () => {
    const { vault, index } = this.#runtime; vault.get(this.#namespace, walletId);
    const a = vault.addAddress(walletId, createWallet(), name); await index.watchIdentity(a.identity); return a;
  }); }
  /**
   * Build a signed payment preview without reserving inputs or broadcasting.
   * @param {string} walletId - Wallet UUID.
   * @param {import('./index.d.ts').Payment} payment - Recipients, ribbits/byte fee rate and coin-selection policy.
   * @returns {Promise<import('./index.d.ts').Quote>} Reviewable transaction ID, fee, inputs and change.
   * @throws {Error} Rejects for stale sync, locked spending, rescan requirements or insufficient funds.
   */
  quote(walletId, payment) { return this.#run(() => this.#runtime.service.quote(this.#namespace, walletId, payment)); }
  /**
   * Persist a signed payment and input reservations before attempting public-peer relay.
   * Authorize and durably save requestId before calling. Reuse the same request after a
   * failure; an uncertain relay may still confirm and never automatically releases inputs.
   * @param {string} walletId - Wallet UUID.
   * @param {import('./index.d.ts').Payment & {requestId: string}} payment - Payment plus a durable idempotency key.
   * @returns {Promise<import('./index.d.ts').Withdrawal>} Saved request; inspect state rather than assuming confirmation.
   */
  withdraw(walletId, { requestId, ...payment }) { return this.#run(() => this.#runtime.service.send(this.#namespace, walletId, payment, requestId)); }
  /**
   * Relay exactly the saved transaction bytes; never create a replacement payment.
   * @param {string} walletId - Wallet UUID.
   * @param {string} withdrawalId - Saved withdrawal UUID, not its requestId or transaction hash.
   * @returns {Promise<import('./index.d.ts').Withdrawal>} Updated relay state or the already-confirmed request.
   */
  rebroadcast(walletId, withdrawalId) { return this.#run(() => this.#runtime.service.rebroadcast(this.#namespace, walletId, withdrawalId)); }
  /**
   * Add or remove manual coin locks. Withdrawal reservations remain independent.
   * @param {string} walletId - Wallet UUID.
   * @param {string[]} outpoints - Up to 400 lowercase txid:vout identifiers.
   * @param {boolean} [locked=true] - Whether to lock the selected coins.
   * @returns {Promise<void>}
   */
  lockCoins(walletId, outpoints, locked = true) { return this.#run(() => {
    const { vault } = this.#runtime; vault.get(this.#namespace, walletId);
    if (!Array.isArray(outpoints) || outpoints.length > 400 || outpoints.some(c => typeof c !== 'string' || !/^[0-9a-f]{64}:\d{1,10}$/.test(c))) throw new Error('Invalid coin outpoints.');
    vault.db.transaction(() => { for (const c of outpoints) vault.db.prepare(locked ? 'INSERT OR IGNORE INTO coin_locks VALUES (?,?)' : 'DELETE FROM coin_locks WHERE walletId=? AND outpoint=?').run(walletId, c); })();
  }); }
  /**
   * Persist a vault-wide lock on new spending, key export and message signing.
   * Already-submitted transactions can still confirm; saved transactions may be rebroadcast.
   * @param {boolean} [locked=true] - Desired spending-lock state.
   * @returns {Promise<{changes: number|bigint, lastInsertRowid: number|bigint}>} SQLite write result.
   */
  lockSpending(locked = true) { return this.#run(() => {
    const { db } = this.#runtime.vault;
    // 'library' ownership stops console operators from releasing a lock set by the host application.
    return db.transaction(() => {
      if (locked) db.prepare("INSERT OR REPLACE INTO settings VALUES ('locked-by','library')").run();
      else db.prepare("DELETE FROM settings WHERE name='locked-by'").run();
      return db.prepare("INSERT OR REPLACE INTO settings VALUES ('locked',?)").run(locked ? '1' : '0');
    })();
  }); }
  /**
   * Encrypt this namespace's keys, contacts, outgoing requests and coin reservations.
   * Store the returned object and its passphrase securely and separately.
   * @param {string} passphrase - Backup passphrase of at least 12 characters.
   * @returns {Promise<import('./index.d.ts').EncryptedBackup>} Version 2 encrypted JSON envelope.
   */
  backup(passphrase) { return this.#run(() => this.#runtime.vault.backup(this.#namespace, passphrase)); }
  /**
   * Restore keys and reservations atomically, then register restored addresses for watching.
   * Existing matching account IDs reject; restored balances require a historical rescan.
   * @param {import('./index.d.ts').EncryptedBackup} backup - Supported encrypted backup envelope.
   * @param {string} passphrase - Passphrase used to encrypt the backup.
   * @returns {Promise<{wallets: number, needsRescan: boolean}>} Restored wallet count and rescan requirement.
   */
  restore(backup, passphrase) { return this.#run(async () => {
    const result = this.#runtime.vault.restore(this.#namespace, backup, passphrase);
    for (const id of this.#runtime.vault.allIdentities()) await this.#runtime.index.watchIdentity(id);
    return result;
  }); }
  /**
   * Import a Pepecoin WIF key and mark its address as requiring a historical rescan.
   * @param {string} walletId - Destination wallet UUID.
   * @param {string} privateKeyWif - Sensitive compressed or uncompressed mainnet WIF.
   * @param {string} [name='Imported key'] - Address label.
   * @returns {Promise<import('./index.d.ts').Address>} Public metadata; never the imported secret.
   */
  importKey(walletId, privateKeyWif, name = 'Imported key') { return this.#run(async () => {
    const { vault, index } = this.#runtime; vault.get(this.#namespace, walletId);
    const key = importWif(privateKeyWif);
    try { const a = vault.addAddress(walletId, key, name, true); await index.watchIdentity(a.identity); return a; }
    finally { key.privateKey.fill(0); }
  }); }
  /**
   * Run a synchronous operation with a decrypted key, then zero that key buffer.
   * @private
   * @template T
   * @param {string} walletId - Wallet UUID.
   * @param {string} address - Address belonging to the wallet.
   * @param {function({privateKey: Buffer, compressed: boolean}): T} action - Synchronous key consumer.
   * @returns {T} Operation result. Do not retain or asynchronously use the key buffer.
   */
  #withKey(walletId, address, action) {
    const { vault } = this.#runtime; vault.get(this.#namespace, walletId);
    if (vault.db.prepare("SELECT value FROM settings WHERE name='locked'").get()?.value === '1') throw new Error('Wallet spending is locked.');
    const a = vault.addresses(walletId).find(a => a.address === address); if (!a) throw new Error('Address not found.');
    const key = vault.signingKey(walletId, a.identity);
    try { return action(key); } finally { key.privateKey.fill(0); }
  }
  /**
   * Export a private key as WIF. The caller must protect this spend-authorizing secret.
   * @param {string} walletId - Wallet UUID.
   * @param {string} address - Address belonging to the wallet.
   * @returns {Promise<string>} Sensitive WIF string.
   * @throws {Error} Rejects if spending is locked or the address is not owned.
   */
  exportKey(walletId, address) { return this.#run(() => this.#withKey(walletId, address, k => wif(k.privateKey, k.compressed))); }
  /**
   * Create a compact Pepecoin message signature, not a payment transaction.
   * @param {string} walletId - Wallet UUID.
   * @param {string} address - Owned signing address.
   * @param {string} message - UTF-8 text, at most 10000 bytes.
   * @returns {Promise<string>} Base64 compact signature.
   */
  signMessage(walletId, address, message) { return this.#run(() => this.#withKey(walletId, address, k => signMessage(k.privateKey, message, k.compressed))); }
  /**
   * Verify a compact message signature without accessing wallet keys.
   * @param {string} address - Claimed mainnet P2PKH signer.
   * @param {string} message - Exact signed text.
   * @param {string} signature - Base64 compact signature.
   * @returns {boolean} False for invalid signatures or malformed input.
   */
  verifyMessage(address, message, signature) { return verifyMessage(address, message, signature); }
  /**
   * Validate and save a mainnet destination in this namespace's address book.
   * @param {string} name - Contact label.
   * @param {string} address - P2PKH or P2SH mainnet destination.
   * @returns {Promise<{id: string}>} New contact UUID.
   */
  saveContact(name, address) { return this.#run(() => { destinationScript(address); return this.#runtime.vault.saveContact(this.#namespace, name, address); }); }
  /**
   * Read public address-book entries for this namespace.
   * @returns {Promise<Array<{id: string, label: string, address: string}>>} Contacts ordered by label.
   */
  listContacts() { return this.#run(() => this.#runtime.vault.contacts(this.#namespace)); }
  /**
   * Reject new work, drain in-flight operations, and release network, database and lock resources.
   * Repeated calls return the same shutdown promise. No new transaction is created.
   * @returns {Promise<void>} Resolves after owned resources are closed.
   */
  close() {
    if (this.#closePromise) return this.#closePromise;
    this.#closing = true;
    this.#closePromise = (async () => { await Promise.allSettled([...this.#pending]); await this.#runtime.close(); this.removeAllListeners(); })();
    return this.#closePromise;
  }
  /**
   * Support explicit asynchronous resource management by awaiting close().
   * @returns {Promise<void>}
   */
  async [Symbol.asyncDispose]() { await this.close(); }
}
export { verifyMessage } from './lib/wallet-signing.js';
