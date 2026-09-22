/**
 * @file Wallet spending policy and indexed-balance projections shared by the library and web app.
 */
import { createHash } from 'node:crypto';
import { buildPayment, pepe } from './wallet-signing.js';
import { label } from './wallet-vault.js';

/**
 * Coordinate the vault, chain index and public-peer relay for trusted callers.
 * A fresh local index is a spending policy check, not full consensus validation.
 */
export class WalletService {
  /**
   * Create a service without starting network activity.
   * @param {Object} dependencies - Shared runtime components.
   * @param {import("./wallet-vault.js").WalletVault} dependencies.vault - Locked vault.
   * @param {import("./chain-index.js").ChainIndex} dependencies.index - Initialized chain index.
   * @param {import("../index.d.ts").SyncStatus} dependencies.status - Mutable sync status shared with the runtime.
   * @param {function(Buffer): Promise<*>} dependencies.broadcast - Relay function that rejects if receipt is uncertain.
   */
  constructor({ vault, index, status, broadcast }) { Object.assign(this, { vault, index, status, broadcast }); this.queue = Promise.resolve(); }
  /**
   * Register every public-key identity in a wallet for future block indexing.
   * @param {import('../index.d.ts').AccountWallet} wallet - Wallet metadata with addresses.
   * @returns {Promise<import('../index.d.ts').AccountWallet>} The same wallet after watchers are registered.
   */
  async watch(wallet) { for (const a of wallet.addresses) await this.index.watchIdentity(a.identity); return wallet; }
  /**
   * Create/retrieve an account wallet and register its addresses with the index.
   * @param {string} owner - Authorized namespace.
   * @param {string} accountId - Stable account identifier.
   * @param {string} name - Display label.
   * @returns {Promise<import('../index.d.ts').AccountWallet>} Wallet metadata.
   */
  async create(owner, accountId, name) { return this.watch(this.vault.create(owner, accountId, name)); }
  /**
   * Calculate indexed balances, maturity, net deposits and withdrawal confirmation states.
   * This read also reconciles saved outgoing states against the index. No mempool scan occurs.
   * @param {string} owner - Authorized namespace.
   * @param {string} id - Wallet UUID.
   * @param {number} [minConfirmations=6] - Required confirmation count, 1–10000.
   * @returns {Promise<import('../index.d.ts').WalletSnapshot>} Public state with decimal-string PEPE amounts.
   */
  async snapshot(owner, id, minConfirmations = 6) {
    const wallet = this.vault.get(owner, id), addresses = this.vault.addresses(id);
    if (!Number.isInteger(minConfirmations) || minConfirmations < 1 || minConfirmations > 10000) throw new Error('Confirmations must be 1–10000.');
    const snapshot = await this.index.walletSnapshot(addresses.map(a => a.identity));
    const blocked = this.vault.blocked(id);
    for (const r of snapshot.legacyPending) blocked.add(`${r.inputTxid}:${r.vout}`);
    const needsRescan = addresses.some(a => a.needsRescan);
    const coins = snapshot.utxos.map(u => {
      const confirmations = Math.max(0, snapshot.height - u.height + 1);
      const reserved = blocked.has(`${u.txid}:${u.vout}`);
      const immature = Boolean(u.coinbase) && confirmations < (snapshot.height >= 1000 ? 240 : 30);
      return { ...u, amount: pepe(u.valueKoinu), confirmations, reserved, immature, spendable: !needsRescan && !reserved && !immature && confirmations >= minConfirmations };
    });
    const sum = xs => xs.reduce((n, c) => n + BigInt(c.valueKoinu), 0n);
    const transactions = new Map();
    for (const t of snapshot.transactions) {
      const old = transactions.get(t.txid) || { txid: t.txid, height: t.height, time: t.time, received: 0n, spent: 0n };
      old.received += BigInt(t.receivedKoinu); old.spent += BigInt(t.spentKoinu); transactions.set(t.txid, old);
    }
    const history = [...transactions.values()].map(t => ({ txid: t.txid, height: t.height, time: t.time, confirmations: snapshot.height - t.height + 1, received: pepe(t.received), spent: pepe(t.spent), net: pepe(t.received - t.spent) })).sort((a,b) => b.height-a.height);
    // Confirmation state is derived from the index on every read (not a timer).
    // Reservations intentionally remain until inputs have actually been spent.
    for (const p of this.vault.outgoing(id)) {
      const state = transactions.has(p.txid) ? 'confirmed' : p.state === 'confirmed' ? 'unverified' : p.state;
      if (p.state !== state) this.vault.setPayment(p.id, state);
    }
    const deposits = history.filter(t => !t.net.startsWith('-') && t.net !== '0.00000000').map(t => ({ id: `${id}:${t.txid}`, txid: t.txid, amount: t.net, height: t.height, confirmations: t.confirmations, eligible: this.indexFresh() && !needsRescan && Number.isSafeInteger(this.status.verifiedHeight) && t.height <= this.status.verifiedHeight && t.confirmations >= Math.max(minConfirmations, coins.some(c => c.txid === t.txid && c.coinbase) ? (snapshot.height >= 1000 ? 240 : 30) : 1) }));
    return { wallet, addresses, needsRescan, indexedHeight: snapshot.height, minConfirmations, balance: pepe(sum(coins)), available: pepe(sum(coins.filter(c => c.spendable))), reserved: pepe(sum(coins.filter(c => c.reserved))), immature: pepe(sum(coins.filter(c => c.immature))), coins, transactions: history, deposits, withdrawals: this.vault.outgoing(id), network: { ...this.status } };
  }
  /**
   * Normalize payment fields before hashing them for idempotency.
   * @param {import('../index.d.ts').Payment} input - Caller-provided fields; full validation occurs during construction.
   * @returns {Object} Canonical payment policy with sorted selected outpoints.
   */
  normalize(input) {
    if (!Array.isArray(input.recipients)) throw new Error('Recipients are required.');
    return { recipients: input.recipients.map(r => ({ address: r.address, amount: r.amount })), feeRate: String(input.feeRate ?? '1000'), minConfirmations: input.minConfirmations ?? 6, sendAll: input.sendAll === true, selected: Array.isArray(input.selected) ? [...input.selected].sort() : [] };
  }
  /**
   * Require unlocked spending and a sufficiently fresh, caught-up local index.
   * @returns {void}
   * @throws {Error} If spending is locked, or with status 503 if the index is not fresh.
   */
  requireSynced() {
    if (this.vault.db.prepare("SELECT value FROM settings WHERE name='locked'").get()?.value === '1') throw new Error('Wallet spending is locked by the operator.');
    if (!this.indexFresh()) throw Object.assign(new Error('Withdrawals are paused until the public-peer index is up to date.'), { status: 503 });
  }
  /**
   * Apply local freshness, height-lag and runtime-state requirements.
   * @returns {boolean} True when the index was caught up within two minutes and is at most two advertised blocks behind.
   */
  indexFresh() { return Boolean(this.status.lastSyncedAt && Number.isFinite(Date.parse(this.status.lastSyncedAt)) && Date.now() - Date.parse(this.status.lastSyncedAt) <= 120000 && !(this.status.targetHeight && this.status.targetHeight > this.status.height + 2) && ['synced','connecting','syncing'].includes(this.status.state)); }
  /**
   * Build a signed payment using confirmed, unlocked, unreserved inputs.
   * Decrypted vault key buffers are cleared after construction; this does not reserve or relay.
   * @param {string} owner - Authorized namespace.
   * @param {string} id - Wallet UUID.
   * @param {Object} input - Normalized payment fields.
   * @returns {Promise<import('../index.d.ts').Quote & {raw: Buffer}>} Signed payment with raw bytes.
   * @throws {Error} Rejects if sync, import state, funds or signing requirements are not met.
   */
  async build(owner, id, input) {
    this.requireSynced();
    const snapshot = await this.snapshot(owner, id, input.minConfirmations);
    if (snapshot.needsRescan) throw new Error('Imported wallet requires a full rescan before spending.');
    const keys = new Map();
    try {
      return buildPayment({ ...input, utxos: snapshot.coins.filter(c => c.spendable), changeAddress: snapshot.addresses[0].address, keyFor: identity => {
        if (!keys.has(identity)) keys.set(identity, this.vault.signingKey(id, identity));
        return keys.get(identity);
      } });
    } finally { for (const k of keys.values()) k?.privateKey.fill(0); }
  }
  /**
   * Return a signed payment preview with raw bytes omitted.
   * @param {string} owner - Authorized namespace.
   * @param {string} id - Wallet UUID.
   * @param {import('../index.d.ts').Payment} body - Requested payment.
   * @returns {Promise<import('../index.d.ts').Quote>} Review metadata; inputs are not reserved.
   */
  async quote(owner, id, body) { const { raw, ...result } = await this.build(owner, id, this.normalize(body)); return result; }
  /**
   * Serialize construction/reservation, persist before relay, and deduplicate retries.
   * Repeating identical fields with the same requestId returns the saved request without
   * another relay. expectedTxid, when supplied, must match the freshly constructed payment.
   * @param {string} owner - Authorized namespace.
   * @param {string} id - Wallet UUID.
   * @param {import('../index.d.ts').Payment} body - Requested payment and optional reviewed transaction ID.
   * @param {string} requestId - Durable idempotency key, at most 128 characters.
   * @returns {Promise<import('../index.d.ts').Withdrawal>} Saved request; relay failure is represented by an unverified state.
   */
  async send(owner, id, body, requestId) {
    this.vault.get(owner, id); requestId = label(requestId, 128);
    const input = this.normalize(body), fingerprint = createHash('sha256').update(JSON.stringify(input)).digest('hex');
    // Serialize signing/reservation across every wallet. The SQLite unique
    // outpoint constraint is the durable final guard against concurrent sends.
    const work = this.queue.then(async () => {
      const existing = this.vault.existing(id, requestId, fingerprint);
      if (existing) return { row: existing, fresh: false };
      const payment = await this.build(owner, id, input);
      if (body.expectedTxid && body.expectedTxid !== payment.txid) throw Object.assign(new Error('Coins or fee changed. Review a fresh quote before sending.'), { status: 409 });
      return { row: this.vault.reserve(id, requestId, fingerprint, payment), fresh: true };
    });
    this.queue = work.catch(() => {});
    const { row, fresh } = await work;
    return fresh ? this.relay(row) : this.vault.publicPayment(row);
  }
  /**
   * Relay exact persisted bytes and save relayed or unverified state.
   * An error is not evidence that a payment cannot confirm; reservations remain in place.
   * @param {Object} row - Internal outgoing row containing id and hex raw bytes.
   * @returns {Promise<import('../index.d.ts').Withdrawal>} Public request metadata.
   */
  async relay(row) {
    try { await this.broadcast(Buffer.from(row.raw, 'hex')); this.vault.setPayment(row.id, 'relayed'); }
    catch (e) { this.vault.setPayment(row.id, 'unverified', `Relay uncertain: ${e.message}`); }
    return this.vault.publicPayment(this.vault.db.prepare('SELECT * FROM outgoing WHERE id=?').get(row.id));
  }
  /**
   * Retry exact saved bytes for an owned withdrawal; confirmed requests are returned unchanged.
   * @param {string} owner - Authorized namespace.
   * @param {string} walletId - Wallet UUID.
   * @param {string} id - Withdrawal UUID.
   * @returns {Promise<import('../index.d.ts').Withdrawal>} Current or updated relay state.
   */
  async rebroadcast(owner, walletId, id) {
    this.vault.get(owner, walletId);
    const row = this.vault.db.prepare('SELECT * FROM outgoing WHERE walletId=? AND id=?').get(walletId, id);
    if (!row) throw new Error('Withdrawal not found.');
    if (row.state === 'confirmed') return this.vault.publicPayment(row);
    return this.relay(row); // Exact persisted bytes; never a replacement payment.
  }
}
