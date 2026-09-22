/**
 * Example: a withdrawal worker that survives timeouts and restarts without paying twice.
 * Needs the public Pepecoin network and a funded wallet:
 *
 *   node examples/withdrawal-worker.js ./wallet-data
 *
 * Pattern: persist the order first → review a quote → withdraw with the order ID as
 * requestId → record the outcome. After a crash, re-run the same order with the same ID.
 */
import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { PepecoinWallet } from 'pepecoin-js-wallet';

/**
 * Create the orders table used by this worker.
 * @param {DatabaseSync} db - Application database.
 * @returns {void}
 */
export function createOrders(db) {
  db.exec(`CREATE TABLE IF NOT EXISTS withdrawal_orders (
    id TEXT PRIMARY KEY, walletId TEXT NOT NULL, destination TEXT NOT NULL, amount TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending', txid TEXT, detail TEXT)`);
}

/**
 * Durably record an order. Your application must already have authorized the user and
 * debited/reserved their ledger balance in the same database transaction.
 * @param {DatabaseSync} db - Application database.
 * @param {{walletId: string, destination: string, amount: string}} order - Decimal PEPE amount.
 * @returns {string} The order ID, reused as the wallet requestId.
 */
export function placeOrder(db, { walletId, destination, amount }) {
  const id = randomUUID();
  db.prepare('INSERT INTO withdrawal_orders (id, walletId, destination, amount) VALUES (?,?,?,?)').run(id, walletId, destination, amount);
  return id;
}

/**
 * Process every order that has not reached a final state. Safe to run repeatedly.
 * @param {PepecoinWallet} wallets - Open wallet library.
 * @param {DatabaseSync} db - Application database.
 * @param {{maxFee?: bigint}} [limits] - Refuse orders whose network fee exceeds maxFee ribbits.
 * @returns {Promise<void>}
 */
export async function processOrders(wallets, db, { maxFee = 10_000_000n } = {}) {
  for (const order of db.prepare("SELECT * FROM withdrawal_orders WHERE status='pending'").all()) {
    const payment = { recipients: [{ address: order.destination, amount: order.amount }], minConfirmations: 6 };
    try {
      // After a crash the wallet may already hold this order; never build it twice.
      let withdrawal = (await wallets.getWithdrawals(order.walletId)).find(w => w.requestId === order.id);
      if (!withdrawal) {
        // 1. Review: a quote reserves nothing and broadcasts nothing.
        const quote = await wallets.quote(order.walletId, payment);
        if (BigInt(quote.feeKoinu) > maxFee) throw new Error(`Fee ${quote.feeKoinu} ribbits is above the limit.`);
        // 2. Submit with the order ID as requestId. expectedTxid rejects if coins changed since review.
        //    Retrying with the same requestId and fields returns the saved withdrawal.
        withdrawal = await wallets.withdraw(order.walletId, { requestId: order.id, ...payment, expectedTxid: quote.txid });
      }
      db.prepare("UPDATE withdrawal_orders SET status='submitted', txid=?, detail=? WHERE id=?").run(withdrawal.txid, withdrawal.state, order.id);
      console.log(`Order ${order.id}: ${withdrawal.state} ${withdrawal.txid}`);
    } catch (error) {
      // 503 = index not caught up yet; try again later. Do NOT create a new order or refund
      // on a timeout: a signed transaction may already exist and can still confirm.
      console.log(`Order ${order.id} not submitted yet: ${error.message}`);
    }
  }

  // 3. Settle: an order is done only when the chain shows its transaction.
  for (const order of db.prepare("SELECT * FROM withdrawal_orders WHERE status='submitted'").all()) {
    const saved = (await wallets.getWithdrawals(order.walletId)).find(w => w.requestId === order.id);
    if (saved?.state === 'confirmed') {
      db.prepare("UPDATE withdrawal_orders SET status='confirmed' WHERE id=?").run(order.id);
      console.log(`Order ${order.id} confirmed in the chain.`);
    } else if (saved?.state === 'unverified' || saved?.state === 'queued') {
      // Relay was not verified (or a restart interrupted it). Resend the exact same bytes;
      // this never creates a second payment.
      await wallets.rebroadcast(order.walletId, saved.id).catch(error => console.log('Rebroadcast failed:', error.message));
    }
  }
}

if (import.meta.main) {
  const [dataDir = './wallet-data', destination, amount] = process.argv.slice(2);
  const db = new DatabaseSync(path.join(path.resolve(dataDir), '..', 'example-orders.db'));
  createOrders(db);
  const wallets = await PepecoinWallet.open({ dataDir: path.resolve(dataDir), namespace: 'shop' });
  const account = await wallets.createWallet('payouts', 'Payout float');
  if (destination && amount) console.log('Placed order', placeOrder(db, { walletId: account.id, destination, amount }));
  else console.log(`Fund ${account.addresses[0].address}, then run: node examples/withdrawal-worker.js ${dataDir} <address> <amount>`);

  // Retry on each new block until every order is confirmed.
  let running = Promise.resolve();
  const run = () => { running = running.then(() => processOrders(wallets, db)).catch(error => console.error(error.message)); };
  wallets.on('block', run);
  wallets.on('sync', state => { if (state.state === 'synced') run(); });
  process.once('SIGINT', async () => { await running; await wallets.close(); db.close(); });
}
