/**
 * Example: credit incoming deposits to an application ledger exactly once.
 * Needs the public Pepecoin network (it syncs on open):
 *
 *   node examples/deposit-watcher.js ./wallet-data
 *
 * The ledger is a SQLite table here; use your application's database in the same way.
 */
import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import { PepecoinWallet } from 'pepecoin-js-wallet';

/**
 * Create the ledger tables. The UNIQUE deposit ID is what prevents double credits.
 * @param {DatabaseSync} db - Application database.
 * @returns {void}
 */
export function createLedger(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS balances (accountId TEXT PRIMARY KEY, ribbits INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS credited_deposits (
      depositId TEXT PRIMARY KEY, accountId TEXT NOT NULL, txid TEXT NOT NULL, ribbits INTEGER NOT NULL, creditedAt TEXT NOT NULL
    );`);
}

/**
 * Convert a decimal PEPE string to integer ribbits without floating point.
 * @param {string} amount - Decimal PEPE, e.g. "12.5".
 * @returns {bigint} Ribbits (1 PEPE = 100,000,000 ribbits).
 */
export function toRibbits(amount) {
  const [whole, fraction = ''] = amount.split('.');
  return BigInt(whole) * 100_000_000n + BigInt(fraction.padEnd(8, '0').slice(0, 8));
}

/**
 * Credit every eligible deposit that has not been credited yet, atomically.
 * Safe to call as often as you like: repeated calls never credit twice.
 * @param {PepecoinWallet} wallets - Open wallet library.
 * @param {DatabaseSync} db - Application ledger.
 * @param {{accountId: string, walletId: string}[]} accounts - Accounts to scan.
 * @returns {Promise<number>} Number of new credits.
 */
export async function creditNewDeposits(wallets, db, accounts) {
  let credited = 0;
  const insert = db.prepare('INSERT OR IGNORE INTO credited_deposits VALUES (?,?,?,?,?)');
  const add = db.prepare('INSERT INTO balances (accountId, ribbits) VALUES (?,?) ON CONFLICT(accountId) DO UPDATE SET ribbits = ribbits + excluded.ribbits');
  for (const { accountId, walletId } of accounts) {
    // eligible = enough confirmations AND the index is caught up AND independent peers
    // confirmed the chain tip. Never credit a deposit that is not eligible.
    for (const deposit of await wallets.getDeposits(walletId, { confirmations: 6 })) {
      if (!deposit.eligible) continue;
      const ribbits = toRibbits(deposit.amount);
      db.exec('BEGIN IMMEDIATE');
      try {
        // The deposit ID is unique per wallet and transaction; a second insert is ignored.
        if (insert.run(deposit.id, accountId, deposit.txid, ribbits, new Date().toISOString()).changes === 1) {
          add.run(accountId, ribbits);
          credited++;
          console.log(`Credited ${deposit.amount} PEPE to ${accountId} (tx ${deposit.txid})`);
        }
        db.exec('COMMIT');
      } catch (error) { db.exec('ROLLBACK'); throw error; }
    }
  }
  return credited;
}

if (import.meta.main) {
  const dataDir = path.resolve(process.argv[2] || './wallet-data');
  const db = new DatabaseSync(path.join(dataDir, '..', 'example-ledger.db'));
  createLedger(db);
  const wallets = await PepecoinWallet.open({ dataDir, namespace: 'shop' });
  const account = await wallets.createWallet('user-1001', 'Alice');
  console.log('Send PEPE to', account.addresses[0].address, 'then wait for 6 confirmations.');
  const accounts = [{ accountId: 'user-1001', walletId: account.id }];

  // Re-check after every indexed block and whenever sync state changes. No polling timer needed.
  let running = Promise.resolve();
  const check = () => { running = running.then(() => creditNewDeposits(wallets, db, accounts)).catch(error => console.error(error.message)); };
  wallets.on('block', check);
  wallets.on('sync', state => { console.log(`sync: ${state.state} at ${state.height}`); if (state.state === 'synced') check(); });

  process.once('SIGINT', async () => { await running; await wallets.close(); db.close(); });
}
