/**
 * Keeps the published examples working. Offline examples run end to end against temporary
 * vaults; network examples have their ledger/worker logic exercised with an in-memory wallet.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';
import os from 'node:os';
import path from 'node:path';
import { runAccountsExample } from '../examples/accounts.js';
import { runSignAndVerifyExample } from '../examples/sign-and-verify.js';
import { runBackupRestoreExample } from '../examples/backup-restore.js';
import { createLedger, creditNewDeposits, toRibbits } from '../examples/deposit-watcher.js';
import { createOrders, placeOrder, processOrders } from '../examples/withdrawal-worker.js';
import { describeStatus } from '../examples/sync-status.js';
import { smallestCoinsFirst } from '../examples/coin-control.js';

const quiet = t => { const log = console.log; console.log = () => {}; t.after(() => { console.log = log; }); };
const temp = async (t, name) => { const dir = await mkdtemp(path.join(os.tmpdir(), name)); t.after(() => rm(dir, { recursive: true, force: true })); return dir; };

test('accounts example creates idempotent wallets and invoice addresses', async t => {
  quiet(t);
  const result = await runAccountsExample(await temp(t, 'pepe-ex-accounts-'));
  assert.equal(result.walletIds.length, 2);
  assert.match(result.invoiceAddress, /^P/);
});

test('sign-and-verify example produces a verifiable signature', async t => {
  quiet(t);
  const result = await runSignAndVerifyExample(await temp(t, 'pepe-ex-sign-'));
  assert.equal(result.valid, true);
  assert.equal(result.tampered, false);
});

test('backup-restore example restores the same addresses into a new vault', async t => {
  quiet(t);
  const result = await runBackupRestoreExample(await temp(t, 'pepe-ex-backup-'), 'example backup passphrase');
  assert.deepEqual(result, { restored: 1, sameAddress: true });
});

test('deposit watcher credits each eligible deposit exactly once', async t => {
  quiet(t);
  assert.equal(toRibbits('12.5'), 1_250_000_000n);
  assert.equal(toRibbits('0.00000001'), 1n);
  const db = new DatabaseSync(':memory:'); createLedger(db);
  const deposits = [
    { id: 'w1:aa', txid: 'aa', amount: '2.00000000', eligible: true },
    { id: 'w1:bb', txid: 'bb', amount: '5.00000000', eligible: false }
  ];
  const wallets = { getDeposits: async () => deposits };
  const accounts = [{ accountId: 'user-1', walletId: 'w1' }];
  assert.equal(await creditNewDeposits(wallets, db, accounts), 1);
  assert.equal(await creditNewDeposits(wallets, db, accounts), 0, 'polling again must not credit twice');
  deposits[1].eligible = true;
  assert.equal(await creditNewDeposits(wallets, db, accounts), 1);
  assert.equal(db.prepare('SELECT ribbits FROM balances').get().ribbits, 700_000_000);
});

test('withdrawal worker never builds an order twice across retries and restarts', async t => {
  quiet(t);
  const db = new DatabaseSync(':memory:'); createOrders(db);
  const saved = [];
  let failNext = true, builds = 0, rebroadcasts = 0;
  const wallets = {
    getWithdrawals: async () => saved,
    quote: async () => ({ txid: 'tx1', feeKoinu: '226000' }),
    withdraw: async (walletId, { requestId, expectedTxid }) => {
      builds++;
      assert.equal(expectedTxid, 'tx1');
      saved.push({ id: 'saved-1', requestId, txid: 'tx1', state: 'unverified' });
      if (failNext) { failNext = false; throw new Error('timeout after the request was persisted'); }
      return saved.at(-1);
    },
    rebroadcast: async () => { rebroadcasts++; }
  };
  const id = placeOrder(db, { walletId: 'w1', destination: 'P-destination', amount: '1.00000000' });
  await processOrders(wallets, db); // times out after persisting
  await processOrders(wallets, db); // restart: finds the saved request instead of building again
  assert.equal(builds, 1);
  assert.equal(db.prepare('SELECT status FROM withdrawal_orders WHERE id=?').get(id).status, 'submitted');
  assert.equal(rebroadcasts, 1, 'unverified relay is retried with the same bytes');
  saved[0].state = 'confirmed';
  await processOrders(wallets, db);
  assert.equal(db.prepare('SELECT status FROM withdrawal_orders WHERE id=?').get(id).status, 'confirmed');
  const expensive = placeOrder(db, { walletId: 'w1', destination: 'P-destination', amount: '1.00000000' });
  await processOrders({ ...wallets, getWithdrawals: async () => [], quote: async () => ({ txid: 'tx2', feeKoinu: '999999999' }) }, db);
  assert.equal(db.prepare('SELECT status FROM withdrawal_orders WHERE id=?').get(expensive).status, 'pending', 'fee limit is enforced');
});

test('sync-status and coin-control helpers', () => {
  assert.equal(describeStatus({ state: 'synced', height: 10, verifiedHeight: 10, targetHeight: 10, progressPercent: 100 }).ready, true);
  assert.equal(describeStatus({ state: 'syncing', height: 12, verifiedHeight: 10, targetHeight: 20, progressPercent: 60 }).ready, false);
  const coin = (txid, value, spendable = true) => ({ txid, vout: 0, valueKoinu: String(value), spendable });
  assert.deepEqual(smallestCoinsFirst([coin('c', 300), coin('a', 100), coin('b', 200), coin('x', 1, false)], 250n), ['a:0', 'b:0']);
});

test('TypeScript example runs with Node type stripping', async t => {
  const mod = await import('../examples/typescript-usage.ts');
  quiet(t);
  await mod.main(await temp(t, 'pepe-ex-ts-'));
  assert.equal(mod.isReady({ state: 'synced', height: 1, verifiedHeight: 1 }), true);
});
