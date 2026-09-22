/**
 * Public package embedding, runtime shutdown, and backup round-trip tests.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readdir } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import { PepecoinWallet, verifyMessage } from 'pepecoin-js-wallet';

test('package entry embeds directly without HTTP, users, API tokens, or process handlers', async t => {
  const dataDir = await mkdtemp(path.join(os.tmpdir(), 'pepe-library-'));
  const original = net.Server.prototype.listen;
  let listeners = 0;
  net.Server.prototype.listen = function (...args) { listeners++; return original.apply(this,args); };
  t.after(() => { net.Server.prototype.listen = original; });
  const signalCounts = ['SIGINT','SIGTERM','exit'].map(e => process.listenerCount(e));
  const wallet = await PepecoinWallet.open({ dataDir, autoSync: false }); t.after(() => wallet.close());
  const account = await wallet.createWallet('account-123','Account One');
  assert.equal((await wallet.createWallet('account-123')).id, account.id);
  assert.equal((await wallet.listWallets()).length, 1);
  assert.equal((await wallet.getBalance(account.id)).balance, '0.00000000');
  assert.equal((await wallet.getDeposits(account.id)).length, 0);
  const address = await wallet.newAddress(account.id, 'Second address');
  assert.notEqual(address.address, account.addresses[0].address);
  const signature = await wallet.signMessage(account.id, address.address, 'Library integration test');
  assert.ok(verifyMessage(address.address, 'Library integration test', signature));
  assert.equal(listeners, 0);
  assert.deepEqual(['SIGINT','SIGTERM','exit'].map(e => process.listenerCount(e)), signalCounts);
  const files = await readdir(dataDir);
  assert.ok(!files.includes('users.json'));assert.ok(!files.includes('apps.json'));
  await assert.rejects(wallet.withdraw(account.id, { requestId:'order-1',recipients:[{address:address.address,amount:'1'}] }), /up to date/);
  await wallet.close(); await wallet.close();
  await assert.rejects(wallet.listWallets(), /closed/);
  const reopened = await PepecoinWallet.open({ dataDir,autoSync:false });
  try { assert.equal((await reopened.createWallet('account-123')).id,account.id); }
  finally { await reopened.close(); }
});

test('library close drains operations, and encrypted backup restores through public methods', async t => {
  const dataDir = await mkdtemp(path.join(os.tmpdir(), 'pepe-library-backup-'));
  const wallet = await PepecoinWallet.open({dataDir,autoSync:false});t.after(()=>wallet.close());
  const creation = wallet.createWallet('queued-account');
  await wallet.close(); const original = await creation;
  const reopened = await PepecoinWallet.open({dataDir,autoSync:false});
  const backup = await reopened.backup('test backup passphrase');await reopened.close();
  const restoredDir = await mkdtemp(path.join(os.tmpdir(), 'pepe-library-restored-'));
  const restored = await PepecoinWallet.open({dataDir:restoredDir,autoSync:false});t.after(()=>restored.close());
  await restored.restore(backup,'test backup passphrase');
  const account = (await restored.listWallets())[0];
  assert.equal(account.addresses[0].address,original.addresses[0].address);
  assert.ok((await restored.getBalance(account.id)).needsRescan);
});
