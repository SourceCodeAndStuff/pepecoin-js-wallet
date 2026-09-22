/**
 * Legacy vault and backup migration tests preserving wallet identities and reservations.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { WalletVault } from '../lib/wallet-vault.js';
import { PepecoinWallet } from 'pepecoin-js-wallet';
import { decryptPrivateKey, encryptPrivateKey, passwordKey } from '../lib/wallet.js';

test('legacy account column and namespace preserve wallet identities across upgrade', async t => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'pepe-upgrade-'));
  const old = new WalletVault(dir);
  const original = old.create('existing-namespace', 'account-42', 'Original');
  old.db.exec('ALTER TABLE wallets RENAME COLUMN accountId TO playerId');
  old.close();
  const wallet = await PepecoinWallet.open({ dataDir: dir, autoSync: false });
  t.after(() => wallet.close());
  const restored = await wallet.createWallet('account-42');
  assert.equal(restored.id, original.id);
  assert.equal(restored.accountId, 'account-42');
  assert.deepEqual(restored.addresses, original.addresses);
  assert.equal((await wallet.listWallets()).length, 1);
});

test('ambiguous default namespace fails closed and releases the runtime lock', async t => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'pepe-namespaces-'));
  const vault = new WalletVault(dir);
  vault.create('first', 'one', 'One');
  vault.create('second', 'two', 'Two');
  vault.close();
  await assert.rejects(PepecoinWallet.open({ dataDir: dir, autoSync: false }), /Specify namespace/);
  const wallet = await PepecoinWallet.open({ dataDir: dir, namespace: 'second', autoSync: false });
  t.after(() => wallet.close());
  assert.equal((await wallet.listWallets())[0].accountId, 'two');
});

test('version 1 encrypted backups preserve account keys and pending input reservations', async t => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'pepe-backup-upgrade-'));
  const vault = new WalletVault(dir); t.after(() => vault.close());
  const original = vault.create('source', 'account-42', 'Original');
  const txid = '11'.repeat(32), outpoint = `${txid}:0`;
  vault.reserve(original.id, 'request-1', 'fingerprint', {
    txid: '22'.repeat(32), raw: Buffer.from('010203', 'hex'), inputs: [{ txid, vout: 0 }]
  });
  vault.db.prepare('INSERT INTO coin_locks VALUES (?,?)').run(original.id, outpoint);
  const passphrase = 'upgrade test passphrase';
  const backup = vault.backup('source', passphrase);
  assert.equal(backup.format, 'pepecoin-js-wallet'); assert.equal(backup.version, 2);
  const key = passwordKey(passphrase, Buffer.from(backup.salt, 'base64url'));
  const data = JSON.parse(decryptPrivateKey(backup.ciphertext, key));
  for (const row of [...data.wallets, ...data.outgoing, ...data.coinLocks]) {
    row.playerId = row.accountId; delete row.accountId;
  }
  const legacy = { ...backup, version: 1, format: 'pepecoin-legacy-wallet', ciphertext: encryptPrivateKey(Buffer.from(JSON.stringify(data)), key) };
  const targetDir = await mkdtemp(path.join(os.tmpdir(), 'pepe-backup-target-'));
  const target = new WalletVault(targetDir); t.after(() => target.close());
  target.restore('destination', legacy, passphrase);
  const restored = target.list('destination')[0];
  assert.equal(restored.accountId, original.accountId);
  assert.equal(restored.addresses[0].address, original.addresses[0].address);
  assert.equal(target.outgoing(restored.id)[0].requestId, 'request-1');
  assert.equal(target.db.prepare('SELECT raw FROM outgoing').get().raw, '010203');
  assert.ok(target.blocked(restored.id).has(outpoint));
  assert.equal(target.db.prepare('SELECT walletId FROM coin_locks').get().walletId, restored.id);
});
