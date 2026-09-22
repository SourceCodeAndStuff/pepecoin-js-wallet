/**
 * Index integrity, Merkle verification, history retention, and data-directory lock tests.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readdir } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import Database from '../lib/sqlite.js';
import { ChainIndex } from '../lib/chain-index.js';
import { hash256d } from '../lib/pepenet-wire.js';
import { acquireServerLock } from '../lib/server-lock.js';

test('data-directory lock prevents concurrent servers and releases cleanly', async () => {
  const dir=await mkdtemp(path.join(os.tmpdir(),'pepe-lock-test-'));
  const release=acquireServerLock(dir);
  assert.throws(()=>acquireServerLock(dir),/locked/);
  release();release();acquireServerLock(dir)();
});

test('wallet-only index verifies Merkle roots and retains more than 100 transactions', async t => {
  const dir=await mkdtemp(path.join(os.tmpdir(),'pepe-merkle-test-'));
  const index=new ChainIndex(dir);t.after(()=>index.close());await index.init();
  const identity=Buffer.alloc(20,9),script=Buffer.concat([Buffer.from('76a914','hex'),identity,Buffer.from('88ac','hex')]);
  await index.watchIdentity(identity.toString('hex'));
  const blocks=[];
  for(let h=1;h<=105;h++) {
    const version=Buffer.alloc(4);version.writeUInt32LE(h);
    const value=Buffer.alloc(8);value.writeBigInt64LE(100000000n);
    const tx=Buffer.concat([version,Buffer.from([1]),Buffer.alloc(36),Buffer.from([0]),Buffer.alloc(4),Buffer.from([1]),value,Buffer.from([script.length]),script,Buffer.alloc(4)]);
    const header=Buffer.alloc(80);hash256d(tx).copy(header,36);header.writeUInt32LE(h,68);
    blocks.push({height:h,rawBlock:Buffer.concat([header,Buffer.from([1]),tx])});
  }
  const invalid=Buffer.from(blocks[0].rawBlock);invalid[36]^=1;
  await assert.rejects(index.ingest(invalid,1),/Merkle root/);
  await index.ingestBatch(blocks);
  const snapshot=await index.walletSnapshot([identity.toString('hex')]);
  assert.equal(snapshot.transactions.length,105);assert.equal(snapshot.utxos.length,105);assert.equal(snapshot.utxos[0].coinbase,1);
  await index.ingest(blocks[0].rawBlock,1);
  assert.equal((await index.walletSnapshot([identity.toString('hex')])).utxos.length,105);
});

test('chain index refuses invalid raw blocks before persisting them', async t => {
  const index = new ChainIndex(await mkdtemp(path.join(os.tmpdir(), 'pepe-index-')));
  t.after(() => index.close());
  await index.init();
  await assert.rejects(index.ingest(Buffer.alloc(80), 1), /Truncated chain message|Invalid block transaction count/);
});

test('chain index quarantines an impossible repeated-hash tail', async t => {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'pepe-index-corrupt-'));
  const db = new Database(path.join(dir, 'chainindex.db'));
  db.exec(`
    CREATE TABLE blocks (height INTEGER PRIMARY KEY, hash TEXT NOT NULL);
    CREATE TABLE wallets (identity TEXT PRIMARY KEY);
  `);
  db.prepare(`INSERT INTO blocks(height, hash) VALUES (?, ?)`).run(1, '11'.repeat(32));
  db.prepare(`INSERT INTO blocks(height, hash) VALUES (?, ?)`).run(2, '11'.repeat(32));
  db.prepare(`INSERT INTO wallets(identity) VALUES (?)`).run('ab'.repeat(20));
  db.close();

  const index = new ChainIndex(dir);
  t.after(() => index.close());
  await index.init();
  assert.equal(index.syncCheckpoint().height, -1);
  assert.equal((await index.walletSnapshot(['ab'.repeat(20)])).height, -1);
  assert.ok((await readdir(dir)).some(name => name.startsWith('chainindex.db.corrupt-')));
});
