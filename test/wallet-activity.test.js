/**
 * Indexed balance and confirmed transaction activity regression tests.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { ChainIndex } from '../lib/chain-index.js';
import { hash256d } from '../lib/pepenet-wire.js';

test('chain index exposes confirmed balance and wallet transaction activity', async t => {
  const index = new ChainIndex(await mkdtemp(path.join(os.tmpdir(), 'pepe-wallet-'))), identity = Buffer.alloc(20, 7);
  t.after(() => index.close());
  await index.init(); await index.watchIdentity(identity.toString('hex'));
  const header = Buffer.alloc(80), output = Buffer.alloc(8); output.writeBigInt64LE(125000000n);
  const script = Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), identity, Buffer.from([0x88, 0xac])]);
  const transaction = Buffer.concat([Buffer.alloc(4), Buffer.from([1]), Buffer.alloc(36), Buffer.from([0]), Buffer.alloc(4), Buffer.from([1]), output, Buffer.from([script.length]), script, Buffer.alloc(4)]);
  hash256d(transaction).copy(header, 36);
  await index.ingestBatch([{
    rawBlock: Buffer.concat([header, Buffer.from([1]), transaction]),
    height: 1
  }]);
  const activity = await index.walletSnapshot([identity.toString('hex')]);
  assert.equal(activity.utxos.reduce((sum, coin) => sum + BigInt(coin.valueKoinu), 0n), 125000000n);
  assert.equal(activity.transactions.length, 1);
  assert.equal(activity.transactions[0].receivedKoinu, '125000000');
});

test('chain index keeps difficulty bits so a restarted sync can validate retargets', async t => {
  const index = new ChainIndex(await mkdtemp(path.join(os.tmpdir(), 'pepe-context-')));
  t.after(() => index.close());
  await index.init();
  assert.deepEqual(index.chainContext(), { height: -1, recent: [] });
  const transaction = Buffer.concat([Buffer.alloc(4), Buffer.from([1]), Buffer.alloc(36), Buffer.from([0]), Buffer.alloc(4), Buffer.from([0]), Buffer.alloc(4)]);
  const blocks = [1, 2, 3].map(height => {
    const header = Buffer.alloc(80); hash256d(transaction).copy(header, 36);
    header.writeUInt32LE(1705975200 + height * 60, 68); header.writeUInt32LE(0x1e0ffff0 - height, 72);
    return { rawBlock: Buffer.concat([header, Buffer.from([1]), transaction]), height };
  });
  await index.ingestBatch(blocks);
  const context = index.chainContext();
  assert.equal(context.height, 3);
  assert.deepEqual(context.recent.map(r => r.bits), [0x1e0ffff0 - 1, 0x1e0ffff0 - 2, 0x1e0ffff0 - 3]);
  assert.deepEqual(context.recent.map(r => r.time), [1705975260, 1705975320, 1705975380]);
});
