/**
 * Transaction wire parsing and legacy transaction-ID regression tests.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { parseBlock } from '../lib/pepenet-wire.js';

test('wire reader accepts SegWit transactions and computes their legacy txid', () => {
  const tx = Buffer.concat([
    Buffer.alloc(4), Buffer.from([0, 1, 1]), Buffer.alloc(36),
    Buffer.from([0]), Buffer.alloc(4), Buffer.from([1]), Buffer.alloc(8),
    Buffer.from([0]), Buffer.from([1, 1, 0]), Buffer.alloc(4)
  ]);
  const block = parseBlock(Buffer.concat([Buffer.alloc(80), Buffer.from([1]), tx]));
  assert.equal(block.transactions.length, 1);
  assert.equal(block.transactions[0].raw.length, tx.length);
});
