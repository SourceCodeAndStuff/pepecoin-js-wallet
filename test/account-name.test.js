/**
 * Account-name normalization and validation regression tests.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeAccountName } from '../lib/wallet.js';

test('account names are required and normalized for stable account identity', () => {
  assert.equal(normalizeAccountName('  Alice_01 '), 'alice_01');
  assert.throws(() => normalizeAccountName(''), /Account name/);
  assert.throws(() => normalizeAccountName('No spaces'), /Account name/);
});
