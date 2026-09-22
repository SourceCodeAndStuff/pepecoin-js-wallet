/**
 * Header consensus checks: scrypt proof of work, AuxPoW proofs, DigiShield retargeting,
 * checkpoints and timestamps. Fixtures are the Pepecoin genesis header and a public
 * Dogecoin merged-mined block (same AuxPoW format, chain ID 0x62).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { hash256d, parseBlock } from '../lib/pepenet-wire.js';
import { PEP_CONSENSUS, checkAuxPow, checkProofOfWork, decodeCompact, encodeCompact, nextWorkRequired, scryptPowHash, validateHeaderChain } from '../lib/pepenet-pow.js';

/**
 * Rebuild the Pepecoin mainnet genesis header from chainparams.cpp.
 * @returns {Buffer} 80-byte header.
 */
function genesisHeader() {
  const header = Buffer.alloc(80);
  header.writeUInt32LE(1, 0);
  Buffer.from('d22a1ba59a39cbd5904624933efb822c8baa121f97060c4cc9ea2f00a4bc6512', 'hex').reverse().copy(header, 36);
  header.writeUInt32LE(1705975200, 68); header.writeUInt32LE(0x1e0ffff0, 72); header.writeUInt32LE(427444, 76);
  return header;
}

test('genesis header satisfies scrypt proof of work and a changed nonce does not', () => {
  const header = genesisHeader();
  assert.equal(Buffer.from(hash256d(header)).reverse().toString('hex'), PEP_CONSENSUS.genesis.hash);
  assert.equal(checkProofOfWork(scryptPowHash(header), 0x1e0ffff0), true);
  header.writeUInt32LE(427445, 76);
  assert.equal(checkProofOfWork(scryptPowHash(header), 0x1e0ffff0), false);
});

test('compact targets round-trip and out-of-range targets are rejected', () => {
  for (const bits of [0x1e0ffff0, 0x1b0404cb, 0x1d00ffff, 0x1a01aa3d]) assert.equal(encodeCompact(decodeCompact(bits).target), bits);
  assert.equal(checkProofOfWork(Buffer.alloc(32), 0x207fffff), false, 'easier than powLimit');
  assert.equal(checkProofOfWork(Buffer.alloc(32), 0x1e8fffff), false, 'negative target');
  assert.equal(checkProofOfWork(Buffer.alloc(32), 0), false, 'zero target');
});

test('DigiShield retarget follows the amplitude filter and step limits', () => {
  const last = { bits: 0x1c0ffff0, time: 1000 };
  const target = decodeCompact(0x1c0ffff0).target;
  assert.equal(nextWorkRequired(last, 940), encodeCompact(target), 'exactly 60s keeps the target');
  assert.equal(nextWorkRequired(last, 1000 - 60 - 80), encodeCompact(target * 70n / 60n), '140s → 60 + 80/8');
  assert.equal(nextWorkRequired(last, 1000 - 100000), encodeCompact(target * 90n / 60n), 'slow blocks capped at +50%');
  assert.equal(nextWorkRequired(last, 1000 + 100000), encodeCompact(target * 45n / 60n), 'fast blocks capped at −25%');
  assert.equal(nextWorkRequired({ bits: 0x1e0ffff0, time: 1000 }, 0), encodeCompact(PEP_CONSENSUS.powLimit), 'never easier than powLimit');
});

test('a real merged-mined block proof verifies and tampering is detected', () => {
  const block = parseBlock(Buffer.from(readFileSync(new URL('./fixtures/dogecoin-block-371337.hex', import.meta.url), 'utf8').trim(), 'hex'));
  const dogecoin = { ...PEP_CONSENSUS, auxpowChainId: 0x62 };
  assert.ok(block.auxpow);
  assert.doesNotThrow(() => checkAuxPow(block.header, block.auxpow, dogecoin));
  assert.throws(() => checkAuxPow(block.header, { ...block.auxpow, chainIndex: block.auxpow.chainIndex ^ 1 }, dogecoin), /index|Merkle/);
  const otherBlock = Buffer.from(block.header); otherBlock[40] ^= 1;
  assert.throws(() => checkAuxPow(otherBlock, block.auxpow, dogecoin), /chain Merkle root/);
  const parent = Buffer.from(block.auxpow.parentHeader); parent[76] ^= 1;
  assert.throws(() => checkAuxPow(block.header, { ...block.auxpow, parentHeader: parent }, dogecoin), /proof-of-work|Merkle/);
});

test('header chain validation enforces checkpoints, difficulty, median time and future limits', () => {
  const now = 1_800_000_000;
  const header = ({ bits = 0x1e0ffff0, time = now - 100, version = 1 } = {}) => {
    const h = Buffer.alloc(80); h.writeUInt32LE(version, 0); h.writeUInt32LE(time, 68); h.writeUInt32LE(bits, 72);
    return { header: h, hash: hash256d(h), auxpow: null };
  };
  const context = { height: 99, recent: Array.from({ length: 11 }, (_, i) => ({ time: now - 2000 + i * 60, bits: 0x1e0ffff0 })) };
  assert.throws(() => validateHeaderChain([header({ bits: 0x1e0fffff })], context, { now }), /difficulty/);
  assert.throws(() => validateHeaderChain([header({ time: now - 2000 })], context, { now }), /median time/);
  assert.throws(() => validateHeaderChain([header({ time: now + 3 * 3600 })], context, { now }), /future/);
  assert.throws(() => validateHeaderChain([header({ bits: nextWorkRequired(context.recent.at(-1), context.recent.at(-2).time) })], context, { now }), /proof-of-work/);
  assert.throws(() => validateHeaderChain([header()], { height: 40476, recent: [] }, { now }), /checkpoint/);
  assert.throws(() => validateHeaderChain([header({ version: 1 })], { height: 50000, recent: [] }, { now }), /Legacy block header after AuxPoW/);
  assert.throws(() => validateHeaderChain([header({ version: 0x620004 })], { height: 50000, recent: [] }, { now }), /chain ID/);
  const genesis = genesisHeader();
  assert.equal(validateHeaderChain([{ header: genesis, hash: hash256d(genesis), auxpow: null }], { height: -1, recent: [] }, { now }).height, 0, 'the pinned genesis checkpoint passes');
});
