/**
 * @file Pepecoin mainnet header consensus checks used before any block body is downloaded:
 * scrypt proof of work, merged-mining (AuxPoW) proofs, DigiShield difficulty, checkpoints,
 * median-time-past and future-time limits. Mirrors pepecoin Core pow.cpp, pepecoin.cpp and auxpow.cpp.
 * This is header-level (SPV) validation. It does not execute scripts or check block subsidies.
 */
import { createHash, scryptSync } from 'node:crypto';

/** Mainnet consensus parameters from pepecoin Core chainparams.cpp. */
export const PEP_CONSENSUS = Object.freeze({
  powLimit: (1n << 236n) - 1n, // 0x00000fff…ff (~uint256(0) >> 20)
  targetTimespan: 60n,
  auxpowChainId: 0x3f,
  auxpowStartHeight: 42000,
  maxFutureSeconds: 2 * 60 * 60,
  medianTimeSpan: 11,
  genesis: Object.freeze({
    height: 0,
    hash: '37981c0c48b8d48965376c8a42ece9a0838daadb93ff975cb091f57f8c2a5faa',
    time: 1705975200,
    bits: 0x1e0ffff0
  }),
  // Display-order hashes pinned by pepecoin Core; a peer cannot fork below them.
  checkpoints: Object.freeze(new Map([
    [0, '37981c0c48b8d48965376c8a42ece9a0838daadb93ff975cb091f57f8c2a5faa'],
    [40477, '3281f3b817f8a21c338c656756dbcfa555a629702e081cdf98d502b848ea5308'],
    [327239, '479d8f991b543cfd785f0a479ffbb2de18987a5d0ba7af33707ba69bc1a5f8b8']
  ]))
});

const MERGED_MINING_HEADER = Buffer.from([0xfa, 0xbe, 0x6d, 0x6d]); // 0xfabe 'mm'
const MAX_CHAIN_BRANCH = 30;

/**
 * Double SHA-256 in wire byte order.
 * @param {Buffer} bytes - Input bytes.
 * @returns {Buffer} 32-byte digest.
 */
const hash256 = bytes => createHash('sha256').update(createHash('sha256').update(bytes).digest()).digest();

/**
 * Interpret a wire-order 256-bit hash as an unsigned integer (Core's UintToArith256).
 * @param {Buffer} hash - 32 bytes, least-significant byte first.
 * @returns {bigint} Integer value.
 */
export const hashToBigInt = hash => BigInt('0x' + Buffer.from(hash).reverse().toString('hex'));

/**
 * Decode a compact difficulty target exactly like arith_uint256::SetCompact.
 * @param {number} bits - Compact nBits value.
 * @returns {{target: bigint, negative: boolean, overflow: boolean}} Decoded target and range flags.
 */
export function decodeCompact(bits) {
  const size = bits >>> 24, word = bits & 0x007fffff;
  const target = size <= 3 ? BigInt(word >>> (8 * (3 - size))) : BigInt(word) << BigInt(8 * (size - 3));
  const negative = word !== 0 && (bits & 0x00800000) !== 0;
  const overflow = word !== 0 && (size > 34 || (word > 0xff && size > 33) || (word > 0xffff && size > 32));
  return { target, negative, overflow };
}

/**
 * Encode a target exactly like arith_uint256::GetCompact (non-negative values).
 * @param {bigint} target - Non-negative 256-bit target.
 * @returns {number} Compact nBits value.
 */
export function encodeCompact(target) {
  let size = target === 0n ? 0 : Math.ceil(target.toString(16).length / 2);
  let compact = size <= 3 ? Number(target << BigInt(8 * (3 - size))) : Number(target >> BigInt(8 * (size - 3)));
  if (compact & 0x00800000) { compact >>>= 8; size++; }
  return ((compact | (size << 24)) >>> 0);
}

/**
 * Check a proof-of-work hash against its compact target (Core's CheckProofOfWork).
 * @param {Buffer} powHash - Wire-order scrypt hash.
 * @param {number} bits - Claimed compact target.
 * @param {bigint} [powLimit] - Easiest allowed target.
 * @returns {boolean} True when the target is in range and the hash meets it.
 */
export function checkProofOfWork(powHash, bits, powLimit = PEP_CONSENSUS.powLimit) {
  const { target, negative, overflow } = decodeCompact(bits);
  if (negative || overflow || target === 0n || target > powLimit) return false;
  return hashToBigInt(powHash) <= target;
}

/**
 * Litecoin-style scrypt(N=1024, r=1, p=1) proof-of-work hash of an 80-byte header.
 * @param {Buffer} header - Serialized base header.
 * @returns {Buffer} Wire-order 32-byte hash.
 */
export const scryptPowHash = header => scryptSync(header, header, 32, { N: 1024, r: 1, p: 1 });

/**
 * Pepecoin's DigiShield retarget (CalculatePepecoinNextWorkRequired). Every block retargets
 * on mainnet, measuring one block interval.
 * @param {{bits: number, time: number}} last - Previous block.
 * @param {number} firstTime - Timestamp of the block before it (or of last itself for height 1).
 * @param {typeof PEP_CONSENSUS} [params] - Consensus parameters.
 * @returns {number} Required compact nBits for the next block.
 */
export function nextWorkRequired(last, firstTime, params = PEP_CONSENSUS) {
  const span = params.targetTimespan;
  // C++ int64 division truncates toward zero, as does BigInt division.
  let modulated = span + (BigInt(last.time) - BigInt(firstTime) - span) / 8n;
  const min = span - span / 4n, max = span + span / 2n;
  if (modulated < min) modulated = min; else if (modulated > max) modulated = max;
  let target = decodeCompact(last.bits).target * modulated / span;
  if (target > params.powLimit) target = params.powLimit;
  return encodeCompact(target);
}

/**
 * Compute a Merkle branch root exactly like CAuxPow::CheckMerkleBranch.
 * @param {Buffer} leaf - Wire-order leaf hash.
 * @param {Buffer[]} branch - Sibling hashes.
 * @param {number} index - Leaf position.
 * @returns {Buffer} Wire-order root.
 */
function merkleBranchRoot(leaf, branch, index) {
  let hash = leaf;
  for (const sibling of branch) {
    hash = index & 1 ? hash256(Buffer.concat([sibling, hash])) : hash256(Buffer.concat([hash, sibling]));
    index >>>= 1;
  }
  return hash;
}

/**
 * Pseudo-random merged-mining slot (CAuxPow::getExpectedIndex) in 32-bit arithmetic.
 * @param {number} nonce - Merged-mining nonce from the parent coinbase.
 * @param {number} chainId - Auxiliary chain ID.
 * @param {number} height - Chain Merkle tree height.
 * @returns {number} Expected slot.
 */
function expectedIndex(nonce, chainId, height) {
  let rand = (Math.imul(nonce >>> 0, 1103515245) + 12345) >>> 0;
  rand = (rand + chainId) >>> 0;
  rand = (Math.imul(rand, 1103515245) + 12345) >>> 0;
  return height >= 32 ? rand : rand % (2 ** height);
}

/**
 * Verify a parsed AuxPoW proof commits to this block (CAuxPow::check) and meets the target.
 * @param {Buffer} header - Child 80-byte header.
 * @param {import('./pepenet-wire.js').AuxPow} auxpow - Parsed merged-mining proof.
 * @param {typeof PEP_CONSENSUS} [params] - Consensus parameters.
 * @returns {void}
 * @throws {Error} If any merged-mining rule fails.
 */
export function checkAuxPow(header, auxpow, params = PEP_CONSENSUS) {
  const chainId = header.readUInt32LE(0) >>> 16;
  if (!checkProofOfWork(scryptPowHash(auxpow.parentHeader), header.readUInt32LE(72), params.powLimit))
    throw new Error('AuxPoW parent block does not meet the proof-of-work target.');
  if (auxpow.coinbaseIndex !== 0) throw new Error('AuxPoW is not a generate transaction.');
  if ((auxpow.parentHeader.readUInt32LE(0) >>> 16) === chainId) throw new Error('AuxPoW parent has our chain ID.');
  if (auxpow.chainBranch.length > MAX_CHAIN_BRANCH) throw new Error('AuxPoW chain Merkle branch too long.');
  const chainRoot = Buffer.from(merkleBranchRoot(hash256(header), auxpow.chainBranch, auxpow.chainIndex)).reverse();
  if (!merkleBranchRoot(auxpow.coinbaseTxid, auxpow.coinbaseBranch, auxpow.coinbaseIndex).equals(auxpow.parentHeader.subarray(36, 68)))
    throw new Error('AuxPoW coinbase is not in the parent block Merkle tree.');
  const script = auxpow.coinbaseScript;
  const head = script.indexOf(MERGED_MINING_HEADER);
  const pc = script.indexOf(chainRoot);
  if (pc < 0) throw new Error('AuxPoW parent coinbase lacks the chain Merkle root.');
  if (head >= 0) {
    if (script.indexOf(MERGED_MINING_HEADER, head + 1) >= 0) throw new Error('Multiple merged-mining headers in coinbase.');
    if (head + MERGED_MINING_HEADER.length !== pc) throw new Error('Merged-mining header is not just before the chain Merkle root.');
  } else if (pc > 20) throw new Error('AuxPoW chain Merkle root must start in the first 20 coinbase bytes.');
  const after = pc + chainRoot.length;
  if (script.length - after < 8) throw new Error('AuxPoW coinbase lacks Merkle size and nonce.');
  if (script.readUInt32LE(after) !== 2 ** auxpow.chainBranch.length) throw new Error('AuxPoW Merkle branch size does not match the coinbase.');
  if (auxpow.chainIndex !== expectedIndex(script.readUInt32LE(after + 4), chainId, auxpow.chainBranch.length))
    throw new Error('AuxPoW wrong chain index.');
}

/**
 * Context-free and version checks for one header (CheckAuxPowProofOfWork plus legacy rules).
 * @param {{header: Buffer, auxpow?: object|null}} h - Parsed header.
 * @param {number} height - Height this header would occupy.
 * @param {typeof PEP_CONSENSUS} [params] - Consensus parameters.
 * @returns {void}
 * @throws {Error} If the header's proof of work or version is invalid.
 */
export function checkHeaderPow(h, height, params = PEP_CONSENSUS) {
  const version = h.header.readInt32LE(0);
  const legacy = version === 1 || (version === 2 && (version >> 16) === 0);
  if (!legacy && (version >> 16) !== params.auxpowChainId) throw new Error('Block header does not have the Pepecoin chain ID.');
  if (legacy && height >= params.auxpowStartHeight) throw new Error('Legacy block header after AuxPoW activation.');
  const isAux = (version & 0x100) !== 0;
  if (isAux !== Boolean(h.auxpow)) throw new Error('AuxPoW flag does not match the header payload.');
  if (isAux && height < params.auxpowStartHeight) throw new Error('AuxPoW block header before AuxPoW activation.');
  if (h.auxpow) checkAuxPow(h.header, h.auxpow, params);
  else if (!checkProofOfWork(scryptPowHash(h.header), h.header.readUInt32LE(72), params.powLimit))
    throw new Error('Block header does not meet its proof-of-work target.');
}

/**
 * Validate a linked page of headers extending a known context and return the updated context.
 * @param {Array<{header: Buffer, hash: Buffer, auxpow?: object|null}>} headers - Parsed headers in order.
 * @param {{height: number, recent: Array<{time: number, bits: number|null}>}} context -
 *   Height of the current tip and up to eleven most recent {time, bits} entries ending at the tip.
 * @param {{params?: typeof PEP_CONSENSUS, now?: number}} [options] - Parameters and clock (Unix seconds).
 * @returns {{height: number, recent: Array<{time: number, bits: number|null}>}} Context after the page.
 * @throws {Error} On any proof-of-work, difficulty, checkpoint or timestamp violation.
 */
export function validateHeaderChain(headers, context, { params = PEP_CONSENSUS, now = Math.floor(Date.now() / 1000) } = {}) {
  let height = context.height;
  const recent = context.recent.slice(-params.medianTimeSpan);
  for (const h of headers) {
    height++;
    const time = h.header.readUInt32LE(68), bits = h.header.readUInt32LE(72);
    const checkpoint = params.checkpoints.get(height);
    if (checkpoint && Buffer.from(h.hash).reverse().toString('hex') !== checkpoint)
      throw new Error(`Header at height ${height} does not match the pinned checkpoint.`);
    const last = recent.at(-1);
    // Contextual difficulty needs the previous two blocks; a legacy index without stored
    // bits validates only proof of work for its first new header.
    if (last && last.bits != null && (recent.length >= 2 || height === 1)) {
      const expected = nextWorkRequired(last, height === 1 ? last.time : recent.at(-2).time, params);
      if (bits !== expected) throw new Error(`Header at height ${height} has incorrect difficulty bits.`);
    }
    if (recent.length) {
      const times = recent.map(r => r.time).sort((a, b) => a - b);
      if (time <= times[Math.floor(times.length / 2)]) throw new Error(`Header at height ${height} is not after the median time past.`);
    }
    if (time > now + params.maxFutureSeconds) throw new Error(`Header at height ${height} is too far in the future.`);
    checkHeaderPow(h, height, params);
    recent.push({ time, bits });
    if (recent.length > params.medianTimeSpan) recent.shift();
  }
  return { height, recent };
}
