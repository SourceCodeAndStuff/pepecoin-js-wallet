/**
 * Example: prove control of a deposit address with a Core-compatible message signature.
 * Runs offline:
 *
 *   node examples/sign-and-verify.js
 */
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { PepecoinWallet, verifyMessage } from 'pepecoin-js-wallet';

/**
 * Sign a challenge with a wallet key, then verify it with and without a wallet instance.
 * @param {string} dataDir - Vault directory to use.
 * @returns {Promise<{address: string, signature: string, valid: boolean, tampered: boolean}>} Results.
 */
export async function runSignAndVerifyExample(dataDir) {
  await using wallets = await PepecoinWallet.open({ dataDir, autoSync: false });
  const account = await wallets.createWallet('treasury');
  const address = account.addresses[0].address;

  // Include something unique (a nonce or timestamp) so an old signature cannot be replayed.
  const message = `Proof of reserves for example.com — ${new Date().toISOString().slice(0, 10)}`;
  const signature = await wallets.signMessage(account.id, address, message);
  console.log('Address:  ', address);
  console.log('Message:  ', message);
  console.log('Signature:', signature);

  // Anyone can verify, including code that never opens a wallet (e.g. a public web service).
  const valid = verifyMessage(address, message, signature);
  const tampered = verifyMessage(address, message + '!', signature);
  console.log('Valid signature:', valid, '| after editing the message:', tampered);

  // Signing and key export are refused while spending is locked.
  await wallets.lockSpending(true);
  await wallets.signMessage(account.id, address, message).then(
    () => console.log('unexpected: signed while locked'),
    error => console.log('While locked:', error.message)
  );
  await wallets.lockSpending(false);
  return { address, signature, valid, tampered };
}

if (import.meta.main) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'pepe-example-sign-'));
  try { await runSignAndVerifyExample(dir); } finally { await rm(dir, { recursive: true, force: true }); }
}
