/**
 * Example: map application users to wallets and hand out receiving addresses.
 * Runs offline (autoSync: false) against a temporary directory:
 *
 *   node examples/accounts.js
 */
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { PepecoinWallet } from 'pepecoin-js-wallet';

/**
 * Create two account wallets, show idempotency, and add a labelled invoice address.
 * @param {string} dataDir - Vault directory to use.
 * @returns {Promise<{walletIds: string[], invoiceAddress: string}>} What the example created.
 */
export async function runAccountsExample(dataDir) {
  // autoSync: false keeps this example offline. Wallet creation never needs the network.
  await using wallets = await PepecoinWallet.open({ dataDir, namespace: 'shop', autoSync: false });

  // Use your own stable user/account ID. Calling createWallet again returns the same wallet
  // and the same first address, so it is safe to call on every login or checkout.
  const alice = await wallets.createWallet('user-1001', 'Alice');
  const again = await wallets.createWallet('user-1001');
  console.log('Alice wallet:', alice.id, 'first address:', alice.addresses[0].address);
  console.log('Same wallet on repeat call:', again.id === alice.id);

  const bob = await wallets.createWallet('user-1002', 'Bob');

  // A fresh address per invoice keeps payments easy to tell apart.
  const invoice = await wallets.newAddress(alice.id, 'Invoice 2026-0042');
  console.log('Invoice address:', invoice.address, `(${invoice.label})`);

  for (const w of await wallets.listWallets()) console.log(`- ${w.accountId}: ${w.addresses.length} address(es)`);
  return { walletIds: [alice.id, bob.id], invoiceAddress: invoice.address };
  // `await using` closes the wallet (and releases the data-directory lock) here.
}

if (import.meta.main) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'pepe-example-accounts-'));
  try { await runAccountsExample(dir); } finally { await rm(dir, { recursive: true, force: true }); }
}
