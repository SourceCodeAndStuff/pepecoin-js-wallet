/**
 * Example: choose which coins a payment spends, freeze coins, and sweep a wallet.
 * Needs a funded, synced wallet:
 *
 *   node examples/coin-control.js ./wallet-data <destination-address>
 */
import path from 'node:path';
import { PepecoinWallet } from 'pepecoin-js-wallet';

/**
 * Pick the smallest spendable coins that cover an amount (a simple consolidation policy).
 * @param {import('pepecoin-js-wallet').Coin[]} coins - Wallet coins from getWallet().
 * @param {bigint} ribbits - Amount to cover, excluding the fee.
 * @returns {string[]} txid:vout outpoints for Payment.selected.
 */
export function smallestCoinsFirst(coins, ribbits) {
  const chosen = [];
  let total = 0n;
  for (const coin of coins.filter(c => c.spendable).sort((a, b) => (BigInt(a.valueKoinu) < BigInt(b.valueKoinu) ? -1 : 1))) {
    chosen.push(`${coin.txid}:${coin.vout}`);
    total += BigInt(coin.valueKoinu);
    if (total > ribbits) break;
  }
  return chosen;
}

if (import.meta.main) {
  const [dataDir = './wallet-data', destination] = process.argv.slice(2);
  await using wallets = await PepecoinWallet.open({ dataDir: path.resolve(dataDir), namespace: 'shop' });
  const account = await wallets.createWallet('payouts');
  await new Promise(resolve => wallets.on('sync', s => { if (s.state === 'synced') resolve(); }));
  const { coins } = await wallets.getWallet(account.id);
  console.log(`${coins.length} coin(s):`);
  for (const c of coins) console.log(`  ${c.txid}:${c.vout}  ${c.amount} PEPE  ${c.spendable ? 'spendable' : c.reserved ? 'reserved' : c.immature ? 'immature' : 'confirming'}`);
  if (!destination || !coins.length) process.exit(0);

  // Freeze the largest coin so automatic selection never touches it (e.g. cold reserve).
  const largest = [...coins].sort((a, b) => (BigInt(b.valueKoinu) > BigInt(a.valueKoinu) ? 1 : -1))[0];
  await wallets.lockCoins(account.id, [`${largest.txid}:${largest.vout}`], true);

  // Quote a payment that spends only the smallest coins.
  const selected = smallestCoinsFirst(coins.filter(c => c !== largest), 100_000_000n);
  const quote = await wallets.quote(account.id, { recipients: [{ address: destination, amount: '1.00000000' }], selected });
  console.log(`Quote ${quote.txid}: ${quote.inputs.length} input(s), fee ${quote.feeKoinu} ribbits, change ${quote.changeKoinu}`);

  // Sweep: sendAll moves every selected spendable coin to one recipient, minus the fee.
  const sweep = await wallets.quote(account.id, { recipients: [{ address: destination, amount: '0.01' }], sendAll: true });
  console.log(`Sweep would send ${sweep.amountKoinu} ribbits with fee ${sweep.feeKoinu}. (Quotes only; nothing was sent.)`);

  await wallets.lockCoins(account.id, [`${largest.txid}:${largest.vout}`], false);
}
