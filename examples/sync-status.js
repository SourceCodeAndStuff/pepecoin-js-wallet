/**
 * Example: follow synchronization, report readiness, and gate your own features on it.
 * Needs the public Pepecoin network:
 *
 *   node examples/sync-status.js ./wallet-data
 */
import path from 'node:path';
import { PepecoinWallet } from 'pepecoin-js-wallet';

/**
 * Summarize a sync status for logs or a health endpoint.
 * @param {import('pepecoin-js-wallet').SyncStatus} s - Status from wallet.status or a 'sync' event.
 * @returns {{ready: boolean, text: string}} Whether withdrawals and deposit crediting can proceed, plus a line of text.
 */
export function describeStatus(s) {
  const ready = s.state === 'synced' && s.verifiedHeight != null && s.verifiedHeight >= s.height;
  const progress = s.progressPercent == null ? '' : ` ${s.progressPercent}%`;
  const target = s.targetHeight == null ? '?' : s.targetHeight;
  const text = `${s.state}${progress} — indexed ${s.height} / network ${target}` +
    (s.verifiedHeight != null ? `, peer-confirmed ${s.verifiedHeight}` : '') +
    (s.error ? ` — ${s.error}` : '');
  return { ready, text };
}

if (import.meta.main) {
  const dataDir = path.resolve(process.argv[2] || './wallet-data');
  // autoSync defaults to true; pass autoSync: false and call startSync() to control timing yourself.
  const wallets = await PepecoinWallet.open({ dataDir, namespace: 'shop', autoSync: false });
  wallets.on('sync', status => console.log(describeStatus(status).text));
  wallets.on('block', block => { if (block.height % 1000 === 0) console.log('indexed block', block.height); });
  wallets.startSync();

  // Example health check your application could expose on its own admin route.
  const timer = setInterval(() => {
    const { ready } = describeStatus(wallets.status);
    console.log(ready ? 'READY: deposits can be credited and withdrawals sent.' : 'NOT READY: keep withdrawals queued.');
  }, 60_000);
  process.once('SIGINT', async () => { clearInterval(timer); await wallets.close(); });
}
