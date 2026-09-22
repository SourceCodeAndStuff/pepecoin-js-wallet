/**
 * Example: take an encrypted backup, store it as a file, and restore it on a new host.
 * Runs offline:
 *
 *   node examples/backup-restore.js
 */
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { PepecoinWallet } from 'pepecoin-js-wallet';

/**
 * Back up one vault and restore it into an empty one.
 * @param {string} workDir - Scratch directory for the two vaults and the backup file.
 * @param {string} passphrase - Backup passphrase (at least 12 characters).
 * @returns {Promise<{restored: number, sameAddress: boolean}>} Restore result.
 */
export async function runBackupRestoreExample(workDir, passphrase) {
  const backupFile = path.join(workDir, 'wallet-backup.json');
  let original;
  {
    await using source = await PepecoinWallet.open({ dataDir: path.join(workDir, 'old-host'), namespace: 'shop', autoSync: false });
    original = await source.createWallet('user-1001', 'Alice');
    await source.saveContact('Cold storage', original.addresses[0].address);
    // The backup is encrypted with the passphrase. Keep the passphrase somewhere else
    // (a password manager or secret store), never next to the backup file.
    const backup = await source.backup(passphrase);
    await writeFile(backupFile, JSON.stringify(backup), { mode: 0o600 });
    console.log('Backup written:', backupFile, `(format ${backup.format} v${backup.version})`);
  }

  // Restore into an EMPTY namespace. Never run two live copies of the same keys.
  await using target = await PepecoinWallet.open({ dataDir: path.join(workDir, 'new-host'), namespace: 'shop', autoSync: false });
  const result = await target.restore(JSON.parse(await readFile(backupFile, 'utf8')), passphrase);
  const [restored] = await target.listWallets();
  const sameAddress = restored.addresses[0].address === original.addresses[0].address;
  console.log(`Restored ${result.wallets} wallet(s); needs rescan: ${result.needsRescan}`);
  console.log('Same address after restore:', sameAddress, '| new wallet ID:', restored.id !== original.id);
  console.log('Contacts:', (await target.listContacts()).map(c => c.label).join(', '));

  // Restored keys have no history in the new index yet. Before crediting or spending,
  // close and reopen once with { rescan: true } and let it finish syncing:
  //   await target.close();
  //   await PepecoinWallet.open({ dataDir, namespace: 'shop', rescan: true });
  return { restored: result.wallets, sameAddress };
}

if (import.meta.main) {
  const dir = await mkdtemp(path.join(os.tmpdir(), 'pepe-example-backup-'));
  try { await runBackupRestoreExample(dir, 'correct horse battery staple'); } finally { await rm(dir, { recursive: true, force: true }); }
}
