/**
 * Example: the library ships TypeScript declarations (index.d.ts). Type-check with
 *   npx tsc --noEmit --module nodenext --target es2022 --strict examples/typescript-usage.ts
 * or run directly on Node 24 with: node examples/typescript-usage.ts
 */
import { PepecoinWallet, verifyMessage, type Deposit, type SyncStatus } from 'pepecoin-js-wallet';

/** Deposits that your ledger may credit now. */
export function creditable(deposits: Deposit[]): Deposit[] {
  return deposits.filter(d => d.eligible);
}

/** True when withdrawals may be attempted. */
export function isReady(status: SyncStatus): boolean {
  return status.state === 'synced' && status.verifiedHeight !== null && status.verifiedHeight >= status.height;
}

export async function main(dataDir: string): Promise<void> {
  const wallets = await PepecoinWallet.open({ dataDir, namespace: 'shop', autoSync: false });
  try {
    const account = await wallets.createWallet('user-1001', 'Alice');
    const address: string = account.addresses[0].address;
    const signature = await wallets.signMessage(account.id, address, 'hello');
    console.log(address, verifyMessage(address, 'hello', signature), isReady(wallets.status));
    console.log(creditable(await wallets.getDeposits(account.id)).length, 'creditable deposit(s)');
  } finally {
    await wallets.close();
  }
}
