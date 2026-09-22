/**
 * @file Public TypeScript contracts and editor documentation for PepeCoin JS Wallet.
 * One ribbit is 0.00000001 PEPE. Legacy *Koinu field names remain for compatibility.
 */
import { EventEmitter } from 'node:events';

/**
 * Configuration for one exclusively locked, namespace-scoped wallet runtime.
 */
export interface WalletOptions {
  /**
   * Required persistent directory. Never open the same data directory in two processes.
   */
  dataDir: string;
  /**
   * Ownership namespace; omitted values preserve the sole existing owner or use default for a fresh vault.
   */
  namespace?: string;
  /**
   * Start public-peer sync after initialization; defaults to true.
   */
  autoSync?: boolean;
  /** Start a fresh index, preserving the old one; use after importing historical keys. */
  rescan?: boolean;
}
/**
 * Public address metadata. identity is hex HASH160; compressed and needsRescan are SQLite integer flags.
 */
export interface Address {
  address: string; identity: string; label: string; compressed: number;
  needsRescan: number; createdAt: string;
}
/**
 * Namespace-owned metadata. accountId is caller-owned; id is the generated wallet UUID.
 */
export interface AccountWallet {
  id: string; owner: string; accountId: string; label: string; createdAt: string; addresses: Address[];
}
/**
 * Local sync state; advertised heights do not establish consensus validity. Timestamps are ISO-8601 strings or null.
 */
export interface SyncStatus {
  state: string; height: number; startHeight: number; blocksSynced: number;
  targetHeight: number | null; progressPercent: number | null; peer: string | null;
  error: string | null; updatedAt: string | null; lastSyncedAt: string | null;
  /** Highest height whose tip independent peers confirmed; deposits above it are never eligible. */
  verifiedHeight: number | null;
}
/**
 * Payment request. Amounts are decimal PEPE strings, never floating-point money values.
 */
export interface Payment {
  /**
   * Mainnet destinations and decimal PEPE amounts; sendAll requires exactly one recipient.
   */
  recipients: { address: string; amount: string }[];
  /**
   * Integer ribbits per serialized byte; minimum and default are 1000.
   */
  feeRate?: string;
  /**
   * Required confirmations, default 6 and range 1–10000. Coinbase maturity applies separately.
   */
  minConfirmations?: number;
  /**
   * Spend selected available coins to one recipient after deducting fees.
   */
  sendAll?: boolean;
  /**
   * Explicit lowercase txid:vout selection; omitted/empty enables automatic input selection.
   */
  selected?: string[];
  /**
   * Reviewed transaction ID; withdrawal rejects if fresh construction produces a different ID.
   */
  expectedTxid?: string;
}
/**
 * Signed-payment review metadata, without raw bytes or reservations. *Koinu values are integer ribbit strings.
 */
export interface Quote {
  /** Legacy *Koinu field names represent integer ribbits (1 PEPE = 100,000,000 ribbits). */
  txid: string; bytes: number; amountKoinu: string; feeKoinu: string;
  totalKoinu: string; changeKoinu: string; changeAddress: string;
  inputs: { identity: string; txid: string; vout: number; valueKoinu: string }[];
  recipients: { address: string; amount: string }[];
}
/**
 * Durable request. relayed is peer receipt, not confirmation; unverified may still confirm.
 */
export interface Withdrawal extends Quote {
  id: string; requestId: string; state: 'queued' | 'relayed' | 'unverified' | 'confirmed';
  error: string | null; createdAt: string;
}
/**
 * Decimal-string PEPE balances. Availability alone does not bypass sync or spending locks.
 */
export interface Balance {
  balance: string; available: string; reserved: string; immature: string;
  indexedHeight: number; needsRescan: boolean;
}
/**
 * Indexed transaction with Unix time in seconds and decimal-string PEPE received/spent/net amounts.
 */
export interface Transaction {
  txid: string; height: number; time: number; confirmations: number;
  received: string; spent: string; net: string;
}
/**
 * Positive net increase. Persist its ID to prevent duplicate credits; eligible is local policy, not consensus proof.
 */
export interface Deposit {
  id: string; txid: string; amount: string; height: number; confirmations: number; eligible: boolean;
}
/**
 * Indexed output with display-order txid, integer-ribbit valueKoinu and decimal-PEPE amount. Reserved includes manual locks.
 */
export interface Coin {
  identity: string; txid: string; vout: number; valueKoinu: string; height: number;
  coinbase: number; amount: string; confirmations: number; reserved: boolean; immature: boolean; spendable: boolean;
}
/**
 * Indexed state combined with address/rescan metadata, reservations and runtime status.
 */
export interface WalletSnapshot extends Balance {
  wallet: Omit<AccountWallet, 'addresses'>; addresses: Address[]; minConfirmations: number;
  coins: Coin[]; transactions: Transaction[]; deposits: Deposit[]; withdrawals: Withdrawal[]; network: SyncStatus;
}
/**
 * Authenticated encrypted backup envelope. Version 2 is written; supported version 1 backups remain readable.
 */
export interface EncryptedBackup { format: string; version: number; salt: string; ciphertext: string; }
/**
 * Trusted in-process wallet. Emits sync with SyncStatus copies and block with {height, hash} after indexing.
 * The host authorizes spending. Open with open() and always await close().
 */
export class PepecoinWallet extends EventEmitter {
  private constructor();
  /**
   * Open a vault, acquire its exclusive data-directory lock, and optionally start sync.
   * An omitted namespace preserves the sole existing namespace; ambiguous vaults reject.
   */
  static open(options: WalletOptions): Promise<PepecoinWallet>;
  /**
   * Detached copy of current synchronization state.
   */
  readonly status: SyncStatus;
  /**
   * Start public-peer synchronization unless an attempt is already running.
   */
  startSync(): void;
  /**
   * Create an account wallet, or return the existing wallet for this namespace/account ID.
   */
  createWallet(accountId: string, label?: string): Promise<AccountWallet>;
  /**
   * List wallets in this namespace without exposing private keys.
   */
  listWallets(): Promise<AccountWallet[]>;
  /**
   * Read indexed balances, coins and history, and reconcile saved withdrawal states.
   */
  getWallet(walletId: string, options?: { confirmations?: number }): Promise<WalletSnapshot>;
  /**
   * Read PEPE balances and rescan status from the current wallet snapshot.
   */
  getBalance(walletId: string, options?: { confirmations?: number }): Promise<Balance>;
  /**
   * Read wallet transactions retained by the local index.
   */
  getTransactions(walletId: string, options?: { confirmations?: number }): Promise<Transaction[]>;
  /**
   * Read positive net wallet increases, excluding outgoing change as a separate deposit.
   * Persist deposit IDs in the caller's ledger to avoid duplicate crediting.
   */
  getDeposits(walletId: string, options?: { confirmations?: number }): Promise<Deposit[]>;
  /**
   * Read saved withdrawal requests with chain-derived confirmation state.
   */
  getWithdrawals(walletId: string): Promise<Withdrawal[]>;
  /**
   * Generate, encrypt, and watch an additional receiving key for this wallet.
   */
  newAddress(walletId: string, label?: string): Promise<Address>;
  /**
   * Build a signed payment preview without reserving inputs or broadcasting.
   */
  quote(walletId: string, payment: Payment): Promise<Quote>;
  /**
   * Persist a signed payment and input reservations before attempting public-peer relay.
   * Authorize and durably save requestId before calling. Reuse the same request after a
   * failure; an uncertain relay may still confirm and never automatically releases inputs.
   */
  withdraw(walletId: string, payment: Payment & { requestId: string }): Promise<Withdrawal>;
  /**
   * Relay exactly the saved transaction bytes; never create a replacement payment.
   */
  rebroadcast(walletId: string, withdrawalId: string): Promise<Withdrawal>;
  /**
   * Add or remove manual coin locks. Withdrawal reservations remain independent.
   */
  lockCoins(walletId: string, outpoints: string[], locked?: boolean): Promise<void>;
  /**
   * Persist a vault-wide lock on new spending, key export and message signing.
   * Already-submitted transactions can still confirm; saved transactions may be rebroadcast.
   */
  lockSpending(locked?: boolean): Promise<unknown>;
  /**
   * Encrypt this namespace's keys, contacts, outgoing requests and coin reservations.
   * Store the returned object and its passphrase securely and separately.
   */
  backup(passphrase: string): Promise<EncryptedBackup>;
  /**
   * Restore keys and reservations atomically, then register restored addresses for watching.
   * Existing matching account IDs reject; restored balances require a historical rescan.
   */
  restore(backup: EncryptedBackup, passphrase: string): Promise<{ wallets: number; needsRescan: boolean }>;
  /**
   * Import a Pepecoin WIF key and mark its address as requiring a historical rescan.
   */
  importKey(walletId: string, privateKeyWif: string, label?: string): Promise<Address>;
  /**
   * Export a private key as WIF. The caller must protect this spend-authorizing secret.
   */
  exportKey(walletId: string, address: string): Promise<string>;
  /**
   * Create a compact Pepecoin message signature, not a payment transaction.
   */
  signMessage(walletId: string, address: string, message: string): Promise<string>;
  /**
   * Verify a compact message signature without accessing wallet keys.
   */
  verifyMessage(address: string, message: string, signature: string): boolean;
  /**
   * Validate and save a mainnet destination in this namespace's address book.
   */
  saveContact(label: string, address: string): Promise<{ id: string }>;
  /**
   * Read public address-book entries for this namespace.
   */
  listContacts(): Promise<{ id: string; label: string; address: string }[]>;
  /**
   * Reject new work, drain in-flight operations, and release network, database and lock resources.
   * Repeated calls return the same shutdown promise. No new transaction is created.
   */
  close(): Promise<void>;
}
/**
 * Verify exact text and a compact Base64 signature against a mainnet P2PKH address. Invalid input returns false.
 */
export function verifyMessage(address: string, message: string, signature: string): boolean;
