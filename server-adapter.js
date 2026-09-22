/**
 * @file Trusted integration exports for a separate server running in the same Node.js process.
 * The adapter exposes low-level vault/runtime/crypto operations, not an HTTP or REST API.
 * Callers must enforce authorization, exclusive storage access and private-key hygiene.
 * For application integrations prefer PepecoinWallet from the package root; importing
 * this adapter alone starts no network activity and opens no data directory.
 */
// Trusted in-process integration surface. This module opens no HTTP or socket server.
export { openWalletRuntime } from './lib/wallet-runtime.js';
export { WalletVault, label } from './lib/wallet-vault.js';
export { WalletService } from './lib/wallet-service.js';
export { normalizeAccountName, passwordKey, passwordHash, passwordMatches, decryptPrivateKey,
  encryptPrivateKey, walletFromPrivateKey, createWallet, destinationScript, importWif, wif } from './lib/wallet.js';
export { signMessage, verifyMessage, ribbit } from './lib/wallet-signing.js';
