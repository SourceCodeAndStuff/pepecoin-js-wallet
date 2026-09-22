/**
 * Example of embedding the wallet library in a trusted Node.js application.
 * No HTTP server or Core RPC is required.
 */
import { PepecoinWallet } from 'pepecoin-js-wallet';

// Runs inside your existing trusted Node.js application server. No HTTP or Core RPC.
/**
 * Open a namespaced wallet runtime and expose account-oriented operations.
 * The caller must authorize withdrawals and provide durable request IDs.
 * @param {string} dataDir - Persistent vault and index directory.
 * @returns {Promise<object>} Account helpers and an explicit close operation.
 */
export async function openWallets(dataDir) {
  const wallets = await PepecoinWallet.open({ dataDir, namespace: 'my-application' });
  return {
    wallets,
    /**
     * Create or retrieve an account wallet and return its first receiving address.
     * @param {string} accountId - Stable application account identifier.
     * @returns {Promise<{walletId: string, address: string}>} Wallet ID and receiving address.
     */
    async addressForAccount(accountId) {
      const wallet = await wallets.createWallet(accountId);
      return { walletId: wallet.id, address: wallet.addresses[0].address };
    },
    /**
     * Read indexed balances for a wallet in this namespace.
     * @param {string} walletId - Wallet ID returned by addressForAccount.
     * @returns {Promise<object>} Current balance summary.
     */
    async balanceForAccount(walletId) { return wallets.getBalance(walletId); },
    /**
     * Submit an already-authorized order using a durable ID for idempotency.
     * @param {{id: string, walletId: string, destination: string, amount: string}} order - Authorized payment with a decimal PEPE amount.
     * @returns {Promise<object>} Persisted withdrawal and relay state, not a block-confirmation guarantee.
     */
    async withdrawAuthorizedOrder(order) {
      // Verify account authorization and reserve the application's balance BEFORE this
      // function. order.id must already be durable in your application database.
      return wallets.withdraw(order.walletId, {
        requestId: order.id,
        recipients: [{ address: order.destination, amount: order.amount }]
      });
    },
    /**
     * Release the runtime when the embedding application shuts down.
     * @returns {Promise<void>} Resolves after resources close.
     */
    async close() { await wallets.close(); }
  };
}
