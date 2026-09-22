# PepeCoin JS Wallet

Import this package into your existing Node.js application server. Your application code creates account wallets and authorizes spending **in the same process**. No REST API, API keys, Core RPC, local node, or separately running wallet service is needed.

## Install in your application project

Requires Node.js **24.13.0 or newer**. SQLite comes from Node itself; no Python, node-gyp, or native npm addon is needed. Node 24 may emit an experimental SQLite warning. Existing vault and index files remain compatible; the driver change does not require a rescan.

To develop from the private repository (requires GitHub access):

```sh
git clone https://github.com/SourceCodeAndStuff/pepecoin-js-wallet.git wallet
cd wallet
npm ci
npm test
```

The optional web app lives in the separate `pepecoin-js-wallet-web` repository. Clone it alongside this library as `web/`; its README describes the two-repository setup. Keep vault data, private keys, credentials, and backups outside version control.

Install this local project as a dependency:

```sh
npm install /path/to/this-project/wallet
```

Replace the path with the wallet library folder; its directory name need not match the package name. The project is an ES module package with TypeScript declarations.

## Use directly

```js
import { PepecoinWallet } from 'pepecoin-js-wallet';

const wallets = await PepecoinWallet.open({
  dataDir: './application-wallet-data',
  namespace: 'my-application'
});

wallets.on('sync', state => console.log(state.state, state.height));
wallets.on('block', block => console.log('Indexed block', block.height));

// Reusing this account ID returns the same wallet and original address.
const account = await wallets.createWallet('account-123', 'Account 123');
const address = account.addresses[0].address;
const balance = await wallets.getBalance(account.id);
const deposits = await wallets.getDeposits(account.id);

// Your application must authorize the account and persist/reserve the order first.
// Call this only when the index is caught up and the wallet is funded.
const withdrawal = await wallets.withdraw(account.id, {
  requestId: 'persisted-application-order-456',
  recipients: [{ address: 'REPLACE_WITH_PEPECOIN_ADDRESS', amount: '1.00000000' }],
  minConfirmations: 6
});

// On application-server shutdown:
await wallets.close();
```

See [examples/wallet.js](examples/wallet.js) for a wrapper around application operations. It performs no HTTP calls.

Importing the package opens no ports and installs no process/signal handlers. `open()` starts public-peer synchronization by default. Use `autoSync: false` when you want to call `startSync()` yourself. Wallet generation works before syncing; withdrawals require a fresh, caught-up index. Your application owns the lifetime and must call `close()`; closing drains in-flight library operations. Do not open the same data directory in two processes.

`namespace` separates account IDs for different applications. It is an organizational boundary, not authentication against code running in the same trusted Node process. The host application is the spending authority. If omitted, the namespace preserves the sole existing wallet namespace, or uses `default` for a fresh vault. If multiple namespaces exist, specify one explicitly.

## Public methods

| Method | Purpose |
| --- | --- |
| `createWallet(accountId, label?)` | Idempotently create/retrieve an account wallet |
| `listWallets()` | List wallets in this namespace |
| `newAddress(walletId, label?)` | Add another receiving address |
| `getWallet(walletId, { confirmations? })` | Balance, coins, history, deposits and withdrawals |
| `getBalance(walletId, options?)` | Balance, available, reserved and immature amounts |
| `getTransactions(walletId, options?)` | Indexed transaction history |
| `getDeposits(walletId, options?)` | Positive net incoming transactions and eligibility |
| `quote(walletId, payment)` | Review deterministic transaction, fee, inputs and change |
| `withdraw(walletId, { requestId, ...payment })` | Sign, persist, reserve inputs and attempt public-peer relay |
| `getWithdrawals(walletId)` | Saved requests and chain-derived confirmation state |
| `rebroadcast(walletId, withdrawalId)` | Relay the exact saved bytes again |
| `lockCoins(walletId, outpoints, locked?)` | Persistent coin control |
| `lockSpending(locked?)` | Pause new spending/signing across the vault |
| `backup(passphrase)`, `restore(backup, passphrase)` | Encrypted backup/restore for this namespace |
| `importKey(walletId, wif, label?)`, `exportKey(walletId, address)` | Compressed/uncompressed WIF keys |
| `signMessage(walletId, address, message)` | Core-compatible compact message signature |
| `verifyMessage(address, message, signature)` | Verify a compact signature |
| `saveContact(label, address)`, `listContacts()` | Address book |
| `status`, `startSync()`, `close()` | Lifecycle and network state |

Public types are in `index.d.ts`. One ribbit is 0.00000001 PEPE (100,000,000 ribbits = 1 PEPE). Existing `*Koinu` property names are retained for compatibility; their integer values are denominated in ribbits. Amounts are decimal **strings**, never floating-point money values. A payment accepts `recipients`, `feeRate` (ribbits/byte, minimum 1000), `minConfirmations` (default 6), `sendAll` (one recipient), `selected` outpoints, and optional reviewed `expectedTxid`. Each recipient must receive at least 0.01 PEPE; smaller change is added to the fee.

## Withdrawal retries and deposits

Save the order ID in your application's database **before** calling `withdraw()`. Reuse the same `requestId` and payment fields after a timeout or restart. Different payment fields with the same ID are rejected. The signed transaction and its input reservations are persisted atomically before network relay. Never create a replacement ID or refund based only on a timeout.

Withdrawal states:

- `queued`: saved locally; relay may not have started.
- `relayed`: a peer served the exact transaction back; not yet a block confirmation.
- `unverified`: relay could not be verified; it **may still confirm**.
- `confirmed`: observed in the indexed chain.

Calling `withdraw()` again returns the existing request. Use `rebroadcast()` to resend its exact bytes. Reserved inputs are not released merely because time passed. Existing signed transactions can confirm while spending is locked. No automatic rebroadcast or application-ledger refund job is installed.

`getDeposits()` reports positive **net** wallet increases, excluding outgoing change as a new deposit. Each row has `id`, `txid`, `amount`, `confirmations`, and `eligible`. Atomically record a unique deposit ID and credit the application ledger so polling cannot credit twice. Do not credit the raw transaction `received` field, which can include change.

Persist the chain TXID and stable account ID too: restored wallets receive new wallet IDs, so reconcile against your application ledger after restoring or rescanning. Unconfirmed incoming mempool transactions are not reported. Normal deposits default to six confirmations; mining rewards use the network's early 30 / later 240 block maturity. Eligibility is a local index policy, not proof of full consensus validity.

## Backup, restore and historical import

Keys are encrypted in `wallets.db` with AES-256-GCM using `wallet.key`. Keep that host secret protected. This is a hot wallet: anyone who compromises the application process or reads both files can spend funds.

`backup(passphrase)` returns an encrypted JSON object; save it safely using your application's storage. Backups contain namespace account keys, contacts, withdrawals, reservations and coin locks. They exclude chain data and optional console login credentials. New backups use format `pepecoin-js-wallet`, version 2; encrypted version 1 backups remain readable. Older account identifier fields migrate to `accountId` without changing addresses.

Restore into an empty installation/namespace; do not run two active copies of the same keys. Imported historical keys require a full rescan:

```js
await wallets.close();
const rescanning = await PepecoinWallet.open({
  dataDir: './application-wallet-data',
  namespace: 'my-application',
  rescan: true
});
```

A rescan creates a new index directory and preserves the old one. Reopen normally to resume it after a restart. Imports added after a rescan starts need a subsequent rescan. Spending remains blocked for incomplete imported wallets.

For whole-host backups, stop the wallet and copy the entire data directory, including databases, WAL files if present, and `wallet.key`. Never generate a replacement for a missing host key: startup refuses to do so. A separate SQLite process guard releases its OS lock automatically on exit. Startup safely replaces a leftover `wallet-server.lock` only after verifying its owner PID has exited; live owners, permission errors, and malformed metadata remain blocked. If manual recovery is needed, verify no process is using the wallet before removing only the marker. Do not delete the process-guard database while a wallet is running.

Existing password-encrypted accounts remain untouched. The optional console still migrates an old wallet on successful login without changing its address. Those wallets use the original operator ID as their namespace; pass the desired namespace explicitly when integrating those wallets. Never delete the old data to switch integrations.

## Separate web app

The optional UI and HTTP/WebSocket server live in the sibling `web/` package, not in this library. From the repository root, `npm start` launches that app. Its authenticated sockets receive sync and wallet updates from this library's runtime events. Installing this wallet package alone does not install or start the web app.

The `pepecoin-js-wallet/server` export is a trusted in-process adapter for the separate server. It exposes the wallet runtime and shared utilities; it creates no HTTP or WebSocket listener. Do not expose that adapter directly to untrusted code.

## Important limitations

This is **not full Pepecoin Core parity or a production-audited custodian**. The index checks linked headers, requested block hashes and transaction Merkle roots; it does not implement full PoW/AuxPoW/difficulty/script consensus validation or automatic chain-reorg rollback. A detected reorg stops indexing for a safe rescan. Do not use it as the sole trust source for real-money application deposits without addressing those gaps and obtaining security review.

Not implemented: wallet.dat compatibility, HD seeds, multisig/PSBT, watch-only wallets, full mempool tracking, mining, hardware signing, or a transactional application ledger. History discarded by the old 100-transaction limit requires a rescan.

Protect the host, use restrictive filesystem/NTFS permissions, and keep encrypted offline backups. POSIX file modes do not replace Windows ACLs. No new authentication records are stored on-chain. All peer connections are outbound to public Pepecoin peers, not a local Core node.

## Verify

```sh
npm test
```

Library tests cover direct import with no HTTP listener or process hooks, lifecycle/reopening, backups, native signing, duplicate withdrawal prevention, sync paging and peer isolation. Browser-session and WebSocket tests belong to the separate web package. No real-money transactions are sent.

From the repository root, `npm run preview` launches the separate web package's synthetic fixture. Never deploy it or fund its addresses.

Protocol references: [Pepecoin Core parameters](https://github.com/pepecoinppc/pepecoin/blob/master/src/chainparams.cpp), [message signing](https://github.com/pepecoinppc/pepecoin/blob/master/src/validation.cpp), [PepeNet reference](https://github.com/PepeNetWeb/namespace-indexer).
