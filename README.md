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

See [Examples](#examples) for complete, runnable programs. None of them performs HTTP calls.

Importing the package opens no ports and installs no process/signal handlers. `open()` starts public-peer synchronization by default. Use `autoSync: false` when you want to call `startSync()` yourself. Wallet generation works before syncing; withdrawals require a fresh, caught-up index. Your application owns the lifetime and must call `close()`; closing drains in-flight library operations. Do not open the same data directory in two processes.

`namespace` separates account IDs for different applications. It is an organizational boundary, not authentication against code running in the same trusted Node process. The host application is the spending authority. If omitted, the namespace preserves the sole existing wallet namespace, or uses `default` for a fresh vault. If multiple namespaces exist, specify one explicitly.

## Examples

Every example is a standalone ES module in [`examples/`](examples). Run them from this directory with `node examples/<name>`. The offline ones use a temporary directory and clean up after themselves; the network ones take a data directory argument (default `./wallet-data`). `npm test` runs all offline examples and the ledger/worker logic of the others, so they stay in step with the API.

| Example | Network | Shows |
| --- | --- | --- |
| [`accounts.js`](examples/accounts.js) | offline | Mapping your user IDs to wallets, idempotent `createWallet`, one address per invoice, `await using` for automatic `close()` |
| [`sign-and-verify.js`](examples/sign-and-verify.js) | offline | Proving control of an address with `signMessage`, verifying with the standalone `verifyMessage`, and signing being refused while spending is locked |
| [`backup-restore.js`](examples/backup-restore.js) | offline | Writing an encrypted backup to a file and restoring it into a new, empty vault |
| [`deposit-watcher.js`](examples/deposit-watcher.js) | public peers | Crediting deposits to your ledger exactly once, driven by `block`/`sync` events (no polling timer) |
| [`withdrawal-worker.js`](examples/withdrawal-worker.js) | public peers | Durable orders → quote review with a fee cap → `withdraw` with `requestId`/`expectedTxid` → settlement, including crash recovery and `rebroadcast` |
| [`sync-status.js`](examples/sync-status.js) | public peers | Following sync progress and turning `status` into a readiness/health check |
| [`coin-control.js`](examples/coin-control.js) | public peers | Listing coins, freezing one with `lockCoins`, spending chosen inputs via `selected`, and quoting a `sendAll` sweep |
| [`typescript-usage.ts`](examples/typescript-usage.ts) | offline | Using the bundled type declarations; Node 24 runs it directly with type stripping |
| [`wallet.js`](examples/wallet.js) | public peers | A small wrapper object exposing account-oriented helpers to the rest of an application |

The two patterns worth copying exactly:

```js
// Deposits: the deposit ID is the idempotency key. Insert it and credit in one DB transaction.
for (const deposit of await wallets.getDeposits(walletId)) {
  if (!deposit.eligible) continue;            // not enough confirmations, or chain not yet confirmed
  db.transaction(() => {
    if (insertCreditedDeposit(deposit.id))    // INSERT OR IGNORE … PRIMARY KEY(depositId)
      addToBalance(accountId, deposit.amount);
  });
}

// Withdrawals: save the order first, then use its ID as requestId on every attempt.
const existing = (await wallets.getWithdrawals(walletId)).find(w => w.requestId === order.id);
const withdrawal = existing ?? await wallets.withdraw(walletId, { requestId: order.id, recipients, expectedTxid: quote.txid });
```

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
| `lockSpending(locked?)` | Pause new spending/signing across the vault; a lock set here cannot be released from the web console |
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

A deposit is `eligible` only when it has the required confirmations, the index is fresh, **and** its block is at or below `status.verifiedHeight` — the height that independent peers confirmed after the last sync (see [Chain validation](#chain-validation)). While a sync is still running, newly indexed deposits stay ineligible.

Persist the chain TXID and stable account ID too: restored wallets receive new wallet IDs, so reconcile against your application ledger after restoring or rescanning. Unconfirmed incoming mempool transactions are not reported. Normal deposits default to six confirmations; mining rewards use the network's early 30 / later 240 block maturity. Eligibility is a local index policy, not proof of full consensus validity.

## Backup, restore and historical import

Keys are encrypted in `wallets.db` with AES-256-GCM using `wallet.key`. Keep that host secret protected. This is a hot wallet: anyone who compromises the application process or reads both files can spend funds.

`backup(passphrase)` returns an encrypted JSON object; save it safely using your application's storage. `restore()` treats the decrypted contents as untrusted: pending withdrawals, input reservations and coin locks are only accepted for wallets inside the same backup (and inputs owned by their keys), and contact addresses are validated, so a crafted backup cannot freeze another namespace's coins. Backups contain namespace account keys, contacts, withdrawals, reservations and coin locks. They exclude chain data and optional console login credentials. New backups use format `pepecoin-js-wallet`, version 2; encrypted version 1 backups remain readable. Older account identifier fields migrate to `accountId` without changing addresses.

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

## Chain validation

The index follows public peers, so it treats every peer as untrusted:

- **Headers are validated before any block is downloaded:** linkage, scrypt proof of work, the full merged-mining (AuxPoW) proof from height 42,000, the chain ID, DigiShield difficulty for every block, median-time-past, the two-hour future limit, and Pepecoin Core's checkpoints (heights 0, 40,477 and 327,239). One invalid header rejects the whole page and the sync retries with a different peer.
- **Block bodies must match their header's Merkle root** before they are buffered, and buffered data is capped at 256 MiB.
- **Independent peers must confirm the tip.** After catching up, at least two other peers in different IPv4 /16 ranges must report the indexed tip on their best chain before the wallet is marked `synced`, `verifiedHeight` advances and deposits can become eligible.
- **Peer claims are bounded.** The network height is the *median* of peers' advertised heights, the sync peer is picked at random from peers at or above that median, `addr` gossip is capped, and headers pages are limited to the protocol's 2,000.
- **Relay needs two witnesses.** A withdrawal is reported `relayed` only after two different peers serve the exact transaction back; otherwise it is `unverified` (it may still confirm).

Existing index files are upgraded in place (a `bits` column is added to `headers`); no rescan is needed. Blocks indexed before the upgrade are not re-validated. If you want every historical header checked, run a rescan.

## Separate web app

The optional UI and HTTP/WebSocket server live in the sibling `web/` package, not in this library. From the repository root, `npm start` launches that app. Its authenticated sockets receive sync and wallet updates from this library's runtime events. Installing this wallet package alone does not install or start the web app.

The `pepecoin-js-wallet/server` export is a trusted in-process adapter for the separate server. It exposes the wallet runtime and shared utilities; it creates no HTTP or WebSocket listener. Do not expose that adapter directly to untrusted code.

## Important limitations

This is **not full Pepecoin Core parity or a production-audited custodian**. It is a header-validating (SPV-style) client: it checks proof of work, merged mining, difficulty, checkpoints and Merkle roots (see [Chain validation](#chain-validation)), but it does not execute scripts, check block subsidies or full transaction validity, or roll back chain reorganizations automatically. A detected reorg stops indexing for a safe rescan. An attacker who controls most of your peers (an eclipse attack) and substantial scrypt hash power could still mislead it. Do not use it as the sole trust source for large real-money deposits without an independent check and a security review.

Not implemented: wallet.dat compatibility, HD seeds, multisig/PSBT, watch-only wallets, full mempool tracking, mining, hardware signing, or a transactional application ledger. History discarded by the old 100-transaction limit requires a rescan.

Protect the host, use restrictive filesystem/NTFS permissions, and keep encrypted offline backups. POSIX file modes do not replace Windows ACLs. No new authentication records are stored on-chain. All peer connections are outbound to public Pepecoin peers, not a local Core node.

## Verify

```sh
npm test
```

Library tests cover direct import with no HTTP listener or process hooks, lifecycle/reopening, backups and hostile restores, native signing, duplicate withdrawal prevention, sync paging, peer isolation, header validation (including a real merged-mined block), peer-confirmation of the tip, and every example in `examples/`. Browser-session and WebSocket tests belong to the separate web package. No real-money transactions are sent.

From the repository root, `npm run preview` launches the separate web package's synthetic fixture. Never deploy it or fund its addresses.

Protocol references: [Pepecoin Core parameters](https://github.com/pepecoinppc/pepecoin/blob/master/src/chainparams.cpp), [message signing](https://github.com/pepecoinppc/pepecoin/blob/master/src/validation.cpp), [PepeNet reference](https://github.com/PepeNetWeb/namespace-indexer).
