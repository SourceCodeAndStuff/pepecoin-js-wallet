/**
 * @file Lifecycle owner for the locked vault, chain worker, sync supervisor and wallet service.
 * The caller owns shutdown; this module installs no process handlers or listening servers.
 */
import path from 'node:path';
import { mkdir } from 'node:fs/promises';
import { EventEmitter } from 'node:events';
import { WalletVault } from './wallet-vault.js';
import { WalletService } from './wallet-service.js';
import { ChainIndex } from './chain-index.js';
import { broadcastDiscoveredTransaction, MultiPeerManager } from './pepenet-p2p.js';
import { PepecoinSync } from './pepenet-sync.js';
import { acquireServerLock } from './server-lock.js';

const TIP_POLL_INTERVAL_MS = 30000;
// No HTTP imports, listening ports, environment mutation, or process handlers.
// The embedding Node application owns this runtime's lifetime.
/**
 * Open shared wallet resources and optionally begin public-peer synchronization.
 * A requested rescan preserves the previous index and marks affected addresses unsafe to
 * spend until catch-up completes. Startup failures close acquired resources and release the lock.
 * @param {Object} [options={}] - Runtime configuration.
 * @param {string} options.dataDir - Required wallet directory; relative paths resolve against cwd.
 * @param {boolean} [options.autoSync=true] - Begin synchronization after initialization.
 * @param {boolean} [options.rescan=false] - Explicitly create a fresh historical index.
 * @param {string[]} [options.extraIdentities=[]] - Additional hex HASH160 identities to watch.
 * @returns {Promise<{vault: import("./wallet-vault.js").WalletVault, index: import("./chain-index.js").ChainIndex, service: import("./wallet-service.js").WalletService, status: import("../index.d.ts").SyncStatus, events: EventEmitter, startSync: function(): void, close: function(): Promise<void>}>} Owned runtime. events emits sync status copies and indexed block objects {height, hash}; status is mutable.
 * @throws {Error} Rejects on invalid configuration, locked storage, missing keys or index startup failure.
 */
export async function openWalletRuntime({ dataDir, autoSync = true, rescan = false, extraIdentities = [] } = {}) {
  if (typeof dataDir !== 'string' || !dataDir.trim()) throw new Error('An explicit dataDir is required.');
  const dir = path.resolve(dataDir);
  await mkdir(dir, { recursive: true });
  const releaseLock = acquireServerLock(dir);
  let vault, chainIndex;
  try {
    vault = new WalletVault(dir);
    if (rescan) {
      const relative = 'rescan-' + Date.now();
      await mkdir(path.join(dir, relative));
      vault.db.transaction(() => {
        vault.db.prepare("INSERT OR REPLACE INTO settings VALUES ('index-directory',?)").run(relative);
        vault.db.prepare("INSERT OR REPLACE INTO settings VALUES ('rescan-active','1')").run();
        vault.db.prepare("INSERT OR REPLACE INTO settings VALUES ('rescan-identities',?)").run(JSON.stringify([...vault.allIdentities(), ...extraIdentities]));
        vault.db.prepare('UPDATE addresses SET needsRescan=1').run();
      })();
    }
    const relative = vault.db.prepare("SELECT value FROM settings WHERE name='index-directory'").get()?.value || '';
    if (relative && !/^rescan-\d+$/.test(relative)) throw new Error('Invalid saved index directory.');
    chainIndex = new ChainIndex(path.join(dir, relative));
    await chainIndex.init();
    for (const identity of new Set([...vault.allIdentities(), ...extraIdentities])) await chainIndex.watchIdentity(identity);
  } catch (e) { await chainIndex?.close(); vault?.close(); releaseLock(); throw e; }
  const syncStatus = { state: 'stopped', height: chainIndex.syncCheckpoint().height, startHeight: -1, blocksSynced: 0, targetHeight: null, progressPercent: null, peer: null, error: null, updatedAt: null, lastSyncedAt: null };
  const events = new EventEmitter();
  const service = new WalletService({ vault, index: chainIndex, status: syncStatus, broadcast: broadcastDiscoveredTransaction });
  let closing = false, activeSync = null, activePeerManager = null;
  /**
   * Run one supervised sync attempt, scheduling public-peer retries or tip polling as needed.
   * @private
   * @returns {Promise<void>} Resolves after setup; sync completion is reported through events.
   */
  const beginSync = async () => {
    if (beginSync.running || closing) return;
    beginSync.running = true;

    let manager;
    let sync;
    let finished = false;

    const schedule = delay => {
      if (closing) return;
      if (beginSync.timer) clearTimeout(beginSync.timer);
      beginSync.timer = setTimeout(() => {
        beginSync.timer = null;
        void beginSync();
      }, delay);
    };

    /**
     * Stop the current attempt, publish terminal status, and optionally schedule another attempt.
     * @private
     * @param {string} state - New synchronization state.
     * @param {string|null} [error=null] - User-visible diagnostic.
     * @param {number|null} [retryDelay=null] - Retry delay in milliseconds, or no retry.
     * @returns {void}
     */
    const finish = (state, error = null, retryDelay = null) => {
      if (finished) return;
      finished = true;

      beginSync.running = false;

      if (sync) sync.stop();
      if (manager) manager.close();
      if (activePeerManager === manager) activePeerManager = null;

      syncStatus.state = state;
      syncStatus.error = error;
      syncStatus.updatedAt = new Date().toISOString();
      events.emit('sync', { ...syncStatus });

      if (retryDelay != null) schedule(retryDelay);
    };

    try {
      if (activePeerManager) {
        activePeerManager.close();
        activePeerManager = null;
      }

      const checkpoint = chainIndex.syncCheckpoint();
      const height =
        Number.isSafeInteger(checkpoint.height) &&
        checkpoint.height >= -1
          ? checkpoint.height
          : -1;

      const tipHash =
        checkpoint.hash instanceof Buffer &&
        checkpoint.hash.length === 32
          ? checkpoint.hash
          : Buffer.alloc(32);

      syncStatus.state = 'connecting';
      syncStatus.height = height;
      syncStatus.startHeight = height;
      syncStatus.blocksSynced = 0;
      syncStatus.error = null;
      syncStatus.updatedAt = new Date().toISOString();

      events.emit('sync', { ...syncStatus });
      manager = new MultiPeerManager({
        maxPeers: 50,
        startHeight: Math.max(height, 0),
        timeoutMs: 15000
      });

      activePeerManager = manager;

      manager.on('ready', ({ peer }) => {
        syncStatus.peer = peer.host;
        syncStatus.targetHeight = manager.remoteStartHeight;
        if (!sync) {
          syncStatus.state = (peer.remoteServices & 1n) === 1n
            ? 'syncing'
            : 'discovering';
        }
        syncStatus.updatedAt = new Date().toISOString();
        events.emit('sync', { ...syncStatus });
      });

      manager.once('archiveReady', () => {
        if (finished) return;

        sync = new PepecoinSync({
          peer: manager,
          index: chainIndex,
          height,
          tipHash
        });
        activeSync = sync;

        sync.on('block', block => {
          const h = block.height;

          if (h > syncStatus.height) {
            syncStatus.height = h;
            syncStatus.blocksSynced = h - syncStatus.startHeight;
          }

          syncStatus.progressPercent =
            syncStatus.targetHeight > 0
              ? Math.min(
                  100,
                  Number(
                    (BigInt(syncStatus.height) * 10000n) /
                      BigInt(syncStatus.targetHeight)
                  ) / 100
                )
              : null;

          syncStatus.updatedAt = new Date().toISOString();
          events.emit('block', { ...block });
          events.emit('sync', { ...syncStatus });
        });

        sync.on('synced', block => {
          if (closing) return;
          if (syncStatus.targetHeight == null || block.height < syncStatus.targetHeight) {
            finish('waiting', 'Peer stopped serving blocks before the advertised network height; retrying.', 5000);
            return;
          }
          syncStatus.height = block.height;
          syncStatus.lastSyncedAt = new Date().toISOString();
          if (vault.db.prepare("SELECT value FROM settings WHERE name='rescan-active'").get()?.value === '1') {
            vault.db.transaction(() => {
              const scanned = JSON.parse(vault.db.prepare("SELECT value FROM settings WHERE name='rescan-identities'").get()?.value || '[]');
              for (const identity of scanned) vault.db.prepare('UPDATE addresses SET needsRescan=0 WHERE identity=?').run(identity);
              vault.db.prepare("INSERT OR REPLACE INTO settings VALUES ('rescan-active','0')").run();
            })();
          }
          finish('synced', null, TIP_POLL_INTERVAL_MS);
        });

        sync.on('error', error => {
          finish('error', error.message, 15000);
        });
        sync.on('reorg', () => {
          finish('rescan_required', 'Chain reorganization detected. Stop the server and run npm run rescan before spending.');
        });

        sync.start();
      });

      manager.on('close', () => {
        if (!finished && sync && !manager.ready)
          finish('waiting', 'Peers disconnected, retrying…', 10000);
      });

      manager.on('error', error => {
        syncStatus.error = error.message;
        syncStatus.updatedAt = new Date().toISOString();
        events.emit('sync', { ...syncStatus });
      });

      manager.on('peerError', ({ peer, error }) => {
        // Candidate dials are expected to fail on a decentralised network.
        // Do not overwrite a real sync error (or interrupt a healthy sync)
        // with an unrelated background connection failure.
        if (!sync && !finished) {
          syncStatus.error = `${peer.host}: ${error.message}`;
          syncStatus.updatedAt = new Date().toISOString();
          events.emit('sync', { ...syncStatus });
        }
      });

      const deadline = setTimeout(() => {
        if (!finished && !manager.hasArchivePeers()) {
          finish(
            'waiting',
            manager.hasReadyPeers()
              ? 'Connected to Pepecoin, but the available peers only serve recent blocks. Looking for a public archive peer; retrying…'
              : 'No public Pepecoin peer completed a handshake; retrying…',
            5000
          );
        }
      }, 60_000);
      deadline.unref();

      void manager.connect().catch(error => {
        finish('error', error.message, 15000);
      });

    } catch (error) {
      finish('error', error.message, 15000);
    }
  };

  beginSync.running = false;
  beginSync.timer = null;


  if (autoSync) void beginSync();
  let closePromise;
  return { vault, index: chainIndex, service, status: syncStatus, events,
    /**
     * Start a supervised attempt unless one is already running.
     * @returns {void}
     * @throws {Error} If runtime shutdown has begun.
     */
    startSync() { if (closing) throw new Error('Wallet runtime is closed.'); void beginSync(); },
    /**
     * Stop peer activity, drain queued ingestion, close databases and release the process lock.
     * @returns {Promise<void>} Shared idempotent shutdown promise.
     */
    close() {
      if (closePromise) return closePromise;
      closing = true;
      if (beginSync.timer) clearTimeout(beginSync.timer);
      activeSync?.stop(); activePeerManager?.close();
      closePromise = (async () => {
        await activeSync?.ingestQueue.catch(() => {});
        await chainIndex.close();
        vault.close(); releaseLock(); events.removeAllListeners();
      })();
      return closePromise;
    }
  };
}
