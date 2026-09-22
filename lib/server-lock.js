/**
 * @file Exclusive data-directory ownership using SQLite and a legacy PID marker.
 */
import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import Database from './sqlite.js';

/**
 * Acquire an OS-backed process lock and safely reclaim only provably stale PID markers.
 * The directory must already exist. Keep the returned closure reachable for the full
 * runtime lifetime; close it before another runtime opens this directory. Never remove
 * the process-guard database while a wallet is running.
 * @param {string} dir - Wallet data directory.
 * @returns {function(): void} Idempotent release function that removes its own marker and closes the guard.
 * @throws {Error} If another owner is alive, metadata is invalid, ownership is uncertain, or storage fails.
 */
export function acquireServerLock(dir) {
  const file = path.join(path.resolve(dir), 'wallet-server.lock');
  const content = JSON.stringify({ pid: process.pid, token: randomUUID(), startedAt: new Date().toISOString() });
  // SQLite supplies an OS-backed, process-lifetime lock. A crash releases it
  // automatically. Holding it also serializes stale-marker recovery so two
  // simultaneous restarts cannot both reclaim the same dead process's lock.
  // This database contains no wallet keys or chain data.
  let guard;
  try {
    guard = new Database(path.join(path.resolve(dir), 'wallet-process-lock.sqlite'), { timeout: 0 });
    guard.exec('CREATE TABLE IF NOT EXISTS process_guard (id INTEGER PRIMARY KEY); BEGIN EXCLUSIVE;');
  } catch (e) {
    guard?.close();
    if (e.code === 'SQLITE_BUSY' || e.code === 'SQLITE_LOCKED' ||
        (e.code === 'ERR_SQLITE_ERROR' && [5, 6].includes(e.errcode & 0xff))) {
      throw new Error('This data directory is locked by another running wallet. Close that wallet before opening another instance.');
    }
    throw e;
  }
  let temporary;
  try {
    let previous;
    try { previous = fs.readFileSync(file, 'utf8'); }
    catch (e) { if (e.code !== 'ENOENT') throw e; }
    if (previous !== undefined) {
      let owner;
      try { owner = JSON.parse(previous); } catch {}
      if (!Number.isSafeInteger(owner?.pid) || owner.pid <= 0) {
        throw new Error('Wallet lock metadata is invalid. Verify no wallet process is running before removing wallet-server.lock.');
      }
      let dead = false;
      try { process.kill(owner.pid, 0); }
      catch (e) {
        // Permission errors are NOT proof that the owner has exited.
        if (e.code === 'ESRCH') dead = true;
        else throw new Error(`Cannot verify wallet lock owner PID ${owner.pid}; refusing to unlock an uncertain owner.`);
      }
      if (!dead) throw new Error(`This data directory is locked by running process ${owner.pid}. Close that wallet first.`);
      // Replace the stale marker without an absent-file window, so older
      // versions that only honor the marker remain excluded as well.
      temporary = `${file}.${randomUUID()}.tmp`;
      fs.writeFileSync(temporary, content, { flag: 'wx', mode: 0o600 });
      fs.renameSync(temporary, file);
      temporary = undefined;
    } else fs.writeFileSync(file, content, { flag: 'wx', mode: 0o600 });
  } catch (e) {
    if (temporary) { try { fs.unlinkSync(temporary); } catch {} }
    guard.close();
    throw e;
  }

  let released = false;
  return () => {
    if (released) return;
    released = true;
    try {
      if (fs.existsSync(file) && fs.readFileSync(file,'utf8') === content) fs.unlinkSync(file);
    } finally { guard.close(); }
  };
}
