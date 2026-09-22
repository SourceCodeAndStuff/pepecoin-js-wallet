/**
 * Data-directory lock ownership and crash recovery tests using temporary directories.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { acquireServerLock } from '../lib/server-lock.js';

/**
 * Allocate a fresh temporary directory for one lock scenario.
 * @returns {string} Absolute fixture directory.
 */
const makeDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'pepe-lock-recovery-'));

test('stale legacy marker is recovered only after its PID has exited', () => {
  const dir = makeDir(), file = path.join(dir, 'wallet-server.lock');
  const pid = Number(execFileSync(process.execPath, ['-p', 'process.pid'], { encoding: 'utf8', timeout: 5000 }).trim());
  fs.writeFileSync(file, JSON.stringify({ pid, token: 'old-crashed-process' }));
  const release = acquireServerLock(dir);
  try {
    assert.equal(JSON.parse(fs.readFileSync(file)).pid, process.pid);
    assert.throws(() => acquireServerLock(dir), /locked/);
  } finally { release(); }
  assert.equal(fs.existsSync(file), false);
});

test('active legacy owner and unreadable metadata fail closed', () => {
  const dir = makeDir(), file = path.join(dir, 'wallet-server.lock');
  const active = JSON.stringify({ pid: process.pid });
  fs.writeFileSync(file, active);
  assert.throws(() => acquireServerLock(dir), /running process/);
  assert.equal(fs.readFileSync(file, 'utf8'), active);
  fs.writeFileSync(file, '{partial');
  assert.throws(() => acquireServerLock(dir), /metadata is invalid/);
  assert.equal(fs.readFileSync(file, 'utf8'), '{partial');
});

test('OS lock is automatically released when an owner exits without cleanup', { timeout: 10000 }, async t => {
  const dir = makeDir();
  const moduleUrl = new URL('../lib/server-lock.js', import.meta.url).href;
  const child = spawn(process.execPath, ['--input-type=module', '-e', `
    import { acquireServerLock } from ${JSON.stringify(moduleUrl)};
    const release = acquireServerLock(${JSON.stringify(dir)});
    console.log('locked');
    process.stdin.once('data', bytes => { if (bytes.toString() === 'release') release(); process.exit(0); });
  `], { stdio: ['pipe','pipe','pipe'] });
  t.after(() => { child.stdin.end(); if (child.exitCode === null) child.kill(); });
  const errors = []; child.stderr.on('data', b => errors.push(b.toString()));
  await once(child.stdout, 'data');
  assert.throws(() => acquireServerLock(dir), /another running wallet/);
  const exited = once(child, 'exit'); child.stdin.write('exit');
  const [code] = await exited; assert.equal(code, 0, errors.join(''));
  assert.equal(fs.existsSync(path.join(dir, 'wallet-server.lock')), true);
  acquireServerLock(dir)();
  assert.equal(fs.existsSync(path.join(dir, 'wallet-server.lock')), false);
});
