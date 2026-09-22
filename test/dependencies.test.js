/** Guard the workspace install against reintroducing native npm build requirements. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';

test('locked dependencies need no Python or native install scripts', () => {
  const lock = JSON.parse(readFileSync(new URL('../package-lock.json', import.meta.url), 'utf8'));
  for (const [name, entry] of Object.entries(lock.packages)) {
    assert.doesNotMatch(name, /(?:^|\/)(?:better-sqlite3|node-gyp|node-addon-api|python[^/]*)$/i);
    assert.notEqual(entry.hasInstallScript, true, `${name} introduces an install script`);
  }
  const manifests = ['../package.json'];
  const workspaceFile = new URL('../../package.json', import.meta.url);
  if (existsSync(workspaceFile)) {
    const workspace = JSON.parse(readFileSync(workspaceFile, 'utf8'));
    if (workspace.name === 'pepecoin-js-wallet-workspace') manifests.push('../../package.json', '../../web/package.json');
  }
  for (const file of manifests) {
    const manifest = JSON.parse(readFileSync(new URL(file, import.meta.url), 'utf8'));
    assert.equal(manifest.engines.node, '>=24.13.0');
  }
});
