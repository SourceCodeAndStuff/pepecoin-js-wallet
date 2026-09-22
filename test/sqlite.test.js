/** Built-in SQLite regression tests: row compatibility, atomicity, nesting, and file safety. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import Database from '../lib/sqlite.js';

test('SQLite preserves plain rows, blobs, named bindings, and exact ribbit strings', t => {
  const db = new Database(':memory:'); t.after(() => db.close());
  db.exec('CREATE TABLE coins (id INTEGER PRIMARY KEY, amount TEXT, raw BLOB)');
  const result = db.prepare('INSERT INTO coins VALUES (@id, @amount, @raw)').run({
    id: 1, amount: '99999999999999999999', raw: Buffer.from([0, 255]), ignored: 'metadata'
  });
  assert.equal(result.changes, 1);
  assert.deepEqual(db.prepare('SELECT * FROM coins WHERE id=?').get(1), {
    id: 1, amount: '99999999999999999999', raw: Buffer.from([0, 255])
  });
  assert.equal(db.prepare('SELECT * FROM coins WHERE id=?').get(2), undefined);
  assert.equal(db.pragma('foreign_keys')[0].foreign_keys, 1);
});

test('transactions preserve arguments and this, commit atomically, and roll back failures', t => {
  const db = new Database(':memory:'); t.after(() => db.close());
  db.exec('CREATE TABLE records (id INTEGER PRIMARY KEY)');
  const insert = db.prepare('INSERT INTO records VALUES (?)');
  const write = db.transaction(function (id) { insert.run(id); return this.result; });
  assert.equal(write.call({ result: 'saved' }, 1), 'saved');
  const fail = db.transaction(() => { insert.run(2); insert.run(1); });
  assert.throws(fail, /UNIQUE/);
  assert.deepEqual(db.prepare('SELECT id FROM records ORDER BY id').all(), [{ id: 1 }]);
  assert.equal(db.connection.isTransaction, false);
});

test('nested transactions use savepoints and outer rollback includes successful inner work', t => {
  const db = new Database(':memory:'); t.after(() => db.close());
  db.exec('CREATE TABLE records (id INTEGER PRIMARY KEY)');
  const insert = db.prepare('INSERT INTO records VALUES (?)');
  db.transaction(() => {
    insert.run(1);
    assert.throws(db.transaction(() => { insert.run(2); throw new Error('inner'); }), /inner/);
    db.transaction(() => insert.run(3))();
  })();
  assert.deepEqual(db.prepare('SELECT id FROM records ORDER BY id').all(), [{ id: 1 }, { id: 3 }]);
  assert.throws(db.transaction(() => {
    db.transaction(() => insert.run(4))();
    throw new Error('outer');
  }), /outer/);
  assert.equal(db.prepare('SELECT id FROM records WHERE id=4').get(), undefined);
});

test('commit-time foreign-key failures roll back and async callbacks are rejected', t => {
  const db = new Database(':memory:'); t.after(() => db.close());
  db.exec('CREATE TABLE parents (id INTEGER PRIMARY KEY); CREATE TABLE children (parent INTEGER REFERENCES parents(id) DEFERRABLE INITIALLY DEFERRED)');
  assert.throws(db.transaction(() => db.prepare('INSERT INTO children VALUES (?)').run(1)), /FOREIGN KEY/);
  assert.deepEqual(db.prepare('SELECT * FROM children').all(), []);
  let invoked = false;
  assert.throws(() => db.transaction(async () => { invoked = true; }), /synchronous/);
  assert.equal(invoked, false);
  assert.throws(db.transaction(() => { db.exec('INSERT INTO parents VALUES (1)'); return Promise.resolve(); }), /promises/);
  assert.deepEqual(db.prepare('SELECT * FROM parents').all(), []);
});

test('SQLite reopens persisted data read-only and close is idempotent', () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'pepe-sqlite-'));
  const file = path.join(dir, 'fixture.sqlite');
  assert.throws(() => new Database(file, { fileMustExist: true }), /does not exist/);
  const writer = new Database(file);
  try { writer.exec('CREATE TABLE records (id INTEGER PRIMARY KEY); INSERT INTO records VALUES (1)'); }
  finally { writer.close(); }
  const reader = new Database(file, { readonly: true });
  try {
    assert.deepEqual(reader.prepare('SELECT * FROM records').all(), [{ id: 1 }]);
    assert.throws(() => reader.exec('INSERT INTO records VALUES (2)'), /readonly/);
  } finally { reader.close(); reader.close(); }
  assert.equal(reader.open, false);
});
