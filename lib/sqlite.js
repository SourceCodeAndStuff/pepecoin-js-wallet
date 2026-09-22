/**
 * Internal SQLite adapter backed by Node's built-in driver, with no npm native addon.
 * Preserves the existing on-disk schemas, plain row objects, and synchronous transactions.
 */
import { DatabaseSync } from 'node:sqlite';
import { existsSync } from 'node:fs';

/**
 * Convert a driver row to the plain objects and Buffer blobs used by the wallet.
 * @param {object|undefined} row - Driver result, or undefined when no row matched.
 * @returns {object|undefined} Normalized row.
 */
function rowObject(row) {
  if (row === undefined) return undefined;
  return Object.fromEntries(Object.entries(row).map(([key, value]) =>
    [key, value instanceof Uint8Array ? Buffer.from(value) : value]));
}

/** Internal database connection; exposes only the operations used by this project. */
export default class Database {
  /**
   * Open an existing SQLite file or create one without changing its schema.
   * @param {string} filename - SQLite filename or :memory:.
   * @param {object} [options] - Connection options.
   * @param {boolean} [options.readonly=false] - Refuse writes and file creation.
   * @param {boolean} [options.fileMustExist=false] - Refuse a missing file.
   * @param {number} [options.timeout=5000] - Lock wait in milliseconds; guards use zero.
   */
  constructor(filename, { readonly = false, fileMustExist = false, timeout = 5000 } = {}) {
    if (fileMustExist && filename !== ':memory:' && !existsSync(filename)) throw new Error('SQLite file does not exist.');
    this.connection = new DatabaseSync(filename, { readOnly: readonly, timeout,
      enableForeignKeyConstraints: true, enableDoubleQuotedStringLiterals: false });
    this.savepointId = 0;
  }

  /** @returns {boolean} Whether this connection is still open. */
  get open() { return this.connection.isOpen; }

  /** Close once; SQLite releases any outstanding transaction and process locks. */
  close() { if (this.open) this.connection.close(); }

  /**
   * Execute trusted internal SQL, possibly containing multiple statements.
   * @param {string} sql - SQL text; use prepare for untrusted values.
   * @returns {void}
   */
  exec(sql) { this.connection.exec(sql); }

  /**
   * Execute a trusted internal PRAGMA and return any rows it produces.
   * @param {string} source - PRAGMA body, without its keyword.
   * @returns {object[]} Result rows.
   */
  pragma(source) { return this.prepare(`PRAGMA ${source}`).all(); }

  /**
   * Prepare a reusable statement accepting positional values or a named parameter object.
   * Extra named fields are ignored for compatibility with existing record inserts.
   * @param {string} sql - SQL with bound placeholders.
   * @returns {{get: Function, all: Function, run: Function}} Synchronous statement methods.
   */
  prepare(sql) {
    const statement = this.connection.prepare(sql);
    statement.setAllowBareNamedParameters(true);
    statement.setAllowUnknownNamedParameters(true);
    return {
      /** @returns {object|undefined} First matching row, or undefined. */
      get(...parameters) { return rowObject(statement.get(...parameters)); },
      /** @returns {object[]} All matching rows as plain objects. */
      all(...parameters) { return statement.all(...parameters).map(rowObject); },
      /** @returns {{changes: number|bigint, lastInsertRowid: number|bigint}} Write metadata. */
      run(...parameters) { return statement.run(...parameters); }
    };
  }

  /**
   * Wrap synchronous work in an atomic transaction, using savepoints for nested calls.
   * A failure rolls back only this scope, including failures during commit/release.
   * Callbacks must not return promises, await work, or manage transactions themselves.
   * @param {Function} work - Synchronous operation; receives the wrapper's arguments/this.
   * @returns {Function} Callable transaction wrapper returning the callback's result.
   */
  transaction(work) {
    if (typeof work !== 'function' || work.constructor?.name === 'AsyncFunction') {
      throw new TypeError('SQLite transactions require a synchronous function.');
    }
    const database = this;
    return function (...args) {
      const nested = database.connection.isTransaction;
      const savepoint = `wallet_tx_${++database.savepointId}`;
      database.exec(nested ? `SAVEPOINT ${savepoint}` : 'BEGIN');
      try {
        const result = work.apply(this, args);
        if (result && typeof result.then === 'function') throw new TypeError('SQLite transactions cannot return promises.');
        database.exec(nested ? `RELEASE ${savepoint}` : 'COMMIT');
        return result;
      } catch (error) {
        if (database.connection.isTransaction) {
          if (nested) {
            database.exec(`ROLLBACK TO ${savepoint}`);
            database.exec(`RELEASE ${savepoint}`);
          } else database.exec('ROLLBACK');
        }
        throw error;
      }
    };
  }
}
