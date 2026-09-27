// Test-side helpers over a running harness cluster (started by tests/sql/run.js,
// which exports its socket through DWARPAL_SQL_* variables). Each test gets a
// fresh database cloned from a prepared template, connects through real roles
// and claims, and drops that database afterwards.

import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { connect, lit, jsonLit, arrayLit, PgError } from './pgwire.js';

export { lit, jsonLit, arrayLit, PgError };

const here = path.dirname(fileURLToPath(import.meta.url));
export const SQL_ROOT = path.resolve(here, '..');
export const REPO_ROOT = path.resolve(SQL_ROOT, '..', '..');
export const MIGRATIONS_DIR = path.join(REPO_ROOT, 'supabase', 'migrations');

export const TEMPLATE_MIGRATED = 'dwarpal_template';
export const TEMPLATE_BASE = 'dwarpal_base';

function env() {
  const socketDir = process.env.DWARPAL_SQL_SOCKET_DIR;
  const port = Number(process.env.DWARPAL_SQL_PORT);
  if (!socketDir || !port) {
    throw new Error('No harness cluster: run the SQL gates through `node tests/sql/run.js` (see tests/sql/README.md).');
  }
  return { socketDir, port };
}

// Bounded waits: a blocked statement fails after lock_timeout instead of
// hanging the run, and no statement may run longer than statement_timeout.
const SESSION_SETTINGS = { lock_timeout: '20s', statement_timeout: '60s', idle_in_transaction_session_timeout: '120s' };

export function open(user, database, settings = {}) {
  return connect({ ...env(), user, database, settings: { ...SESSION_SETTINGS, ...settings } });
}

export function migrationFiles() {
  return fs.readdirSync(MIGRATIONS_DIR).filter((name) => name.endsWith('.sql')).sort().map((name) => path.join(MIGRATIONS_DIR, name));
}

export function readFixture(name) {
  return fs.readFileSync(path.join(SQL_ROOT, 'fixtures', name), 'utf8');
}

export function uuid() {
  return randomUUID();
}

/** An actor as PostgREST would present it: a database role plus JWT claims. */
export const actors = {
  anon: () => ({ role: 'anon', claims: { role: 'anon', iss: 'supabase' } }),
  service: () => ({ role: 'service_role', claims: { role: 'service_role', iss: 'supabase' } }),
  user: (sub, aal = 'aal1', extra = {}) => ({
    role: 'authenticated',
    claims: { sub, role: 'authenticated', aud: 'authenticated', aal, session_id: `session-${sub.slice(-4)}`, is_anonymous: false, ...extra },
  }),
  /** Raw role and claims text, for malformed-claim tests. */
  raw: (role, claimsText) => ({ role, claimsText }),
};

function prelude(actor) {
  const claims = actor.claimsText ?? JSON.stringify(actor.claims);
  return `select set_config('role', ${lit(actor.role)}, true), set_config('request.jwt.claims', ${lit(claims)}, true)`;
}

/** Parses the single jsonb/boolean/text value a call returns. */
export function parseValue(text) {
  if (text === null) return null;
  if (text === 't') return true;
  if (text === 'f') return false;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

export class TestDatabase {
  constructor(name, admin) {
    this.name = name;
    this.admin = admin;
    this.connections = [];
  }

  async connection(user) {
    const c = await open(user, this.name);
    this.connections.push(c);
    return c;
  }

  /** One transaction as `actor`; resolves with the parsed value of `sql`'s last statement. */
  async as(actor, sql, { settings = [] } = {}) {
    const c = await this.pooled(actor.role === 'postgres' ? 'postgres' : 'authenticator');
    const extra = settings.map(([k, v]) => `select set_config(${lit(k)}, ${lit(v)}, true);`).join(' ');
    const head = actor.role === 'postgres' ? '' : `${prelude(actor)};`;
    try {
      const results = await c.query(`begin; ${head} ${extra} ${sql}; commit;`);
      const last = results[results.length - 2];
      if (!last || last.rows.length === 0) return null;
      const row = last.rows[0];
      return parseValue(row[Object.keys(row)[0]]);
    } catch (error) {
      if (c.txStatus !== 'I') await c.query('rollback').catch(() => {});
      throw error;
    }
  }

  async pooled(user) {
    this.pool ??= new Map();
    if (!this.pool.has(user)) this.pool.set(user, await this.connection(user));
    return this.pool.get(user);
  }

  /** Calls `fn(args)` with named arguments as `actor`. */
  call(actor, fn, args = {}, options) {
    const list = Object.entries(args).map(([k, v]) => `${k} => ${v?.sql ?? lit(v)}`).join(', ');
    return this.as(actor, `select ${fn}(${list})`, options);
  }

  /** A dedicated session for concurrency tests: explicit begin / query / commit. */
  async session(actor) {
    const c = await this.connection(actor.role === 'postgres' ? 'postgres' : 'authenticator');
    return new Session(c, actor);
  }

  /** Superuser rows (test inspection only). */
  rows(sql) {
    return this.admin.rows(sql);
  }

  async count(table, where = 'true') {
    return Number(await this.admin.value(`select count(*) from ${table} where ${where}`));
  }

  /** Waits until backend `pid` is blocked on an advisory lock, observed in pg_locks. */
  async waitForAdvisoryWait(pid, { timeoutMs = 10_000 } = {}) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const waiting = await this.admin.value(
        `select count(*) from pg_locks where pid = ${pid} and locktype = 'advisory' and not granted`);
      if (Number(waiting) > 0) return;
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
    throw new Error(`backend ${pid} did not block on an advisory lock within ${timeoutMs} ms`);
  }

  async createUser({ id = uuid(), email, confirmed = true, anonymous = false } = {}) {
    await this.admin.query(`insert into auth.users (id, email, email_confirmed_at, is_anonymous) values (${lit(id)}, ${lit(email ?? `user-${id.slice(0, 8)}@example.test`)}, ${confirmed ? 'now()' : 'null'}, ${anonymous})`);
    return id;
  }

  async installFaults() {
    await this.admin.query(readFixture('faults.sql'));
  }

  async close() {
    for (const c of this.connections) await c.close();
    this.connections = [];
    this.pool = null;
  }
}

export class Session {
  constructor(connection, actor) {
    this.connection = connection;
    this.actor = actor;
    this.pid = connection.pid;
  }

  begin() {
    const head = this.actor.role === 'postgres' ? '' : `${prelude(this.actor)};`;
    return this.connection.query(`begin; ${head}`);
  }

  /** Resolves with the parsed value of the last statement. */
  async query(sql) {
    const results = await this.connection.query(sql);
    const last = results[results.length - 1];
    if (!last || last.rows.length === 0) return null;
    const row = last.rows[0];
    return parseValue(row[Object.keys(row)[0]]);
  }

  call(fn, args = {}) {
    const list = Object.entries(args).map(([k, v]) => `${k} => ${v?.sql ?? lit(v)}`).join(', ');
    return this.query(`select ${fn}(${list})`);
  }

  commit() {
    return this.connection.query('commit');
  }

  rollback() {
    return this.connection.query('rollback');
  }
}

/** Raw SQL argument for call(): passed through unquoted. */
export function sqlArg(sql) {
  return { sql };
}

let counter = 0;

/** Creates a database cloned from `template`, runs fn, then drops it. */
export async function withDatabase(fn, { template = TEMPLATE_MIGRATED } = {}) {
  const name = `t_${process.pid}_${Date.now().toString(36)}_${(counter += 1)}`;
  const root = await open('supabase_admin', 'postgres');
  let db;
  try {
    await root.query(`create database ${name} template ${template}`);
    await root.query(`grant create, connect, temporary on database ${name} to postgres; grant connect, temporary on database ${name} to authenticator`);
    const admin = await open('supabase_admin', name);
    db = new TestDatabase(name, admin);
    db.connections.push(admin);
    return await fn(db);
  } finally {
    if (db) await db.close();
    await root.query(`drop database if exists ${name} with (force)`).catch(() => {});
    await root.close();
  }
}

/** Asserts a kit refusal: SQLSTATE DW001 with `code` as the message. */
export async function refusal(promise, code) {
  try {
    await promise;
  } catch (error) {
    if (!(error instanceof PgError)) throw error;
    if (error.code !== 'DW001' || error.message !== code) {
      throw new Error(`expected refusal ${code}, got ${error.code} ${error.message}`);
    }
    return error;
  }
  throw new Error(`expected refusal ${code}, but the call succeeded`);
}

/** Asserts a database error with SQLSTATE `sqlstate` (never a kit refusal or success). */
export async function dbError(promise, sqlstate) {
  try {
    await promise;
  } catch (error) {
    if (!(error instanceof PgError)) throw error;
    if (sqlstate && error.code !== sqlstate) throw new Error(`expected SQLSTATE ${sqlstate}, got ${error.code} ${error.message}`);
    return error;
  }
  throw new Error(`expected a database error${sqlstate ? ` ${sqlstate}` : ''}, but the call succeeded`);
}
