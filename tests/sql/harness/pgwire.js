// Minimal PostgreSQL frontend/backend protocol 3.0 client for the SQL test
// harness: trust authentication over the harness's private Unix socket and
// the simple-query protocol only. It exists so the SQL gates need no npm
// dependency, and so tests can hold several real sessions open at once.
//
// Values are returned as text (or null). Queries on one connection run one
// at a time; concurrency comes from separate connections. Every query is
// bounded by a client-side timeout that cancels the backend statement.

import net from 'node:net';
import path from 'node:path';

export class PgError extends Error {
  constructor(fields) {
    super(fields.M ?? 'PostgreSQL error');
    this.name = 'PgError';
    this.code = fields.C;
    this.severity = fields.S;
    this.detail = fields.D;
    this.hint = fields.H;
    this.where = fields.W;
  }
}

const DEFAULT_TIMEOUT_MS = 30_000;

function socketPath(socketDir, port) {
  return path.join(socketDir, `.s.PGSQL.${port}`);
}

function startupMessage(params) {
  const parts = [];
  for (const [key, value] of Object.entries(params)) parts.push(`${key}\0${value}\0`);
  const body = Buffer.from(`${parts.join('')}\0`, 'utf8');
  const head = Buffer.alloc(8);
  head.writeInt32BE(8 + body.length, 0);
  head.writeInt32BE(196608, 4);
  return Buffer.concat([head, body]);
}

function frame(type, body) {
  const head = Buffer.alloc(5);
  head.write(type, 0, 'latin1');
  head.writeInt32BE(4 + body.length, 1);
  return Buffer.concat([head, body]);
}

function readFields(payload) {
  const fields = {};
  let offset = 0;
  while (offset < payload.length && payload[offset] !== 0) {
    const code = String.fromCharCode(payload[offset]);
    const end = payload.indexOf(0, offset + 1);
    fields[code] = payload.toString('utf8', offset + 1, end);
    offset = end + 1;
  }
  return fields;
}

export class Connection {
  constructor(socket, options) {
    this.socket = socket;
    this.options = options;
    this.buffer = Buffer.alloc(0);
    this.parameters = {};
    this.pid = null;
    this.secret = null;
    this.txStatus = null;
    this.closed = false;
    this.pending = null;
    this.chain = Promise.resolve();
    this.notices = [];
    socket.on('data', (chunk) => this.onData(chunk));
    socket.on('error', (error) => this.onClose(error));
    socket.on('close', () => this.onClose(new Error('connection closed')));
  }

  onClose(error) {
    if (this.closed) return;
    this.closed = true;
    if (this.pending) {
      const { reject } = this.pending;
      this.pending = null;
      reject(error);
    }
  }

  onData(chunk) {
    this.buffer = this.buffer.length ? Buffer.concat([this.buffer, chunk]) : chunk;
    while (this.buffer.length >= 5) {
      const type = String.fromCharCode(this.buffer[0]);
      const length = this.buffer.readInt32BE(1);
      if (this.buffer.length < 1 + length) break;
      const payload = this.buffer.subarray(5, 1 + length);
      this.buffer = this.buffer.subarray(1 + length);
      this.onMessage(type, payload);
    }
  }

  onMessage(type, payload) {
    const state = this.pending;
    switch (type) {
      case 'R': {
        const code = payload.readInt32BE(0);
        if (code !== 0 && state) {
          // The server now waits for a password that will never come.
          this.pending = null;
          clearTimeout(state.timer);
          this.socket.destroy();
          state.reject(new Error(`unsupported authentication request ${code}; the harness uses trust on a private socket`));
        }
        break;
      }
      case 'S': {
        const end = payload.indexOf(0);
        this.parameters[payload.toString('utf8', 0, end)] = payload.toString('utf8', end + 1, payload.length - 1);
        break;
      }
      case 'K':
        this.pid = payload.readInt32BE(0);
        this.secret = payload.readInt32BE(4);
        break;
      case 'T': {
        const count = payload.readInt16BE(0);
        const fields = [];
        let offset = 2;
        for (let i = 0; i < count; i += 1) {
          const end = payload.indexOf(0, offset);
          fields.push(payload.toString('utf8', offset, end));
          offset = end + 1 + 18;
        }
        if (state) state.current = { command: null, fields, rows: [] };
        break;
      }
      case 'D': {
        const count = payload.readInt16BE(0);
        const row = {};
        let offset = 2;
        for (let i = 0; i < count; i += 1) {
          const size = payload.readInt32BE(offset);
          offset += 4;
          const name = state?.current?.fields[i] ?? String(i);
          if (size < 0) row[name] = null;
          else {
            row[name] = payload.toString('utf8', offset, offset + size);
            offset += size;
          }
        }
        state?.current?.rows.push(row);
        break;
      }
      case 'C': {
        const command = payload.toString('utf8', 0, payload.length - 1);
        if (state) {
          const result = state.current ?? { fields: [], rows: [] };
          result.command = command;
          state.results.push(result);
          state.current = null;
        }
        break;
      }
      case 'I':
        if (state) state.results.push({ command: '', fields: [], rows: [] });
        break;
      case 'E':
        if (state && !state.error) state.error = new PgError(readFields(payload));
        break;
      case 'N':
        this.notices.push(readFields(payload));
        break;
      case 'Z':
        this.txStatus = String.fromCharCode(payload[0]);
        if (state) {
          this.pending = null;
          clearTimeout(state.timer);
          if (state.error) state.reject(state.error);
          else state.resolve(state.results);
        }
        break;
      default:
        break;
    }
  }

  send(buffer, timeoutMs) {
    return new Promise((resolve, reject) => {
      if (this.closed) {
        reject(new Error('connection is closed'));
        return;
      }
      const state = { resolve, reject, results: [], current: null, error: null, timer: null };
      state.timer = setTimeout(() => {
        state.error = state.error ?? new Error(`query timed out after ${timeoutMs} ms`);
        this.cancel().catch(() => {});
        // Give the cancel a moment to produce ReadyForQuery, then give up on the socket.
        setTimeout(() => {
          if (this.pending === state) {
            this.pending = null;
            this.socket.destroy();
            reject(state.error);
          }
        }, 2_000).unref();
      }, timeoutMs);
      state.timer.unref?.();
      this.pending = state;
      this.socket.write(buffer);
    });
  }

  /** Runs `sql` (one or more statements) and resolves with one result per statement. */
  query(sql, { timeoutMs = this.options.timeoutMs } = {}) {
    if (typeof sql !== 'string' || sql.includes('\0')) throw new TypeError('query: sql must be a string without NUL');
    const run = () => this.send(frame('Q', Buffer.from(`${sql}\0`, 'utf8')), timeoutMs);
    const next = this.chain.then(run, run);
    this.chain = next.catch(() => {});
    return next;
  }

  /** Rows of the last statement in `sql`. */
  async rows(sql, options) {
    const results = await this.query(sql, options);
    return results.length ? results[results.length - 1].rows : [];
  }

  /** First column of the first row of the last statement, or null. */
  async value(sql, options) {
    const rows = await this.rows(sql, options);
    if (rows.length === 0) return null;
    const first = rows[0];
    return first[Object.keys(first)[0]];
  }

  cancel() {
    return new Promise((resolve) => {
      if (this.pid === null) {
        resolve();
        return;
      }
      const socket = net.createConnection(socketPath(this.options.socketDir, this.options.port));
      socket.on('connect', () => {
        const message = Buffer.alloc(16);
        message.writeInt32BE(16, 0);
        message.writeInt32BE(80877102, 4);
        message.writeInt32BE(this.pid, 8);
        message.writeInt32BE(this.secret, 12);
        socket.end(message);
      });
      socket.on('close', resolve);
      socket.on('error', resolve);
    });
  }

  async close() {
    if (this.closed) return;
    try {
      this.socket.write(frame('X', Buffer.alloc(0)));
    } catch {
      // The socket may already be gone; closing is best effort.
    }
    this.socket.end();
    this.closed = true;
  }
}

/**
 * Opens a connection. `options`: socketDir, port, user, database,
 * timeoutMs (per query) and optional server `settings` (sent as startup
 * options, e.g. { lock_timeout: '15s' }).
 */
export function connect(options) {
  const { socketDir, port, user, database, settings = {}, timeoutMs = DEFAULT_TIMEOUT_MS } = options;
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath(socketDir, port));
    const connection = new Connection(socket, { socketDir, port, timeoutMs });
    socket.once('error', reject);
    socket.once('connect', () => {
      socket.off('error', reject);
      const opts = Object.entries(settings).map(([k, v]) => `-c ${k}=${String(v).replace(/[\\ ]/g, '\\$&')}`).join(' ');
      const params = { user, database, application_name: options.applicationName ?? 'dwarpal-sql-tests', client_encoding: 'UTF8' };
      if (opts) params.options = opts;
      connection
        .send(startupMessage(params), timeoutMs)
        .then(() => {
          if (connection.parameters.standard_conforming_strings !== 'on') {
            connection.close();
            reject(new Error('standard_conforming_strings must be on for literal quoting'));
            return;
          }
          resolve(connection);
        }, reject);
    });
  });
}

/** SQL literal for a JS value: null, boolean, finite number or string (no NUL). */
export function lit(value) {
  if (value === null || value === undefined) return 'NULL';
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('lit: numbers must be finite');
    return String(value);
  }
  if (typeof value === 'string') {
    if (value.includes('\0')) throw new TypeError('lit: strings may not contain NUL');
    return `'${value.replace(/'/g, "''")}'`;
  }
  throw new TypeError('lit: unsupported value');
}

/** jsonb literal built from JSON text (so representability is decided by PostgreSQL). */
export function jsonLit(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  return `${lit(text)}::jsonb`;
}

/** Typed array literal, e.g. arrayLit(ids, 'uuid'). */
export function arrayLit(values, type) {
  if (!Array.isArray(values)) throw new TypeError('arrayLit: values must be an array');
  return values.length === 0 ? `'{}'::${type}[]` : `ARRAY[${values.map(lit).join(', ')}]::${type}[]`;
}
