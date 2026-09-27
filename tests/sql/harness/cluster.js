// Throwaway PostgreSQL cluster for the SQL gates. The harness never connects
// to an existing server: it creates a brand-new data directory in a fresh
// temporary directory, starts a postmaster that listens only on a Unix socket
// inside that directory (no TCP listener), and on teardown stops only that
// postmaster and removes only that directory. Destructive test setup is
// therefore bounded to resources this module created.

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const MARKER = 'dwarpal-sql-cluster.json';
const PORT = 5432;

function run(bin, args, { timeoutMs = 120_000, env } = {}) {
  const result = spawnSync(bin, args, { encoding: 'utf8', timeout: timeoutMs, env: { ...process.env, ...env } });
  if (result.error) throw new Error(`${path.basename(bin)} failed to run: ${result.error.message}`);
  if (result.status !== 0) {
    throw new Error(`${path.basename(bin)} exited with ${result.status}: ${(result.stderr || result.stdout).trim().slice(0, 2000)}`);
  }
  return result.stdout;
}

/** Resolves and checks the PostgreSQL binaries directory. */
export function resolvePgBin(pgBin) {
  if (!pgBin) throw new Error('Set DWARPAL_PG_BIN (or --pg-bin) to the bin directory of a PostgreSQL build; see tests/sql/README.md.');
  const dir = path.resolve(pgBin);
  for (const tool of ['initdb', 'postgres', 'pg_ctl']) {
    const file = path.join(dir, tool);
    if (!fs.existsSync(file)) throw new Error(`${file} does not exist`);
  }
  return dir;
}

export function serverVersion(pgBin) {
  return run(path.join(pgBin, 'postgres'), ['--version']).trim();
}

/**
 * Creates and starts a cluster under a new directory inside `workDir`.
 * Returns a handle for stopCluster.
 */
export function startCluster({ pgBin, workDir = os.tmpdir(), logPath }) {
  fs.mkdirSync(workDir, { recursive: true });
  const root = fs.mkdtempSync(path.join(workDir, 'dwsql-'));
  fs.chmodSync(root, 0o700);
  // The socket lives directly in the private root; Unix socket paths are
  // limited to 107 bytes, so a deep work directory is refused up front.
  const handle = { root, dataDir: path.join(root, 'data'), socketDir: root, port: PORT, pgBin, started: false };
  const socketFile = path.join(root, `.s.PGSQL.${PORT}`);
  if (Buffer.byteLength(socketFile) > 107) {
    fs.rmSync(root, { recursive: true, force: true });
    throw new Error(`socket path ${socketFile} is too long for a Unix socket; choose a shorter --work-dir`);
  }
  fs.writeFileSync(path.join(root, MARKER), JSON.stringify({ createdBy: 'tests/sql/harness/cluster.js', createdAt: new Date().toISOString() }));
  handle.logPath = logPath ?? path.join(root, 'postgres.log');
  run(path.join(pgBin, 'initdb'), ['-D', handle.dataDir, '-U', 'supabase_admin', '--auth=trust', '-E', 'UTF8', '--no-locale', '--no-sync'], {
    env: { TZ: 'UTC' },
  });
  // Unix socket only, in a private directory. Durability settings are off
  // because the cluster is discarded after the run.
  const settings = [
    `-c listen_addresses=''`,
    `-c unix_socket_directories='${handle.socketDir}'`,
    `-c unix_socket_permissions=0700`,
    `-c port=${PORT}`,
    '-c fsync=off',
    '-c synchronous_commit=off',
    '-c full_page_writes=off',
    '-c max_connections=300',
    '-c TimeZone=UTC',
    '-c log_min_messages=warning',
    '-c log_min_error_statement=panic',
  ].join(' ');
  run(path.join(pgBin, 'pg_ctl'), ['-D', handle.dataDir, '-l', handle.logPath, '-o', settings, '-w', '-t', '60', 'start']);
  handle.started = true;
  handle.pid = Number(fs.readFileSync(path.join(handle.dataDir, 'postmaster.pid'), 'utf8').split('\n')[0]);
  return handle;
}

/** Stops the postmaster this handle started and removes the directory it created. */
export function stopCluster(handle, { keep = false } = {}) {
  if (!handle) return;
  if (handle.started && fs.existsSync(path.join(handle.dataDir, 'postmaster.pid'))) {
    const pid = Number(fs.readFileSync(path.join(handle.dataDir, 'postmaster.pid'), 'utf8').split('\n')[0]);
    if (pid !== handle.pid) throw new Error('postmaster.pid no longer names the postmaster this harness started; not stopping it');
    run(path.join(handle.pgBin, 'pg_ctl'), ['-D', handle.dataDir, '-m', 'fast', '-w', '-t', '60', 'stop']);
  }
  handle.started = false;
  if (keep) return;
  // Only a directory carrying this module's marker is ever removed.
  if (fs.existsSync(path.join(handle.root, MARKER))) fs.rmSync(handle.root, { recursive: true, force: true });
}
