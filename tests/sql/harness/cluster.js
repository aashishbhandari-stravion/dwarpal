// Throwaway PostgreSQL cluster for the SQL gates. The harness never connects
// to an existing server: it creates a brand-new data directory in a fresh
// temporary directory, starts a postmaster that listens only on a Unix socket
// inside that directory (no TCP listener), and on teardown stops only that
// postmaster and removes only that directory. Destructive test setup is
// therefore bounded to resources this module created.
//
// Lifetime: createCluster makes the marked directory and returns the handle
// before anything can fail, startCluster initializes and starts it, and
// stopCluster tears down whatever exists, including a partial start. Teardown
// never throws; it returns a report, and a report with failures says what may
// be left behind.

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
    const reason = result.status === null ? `was killed by ${result.signal}` : `exited with ${result.status}`;
    throw new Error(`${path.basename(bin)} ${reason}: ${(result.stderr || result.stdout || '').trim().slice(0, 2000)}`);
  }
  return result.stdout;
}

function sleep(ms) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
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
 * Creates the private, marked directory for a new cluster inside `workDir`
 * and returns its handle. Nothing runs yet.
 */
export function createCluster({ pgBin, workDir = os.tmpdir(), logPath }) {
  // Absolute: the postmaster changes into its data directory.
  const parent = path.resolve(workDir);
  fs.mkdirSync(parent, { recursive: true });
  const root = fs.mkdtempSync(path.join(parent, 'dwsql-'));
  fs.chmodSync(root, 0o700);
  fs.writeFileSync(path.join(root, MARKER), JSON.stringify({ createdBy: 'tests/sql/harness/cluster.js', createdAt: new Date().toISOString() }));
  const handle = {
    root, dataDir: path.join(root, 'data'), socketDir: root, port: PORT, pgBin, pid: null, logPath: logPath ?? path.join(root, 'postgres.log'),
  };
  // The socket lives directly in the private root; Unix socket paths are
  // limited to 107 bytes, so a deep work directory is refused up front.
  const socketFile = path.join(root, `.s.PGSQL.${PORT}`);
  if (Buffer.byteLength(socketFile) > 107) {
    fs.rmSync(root, { recursive: true, force: true });
    throw new Error(`socket path ${socketFile} is too long for a Unix socket; choose a shorter --work-dir`);
  }
  return handle;
}

/**
 * Initializes and starts the handle's cluster. On failure whatever was
 * created still belongs to the handle, and stopCluster tears it down.
 */
export function startCluster(handle) {
  run(path.join(handle.pgBin, 'initdb'), ['-D', handle.dataDir, '-U', 'supabase_admin', '--auth=trust', '-E', 'UTF8', '--no-locale', '--no-sync'], {
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
  run(path.join(handle.pgBin, 'pg_ctl'), ['-D', handle.dataDir, '-l', handle.logPath, '-o', settings, '-w', '-t', '60', 'start']);
  handle.pid = readPid(handle);
  if (handle.pid === null) throw new Error('pg_ctl reported a start but postmaster.pid is missing');
  return handle;
}

function readPid(handle) {
  try {
    const pid = Number(fs.readFileSync(path.join(handle.dataDir, 'postmaster.pid'), 'utf8').split('\n')[0]);
    return Number.isInteger(pid) && pid > 0 ? pid : null;
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

/**
 * True while `pid` is a postmaster of `dataDir`. Where /proc exists its
 * command line must name that data directory, so a recycled pid is never
 * taken for ours; elsewhere a live pid is assumed to be ours.
 */
export function postmasterRunning(pid, dataDir) {
  try {
    process.kill(pid, 0);
  } catch (error) {
    if (error.code === 'ESRCH') return false;
  }
  try {
    return fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0').includes(dataDir);
  } catch {
    return !fs.existsSync('/proc/self');
  }
}

/**
 * Stops the postmaster running in the handle's data directory, if any, and
 * removes the directory unless `keep`. Returns { root, pid, stoppedBy,
 * running, removed, failures }: stoppedBy is 'fast', 'immediate' or null
 * (nothing was running), and any failure means the teardown did not go as
 * intended even if a fallback recovered. Only a directory carrying this
 * module's marker is removed, and never while its postmaster runs.
 */
export function stopCluster(handle, { keep = false } = {}) {
  const report = { root: handle?.root ?? null, pid: null, stoppedBy: null, running: false, removed: false, failures: [] };
  if (!handle) return report;
  try {
    report.pid = readPid(handle);
  } catch (error) {
    report.failures.push(`cannot read postmaster.pid: ${error.message}`);
  }
  if (report.pid !== null) {
    report.running = postmasterRunning(report.pid, handle.dataDir);
    if (handle.pid !== null && report.pid !== handle.pid) {
      report.failures.push(`postmaster.pid names ${report.pid}, not the postmaster this harness started (${handle.pid}); not stopping it`);
      return report;
    }
    for (const mode of ['fast', 'immediate']) {
      if (!report.running) break;
      let stopped = true;
      try {
        run(path.join(handle.pgBin, 'pg_ctl'), ['-D', handle.dataDir, '-m', mode, '-w', '-t', '60', 'stop'], { timeoutMs: 90_000 });
      } catch (error) {
        stopped = false;
        report.failures.push(`pg_ctl ${mode} stop failed: ${error.message}`);
      }
      for (let waited = 0; waited < (stopped ? 5_000 : 500) && postmasterRunning(report.pid, handle.dataDir); waited += 50) sleep(50);
      report.running = postmasterRunning(report.pid, handle.dataDir);
      if (!report.running) report.stoppedBy = mode;
    }
    if (report.running) {
      report.failures.push(`postmaster ${report.pid} is still running`);
      return report;
    }
  }
  if (keep) return report;
  if (!fs.existsSync(path.join(handle.root, MARKER))) {
    report.failures.push(`${handle.root} carries no harness marker; not removing it`);
    return report;
  }
  try {
    fs.rmSync(handle.root, { recursive: true, force: true });
  } catch (error) {
    report.failures.push(`cannot remove ${handle.root}: ${error.message}`);
  }
  report.removed = !fs.existsSync(handle.root);
  if (!report.removed && report.failures.length === 0) report.failures.push(`${handle.root} still exists after removal`);
  return report;
}
