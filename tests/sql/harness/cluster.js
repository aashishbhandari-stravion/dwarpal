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
    root, dataDir: path.join(root, 'data'), socketDir: root, port: PORT, pgBin, pid: null, startAttempted: false, logPath: logPath ?? path.join(root, 'postgres.log'),
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
  // From here a postmaster may exist, so teardown must establish its absence.
  handle.startAttempted = true;
  run(path.join(handle.pgBin, 'pg_ctl'), ['-D', handle.dataDir, '-l', handle.logPath, '-o', settings, '-w', '-t', '60', 'start']);
  const file = readPidFile(handle);
  if (file.pid === undefined) throw new Error(`pg_ctl reported a start but postmaster.pid is ${file.problem} (${file.detail})`);
  if (postmasterState(file.pid, handle.dataDir).state === 'gone') throw new Error(`pg_ctl reported a start but postmaster ${file.pid} is not running`);
  handle.pid = file.pid;
  return handle;
}

/**
 * Reads postmaster.pid: { pid } or { problem: 'missing' | 'malformed' |
 * 'unreadable', detail }. Never throws.
 */
function readPidFile(handle) {
  let text;
  try {
    text = fs.readFileSync(path.join(handle.dataDir, 'postmaster.pid'), 'utf8');
  } catch (error) {
    if (error.code === 'ENOENT') return { problem: 'missing', detail: 'no such file' };
    return { problem: 'unreadable', detail: error.message };
  }
  const line = text.split('\n')[0];
  const pid = /^[1-9][0-9]*$/.test(line) ? Number(line) : NaN;
  return Number.isSafeInteger(pid) ? { pid } : { problem: 'malformed', detail: `first line is ${JSON.stringify(line.slice(0, 40))}` };
}

const hasProcfs = () => fs.existsSync('/proc/self');

/**
 * What is known about `pid` as a postmaster of `dataDir`: { state: 'ours' }
 * when it exists and its /proc command line names that data directory,
 * { state: 'gone' } when it no longer exists or the pid now belongs to
 * another program, and { state: 'unknown', reason } when that cannot be
 * established (an inspection error, or no /proc to verify identity with).
 * Unknown is never treated as stopped.
 */
function postmasterState(pid, dataDir) {
  try {
    process.kill(pid, 0);
  } catch (error) {
    if (error.code === 'ESRCH') return { state: 'gone' };
  }
  if (!hasProcfs()) return { state: 'unknown', reason: `pid ${pid} exists and there is no /proc to verify what it is` };
  let args;
  try {
    args = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0');
  } catch (error) {
    if (error.code === 'ENOENT' || error.code === 'ESRCH') return { state: 'gone' };
    return { state: 'unknown', reason: `cannot inspect pid ${pid}: ${error.message}` };
  }
  return args.includes(dataDir) ? { state: 'ours' } : { state: 'gone' };
}

/**
 * Pids of every process whose /proc command line names `dataDir`, or an
 * error when that cannot be established. A process whose command line cannot
 * be read is skipped only when it belongs to another user (a postmaster
 * started here runs as this user).
 */
function processesNaming(dataDir) {
  if (!hasProcfs()) return { error: 'there is no /proc to search' };
  let entries;
  try {
    entries = fs.readdirSync('/proc');
  } catch (error) {
    return { error: `cannot list /proc: ${error.message}` };
  }
  const pids = [];
  for (const name of entries.filter((n) => /^[0-9]+$/.test(n))) {
    try {
      if (fs.readFileSync(`/proc/${name}/cmdline`, 'utf8').split('\0').includes(dataDir)) pids.push(Number(name));
    } catch (error) {
      if (error.code === 'ENOENT' || error.code === 'ESRCH') continue;
      let uid = null;
      try {
        uid = fs.statSync(`/proc/${name}`).uid;
      } catch (statError) {
        if (statError.code === 'ENOENT') continue;
      }
      if (uid !== null && uid !== process.getuid()) continue;
      return { error: `cannot inspect pid ${name}: ${error.message}` };
    }
  }
  return { pids };
}

/**
 * Stops the postmaster this handle started, if any, and removes the directory
 * unless `keep`. Returns { root, pid, stoppedBy, running, removed, failures }:
 * pid is the postmaster the teardown acted on (the one recorded at start, or
 * the pid file's after a partial start), stoppedBy is 'fast', 'immediate' or
 * null (nothing was running), running is true, false or null (unknown), and
 * any failure means the teardown did not go as intended even if a fallback
 * recovered.
 *
 * The directory is removed only when it carries this module's marker and the
 * postmaster is positively established to be gone: the acted-on pid no longer
 * exists as a postmaster of this data directory and, once a start was
 * attempted, no process names the data directory. A missing, malformed or
 * unreadable pid file never counts as "stopped"; the recorded pid is then
 * verified through /proc and signalled directly, and a pid that cannot be
 * verified is never signalled. When absence cannot be established the
 * directory is kept and the report says so.
 */
export function stopCluster(handle, { keep = false } = {}) {
  const report = { root: handle?.root ?? null, pid: null, stoppedBy: null, running: false, removed: false, failures: [] };
  if (!handle) return report;
  const file = readPidFile(handle);
  if (handle.pid !== null && file.pid !== undefined && file.pid !== handle.pid) {
    const seen = postmasterState(file.pid, handle.dataDir);
    report.pid = file.pid;
    report.running = seen.state === 'unknown' ? null : seen.state === 'ours';
    report.failures.push(`postmaster.pid names ${file.pid}, not the postmaster this harness started (${handle.pid}); not stopping it`);
    return report;
  }
  const target = handle.pid ?? file.pid ?? null;
  report.pid = target;
  if (target !== null) {
    let seen = postmasterState(target, handle.dataDir);
    if (file.problem && (file.problem !== 'missing' || seen.state !== 'gone')) {
      report.failures.push(`postmaster.pid is ${file.problem} (${file.detail}) while the postmaster this harness started is pid ${target}`);
    }
    for (const mode of ['fast', 'immediate']) {
      if (seen.state === 'gone') break;
      const viaPgCtl = file.pid === target;
      if (seen.state === 'unknown' && !(viaPgCtl && !hasProcfs())) {
        report.failures.push(`cannot verify that pid ${target} is this cluster's postmaster (${seen.reason}); not signalling it`);
        break;
      }
      let issued = true;
      try {
        if (viaPgCtl) run(path.join(handle.pgBin, 'pg_ctl'), ['-D', handle.dataDir, '-m', mode, '-w', '-t', '60', 'stop'], { timeoutMs: 90_000 });
        else process.kill(target, mode === 'fast' ? 'SIGINT' : 'SIGQUIT');
      } catch (error) {
        issued = false;
        report.failures.push(`${viaPgCtl ? 'pg_ctl' : 'signalling'} ${mode} stop failed: ${error.message}`);
      }
      for (let waited = 0; waited < (issued ? 5_000 : 500) && postmasterState(target, handle.dataDir).state !== 'gone'; waited += 50) sleep(50);
      seen = postmasterState(target, handle.dataDir);
      if (seen.state === 'gone') report.stoppedBy = mode;
    }
    if (seen.state !== 'gone') {
      report.running = seen.state === 'ours' ? true : null;
      report.failures.push(seen.state === 'ours' ? `postmaster ${target} is still running` : `cannot establish that postmaster ${target} has stopped: ${seen.reason}`);
      return report;
    }
  } else if (file.problem && file.problem !== 'missing') {
    report.failures.push(`postmaster.pid is ${file.problem} (${file.detail})`);
  }
  if (keep) return report;
  if (handle.startAttempted) {
    const others = processesNaming(handle.dataDir);
    if (others.error && !(target !== null && !hasProcfs())) {
      report.running = null;
      report.failures.push(`cannot establish that no postmaster uses ${handle.dataDir} (${others.error}); not removing it`);
      return report;
    }
    if (others.pids?.length) {
      report.running = true;
      report.failures.push(`pid ${others.pids.join(', ')} still names ${handle.dataDir}; not removing it`);
      return report;
    }
  }
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
