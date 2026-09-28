// The runner's own lifetime handling. Most cases run the real tests/sql/run.js
// on a tiny test file with the PostgreSQL binaries behind a wrapper that can
// make initdb, pg_ctl start or pg_ctl stop fail, or with an inner test that
// damages postmaster.pid, then check the exact exit status, the messages and
// what is left on disk and in the process table. The remaining cases call the
// harness teardown directly on a real cluster with process inspection made to
// fail, behind a guard that refuses (and records) any removal of the cluster
// directory while its postmaster is alive.
// Anything a case leaves behind (which is what some cases must prove) is
// reclaimed afterwards: only postmasters whose command line names a data
// directory inside the case's own scratch area, and only directories carrying
// the harness marker, removed once no such postmaster is left. Servers are
// identified through /proc, so these gates need Linux.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { SQL_ROOT } from '../harness/db.js';
import { createCluster, startCluster, stopCluster } from '../harness/cluster.js';

const RUNNER = path.join(SQL_ROOT, 'run.js');
const MARKER = 'dwarpal-sql-cluster.json';
// The checks below use these even while a case replaces them on `fs`.
const readFile = fs.readFileSync.bind(fs);
const readDir = fs.readdirSync.bind(fs);
const removePath = fs.rmSync.bind(fs);

function realBin() {
  const bin = process.env.DWARPAL_PG_BIN;
  if (!bin) throw new Error('DWARPAL_PG_BIN is not set; run through tests/sql/run.js');
  return path.resolve(bin);
}

// Damages to postmaster.pid, applied to a live cluster's pid file.
const PID_FAULTS = {
  unreadable: (file) => fs.chmodSync(file, 0),
  missing: (file) => fs.renameSync(file, `${file}.aside`),
  malformed: (file) => fs.writeFileSync(file, 'not-a-pid\n'),
};

const damageInner = (fault) => `import { test } from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
test('inner case damages postmaster.pid', () => {
  const file = path.join(process.env.DWARPAL_SQL_SOCKET_DIR, 'data', 'postmaster.pid');
  (${PID_FAULTS[fault]})(file);
});
`;

const INNER = {
  pass: "import { test } from 'node:test';\ntest('inner case passes', () => {});\n",
  fail: "import { test } from 'node:test';\ntest('inner case fails', () => { throw new Error('inner failure'); });\n",
  // Records its pid, then waits long enough that only a signal ends it.
  wait: `import { test } from 'node:test';
import fs from 'node:fs';
test('inner case waits', async () => {
  fs.writeFileSync(process.env.DWARPAL_TEARDOWN_READY, String(process.pid));
  await new Promise((resolve) => setTimeout(resolve, 120_000));
});
`,
};

/**
 * A scratch area: bin/ wraps the real binaries with the requested faults,
 * work/ receives the runner's cluster directory, and the inner test file.
 */
function scratch(t, { initdb = 'ok', start = 'ok', stop = 'ok', inner = 'pass' }) {
  if (!fs.existsSync('/proc/self')) throw new Error('the teardown gates identify leftover servers through /proc (Linux only)');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dwrt-'));
  const bin = path.join(dir, 'bin');
  const work = path.join(dir, 'work');
  fs.mkdirSync(bin);
  fs.mkdirSync(work);
  const real = realBin();
  fs.symlinkSync(path.join(real, 'postgres'), path.join(bin, 'postgres'));
  if (initdb === 'fail') {
    fs.writeFileSync(path.join(bin, 'initdb'), '#!/bin/sh\necho "injected initdb failure" >&2\nexit 79\n', { mode: 0o700 });
  } else {
    fs.symlinkSync(path.join(real, 'initdb'), path.join(bin, 'initdb'));
  }
  const onStop = {
    ok: '',
    fail: 'echo "injected pg_ctl stop failure" >&2; exit 77',
    'fail-fast': 'case " $* " in *" -m fast "*) echo "injected pg_ctl fast stop failure" >&2; exit 77;; esac',
  }[stop];
  const onStart = {
    ok: '',
    'fail-before': 'echo "injected pg_ctl start failure" >&2; exit 78',
    'fail-after': `"${real}/pg_ctl" "$@"; echo "injected failure after start" >&2; exit 78`,
  }[start];
  fs.writeFileSync(path.join(bin, 'pg_ctl'), `#!/bin/sh
case " $* " in
  *" stop "*) ${onStop} ;;
  *" start "*) ${onStart} ;;
esac
exec "${real}/pg_ctl" "$@"
`, { mode: 0o700 });
  const file = path.join(dir, 'inner.test.mjs');
  fs.writeFileSync(file, INNER[inner] ?? damageInner(inner));
  const ready = path.join(dir, 'ready');
  t.after(() => reclaim(dir, work));
  return { dir, bin, work, file, ready };
}

/** Runs the runner to completion, or sends `signal` once the inner test is ready. */
function runRunner(s, { signal } = {}) {
  return new Promise((resolve, reject) => {
    // A clean environment for the nested run: node:test refuses to run
    // files from a process that looks like one of its own test children.
    const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('NODE_TEST') && !k.startsWith('DWARPAL_')));
    const child = spawn(process.execPath, [RUNNER, '--pg-bin', s.bin, '--work-dir', s.work, '--timeout', '300', s.file], {
      env: { ...env, DWARPAL_TEARDOWN_READY: s.ready },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    child.stdout.on('data', (d) => { output += d; });
    child.stderr.on('data', (d) => { output += d; });
    const killer = setTimeout(() => child.kill('SIGKILL'), 240_000);
    let poll;
    if (signal) {
      poll = setInterval(() => {
        if (fs.existsSync(s.ready) && fs.readFileSync(s.ready, 'utf8').length > 0) {
          clearInterval(poll);
          child.kill(signal);
        }
      }, 50);
    }
    child.on('error', reject);
    child.on('close', (code, sig) => {
      clearTimeout(killer);
      clearInterval(poll);
      resolve({ code, signal: sig, output });
    });
  });
}

function clusterDirs(work) {
  return fs.readdirSync(work).filter((n) => n.startsWith('dwsql-')).map((n) => path.join(work, n));
}

function postmasterOf(dir) {
  try {
    return Number(readFile(path.join(dir, 'data', 'postmaster.pid'), 'utf8').split('\n')[0]);
  } catch {
    return null;
  }
}

/**
 * 'ours' while `pid` is a postmaster of `dataDir` (its /proc command line
 * names that data directory), 'gone' once it is not; throws when that cannot
 * be established. Independent of the harness code under test.
 */
function postmasterState(pid, dataDir) {
  try {
    process.kill(pid, 0);
  } catch (error) {
    if (error.code === 'ESRCH') return 'gone';
  }
  try {
    return readFile(`/proc/${pid}/cmdline`, 'utf8').split('\0').includes(dataDir) ? 'ours' : 'gone';
  } catch (error) {
    if (error.code === 'ENOENT') return 'gone';
    throw new Error(`cannot inspect pid ${pid}: ${error.message}`);
  }
}

function processAlive(pid) {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return error.code !== 'ESRCH';
  }
}

/** Postgres processes of this user whose command line names a path inside `work`. */
function postmastersIn(work) {
  const pids = [];
  for (const name of readDir('/proc').filter((n) => /^[0-9]+$/.test(n))) {
    let args;
    try {
      args = readFile(`/proc/${name}/cmdline`, 'utf8').split('\0');
    } catch (error) {
      if (error.code === 'ENOENT' || error.code === 'ESRCH') continue;
      if (fs.statSync(`/proc/${name}`, { throwIfNoEntry: false })?.uid !== process.getuid()) continue;
      throw new Error(`cannot inspect pid ${name}: ${error.message}`);
    }
    if (path.basename(args[0]) === 'postgres' && args.some((a) => a.startsWith(`${work}${path.sep}`))) pids.push(Number(name));
  }
  return pids;
}

function waitGone(pids, ms) {
  for (let waited = 0; waited < ms && pids.some(processAlive); waited += 50) Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 50);
  return pids.filter(processAlive);
}

/**
 * Stops and removes whatever a case left: postmasters whose command line
 * names a directory in the case's work area (fast, then immediate shutdown),
 * then marked directories, only once no such postmaster is left.
 */
function reclaim(dir, work) {
  if (fs.existsSync(work)) {
    let left = postmastersIn(work);
    for (const signal of ['SIGINT', 'SIGQUIT']) {
      for (const pid of left) process.kill(pid, signal);
      left = waitGone(left, 10_000);
    }
    if (left.length > 0 || postmastersIn(work).length > 0) throw new Error(`could not stop leftover postmaster(s) in ${work}: ${left.join(', ')}`);
    for (const cluster of clusterDirs(work)) {
      if (!fs.existsSync(path.join(cluster, MARKER))) throw new Error(`${cluster} has no harness marker; left untouched`);
      removePath(cluster, { recursive: true, force: true });
    }
  }
  removePath(dir, { recursive: true, force: true });
}

/**
 * Replaces fs[name] for the duration of `fn`. The removal guard is always
 * installed too: it records, for each attempt to remove the cluster
 * directory, whether its postmaster was still alive, and refuses the removal
 * if so.
 */
function withFs(handle, replacements, fn) {
  const attempts = [];
  const originals = { rmSync: fs.rmSync };
  fs.rmSync = function guardedRm(target, options) {
    if (path.resolve(String(target)) === handle.root) {
      const state = postmasterState(handle.pid, handle.dataDir);
      attempts.push(state);
      if (state !== 'gone') throw new Error('test guard: refused to remove the directory of a running postmaster');
    }
    return removePath(target, options);
  };
  for (const [name, make] of Object.entries(replacements)) {
    originals[name] = fs[name];
    fs[name] = make(originals[name]);
  }
  try {
    return { result: fn(), attempts };
  } finally {
    Object.assign(fs, originals);
  }
}

/** A real cluster started through the harness in the case's scratch area. */
function ownedCluster(t) {
  const s = scratch(t, {});
  const handle = createCluster({ pgBin: realBin(), workDir: s.work });
  startCluster(handle);
  assert.equal(postmasterState(handle.pid, handle.dataDir), 'ours');
  return { s, handle, pidFile: path.join(handle.dataDir, 'postmaster.pid') };
}

const failWith = (code, what) => () => { throw Object.assign(new Error(`${code}: injected failure, ${what}`), { code }); };

const lineOf = (output, pattern) => output.split('\n').find((l) => pattern.test(l));
const startedPid = (output) => Number(/throwaway cluster: pid (\d+)/.exec(output)?.[1]);

test('a passing run that tears down cleanly exits 0 and leaves nothing', async (t) => {
  const s = scratch(t, {});
  const r = await runRunner(s);
  assert.equal(r.code, 0, r.output);
  const pid = startedPid(r.output);
  assert.match(r.output, new RegExp(`cluster stopped \\(postmaster pid ${pid}, fast shutdown\\) and removed: `));
  assert.equal(lineOf(r.output, /\] exit status/), '[sql-gates] exit status 0: tests 0, harness ok, teardown ok');
  assert.doesNotMatch(r.output, /TEARDOWN FAILED/);
  assert.equal(processAlive(pid), false);
  assert.deepEqual(clusterDirs(s.work), []);
});

test('a failing run keeps its test status and still tears down', async (t) => {
  const s = scratch(t, { inner: 'fail' });
  const r = await runRunner(s);
  assert.equal(r.code, 1, r.output);
  assert.match(r.output, /test run exit status 1/);
  assert.equal(lineOf(r.output, /\] exit status/), '[sql-gates] exit status 1: tests 1, harness ok, teardown ok');
  assert.equal(processAlive(startedPid(r.output)), false);
  assert.deepEqual(clusterDirs(s.work), []);
});

for (const inner of ['pass', 'fail']) {
  test(`a ${inner === 'pass' ? 'passing' : 'failing'} run whose pg_ctl stop fails exits 1 and names the running server it left`, async (t) => {
    const s = scratch(t, { stop: 'fail', inner });
    const r = await runRunner(s);
    assert.equal(r.code, 1, r.output);
    const pid = startedPid(r.output);
    assert.match(r.output, /TEARDOWN FAILED: pg_ctl fast stop failed: pg_ctl exited with 77: injected pg_ctl stop failure/);
    assert.match(r.output, /TEARDOWN FAILED: pg_ctl immediate stop failed: pg_ctl exited with 77/);
    assert.match(r.output, new RegExp(`TEARDOWN FAILED: postmaster ${pid} is still running`));
    assert.match(r.output, new RegExp(`cluster state after teardown: postmaster pid ${pid} STILL RUNNING; directory left at `));
    assert.doesNotMatch(r.output, /and removed|stopped \(/);
    assert.match(r.output, new RegExp(`test run exit status ${inner === 'pass' ? 0 : 1}`));
    assert.equal(lineOf(r.output, /\] exit status/), `[sql-gates] exit status 1: tests ${inner === 'pass' ? 0 : 1}, harness ok, teardown FAILED`);
    const [dir] = clusterDirs(s.work);
    assert.equal(clusterDirs(s.work).length, 1);
    assert.equal(postmasterOf(dir), pid);
    assert.equal(postmasterState(pid, path.join(dir, 'data')), 'ours', 'the server really is still running');
    reclaim(s.dir, s.work);
    assert.equal(processAlive(pid), false);
  });
}

test('a failed fast stop recovered by an immediate stop is still reported as a teardown failure', async (t) => {
  const s = scratch(t, { stop: 'fail-fast' });
  const r = await runRunner(s);
  assert.equal(r.code, 1, r.output);
  const pid = startedPid(r.output);
  assert.match(r.output, /TEARDOWN FAILED: pg_ctl fast stop failed: pg_ctl exited with 77/);
  assert.match(r.output, new RegExp(`cluster state after teardown: postmaster pid ${pid} not running; directory removed`));
  assert.equal(lineOf(r.output, /\] exit status/), '[sql-gates] exit status 1: tests 0, harness ok, teardown FAILED');
  assert.equal(processAlive(pid), false);
  assert.deepEqual(clusterDirs(s.work), []);
});

test('a start that fails after the postmaster came up is torn down: harness failure, server stopped, directory removed', async (t) => {
  const s = scratch(t, { start: 'fail-after' });
  const r = await runRunner(s);
  assert.equal(r.code, 1, r.output);
  assert.match(r.output, /harness failure: pg_ctl exited with 78: .*injected failure after start/s);
  const pid = Number(/cluster stopped \(postmaster pid (\d+), fast shutdown\) and removed: /.exec(r.output)?.[1]);
  assert.ok(pid > 0, r.output);
  assert.equal(lineOf(r.output, /\] exit status/), '[sql-gates] exit status 1: tests not run, harness failed, teardown ok');
  assert.equal(processAlive(pid), false);
  assert.deepEqual(clusterDirs(s.work), []);
});

for (const [label, fault, message] of [
  ['pg_ctl start', { start: 'fail-before' }, /harness failure: pg_ctl exited with 78: injected pg_ctl start failure/],
  ['initdb', { initdb: 'fail' }, /harness failure: initdb exited with 79: injected initdb failure/],
]) {
  test(`a failing ${label} leaves no directory behind`, async (t) => {
    const s = scratch(t, fault);
    const r = await runRunner(s);
    assert.equal(r.code, 1, r.output);
    assert.match(r.output, message);
    assert.match(r.output, /cluster had no running postmaster and removed: /);
    assert.equal(lineOf(r.output, /\] exit status/), '[sql-gates] exit status 1: tests not run, harness failed, teardown ok');
    assert.deepEqual(clusterDirs(s.work), []);
  });
}

test('SIGTERM during the test run stops the tests, tears down and exits 143', async (t) => {
  const s = scratch(t, { inner: 'wait' });
  const r = await runRunner(s, { signal: 'SIGTERM' });
  assert.equal(r.code, 143, r.output);
  const innerPid = Number(fs.readFileSync(s.ready, 'utf8'));
  assert.equal(processAlive(innerPid), false, 'the test process was stopped');
  const pid = startedPid(r.output);
  assert.match(r.output, /received SIGTERM; stopping the test run, then tearing down/);
  assert.match(r.output, new RegExp(`cluster stopped \\(postmaster pid ${pid}, fast shutdown\\) and removed: `));
  assert.match(lineOf(r.output, /\] exit status/), /^\[sql-gates\] exit status 143: tests \d+, harness ok, teardown ok, interrupted by SIGTERM$/);
  assert.equal(processAlive(pid), false);
  assert.deepEqual(clusterDirs(s.work), []);
});

test('SIGINT with a failing stop exits 130 and reports the server it left', async (t) => {
  const s = scratch(t, { inner: 'wait', stop: 'fail' });
  const r = await runRunner(s, { signal: 'SIGINT' });
  assert.equal(r.code, 130, r.output);
  const pid = startedPid(r.output);
  assert.match(r.output, new RegExp(`cluster state after teardown: postmaster pid ${pid} STILL RUNNING; directory left at `));
  assert.match(lineOf(r.output, /\] exit status/), /^\[sql-gates\] exit status 130: tests \d+, harness ok, teardown FAILED, interrupted by SIGINT$/);
  const [dir] = clusterDirs(s.work);
  assert.equal(postmasterState(pid, path.join(dir, 'data')), 'ours');
  reclaim(s.dir, s.work);
  assert.equal(processAlive(pid), false);
});

for (const fault of Object.keys(PID_FAULTS)) {
  test(`a run whose postmaster.pid is ${fault} stops the started postmaster before removing its directory and exits 1`, async (t) => {
    if (fault === 'unreadable' && process.getuid() === 0) throw new Error('an unreadable pid file needs a non-root user');
    const s = scratch(t, { inner: fault });
    const r = await runRunner(s);
    assert.equal(r.code, 1, r.output);
    const pid = startedPid(r.output);
    assert.match(r.output, new RegExp(`TEARDOWN FAILED: postmaster\\.pid is ${fault} \\(.+\\) while the postmaster this harness started is pid ${pid}\n`));
    assert.match(r.output, new RegExp(`cluster state after teardown: postmaster pid ${pid} not running; directory removed`));
    assert.equal(lineOf(r.output, /\] exit status/), '[sql-gates] exit status 1: tests 0, harness ok, teardown FAILED');
    assert.equal(processAlive(pid), false);
    assert.deepEqual(clusterDirs(s.work), []);
  });

  test(`teardown with ${fault === 'unreadable' ? 'an' : 'a'} ${fault} postmaster.pid removes the directory only after the started postmaster is gone`, (t) => {
    if (fault === 'unreadable' && process.getuid() === 0) throw new Error('an unreadable pid file needs a non-root user');
    const { handle, pidFile } = ownedCluster(t);
    const pid = handle.pid;
    PID_FAULTS[fault](pidFile);
    const { result: report, attempts } = withFs(handle, {}, () => stopCluster(handle));
    assert.deepEqual(attempts, ['gone'], 'one removal, attempted after the postmaster was gone');
    assert.equal(report.pid, pid);
    assert.equal(report.stoppedBy, 'fast');
    assert.equal(report.running, false);
    assert.equal(report.removed, true);
    assert.equal(report.failures.length, 1, report.failures.join('\n'));
    assert.match(report.failures[0], new RegExp(`^postmaster\\.pid is ${fault} \\(.+\\) while the postmaster this harness started is pid ${pid}$`));
    assert.equal(postmasterState(pid, handle.dataDir), 'gone');
    assert.equal(fs.existsSync(handle.root), false);
  });
}

test('a failed process inspection leaves the server and its directory alone and reports its state as unknown', (t) => {
  const { handle } = ownedCluster(t);
  const pid = handle.pid;
  const cmdline = `/proc/${pid}/cmdline`;
  const { result: report, attempts } = withFs(handle, {
    readFileSync: (original) => function readFileSync(file, ...rest) {
      if (file === cmdline) failWith('EACCES', `open '${file}'`)();
      return original.call(this, file, ...rest);
    },
  }, () => stopCluster(handle));
  assert.deepEqual(attempts, [], 'no removal was attempted');
  assert.equal(report.pid, pid);
  assert.equal(report.stoppedBy, null);
  assert.equal(report.running, null);
  assert.equal(report.removed, false);
  assert.deepEqual(report.failures, [
    `cannot verify that pid ${pid} is this cluster's postmaster (cannot inspect pid ${pid}: EACCES: injected failure, open '${cmdline}'); not signalling it`,
    `cannot establish that postmaster ${pid} has stopped: cannot inspect pid ${pid}: EACCES: injected failure, open '${cmdline}'`,
  ]);
  assert.equal(postmasterState(pid, handle.dataDir), 'ours', 'the server was not signalled');
  assert.equal(fs.existsSync(path.join(handle.root, MARKER)), true, 'the directory is kept');
  // Once inspection works again, the same handle tears down normally.
  const retry = stopCluster(handle);
  assert.deepEqual(retry.failures, []);
  assert.equal(retry.stoppedBy, 'fast');
  assert.equal(retry.removed, true);
  assert.equal(postmasterState(pid, handle.dataDir), 'gone');
});

test('a process table that cannot be searched after the stop keeps the directory and reports the state as unknown', (t) => {
  const { handle } = ownedCluster(t);
  const pid = handle.pid;
  const { result: report, attempts } = withFs(handle, {
    readdirSync: (original) => function readdirSync(dir, ...rest) {
      if (dir === '/proc') failWith('EIO', "scandir '/proc'")();
      return original.call(this, dir, ...rest);
    },
  }, () => stopCluster(handle));
  assert.deepEqual(attempts, [], 'no removal was attempted');
  assert.equal(report.pid, pid);
  assert.equal(report.stoppedBy, 'fast');
  assert.equal(report.running, null);
  assert.equal(report.removed, false);
  assert.deepEqual(report.failures, [
    `cannot establish that no postmaster uses ${handle.dataDir} (cannot list /proc: EIO: injected failure, scandir '/proc'); not removing it`,
  ]);
  assert.equal(postmasterState(pid, handle.dataDir), 'gone');
  assert.equal(fs.existsSync(path.join(handle.root, MARKER)), true, 'the directory is kept');
  const retry = stopCluster(handle);
  assert.deepEqual(retry.failures, []);
  assert.equal(retry.stoppedBy, null);
  assert.equal(retry.removed, true);
});

test('another process naming the data directory keeps the directory after the postmaster stopped', async (t) => {
  const { handle } = ownedCluster(t);
  const pid = handle.pid;
  const other = spawn(process.execPath, ['-e', 'setTimeout(() => {}, 60_000)', handle.dataDir], { stdio: 'ignore' });
  t.after(() => { other.kill('SIGKILL'); });
  for (let waited = 0; waited < 5_000 && postmasterState(other.pid, handle.dataDir) !== 'ours'; waited += 50) await new Promise((r) => setTimeout(r, 50));
  const { result: report, attempts } = withFs(handle, {}, () => stopCluster(handle));
  assert.deepEqual(attempts, []);
  assert.equal(report.stoppedBy, 'fast');
  assert.equal(report.running, true);
  assert.equal(report.removed, false);
  assert.deepEqual(report.failures, [`pid ${other.pid} still names ${handle.dataDir}; not removing it`]);
  assert.equal(postmasterState(pid, handle.dataDir), 'gone');
  other.kill('SIGKILL');
  await new Promise((resolve) => (other.exitCode !== null || other.signalCode !== null ? resolve() : other.once('exit', resolve)));
  const retry = stopCluster(handle);
  assert.deepEqual(retry.failures, []);
  assert.equal(retry.removed, true);
});
