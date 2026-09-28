// The runner's own lifetime handling. Each case runs the real tests/sql/run.js
// on a tiny test file with the PostgreSQL binaries behind a wrapper that can
// make initdb, pg_ctl start or pg_ctl stop fail, then checks the exact exit
// status, the messages and what is left on disk and in the process table.
// Anything a case leaves behind (which is what some cases must prove) is
// reclaimed afterwards: only directories carrying the harness marker, and
// only the postmaster whose command line names that directory's data dir.
// Leftover servers are identified through /proc, so these gates need Linux.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { SQL_ROOT } from '../harness/db.js';

const RUNNER = path.join(SQL_ROOT, 'run.js');
const MARKER = 'dwarpal-sql-cluster.json';

function realBin() {
  const bin = process.env.DWARPAL_PG_BIN;
  if (!bin) throw new Error('DWARPAL_PG_BIN is not set; run through tests/sql/run.js');
  return path.resolve(bin);
}

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
  fs.writeFileSync(file, INNER[inner]);
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
    return Number(fs.readFileSync(path.join(dir, 'data', 'postmaster.pid'), 'utf8').split('\n')[0]);
  } catch {
    return null;
  }
}

/**
 * True while `pid` is a postmaster of `dataDir`: its /proc command line names
 * that data directory. Independent of the harness code under test.
 */
function postmasterRunning(pid, dataDir) {
  try {
    return fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0').includes(dataDir);
  } catch {
    return false;
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

/** Stops and removes whatever a case left: marked directories and their own postmaster only. */
function reclaim(dir, work) {
  for (const cluster of fs.existsSync(work) ? clusterDirs(work) : []) {
    if (!fs.existsSync(path.join(cluster, MARKER))) throw new Error(`${cluster} has no harness marker; left untouched`);
    const pid = postmasterOf(cluster);
    const dataDir = path.join(cluster, 'data');
    if (pid && postmasterRunning(pid, dataDir)) {
      const stop = spawnSync(path.join(realBin(), 'pg_ctl'), ['-D', dataDir, '-m', 'fast', '-w', '-t', '60', 'stop'], { encoding: 'utf8', timeout: 90_000 });
      if (stop.status !== 0 || postmasterRunning(pid, dataDir)) throw new Error(`could not stop leftover postmaster ${pid}: ${stop.stderr}`);
    }
    fs.rmSync(cluster, { recursive: true, force: true });
  }
  fs.rmSync(dir, { recursive: true, force: true });
}

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
    assert.equal(postmasterRunning(pid, path.join(dir, 'data')), true, 'the server really is still running');
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
  assert.equal(postmasterRunning(pid, path.join(dir, 'data')), true);
  reclaim(s.dir, s.work);
  assert.equal(processAlive(pid), false);
});
