#!/usr/bin/env node
// SQL gate runner. Creates a throwaway PostgreSQL cluster (harness/cluster.js),
// prepares two template databases from the test fixtures and the exact
// migration files, runs the node:test suites in tests/sql/cases against it,
// then stops the cluster and removes it.
//
//   DWARPAL_PG_BIN=<dir with initdb/postgres/pg_ctl> node tests/sql/run.js [options] [case files...]
//
// Options: --pg-bin <dir>, --work-dir <dir> (parent of the throwaway cluster,
// default the OS temp dir), --keep (leave the stopped cluster for inspection),
// --concurrency <n> (test files in parallel, default 4), --timeout <seconds>
// (whole test run, default 1200), --tap <file> (also write TAP output there).
//
// Exit status: 128 + the signal number when interrupted by SIGINT or SIGTERM;
// otherwise the test run's status when it failed; otherwise 1 when the harness
// or the teardown failed; 0 only when the tests passed and the cluster was
// verifiably stopped and removed (or kept, with --keep). The last line always
// states the status and each part of it; a teardown failure names what was
// left behind.

import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import { resolvePgBin, serverVersion, createCluster, startCluster, stopCluster } from './harness/cluster.js';
import { connect } from './harness/pgwire.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..', '..');

function parseArgs(argv) {
  const out = { pgBin: process.env.DWARPAL_PG_BIN, workDir: process.env.DWARPAL_SQL_WORK_DIR, keep: false, concurrency: 4, timeout: 1200, tap: null, files: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      if (i + 1 >= argv.length) throw new Error(`${arg} needs a value`);
      i += 1;
      return argv[i];
    };
    if (arg === '--pg-bin') out.pgBin = next();
    else if (arg === '--work-dir') out.workDir = next();
    else if (arg === '--keep') out.keep = true;
    else if (arg === '--concurrency') out.concurrency = Number(next());
    else if (arg === '--timeout') out.timeout = Number(next());
    else if (arg === '--tap') out.tap = path.resolve(next());
    else if (arg.startsWith('--')) throw new Error(`unknown option ${arg}`);
    else out.files.push(path.resolve(arg));
  }
  if (!Number.isInteger(out.concurrency) || out.concurrency < 1) throw new Error('--concurrency must be a positive integer');
  if (!Number.isFinite(out.timeout) || out.timeout <= 0) throw new Error('--timeout must be positive');
  return out;
}

function fixture(name) {
  return fs.readFileSync(path.join(here, 'fixtures', name), 'utf8');
}

async function prepareTemplates(cluster) {
  const base = { socketDir: cluster.socketDir, port: cluster.port };
  const root = await connect({ ...base, user: 'supabase_admin', database: 'postgres' });
  try {
    await root.query(fixture('supabase-roles.sql'));
    await root.query('create database dwarpal_base');
  } finally {
    await root.close();
  }
  const baseDb = await connect({ ...base, user: 'supabase_admin', database: 'dwarpal_base' });
  try {
    await baseDb.query(fixture('supabase-auth.sql'));
  } finally {
    await baseDb.close();
  }
  const root2 = await connect({ ...base, user: 'supabase_admin', database: 'postgres' });
  const migrations = [];
  try {
    await root2.query('create database dwarpal_template template dwarpal_base');
    await root2.query('grant create, connect, temporary on database dwarpal_template to postgres');
    const migrator = await connect({ ...base, user: 'postgres', database: 'dwarpal_template' });
    try {
      const dir = path.join(repoRoot, 'supabase', 'migrations');
      for (const name of fs.readdirSync(dir).filter((n) => n.endsWith('.sql')).sort()) {
        const bytes = fs.readFileSync(path.join(dir, name));
        // One simple-query message: the whole file runs as one implicit transaction.
        await migrator.query(bytes.toString('utf8'), { timeoutMs: 120_000 });
        migrations.push({ file: `supabase/migrations/${name}`, sha256: createHash('sha256').update(bytes).digest('hex'), bytes: bytes.length });
      }
    } finally {
      await migrator.close();
    }
  } finally {
    await root2.close();
  }
  return migrations;
}

function runTests(files, cluster, options, state) {
  return new Promise((resolve) => {
    const reporters = ['--test-reporter=spec', '--test-reporter-destination=stdout'];
    if (options.tap) reporters.push('--test-reporter=tap', `--test-reporter-destination=${options.tap}`);
    const args = ['--test', `--test-concurrency=${options.concurrency}`, ...reporters, ...files];
    const child = spawn(process.execPath, args, {
      cwd: repoRoot,
      stdio: 'inherit',
      env: {
        ...process.env,
        DWARPAL_PG_BIN: cluster.pgBin,
        DWARPAL_SQL_SOCKET_DIR: cluster.socketDir,
        DWARPAL_SQL_PORT: String(cluster.port),
      },
    });
    state.child = child;
    const timer = setTimeout(() => {
      console.error(`[sql-gates] test run exceeded ${options.timeout} s; terminating it`);
      child.kill('SIGTERM');
      setTimeout(() => child.kill('SIGKILL'), 10_000).unref();
    }, options.timeout * 1000);
    child.on('exit', (code, signal) => {
      clearTimeout(timer);
      state.child = null;
      resolve(code ?? (signal ? 1 : 0));
    });
  });
}

/** Tears the cluster down once and prints what actually happened. */
function teardown(state, options) {
  if (state.teardown) return state.teardown;
  const report = stopCluster(state.cluster, { keep: options.keep });
  state.teardown = report;
  if (!state.cluster) return report;
  const stopped = report.stoppedBy ? `stopped (postmaster pid ${report.pid}, ${report.stoppedBy} shutdown)` : 'had no running postmaster';
  if (report.failures.length > 0) {
    for (const failure of report.failures) console.error(`[sql-gates] TEARDOWN FAILED: ${failure}`);
    const server = report.pid === null ? 'no postmaster.pid' : `postmaster pid ${report.pid} ${report.running ? 'STILL RUNNING' : 'not running'}`;
    console.error(`[sql-gates] cluster state after teardown: ${server}; directory ${report.removed ? 'removed' : `left at ${report.root}`}`);
  } else if (options.keep) {
    console.log(`[sql-gates] cluster ${stopped} and kept at ${report.root}`);
  } else {
    console.log(`[sql-gates] cluster ${stopped} and removed: ${report.root}`);
  }
  return report;
}

function exitStatus({ interrupted, testStatus, harnessError, report }) {
  if (interrupted) return 128 + os.constants.signals[interrupted];
  if (testStatus !== null && testStatus !== 0) return testStatus;
  if (harnessError || report.failures.length > 0) return 1;
  return 0;
}

async function main() {
  const state = { cluster: null, child: null, interrupted: null, teardown: null };
  let testStatus = null;
  let harnessError = null;
  let options = { keep: false };
  const finish = () => {
    const report = teardown(state, options);
    const status = exitStatus({ interrupted: state.interrupted, testStatus, harnessError, report });
    const parts = [`tests ${testStatus ?? 'not run'}`, `harness ${harnessError ? 'failed' : 'ok'}`,
      `teardown ${report.failures.length > 0 ? 'FAILED' : 'ok'}`];
    if (state.interrupted) parts.push(`interrupted by ${state.interrupted}`);
    console.log(`[sql-gates] exit status ${status}: ${parts.join(', ')}`);
    return status;
  };
  // First signal: stop the test run and let the normal path tear down.
  // Second signal: tear down now and exit.
  const onSignal = (signal) => {
    if (state.interrupted) {
      console.error(`[sql-gates] received ${signal} again; tearing down now`);
      state.child?.kill('SIGKILL');
      process.exit(finish());
    }
    state.interrupted = signal;
    console.error(`[sql-gates] received ${signal}; stopping the test run, then tearing down`);
    state.child?.kill('SIGTERM');
  };
  process.on('SIGINT', onSignal);
  process.on('SIGTERM', onSignal);
  try {
    options = parseArgs(process.argv.slice(2));
    const pgBin = resolvePgBin(options.pgBin);
    const casesDir = path.join(here, 'cases');
    const files = options.files.length
      ? options.files
      : fs.readdirSync(casesDir).filter((n) => n.endsWith('.test.js')).sort().map((n) => path.join(casesDir, n));
    console.log(`[sql-gates] server: ${serverVersion(pgBin)}`);
    console.log(`[sql-gates] node: ${process.version}`);
    state.cluster = createCluster({ pgBin, workDir: options.workDir });
    startCluster(state.cluster);
    console.log(`[sql-gates] throwaway cluster: pid ${state.cluster.pid}, unix socket only (${state.cluster.socketDir})`);
    if (!state.interrupted) {
      const migrations = await prepareTemplates(state.cluster);
      for (const m of migrations) console.log(`[sql-gates] migration ${m.file} sha256 ${m.sha256} (${m.bytes} bytes)`);
    }
    if (!state.interrupted) {
      testStatus = await runTests(files, state.cluster, options, state);
      console.log(`[sql-gates] test run exit status ${testStatus}`);
    }
  } catch (error) {
    harnessError = error;
    console.error(`[sql-gates] harness failure: ${error.message}`);
  }
  process.exitCode = finish();
}

main();
