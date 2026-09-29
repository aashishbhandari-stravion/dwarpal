#!/usr/bin/env node
// Hosted verification harness. See tests/hosted/README.md.
//
//   node tests/hosted/run.js inventory [--json]
//   node tests/hosted/run.js plan [--target <descriptor>] [--env-path <file>] [--interactive]
//   DWARPAL_HOSTED_CONFIRM_REF=<ref> node tests/hosted/run.js run --target <descriptor> --evidence-dir <new dir>
//        [--env-path <file>] [--only <ids or prefixes>] [--interactive]
//   DWARPAL_HOSTED_CONFIRM_REF=<ref> node tests/hosted/run.js cleanup --from <earlier evidence dir> --target <descriptor>
//        --evidence-dir <new dir> [--env-path <file>]
//   node tests/hosted/run.js verify-evidence --evidence-dir <dir>
//
// Exit status: 0 every required case passed; 1 a case failed or evidence
// leaked; 3 incomplete (blocked or not_run cases remain); 4 the target or its
// authorization was refused before any network call; 2 usage; 70 internal.

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { CASES, ACTORS, ACTION_CLASSES, CAPABILITIES, inventoryProblems } from './lib/inventory.js';
import { readDescriptor, readCredentials, authorize, capabilities, TargetError } from './lib/target.js';
import { Redactor } from './lib/redact.js';
import { Evidence, EvidenceError, sha256File } from './lib/evidence.js';
import { Ledger } from './lib/ledger.js';
import { createGate } from './lib/net.js';
import { createHosted } from './lib/hosted.js';
import { Actors, newRunId } from './lib/actors.js';
import { clientIds } from './lib/fixtures.js';
import { runProcedures } from './lib/runner.js';
import { summarise } from './lib/status.js';
import { createPrompter } from './lib/interactive.js';
import { PUBLIC_ROOT } from './lib/paths.js';
import { PROCEDURES } from './lib/procedures.js';

export const EXIT = Object.freeze({ passed: 0, failed: 1, usage: 2, incomplete: 3, refused: 4, internal: 70 });
const SPEC = { target: 'value', 'env-path': 'value', 'evidence-dir': 'value', only: 'value', from: 'value', interactive: 'flag', json: 'flag' };

class UsageError extends Error {}

function parse(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const name = argv[i].replace(/^--/, '');
    if (!argv[i].startsWith('--') || !Object.hasOwn(SPEC, name)) throw new UsageError(`unknown argument ${argv[i].slice(0, 40)}`);
    if (Object.hasOwn(out, name)) throw new UsageError(`--${name} given twice`);
    if (SPEC[name] === 'flag') out[name] = true;
    else {
      if (i + 1 >= argv.length) throw new UsageError(`--${name} needs a value`);
      out[name] = argv[i += 1];
    }
  }
  return out;
}

/** Commit, tree and cleanliness of the public source the harness runs from. */
export function sourceIdentity(root = PUBLIC_ROOT) {
  const git = (...args) => spawnSync('git', ['-C', root, ...args], { encoding: 'utf8' });
  const head = git('rev-parse', 'HEAD').stdout.trim();
  const tree = git('rev-parse', 'HEAD^{tree}').stdout.trim();
  const status = git('status', '--porcelain', '--untracked-files=all');
  return { commit: head || null, tree: tree || null, clean: status.status === 0 && status.stdout.trim() === '' };
}

/** Case ids selected by --only (ids or prefixes); target checks and cleanup are always included. */
export function selectionFor(only, cases = CASES) {
  if (!only) return null;
  const wanted = only.split(',').map((s) => s.trim()).filter(Boolean);
  const set = new Set(cases.filter((c) => c.id.startsWith('T.') || c.id.startsWith('C.')).map((c) => c.id));
  for (const w of wanted) {
    const hits = cases.filter((c) => c.id === w || c.id.startsWith(`${w}.`) || c.procedure === w);
    if (hits.length === 0) throw new UsageError(`--only: nothing matches ${w.slice(0, 40)}`);
    for (const c of hits) set.add(c.id);
  }
  return set;
}

/** Offline gating: what each case would be, given the inputs, without any network call. */
export function plan({ descriptor, creds, interactive, actions }) {
  const caps = capabilities(descriptor, creds, { interactive });
  return CASES.map((c) => {
    const missing = c.needs.filter((n) => caps[n] !== true);
    const unauthorized = c.authorize.filter((a) => !actions.has(a));
    return { id: c.id, required: c.required, gate: missing.length === 0 && unauthorized.length === 0 ? 'ready' : 'blocked', missing, unauthorized };
  });
}

function writeRefusal(dir, problems, redactor, io) {
  if (!dir) return;
  try {
    const evidence = new Evidence(dir, redactor);
    evidence.writeJson('run.json', { schema: 'dwarpal-hosted-run/1', refused: problems, source: sourceIdentity(), node: process.version, network: 'no call made' });
    const records = new Map(CASES.map((c) => [c.id, { id: c.id, status: 'blocked', reason: 'target_refused', hosted: false }]));
    evidence.writeJson('summary.json', summarise(CASES, records));
    evidence.finalize();
  } catch (error) {
    io.stderr.write(`[hosted] refusal evidence not written: ${error instanceof EvidenceError ? error.reason : 'error'}\n`);
  }
}

async function execute(command, options, io) {
  const redactor = new Redactor();
  const interactive = options.interactive === true;
  let descriptor;
  try {
    descriptor = readDescriptor(options.target);
  } catch (error) {
    if (!(error instanceof TargetError)) throw error;
    io.stdout.write(`${JSON.stringify({ result: 'refused', problems: error.problems }, null, 2)}\n`);
    writeRefusal(options['evidence-dir'], error.problems, redactor, io);
    return EXIT.refused;
  }
  let creds;
  let authorization;
  const source = sourceIdentity();
  try {
    creds = readCredentials(io.env, options['env-path']);
    authorization = authorize({ descriptor, creds, confirmRef: io.env.DWARPAL_HOSTED_CONFIRM_REF, now: io.now() });
    if (!source.clean) throw new TargetError(['source_tree_not_clean']);
  } catch (error) {
    if (!(error instanceof TargetError)) throw error;
    io.stdout.write(`${JSON.stringify({ result: 'refused', problems: error.problems }, null, 2)}\n`);
    writeRefusal(options['evidence-dir'], error.problems, redactor, io);
    return EXIT.refused;
  }

  let previous = null;
  if (command === 'cleanup') {
    const from = path.resolve(options.from);
    previous = JSON.parse(fs.readFileSync(path.join(from, 'run.json'), 'utf8'));
    if (previous.target?.ref !== authorization.ref) throw new UsageError('--from belongs to another target');
  }
  const evidence = new Evidence(options['evidence-dir'], redactor);
  const runId = previous?.runId ?? newRunId();
  const ledgerFile = path.join(evidence.dir, 'state', 'ledger.jsonl');
  const ledger = new Ledger(ledgerFile);
  // A cleanup continues from a copy: the earlier run's evidence stays exactly as its manifest records it.
  if (previous) fs.copyFileSync(path.join(path.resolve(options.from), 'state', 'ledger.jsonl'), ledgerFile, fs.constants.COPYFILE_EXCL);
  const gate = createGate({ fetch: io.fetch, onCall: (call) => evidence.append('calls.jsonl', call) });
  gate.open(authorization.origins);
  const clock = { now: io.now, sleep: io.sleep };
  const hosted = createHosted({ gate, target: authorization, creds, redactor, limits: descriptor.limits, sleep: io.sleep, clockNow: io.now });
  const actors = new Actors({ hosted, ledger, redactor, template: descriptor.identities?.emailTemplate ?? null, runId, actions: authorization.actions, sleep: io.sleep });
  const caps = capabilities(descriptor, creds, { interactive });
  const selection = command === 'cleanup' ? new Set(CASES.filter((c) => c.procedure === 'cleanup').map((c) => c.id)) : selectionFor(options.only);
  evidence.writeJson('run.json', {
    schema: 'dwarpal-hosted-run/1', command, runId, startedAt: new Date(io.now()).toISOString(), node: process.version, source,
    target: { ref: authorization.ref, url: authorization.url, authorizationRecord: authorization.record, actions: [...authorization.actions].sort() },
    capabilities: caps, selection: selection ? [...selection].sort() : 'all', ledger: path.relative(evidence.dir, ledgerFile),
    ...(previous ? { continuesRun: previous.runId, previousLedgerSha256: sha256File(path.join(path.resolve(options.from), 'state', 'ledger.jsonl')) } : {}),
    migrations: fs.readdirSync(path.join(PUBLIC_ROOT, 'supabase', 'migrations')).sort().map((f) => ({ file: f, sha256: sha256File(path.join(PUBLIC_ROOT, 'supabase', 'migrations', f)) })),
  });
  const ctx = {
    hosted, actors, ledger, redactor, gate, creds, descriptor, runId, caps, actions: authorization.actions, clock,
    ids: clientIds(runId), state: {}, prompt: createPrompter({ enabled: interactive }), callbackPort: descriptor.callbackPort ?? 54329,
    identity: { urlMatches: creds.SUPABASE_URL === authorization.url, refConfirmed: true, authorizationCurrent: true, sourceClean: source.clean },
  };
  const { summary } = await runProcedures({ procedures: PROCEDURES, ctx, selection, capabilities: caps, actions: authorization.actions, hosted: true, evidence });
  gate.close();
  evidence.writeJson('summary.json', { ...summary, residue: ctx.state.residue ?? null, finishedAt: new Date(io.now()).toISOString(), calls: gate.counts.total });
  const { leaks } = evidence.finalize([ledgerFile]);
  io.stdout.write(`${JSON.stringify({ verdict: leaks.length > 0 ? 'failed' : summary.verdict, counts: summary.counts, leaks: leaks.length, evidence: evidence.dir }, null, 2)}\n`);
  if (leaks.length > 0 || summary.verdict === 'failed') return EXIT.failed;
  return summary.verdict === 'passed' ? EXIT.passed : EXIT.incomplete;
}

function verifyEvidence(dir, io) {
  const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  const redactor = new Redactor();
  const problems = [];
  for (const f of manifest.files) {
    const file = path.join(dir, f.file);
    if (!fs.existsSync(file)) problems.push({ file: f.file, problem: 'missing' });
    else if (sha256File(file) !== f.sha256) problems.push({ file: f.file, problem: 'hash_mismatch' });
    else if (redactor.scan(fs.readFileSync(file, 'utf8')).length > 0) problems.push({ file: f.file, problem: 'leak_pattern' });
  }
  io.stdout.write(`${JSON.stringify({ files: manifest.files.length, leakScan: manifest.leakScan, problems }, null, 2)}\n`);
  return problems.length === 0 && manifest.leakScan === 'clean' ? EXIT.passed : EXIT.failed;
}

export async function main(argv, io) {
  const command = argv[0];
  try {
    const options = parse(argv.slice(1));
    if (command === 'inventory') {
      const problems = inventoryProblems();
      const data = { cases: CASES, actors: ACTORS, actionClasses: ACTION_CLASSES, capabilities: CAPABILITIES, problems };
      if (options.json) io.stdout.write(`${JSON.stringify(data, null, 2)}\n`);
      else for (const c of CASES) io.stdout.write(`${c.id.padEnd(42)} ${c.lld.padEnd(6)} ${c.paths.join('+').padEnd(22)} ${c.title}\n`);
      return problems.length === 0 ? EXIT.passed : EXIT.internal;
    }
    if (command === 'plan') {
      let descriptor = null;
      let problems = [];
      try {
        descriptor = options.target ? readDescriptor(options.target) : null;
      } catch (error) {
        if (!(error instanceof TargetError)) throw error;
        problems = error.problems;
      }
      const creds = readCredentials(io.env, options['env-path']);
      const actions = new Set(descriptor?.authorization?.actions ?? []);
      const rows = plan({ descriptor, creds, interactive: options.interactive === true, actions });
      const ready = rows.filter((r) => r.gate === 'ready').length;
      io.stdout.write(`${JSON.stringify({ descriptor: descriptor ? 'valid' : options.target ? 'refused' : 'none', problems, cases: rows.length, ready, blocked: rows.length - ready, network: 'no call made', rows }, null, 2)}\n`);
      return EXIT.incomplete;
    }
    if (command === 'run' || command === 'cleanup') {
      if (!options.target || !options['evidence-dir'] || (command === 'cleanup' && !options.from)) throw new UsageError('--target and --evidence-dir are required (and --from for cleanup)');
      return await execute(command, options, io);
    }
    if (command === 'verify-evidence') {
      if (!options['evidence-dir']) throw new UsageError('--evidence-dir is required');
      return verifyEvidence(options['evidence-dir'], io);
    }
    throw new UsageError('commands: inventory, plan, run, cleanup, verify-evidence');
  } catch (error) {
    if (error instanceof UsageError) {
      io.stderr.write(`[hosted] ${error.message}\n`);
      return EXIT.usage;
    }
    if (error instanceof TargetError) {
      io.stdout.write(`${JSON.stringify({ result: 'refused', problems: error.problems }, null, 2)}\n`);
      return EXIT.refused;
    }
    if (error instanceof EvidenceError) {
      io.stderr.write(`[hosted] evidence refused: ${error.reason}\n`);
      return EXIT.refused;
    }
    io.stderr.write(`[hosted] internal error: ${error?.name ?? 'Error'}\n`);
    return EXIT.internal;
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const code = await main(process.argv.slice(2), {
    env: process.env, stdout: process.stdout, stderr: process.stderr, fetch: globalThis.fetch,
    now: Date.now, sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
  });
  process.exitCode = code;
}
