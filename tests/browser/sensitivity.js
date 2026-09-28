#!/usr/bin/env node
// Guard sensitivity for the browser kit. For each critical guard, a
// disposable copy of the kit and its tests is made with that one guard
// removed, and the named test must then fail; an unmutated copy runs first
// and must pass. The repository itself is never modified.
//
//   node tests/browser/sensitivity.js [--report <file>]
//
// Exit 0 only when the baseline passed and every mutation was detected.

import { spawnSync } from 'node:child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');

const MUTATIONS = [
  {
    id: 'pkce-binding',
    guard: 'verifiers are per tab and exchanged by explicit flow id',
    edits: [
      ['packages/browser/lib/storage.js', "return key.endsWith(VERIFIER_SUFFIX) ? tab : local;", 'return local;'],
      ['packages/browser/controller.js', 'exchangeCodeForSession(callback.code, { flowId: record.id })', 'exchangeCodeForSession(callback.code)'],
    ],
    test: ['tests/browser/oauth.test.js', 'overlapping starts in two tabs'],
  },
  {
    id: 'oauth-flow-record',
    guard: 'a callback needs this tab\'s fresh oauth flow record',
    // A naive callback that exchanges whenever a code is present.
    edits: [
      ['packages/browser/controller.js', "callback.code === null || record?.kind !== 'oauth'", 'callback.code === null'],
      ['packages/browser/controller.js', 'exchangeCodeForSession(callback.code, { flowId: record.id })', 'exchangeCodeForSession(callback.code, { flowId: record?.id })'],
    ],
    test: ['tests/browser/oauth.test.js', 'stale flow'],
  },
  {
    id: 'next-stored-revalidation',
    guard: 'a stored return path is re-validated on use',
    edits: [['packages/browser/controller.js', 'if (record && flows.includes(record.kind)) return resolveReturnPath(record.next, this.#config);', 'if (record && flows.includes(record.kind)) return record.next;']],
    test: ['tests/browser/oauth.test.js', 'tampered stored return path'],
  },
  {
    id: 'next-query-validation',
    guard: '`next` from the address goes through core resolveReturnPath',
    edits: [['packages/browser/lib/location.js', 'resolveReturnPath(nextValues[0], config)', 'nextValues[0]']],
    test: ['tests/browser/oauth.test.js', 'abuse'],
  },
  {
    id: 'click-only-link',
    guard: 'a link is verified only on the user\'s click',
    edits: [['packages/browser/controller.js', "return this.#show(epoch, { screen: this.#route, state: 'idle', link: true });", 'return this.#confirmLinkIn(epoch);']],
    test: ['tests/browser/signup-verify.test.js', 'verifies nothing'],
  },
  {
    id: 'single-action',
    guard: 'one action at a time: a double click sends one request',
    edits: [['packages/browser/controller.js', 'if (this.#busyEpoch !== null || this.#signingOut) return Promise.resolve(this.#view);', 'if (this.#signingOut) return Promise.resolve(this.#view);']],
    test: ['tests/browser/signup-verify.test.js', 'second click on the same page'],
  },
  {
    id: 'consumed-link',
    guard: 'a consumed link is already_used without a request',
    edits: [['packages/browser/controller.js', "if (link.consumed) return this.#show(epoch, { screen, state: 'already_used' });", '']],
    test: ['tests/browser/signup-verify.test.js', 'second click on the same page'],
  },
  {
    id: 'join-once',
    guard: 'join_client only while enrolled_at is null',
    edits: [['packages/browser/lib/onboarding.js', 'if (access.principal.access.enrolledAt === null) {', 'if (true) {']],
    test: ['tests/browser/onboarding.test.js', 'loses its answer'],
  },
  {
    id: 'closed-no-retry',
    guard: 'closed is no_access with no retry',
    edits: [['packages/browser/lib/onboarding.js', "if (result === 'closed') return { kind: 'no_access', principal: access.principal };", "if (result === 'closed') return { kind: 'setup_pending', reason: 'unavailable' };"]],
    test: ['tests/browser/onboarding.test.js', 'closed client'],
  },
  {
    id: 'recovery-lock',
    guard: 'a recovery session is confined to the reset screen',
    edits: [['packages/browser/lib/onboarding.js', "if (ctx.storage.readRecovery() !== null) return { kind: 'recovery_pending' };", '']],
    test: ['tests/browser/recovery.test.js', 'L13: a failed password update'],
  },
  {
    id: 'recovery-marker-first',
    guard: 'the recovery marker is written before verification',
    edits: [['packages/browser/controller.js', "if (link.type === 'recovery') this.#storage.writeRecovery('verifying', null);", '']],
    test: ['tests/browser/recovery.test.js', 'page that dies'],
  },
  {
    id: 'signout-local-clear',
    guard: 'sign-out clears local state even when Auth fails',
    edits: [['packages/browser/controller.js', "const local = this.#clearLocal() ? 'cleared' : 'failed';", "const local = remote !== 'unconfirmed' && this.#clearLocal() ? 'cleared' : 'failed';"]],
    test: ['tests/browser/signout.test.js', 'unreachable, errors or hangs'],
  },
  {
    id: 'signout-late-session',
    guard: 'a sign-in answer that arrives after sign-out is wiped',
    edits: [['packages/browser/controller.js', 'if (this.#hasStoredSession() && !this.#clearLocal() && epoch === this.#epoch) {', 'if (false) {']],
    test: ['tests/browser/signout.test.js', 'running sign-in wins'],
  },
  {
    id: 'mfa-aal2',
    guard: 'MFA continues only once the session carries aal2',
    edits: [['packages/browser/controller.js', "if ((await current()) === 'aal2') return true;", 'return true;']],
    test: ['tests/browser/mfa.test.js', 'failed aal2 refresh'],
  },
  {
    id: 'access-client-scope',
    guard: 'an access answer for another client fails closed',
    edits: [['packages/browser/lib/onboarding.js', 'return { principal: principalFromAccess(answer.value, { clientId: ctx.config.clientId, identity, session: sessionInfo }) };', 'return { principal: principalFromAccess({ ...answer.value, client_id: ctx.config.clientId }, { clientId: ctx.config.clientId, identity, session: sessionInfo }) };']],
    test: ['tests/browser/onboarding.test.js', 'another client'],
  },
];

function makeCopy() {
  const dir = mkdtempSync(join(tmpdir(), 'dwarpal-browser-sensitivity-'));
  for (const part of ['packages', 'scripts', 'tests/browser']) cpSync(join(ROOT, part), join(dir, part), { recursive: true });
  cpSync(join(ROOT, 'package.json'), join(dir, 'package.json'));
  symlinkSync(join(ROOT, 'node_modules'), join(dir, 'node_modules'), 'dir');
  return dir;
}

function runTest(dir, [file, pattern]) {
  const result = spawnSync(process.execPath, ['--test', '--test-name-pattern', pattern, file], { cwd: dir, encoding: 'utf8', timeout: 120000 });
  const tests = /ℹ tests (\d+)/.exec(result.stdout)?.[1] ?? '0';
  return { status: result.status, tests: Number(tests) };
}

const reportIndex = process.argv.indexOf('--report');
const reportPath = reportIndex > 0 ? resolve(process.argv[reportIndex + 1]) : null;
const lines = [];
let ok = true;

const baseDir = makeCopy();
try {
  for (const mutation of MUTATIONS) {
    const base = runTest(baseDir, mutation.test);
    const pass = base.status === 0 && base.tests > 0;
    ok &&= pass;
    lines.push(`baseline ${mutation.id}: ${pass ? 'pass' : 'FAIL'} (exit ${base.status}, tests ${base.tests})`);
  }
} finally {
  rmSync(baseDir, { recursive: true, force: true });
}

for (const mutation of MUTATIONS) {
  const dir = makeCopy();
  try {
    for (const [file, from, to] of mutation.edits) {
      const path = join(dir, file);
      const text = readFileSync(path, 'utf8');
      const count = text.split(from).length - 1;
      if (count !== 1) throw new Error(`${mutation.id}: expected one occurrence in ${file}, found ${count}`);
      writeFileSync(path, text.replace(from, to));
    }
    const run = runTest(dir, mutation.test);
    const detected = run.status !== 0 && run.tests > 0;
    ok &&= detected;
    lines.push(`mutation ${mutation.id}: ${detected ? 'detected' : 'NOT DETECTED'} (exit ${run.status}, tests ${run.tests}) — ${mutation.guard}`);
  } catch (error) {
    ok = false;
    lines.push(`mutation ${mutation.id}: ERROR ${error.message}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

lines.push(`[browser-sensitivity] ${ok ? 'ok' : 'FAILED'}: ${MUTATIONS.length} mutations`);
const output = `${lines.join('\n')}\n`;
process.stdout.write(output);
if (reportPath) writeFileSync(reportPath, output);
process.exitCode = ok ? 0 : 1;
