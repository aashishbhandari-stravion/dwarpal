// Harness self-tests: no network, no hosted project. They prove the harness
// fails closed (gating, statuses, authorization, evidence location, leak
// scan, ledger, network gate) and that its pure parts compute what the cases
// rely on. None of this is hosted evidence.
//
//   node --test tests/hosted/selftest/*.test.js

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { CASES, ACTORS, inventoryProblems } from '../lib/inventory.js';
import { PROCEDURES } from '../lib/procedures.js';
import { normaliseRecord, summarise, Blocked } from '../lib/status.js';
import { descriptorProblems, authorize, readCredentials, TargetError, MANAGEMENT_ORIGIN } from '../lib/target.js';
import { Redactor } from '../lib/redact.js';
import { Evidence, EvidenceError, sha256File } from '../lib/evidence.js';
import { Ledger } from '../lib/ledger.js';
import { createGate, NetworkClosedError } from '../lib/net.js';
import { totp, hotp, base32Decode } from '../lib/totp.js';
import { runProcedures } from '../lib/runner.js';
import { parseProbe, nullCall, probeStatement } from '../lib/sqlprobe.js';
import { executionFindings } from '../cases/routing.js';
import { parseConfirmationLink, smtpAddress } from '../cases/providers.js';
import { main, selectionFor, EXIT } from '../run.js';
import { PUBLIC_ROOT } from '../lib/paths.js';

const here = path.dirname(new URL(import.meta.url).pathname);
const REF = 'abcdefghijklmnopqrst';
const URL_ = `https://${REF}.supabase.co`;

function tmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'dwh-selftest-'));
}

function descriptor(overrides = {}) {
  return {
    schema: 'dwarpal-hosted-target/1',
    project: { ref: REF, url: URL_ },
    authorization: { record: 'AUTH-TEST-1', isolated: true, disposable: true, noProductionData: true, expiresAt: '2999-01-01T00:00:00Z', actions: ['connect', 'create_users', 'mutations'] },
    identities: { emailTemplate: 'owner+{tag}@example.test' },
    ...overrides,
  };
}

const CREDS = { SUPABASE_URL: URL_, SUPABASE_PUBLISHABLE_KEY: 'sb_publishable_selftestkey', SUPABASE_SECRET_KEY: 'sb_secret_selftestsecretvalue' };

function capture() {
  let out = '';
  let err = '';
  return { stdout: { write: (s) => { out += s; } }, stderr: { write: (s) => { err += s; } }, get out() { return out; }, get err() { return err; } };
}

function noNetwork() {
  const calls = [];
  const fetch = async (...args) => {
    calls.push(args);
    throw new Error('network must not be reached');
  };
  return { fetch, calls };
}

// Inventory ---------------------------------------------------------------------

test('inventory is consistent: unique ids, known capabilities and classes, a procedure for every group', () => {
  assert.deepEqual(inventoryProblems(), []);
  const groups = new Set(PROCEDURES.map((p) => p.group));
  assert.deepEqual([...new Set(CASES.map((c) => c.procedure))].filter((g) => !groups.has(g)), []);
  assert.deepEqual([...groups].filter((g) => !CASES.some((c) => c.procedure === g)), []);
  assert.equal(PROCEDURES.at(-1).group, 'cleanup');
  assert.equal(PROCEDURES[0].group, 'target');
});

test('every actor alias the procedures create is declared in the inventory', () => {
  const declared = new Set(ACTORS.map((a) => a.id));
  const used = new Set();
  const dir = path.join(here, '..', 'cases');
  for (const file of fs.readdirSync(dir)) {
    const text = fs.readFileSync(path.join(dir, file), 'utf8');
    const patterns = [/actors\.(?:user|signIn|aal2|get)\('([a-z0-9_]+)'/g, /signedInMember\(ctx, '([a-z0-9_]+)'/g, /bootstrap\(ctx, '[A-Z0-9]+', '([a-z0-9_]+)'/g];
    for (const p of patterns) for (const m of text.matchAll(p)) used.add(m[1]);
  }
  assert.ok(used.size > 20);
  assert.deepEqual([...used].filter((a) => !declared.has(a)).sort(), []);
});

test('the L25, L27-L35, routing, doctor and provider requirements each have cases', () => {
  for (const prefix of ['L25.', 'L27.', 'L28.http.', 'L28.sql.', 'L28.policy.', 'L29.', 'L30.', 'L31.', 'L32.', 'L33.', 'L34.', 'L35.', 'M.S0.', 'M.S1.', 'M.S2.', 'P.smtp.', 'P.google.', 'P.totp.', 'C.']) {
    assert.ok(CASES.some((c) => c.id.startsWith(prefix)), prefix);
  }
  assert.deepEqual(CASES.filter((c) => c.lld === 'L35').map((c) => c.id), ['L35.a', 'L35.b', 'L35.c', 'L35.d']);
  assert.deepEqual(CASES.filter((c) => !c.required).map((c) => c.id), ['L32.email_two_matches']);
});

// Statuses ----------------------------------------------------------------------

test('a pass needs hosted provenance, assertions and evidence references', () => {
  const ok = { id: 'X', status: 'passed', assertions: [{ ok: true, evidence: 'observations.jsonl#1' }] };
  assert.equal(normaliseRecord(ok, { hosted: true }).status, 'passed');
  const rehearsed = normaliseRecord(ok, { hosted: false });
  assert.deepEqual([rehearsed.status, rehearsed.reason, rehearsed.rehearsal.status], ['not_run', 'not_hosted', 'passed']);
  assert.deepEqual(normaliseRecord({ id: 'X', status: 'passed', assertions: [] }, { hosted: true }).reason, 'invalid_pass_record');
  assert.deepEqual(normaliseRecord({ id: 'X', status: 'passed', assertions: [{ ok: true, evidence: null }] }, { hosted: true }).status, 'failed');
  assert.deepEqual(normaliseRecord({ id: 'X', status: 'passed', assertions: [{ ok: false, evidence: 'e#1' }] }, { hosted: true }).status, 'failed');
  assert.equal(normaliseRecord({ id: 'X', status: 'maybe' }, { hosted: true }).reason, 'invalid_status');
  assert.equal(normaliseRecord({ id: 'X', status: 'blocked', reason: 'Bad Reason' }, { hosted: true }).reason, 'invalid_reason');
});

test('the verdict is passed only when every required case passed', () => {
  const inv = [{ id: 'a', required: true }, { id: 'b', required: true }, { id: 'c', required: false }];
  const rec = (id, status) => [id, { id, status, reason: status === 'passed' ? null : 'x', hosted: true, assertions: [] }];
  assert.equal(summarise(inv, new Map([rec('a', 'passed'), rec('b', 'passed')])).verdict, 'passed');
  assert.equal(summarise(inv, new Map([rec('a', 'passed'), rec('b', 'blocked')])).verdict, 'incomplete');
  assert.equal(summarise(inv, new Map([rec('a', 'passed')])).cases.find((c) => c.id === 'b').reason, 'no_record');
  assert.equal(summarise(inv, new Map([rec('a', 'failed'), rec('b', 'passed')])).verdict, 'failed');
  assert.equal(summarise(inv, new Map([rec('a', 'passed'), rec('b', 'passed'), rec('zz', 'passed')])).verdict, 'failed');
  assert.equal(summarise(inv, new Map([rec('a', 'passed'), rec('b', 'passed'), rec('c', 'failed')])).verdict, 'passed');
  assert.equal(summarise([], new Map()).verdict, 'incomplete');
});

// Target and authorization --------------------------------------------------------

test('the descriptor must record an isolated, disposable, current authorization', () => {
  assert.deepEqual(descriptorProblems(descriptor()), []);
  assert.ok(descriptorProblems(descriptor({ authorization: { ...descriptor().authorization, isolated: false } })).includes('authorization_isolated'));
  assert.ok(descriptorProblems(descriptor({ authorization: { ...descriptor().authorization, actions: ['connect', 'deploy'] } })).includes('authorization_actions'));
  assert.ok(descriptorProblems(descriptor({ project: { ref: REF, url: 'https://other.supabase.co' } })).includes('project_url_not_ref_url'));
  assert.ok(descriptorProblems(descriptor({ project: { ref: 'short', url: 'https://short.supabase.co' } })).includes('project_ref'));
  assert.ok(descriptorProblems({ ...descriptor(), authorization: undefined }).includes('authorization_missing'));
  assert.ok(descriptorProblems(descriptor({ identities: { emailTemplate: 'no-tag@example.test' } })).includes('email_template'));
});

test('authorize refuses before any network call unless every condition holds', () => {
  const ok = authorize({ descriptor: descriptor(), creds: CREDS, confirmRef: REF, now: Date.parse('2026-01-01') });
  assert.deepEqual(ok.origins, [URL_]);
  const withToken = authorize({ descriptor: descriptor(), creds: { ...CREDS, SUPABASE_ACCESS_TOKEN: 'sbp_selftesttokenvalue' }, confirmRef: REF });
  assert.deepEqual(withToken.origins, [URL_, MANAGEMENT_ORIGIN]);
  const refused = (input, problem) => {
    assert.throws(() => authorize({ descriptor: descriptor(), creds: CREDS, confirmRef: REF, ...input }), (e) => e instanceof TargetError && e.problems.includes(problem), problem);
  };
  refused({ confirmRef: undefined }, 'confirm_ref_mismatch');
  refused({ confirmRef: 'zzzzzzzzzzzzzzzzzzzz' }, 'confirm_ref_mismatch');
  refused({ creds: { ...CREDS, SUPABASE_URL: 'https://zzzzzzzzzzzzzzzzzzzz.supabase.co' } }, 'env_url_mismatch');
  refused({ now: Date.parse('3000-01-01') }, 'authorization_expired');
  refused({ creds: { ...CREDS, SUPABASE_SECRET_KEY: undefined } }, 'secret_key_missing_or_wrong_kind');
  refused({ creds: { ...CREDS, SUPABASE_SECRET_KEY: 'sb_publishable_selftestkey' } }, 'secret_key_missing_or_wrong_kind');
  refused({ creds: { ...CREDS, SUPABASE_PUBLISHABLE_KEY: 'sb_secret_x' } }, 'publishable_key_missing_or_wrong_kind');
  assert.throws(() => authorize({ descriptor: descriptor({ authorization: { ...descriptor().authorization, actions: ['mutations'] } }), creds: CREDS, confirmRef: REF }),
    (e) => e.problems.includes('connect_not_authorized'));
});

test('an env file must be owner-only and outside every Git working tree', () => {
  const dir = tmp();
  const file = path.join(dir, 'hosted.env');
  fs.writeFileSync(file, 'SUPABASE_SECRET_KEY=sb_secret_fromfile\nOTHER=x\n', { mode: 0o644 });
  assert.throws(() => readCredentials({}, file), (e) => e.problems.includes('env_file_group_or_world_accessible'));
  fs.chmodSync(file, 0o600);
  assert.deepEqual(readCredentials({ SUPABASE_URL: URL_ }, file), { SUPABASE_URL: URL_, SUPABASE_SECRET_KEY: 'sb_secret_fromfile' });
  assert.equal(readCredentials({ SUPABASE_SECRET_KEY: 'sb_secret_fromenv' }, file).SUPABASE_SECRET_KEY, 'sb_secret_fromenv');
  const inRepo = path.join(PUBLIC_ROOT, 'internal', 'scratch');
  if (fs.existsSync(inRepo)) {
    const repoFile = path.join(fs.mkdtempSync(path.join(inRepo, 'dwh-')), 'x.env');
    fs.writeFileSync(repoFile, 'SUPABASE_SECRET_KEY=sb_secret_x\n', { mode: 0o600 });
    try {
      assert.throws(() => readCredentials({}, repoFile), (e) => e.problems.includes('env_file_inside_git_tree'));
    } finally {
      fs.rmSync(path.dirname(repoFile), { recursive: true });
    }
  }
});

// Redaction and evidence ---------------------------------------------------------

test('sanitation removes secrets, tokens, keys, addresses and hashes; aliases stay stable', () => {
  const r = new Redactor();
  r.secret('correct-horse-battery', 'password');
  r.alias('owner+hv1-a@example.test', 'member_a');
  r.alias('11111111-2222-4333-8444-555555555555', 'member_a');
  const jwt = 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl';
  const text = r.sanitizeText(`pw correct-horse-battery ${jwt} sb_secret_abc sbp_0123456789abcdef otpauth://totp/x?secret=ABC owner+hv1-a@example.test other@example.org ${'a'.repeat(48)} 11111111-2222-4333-8444-555555555555 99999999-2222-4333-8444-555555555555 99999999-2222-4333-8444-555555555555`);
  assert.equal(text, 'pw [secret:password] [jwt] [sb_secret] [management_token] [otpauth] <member_a> [email] [hex] <member_a> uuid-1 uuid-1');
  assert.deepEqual(r.scan(`x ${jwt}`).map((h) => h.label), ['jwt']);
  assert.deepEqual(r.scan('x correct-horse-battery').map((h) => h.label), ['password']);
  assert.deepEqual(r.scan('x <member_a> [jwt] uuid-1'), []);
  assert.throws(() => r.secret('abc', 'short'));
  assert.deepEqual(r.sanitize({ 'correct-horse-battery': [jwt, 1, null] }), { '[secret:password]': ['[jwt]', 1, null] });
});

test('evidence refuses the public tree, an existing directory, and quarantines a leak', () => {
  assert.throws(() => new Evidence(path.join(PUBLIC_ROOT, 'tests', 'hosted', 'evidence-x'), new Redactor()), (e) => e instanceof EvidenceError && e.reason === 'inside_public_tree');
  const parent = tmp();
  const dir = path.join(parent, 'run');
  const r = new Redactor();
  const ev = new Evidence(dir, r);
  assert.throws(() => new Evidence(dir, r), (e) => e.reason === 'directory_exists');
  assert.equal(ev.observe('p', 'first', { token: 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln' }), 'observations.jsonl#1');
  assert.equal(ev.observe('p', 'second', { ok: true }), 'observations.jsonl#2');
  // A secret learnt only after it was written: the scan catches what sanitation could not.
  fs.appendFileSync(ev.file('late.jsonl'), '{"v":"late-secret-value"}\n');
  r.secret('late-secret-value', 'late');
  const { leaks, manifest } = ev.finalize();
  assert.deepEqual(leaks.map((l) => l.file), ['late.jsonl']);
  assert.equal(manifest.leakScan, 'leaks_quarantined');
  assert.ok(fs.existsSync(path.join(dir, 'late.jsonl.quarantine')));
  const obs = manifest.files.find((f) => f.file === 'observations.jsonl');
  assert.equal(obs.sha256, sha256File(path.join(dir, 'observations.jsonl')));
  assert.ok(!fs.readFileSync(path.join(dir, 'observations.jsonl'), 'utf8').includes('eyJ'));
  assert.equal((fs.statSync(dir).mode & 0o777), 0o700);
});

test('the ledger is write-ahead, survives a torn line and reports what is not removed', () => {
  const file = path.join(tmp(), 'state', 'ledger.jsonl');
  const l = new Ledger(file);
  l.intent('user', 'member_a');
  l.created('user', 'member_a', { id: '11111111-2222-4333-8444-555555555555' });
  l.intent('user', 'lost');
  l.intent('grant_widening', 'W1');
  l.removed('grant_widening', 'W1');
  fs.appendFileSync(file, '{"op":"crea');
  const out = l.outstanding().map((e) => [e.kind, e.key, e.op, e.id]);
  assert.deepEqual(out, [['user', 'member_a', 'created', '11111111-2222-4333-8444-555555555555'], ['user', 'lost', 'intent', null]]);
  assert.throws(() => l.intent('secret', 'x'));
  assert.throws(() => l.intent('user', 'has space'));
  assert.ok(!fs.readFileSync(file, 'utf8').includes('@'));
});

// Network gate ---------------------------------------------------------------------

test('the network gate is closed by default and admits only authorized origins', async () => {
  const inner = noNetwork();
  const seen = [];
  const gate = createGate({ fetch: async () => new Response('{}', { status: 200 }), onCall: (c) => seen.push(c) });
  await assert.rejects(gate.fetch(`${URL_}/auth/v1/user`), (e) => e instanceof NetworkClosedError && e.reason === 'closed');
  gate.open([URL_]);
  await assert.rejects(gate.fetch('https://api.supabase.com/v1/projects'), (e) => e.reason === 'origin_not_authorized');
  assert.equal((await gate.fetch(`${URL_}/auth/v1/user?x=1`)).status, 200);
  assert.equal((await gate.fetch('http://127.0.0.1:9/x')).status, 200);
  gate.close();
  await assert.rejects(gate.fetch(`${URL_}/auth/v1/user`), (e) => e.reason === 'closed');
  assert.deepEqual(seen.map((c) => [c.origin, c.path, c.status]), [[URL_, '/auth/v1/user?x=1', 200], ['loopback', '/x', 200]]);
  assert.equal(inner.calls.length, 0);
});

// Pure helpers ---------------------------------------------------------------------

test('TOTP matches the RFC 6238 SHA-1 vectors', () => {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  assert.deepEqual(base32Decode(secret).toString(), '12345678901234567890');
  assert.equal(hotp(base32Decode(secret), 1, 8), '94287082');
  assert.equal(totp(secret, 59), '287082');
  assert.equal(totp(secret, 1111111109), '081804');
  assert.equal(totp(secret, 1234567890), '005924');
  assert.equal(totp(secret, 20000000000), '353130');
});

test('probe helpers: marker parsing, sub-select arguments, role allow-list', () => {
  const hex = Buffer.from(JSON.stringify([{ outcome: 'value', value: 'x' }])).toString('hex');
  assert.deepEqual(parseProbe(`Failed to run sql query: ERROR: P0001: DWPROBE[${hex}]\nCONTEXT: ...`), [{ outcome: 'value', value: 'x' }]);
  assert.equal(parseProbe('Failed to run sql query: ERROR: 42501: permission denied'), null);
  assert.equal(parseProbe(undefined), null);
  assert.equal(nullCall('auth_kit', 'has_role', ['text', 'text']), "select coalesce((auth_kit.has_role((select null::text), (select null::text)))::text, 'null')");
  assert.throws(() => nullCall('auth_kit; drop', 'x', []));
  assert.throws(() => probeStatement([{ role: 'postgres', claims: null, sql: 'select 1' }]));
});

test('execution findings flag a widened grant, a narrowed grant and an invalid probe', () => {
  const f = (schema, name, grants) => ({ schema, name, anon: false, authenticated: false, service_role: true, ...grants });
  const denied = { outcome: 'error', sqlstate: '42501', denied: 'function' };
  const ran = { outcome: 'value', value: 'null' };
  const clean = executionFindings([], [
    { f: f('auth_kit_private', 'register_client_impl'), role: 'authenticated', outcome: denied },
    { f: f('auth_kit_private', 'join_client_impl', { authenticated: true }), role: 'authenticated', outcome: ran },
  ]);
  assert.deepEqual(clean, []);
  const widened = executionFindings([], [{ f: f('auth_kit_private', 'register_client_impl', { authenticated: true }), role: 'authenticated', outcome: ran }]);
  assert.deepEqual(widened.map((x) => [x.object, x.catalog, x.probe]), [['auth_kit_private.register_client_impl', true, 'executed']]);
  const narrowed = executionFindings([], [{ f: f('auth_kit_private', 'join_client_impl'), role: 'authenticated', outcome: denied }]);
  assert.equal(narrowed.length, 1);
  const invalid = executionFindings([], [{ f: f('auth_kit_private', 'register_client_impl'), role: 'authenticated', outcome: { outcome: 'error', sqlstate: '42883' } }]);
  assert.deepEqual(invalid.map((x) => x.probe), ['invalid']);
});

test('confirmation links and per-run SMTP addresses', () => {
  assert.deepEqual(parseConfirmationLink('https://x.supabase.co/auth/v1/verify?token=abc123&type=signup&redirect_to=https://e.test'), { token: 'abc123', type: 'signup' });
  assert.deepEqual(parseConfirmationLink(' https://e.test/confirm?token_hash=h1&type=email '), { token: 'h1', type: 'email' });
  assert.equal(parseConfirmationLink('not a link'), null);
  assert.equal(parseConfirmationLink('https://e.test/?type=signup'), null);
  assert.equal(smtpAddress('box+{tag}@mail.test', 'ab12cd34'), 'box+hvab12cd34-smtp@mail.test');
  assert.equal(smtpAddress('box@mail.test', 'ab12cd34'), 'box@mail.test');
});

// Runner ---------------------------------------------------------------------------

function fakeEvidence() {
  const lines = [];
  return { lines, append: (name, v) => { lines.push([name, v]); return `${name}#${lines.length}`; }, observe: (p, w, v) => { lines.push(['obs', w, v]); return `observations.jsonl#${lines.length}`; } };
}

const RUNNER_CASES = [
  { id: 'T.x', procedure: 'target', needs: [], authorize: [], required: true },
  { id: 'a.one', procedure: 'a', needs: [], authorize: [], required: true },
  { id: 'a.two', procedure: 'a', needs: [], authorize: [], required: true },
  { id: 'b.needs', procedure: 'b', needs: ['management_token'], authorize: [], required: true },
  { id: 'b.auth', procedure: 'b', needs: [], authorize: ['catalog_mutation'], required: true },
  { id: 'c.one', procedure: 'c', needs: [], authorize: [], required: true },
  { id: 'd.one', procedure: 'd', needs: [], authorize: [], required: true },
  { id: 'e.one', procedure: 'e', needs: [], authorize: [], required: true },
];

test('runner: gating, target dependencies, thrown errors and unreported cases all fail closed', async () => {
  const procedures = [
    { id: 'target', group: 'target', run: async (ctx) => { const c = ctx.check('T.x'); c.assert('ok', 1, 2); ctx.finish(c); } },
    { id: 'a', group: 'a', run: async (ctx) => { const c = ctx.check('a.one'); c.assert('fine', 1, 1); ctx.finish(c); } },
    { id: 'b', group: 'b', run: async () => { throw new Error('must not run: every case gated'); } },
    { id: 'c', group: 'c', requiresTargets: ['T.x'], run: async () => { throw new Error('must not run'); } },
    { id: 'd', group: 'd', run: async () => { throw new Blocked('rate_limited'); } },
    { id: 'e', group: 'e', run: async () => { throw new Error('boom'); } },
  ];
  const { records, summary } = await runProcedures({
    procedures, ctx: {}, selection: null, capabilities: { management_token: false }, actions: new Set(), hosted: true, evidence: fakeEvidence(), cases: RUNNER_CASES,
  });
  const got = Object.fromEntries([...records].map(([id, r]) => [id, `${r.status}:${r.reason}`]));
  assert.deepEqual(got, {
    'b.needs': 'blocked:missing_management_token',
    'b.auth': 'blocked:not_authorized_catalog_mutation',
    'T.x': 'failed:assertion_failed',
    'a.one': 'passed:null',
    'a.two': 'failed:not_reported',
    'c.one': 'blocked:target_t_x',
    'd.one': 'blocked:rate_limited',
    'e.one': 'failed:harness_error',
  });
  assert.equal(summary.verdict, 'failed');
});

test('runner: a rehearsal (hosted false) can never pass a case', async () => {
  const procedures = [{ id: 'a', group: 'a', run: async (ctx) => { for (const id of ['a.one', 'a.two']) { const c = ctx.check(id); c.assert('fine', 1, 1); ctx.finish(c); } } }];
  const { records, summary } = await runProcedures({
    procedures, ctx: {}, selection: new Set(['a.one', 'a.two']), capabilities: {}, actions: new Set(), hosted: false, evidence: fakeEvidence(), cases: RUNNER_CASES.filter((c) => c.procedure === 'a'),
  });
  assert.deepEqual([...records.values()].map((r) => [r.status, r.reason, r.rehearsal.status]), [['not_run', 'not_hosted', 'passed'], ['not_run', 'not_hosted', 'passed']]);
  assert.equal(summary.verdict, 'incomplete');
});

test('runner: a procedure cannot report another group\'s case or report a case twice', async () => {
  const cases = RUNNER_CASES.filter((c) => c.procedure === 'a' || c.procedure === 'c');
  const run = (fn) => runProcedures({ procedures: [{ id: 'a', group: 'a', run: fn }], ctx: {}, selection: null, capabilities: {}, actions: new Set(), hosted: true, evidence: fakeEvidence(), cases });
  const cross = await run(async (ctx) => { ctx.wants('c.one'); });
  assert.equal(cross.records.get('a.one').reason, 'harness_error');
  const twice = await run(async (ctx) => { ctx.notRun('a.one', 'x'); ctx.notRun('a.one', 'x'); });
  assert.equal(twice.records.get('a.two').reason, 'harness_error');
});

// CLI --------------------------------------------------------------------------------

function io(env = {}) {
  const c = capture();
  const net = noNetwork();
  return { c, net, io: { env, stdout: c.stdout, stderr: c.stderr, fetch: net.fetch, now: Date.now, sleep: async () => {} } };
}

test('run refuses without an authorized target and makes no network call', async () => {
  const dir = tmp();
  const target = path.join(dir, 'target.json');
  fs.writeFileSync(target, JSON.stringify(descriptor()));
  // No confirmation of the project ref.
  const a = io({ ...CREDS });
  assert.equal(await main(['run', '--target', target, '--evidence-dir', path.join(dir, 'ev1')], a.io), EXIT.refused);
  assert.ok(JSON.parse(a.c.out).problems.includes('confirm_ref_mismatch'));
  assert.equal(a.net.calls.length, 0);
  const summary = JSON.parse(fs.readFileSync(path.join(dir, 'ev1', 'summary.json'), 'utf8'));
  assert.equal(summary.verdict, 'incomplete');
  assert.equal(summary.counts.blocked, CASES.length);
  assert.equal(JSON.parse(fs.readFileSync(path.join(dir, 'ev1', 'run.json'), 'utf8')).network, 'no call made');
  // A descriptor without an authorization.
  const bad = path.join(dir, 'bad.json');
  fs.writeFileSync(bad, JSON.stringify({ ...descriptor(), authorization: undefined }));
  const b = io({ ...CREDS, DWARPAL_HOSTED_CONFIRM_REF: REF });
  assert.equal(await main(['run', '--target', bad, '--evidence-dir', path.join(dir, 'ev2')], b.io), EXIT.refused);
  assert.equal(b.net.calls.length, 0);
  // An unreadable descriptor.
  const c = io({ ...CREDS, DWARPAL_HOSTED_CONFIRM_REF: REF });
  assert.equal(await main(['run', '--target', path.join(dir, 'missing.json'), '--evidence-dir', path.join(dir, 'ev3')], c.io), EXIT.refused);
  assert.equal(c.net.calls.length, 0);
  // Evidence inside the public tree is refused too.
  const d = io({ ...CREDS });
  assert.equal(await main(['run', '--target', target, '--evidence-dir', path.join(PUBLIC_ROOT, 'tests', 'hosted', 'ev')], d.io), EXIT.refused);
  assert.ok(!fs.existsSync(path.join(PUBLIC_ROOT, 'tests', 'hosted', 'ev')));
});

test('plan and inventory make no network call; selection always keeps target and cleanup checks', async () => {
  const a = io({});
  assert.equal(await main(['plan'], a.io), EXIT.incomplete);
  const planned = JSON.parse(a.c.out);
  assert.deepEqual([planned.cases, planned.ready, planned.network], [CASES.length, 0, 'no call made']);
  const b = io({});
  assert.equal(await main(['inventory', '--json'], b.io), EXIT.passed);
  assert.equal(JSON.parse(b.c.out).cases.length, CASES.length);
  assert.equal(a.net.calls.length + b.net.calls.length, 0);
  const sel = selectionFor('L35,routing');
  assert.ok(sel.has('L35.a') && sel.has('L28.sql.public_execute') && sel.has('T.identity') && sel.has('C.users_deleted'));
  assert.ok(!sel.has('L25.signout.node'));
  const c = io({});
  assert.equal(await main(['run', '--target', 'x', '--evidence-dir', 'y', '--only', 'nothing-like-this'], c.io), EXIT.refused);
  const d = io({});
  assert.equal(await main(['bogus'], d.io), EXIT.usage);
});

test('the loopback OAuth callback resolves with the query and serves only its path', async () => {
  const { awaitCallback } = await import('../lib/interactive.js');
  const port = 20000 + Math.floor(Math.random() * 20000);
  const pending = awaitCallback(port, '/hosted/callback', { timeoutMs: 5_000 });
  await new Promise((r) => setTimeout(r, 50));
  assert.equal((await fetch(`http://127.0.0.1:${port}/other`)).status, 404);
  const res = await fetch(`http://127.0.0.1:${port}/hosted/callback?code=abc&state=x`);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('cache-control'), 'no-store');
  assert.equal((await pending).get('code'), 'abc');
});

test('without a terminal the interactive cases are blocked, never guessed', async () => {
  const { createPrompter } = await import('../lib/interactive.js');
  await assert.rejects(createPrompter({ enabled: true, input: { isTTY: false } }).ask('x'), (e) => e instanceof Blocked && e.reason === 'interactive_unavailable');
  await assert.rejects(createPrompter({ enabled: false }).ask('x'), (e) => e.reason === 'interactive_unavailable');
});
