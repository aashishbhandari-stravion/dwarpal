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
import { CASES, ACTORS, EARLIER_LANE_EVIDENCE, inventoryProblems } from '../lib/inventory.js';
import { PROCEDURES } from '../lib/procedures.js';
import { normaliseRecord, summarise, Blocked } from '../lib/status.js';
import { descriptorProblems, authorize, readCredentials, readDoctorConfig, TargetError, MANAGEMENT_ORIGIN } from '../lib/target.js';
import { Redactor } from '../lib/redact.js';
import { Evidence, EvidenceError, sha256File } from '../lib/evidence.js';
import { Ledger } from '../lib/ledger.js';
import { createGate, NetworkClosedError } from '../lib/net.js';
import { totp, hotp, base32Decode } from '../lib/totp.js';
import { runProcedures } from '../lib/runner.js';
import { GRANT_VIOLATIONS_SQL, parseProbe, nullCall, probeStatement } from '../lib/sqlprobe.js';
import { executionFindings } from '../cases/routing.js';
import { parseConfirmationLink, smtpAddress } from '../cases/providers.js';
import { insertNote } from '../cases/policy.js';
import { ordersGuard } from '../cases/orders.js';
import { createPrincipal } from '../../../packages/core/index.js';
import { procedures as cleanupProcedures } from '../cases/cleanup.js';
import { knownCount, rowSql, rowTitle, settleRows } from '../lib/rows.js';
import { main, selectionFor, plan, EXIT } from '../run.js';
import { PUBLIC_ROOT, credentialFileProblem, evidenceLocationProblem } from '../lib/paths.js';
import { spawnSync } from 'node:child_process';

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
  for (const prefix of ['L25.', 'L26.aal1.', 'L26.aal2.', 'PW.', 'L27.', 'L28.http.', 'L28.sql.', 'L28.policy.', 'L29.', 'L30.', 'L31.', 'L32.', 'L33.', 'L34.', 'L35.', 'M.S0.', 'M.S1.', 'M.S2.', 'P.smtp.', 'P.google.', 'P.totp.', 'C.']) {
    assert.ok(CASES.some((c) => c.id.startsWith(prefix)), prefix);
  }
  assert.deepEqual(CASES.filter((c) => c.lld === 'L35').map((c) => c.id), ['L35.a', 'L35.b', 'L35.c', 'L35.d']);
  // The owner's L32 disposition: no hosted duplicate-user case; ambiguous_user is unit/CLI evidence only.
  assert.deepEqual(CASES.filter((c) => !c.required).map((c) => c.id), []);
  assert.equal(CASES.some((c) => c.id === 'L32.email_two_matches'), false);
  assert.deepEqual(CASES.filter((c) => c.lld === 'L32').map((c) => c.id).sort(),
    ['L32.email_unique_match', 'L32.email_zero_matches', 'L32.lookup_incomplete', 'L32.user_id_confirmed', 'L32.user_id_unconfirmed']);
  assert.ok(EARLIER_LANE_EVIDENCE.some((e) => e.lld === 'L32' && e.cases.includes('ambiguous_user') && /not hosted proof/.test(e.rerun)));
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

/** A disposable Git working tree (tracked/ and an ignored ignored/) plus a directory outside it. */
function linkWorld() {
  const base = fs.realpathSync(tmp());
  const repo = path.join(base, 'repo');
  const outside = path.join(base, 'outside');
  for (const d of [repo, path.join(repo, 'tracked'), path.join(repo, 'ignored'), outside]) fs.mkdirSync(d);
  assert.equal(spawnSync('git', ['init', '-q', repo]).status, 0);
  fs.writeFileSync(path.join(repo, '.gitignore'), 'ignored/\n');
  return { base, repo, outside };
}

test('credential files are judged where they resolve: symlinks, symlinked directories and hard links are refused (L06-4)', () => {
  const { repo, outside } = linkWorld();
  const inTree = path.join(repo, 'tracked', 'hosted.env');
  fs.writeFileSync(inTree, 'SUPABASE_SECRET_KEY=sb_secret_intree\n', { mode: 0o600 });
  assert.equal(credentialFileProblem(inTree), 'inside_git_tree');
  // An owner-only symlink outside the tree pointing at the tracked file.
  const link = path.join(outside, 'hosted.env');
  fs.symlinkSync(inTree, link);
  assert.equal(credentialFileProblem(link), 'symlink');
  assert.throws(() => readCredentials({}, link), (e) => e instanceof TargetError && e.problems.includes('env_file_symlink'));
  // A real file reached through a symlinked directory that resolves into the tree.
  const dirLink = path.join(outside, 'dir');
  fs.symlinkSync(path.join(repo, 'tracked'), dirLink);
  assert.equal(credentialFileProblem(path.join(dirLink, 'hosted.env')), 'inside_git_tree');
  assert.throws(() => readCredentials({}, path.join(dirLink, 'hosted.env')), (e) => e.problems.includes('env_file_inside_git_tree'));
  // A hard link outside the tree to the tracked file.
  const hard = path.join(outside, 'hard.env');
  fs.linkSync(inTree, hard);
  assert.equal(credentialFileProblem(hard), 'hard_linked');
  assert.throws(() => readCredentials({}, hard), (e) => e.problems.includes('env_file_hard_linked'));
  // A genuine owner-only file outside every tree still reads.
  const good = path.join(outside, 'good.env');
  fs.writeFileSync(good, 'SUPABASE_SECRET_KEY=sb_secret_good\n', { mode: 0o600 });
  assert.equal(credentialFileProblem(good), null);
  assert.deepEqual(readCredentials({}, good), { SUPABASE_SECRET_KEY: 'sb_secret_good' });
});

test('evidence is judged and created where it resolves: a link into the public tree is refused, the ignored part allowed (L06-4)', () => {
  const { repo, outside } = linkWorld();
  const tracked = path.join(repo, 'tracked');
  assert.equal(evidenceLocationProblem(path.join(tracked, 'run'), repo), 'inside_public_tree');
  // An external symlink to a tracked directory, as the directory or as an ancestor.
  const evLink = path.join(outside, 'ev');
  fs.symlinkSync(tracked, evLink);
  assert.equal(evidenceLocationProblem(evLink, repo), 'inside_public_tree');
  assert.equal(evidenceLocationProblem(path.join(evLink, 'run'), repo), 'inside_public_tree');
  assert.throws(() => new Evidence(path.join(evLink, 'run'), new Redactor(), { root: repo }), (e) => e instanceof EvidenceError && e.reason === 'inside_public_tree');
  assert.equal(fs.existsSync(path.join(tracked, 'run')), false);
  // A dangling symlink on the way could be created anywhere later: refused.
  const dangling = path.join(outside, 'dangling');
  fs.symlinkSync(path.join(tracked, 'later'), dangling);
  assert.equal(evidenceLocationProblem(path.join(dangling, 'run'), repo), 'dangling_symlink');
  assert.throws(() => new Evidence(path.join(dangling, 'run'), new Redactor(), { root: repo }), (e) => e.reason === 'dangling_symlink');
  assert.equal(fs.existsSync(path.join(tracked, 'later')), false);
  // The public root named through a symlink is resolved too.
  const rootLink = path.join(outside, 'root');
  fs.symlinkSync(repo, rootLink);
  assert.equal(evidenceLocationProblem(path.join(tracked, 'run'), rootLink), 'inside_public_tree');
  // A link into the ignored part is allowed; the evidence lands at the resolved place.
  const ignLink = path.join(outside, 'ign');
  fs.symlinkSync(path.join(repo, 'ignored'), ignLink);
  assert.equal(evidenceLocationProblem(path.join(ignLink, 'run'), repo), null);
  const ev = new Evidence(path.join(ignLink, 'run'), new Redactor(), { root: repo });
  assert.equal(ev.dir, path.join(repo, 'ignored', 'run'));
  ev.observe('p', 'x', { ok: true });
  const status = spawnSync('git', ['-C', repo, 'status', '--porcelain', '--untracked-files=all'], { encoding: 'utf8' });
  assert.equal(status.stdout.split('\n').filter((l) => l.includes('run')).length, 0);
});

test('complete D1 catalog proof needs a valid consumer config for this project; without it those cases are blocked (L06-3)', () => {
  const dir = tmp();
  const file = path.join(dir, 'consumer.json');
  const config = {
    clientId: 'rls-demo', supabaseUrl: URL_, publishableKey: 'sb_publishable_configkey', origin: 'https://consumer.example.test',
    routes: { prefix: '/account' }, allowedReturnPaths: ['/app'], defaultReturnPath: '/app', providers: { email: true, google: false }, selfSignup: true,
  };
  const withConfig = (f) => descriptor({ doctor: { configFile: f } });
  assert.deepEqual(descriptorProblems(descriptor({ doctor: { configFile: 'relative.json' } })), ['doctor_config_file']);
  assert.deepEqual(readDoctorConfig(descriptor()), { problem: 'doctor_config_missing' });
  assert.deepEqual(readDoctorConfig(withConfig(file)), { problem: 'doctor_config_unreadable' });
  fs.writeFileSync(file, JSON.stringify({ ...config, routes: { prefix: 'no-slash' } }));
  assert.deepEqual(readDoctorConfig(withConfig(file)), { problem: 'doctor_config_invalid' });
  fs.writeFileSync(file, JSON.stringify({ ...config, supabaseUrl: 'https://zyxwvutsrqponmlkjihg.supabase.co' }));
  assert.deepEqual(readDoctorConfig(withConfig(file)), { problem: 'doctor_config_other_project' });
  fs.writeFileSync(file, JSON.stringify(config));
  assert.equal(readDoctorConfig(withConfig(file)).config.clientId, 'rls-demo');

  const creds = { ...CREDS, SUPABASE_ACCESS_TOKEN: 'sbp_0123456789abcdef0123' };
  const actions = new Set(['connect', 'create_users', 'mutations', 'catalog_mutation']);
  const gates = (d) => Object.fromEntries(plan({ descriptor: d, creds, interactive: false, actions })
    .filter((c) => c.id.startsWith('L33.')).map((c) => [c.id, c.gate === 'ready' ? 'ready' : c.missing.join('+')]));
  assert.deepEqual(gates(descriptor()), {
    'L33.secret_only_incomplete': 'ready', 'L33.catalog_ok': 'doctor_config', 'L33.probe_mode': 'ready',
    'L33.catalog_detects_widening': 'doctor_config', 'L33.probe_detects_widening': 'ready', 'L33.widening_reverted': 'doctor_config',
  });
  assert.ok(Object.values(gates(withConfig(file))).every((g) => g === 'ready'));
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

// L26 order guard -----------------------------------------------------------------

const ORDER_ROLES = {
  customer: { flags: { selfAssignable: true, managesMembers: false, mfaRequired: false }, permissions: ['orders:read:own'], grantedVia: 'join' },
  staff: { flags: { selfAssignable: false, managesMembers: false, mfaRequired: true }, permissions: ['orders:read:any'], grantedVia: 'manager' },
};

function orderPrincipal(userId, roles, aal) {
  const at = '2026-01-01T00:00:00.000Z';
  return createPrincipal({
    clientId: 'orders-demo',
    identity: { userId, verifiedEmail: 'someone@example.test', providers: ['email'] },
    session: { id: `s-${aal}`, aal, issuedAt: at, expiresAt: '2026-01-01T00:30:00.000Z', checkedAt: at },
    enrolledAt: at,
    memberships: roles.map((roleKey) => ({ clientId: 'orders-demo', roleKey, grantedAt: at, ...ORDER_ROLES[roleKey] })),
  });
}

test('the L26 Node guard is the literal S4 sequence: own order by ownership, any order only through an active role', async () => {
  const me = '00000000-0000-4000-8000-00000000000a';
  const other = '00000000-0000-4000-8000-00000000000b';
  const guard = ordersGuard(new Map([['1', { id: '1', userId: other }], ['2', { id: '2', userId: me }]]));
  const get = (principal, path) => guard(principal, new URL(path, 'http://localhost'));
  const aal1 = orderPrincipal(me, ['customer', 'staff'], 'aal1');
  assert.deepEqual(await get(aal1, '/orders/1'), { status: 403, body: { error: 'forbidden', withheld: ['staff'] } });
  assert.deepEqual(await get(aal1, '/orders/2'), { status: 200, body: { id: '2' } });
  const aal2 = orderPrincipal(me, ['customer', 'staff'], 'aal2');
  assert.deepEqual([(await get(aal2, '/orders/1')).status, (await get(aal2, '/orders/2')).status], [200, 200]);
  // A customer holding only the own key reaches their own order: no unscoped key is checked first (R3).
  const customer = orderPrincipal(me, ['customer'], 'aal1');
  assert.deepEqual(await get(customer, '/orders/2'), { status: 200, body: { id: '2' } });
  assert.deepEqual(await get(customer, '/orders/1'), { status: 403, body: { error: 'forbidden', withheld: [] } });
  // Staff alone at aal1: no role grants the own key, and the broad one is withheld (named for the MFA offer).
  assert.deepEqual(await get(orderPrincipal(me, ['staff'], 'aal1'), '/orders/2'), { status: 403, body: { error: 'forbidden', withheld: ['staff'] } });
  assert.equal((await get(aal2, '/orders/9')).status, 404);
  await assert.rejects(get(null, '/orders/2'), (e) => e.code === 'no_token');
});

// Consumer-row residue (L06-8) -----------------------------------------------------

const KIT_ZERO = Object.freeze({ clients: 0, memberships: 0, enrollments: 0, membership_events: 0, request_log: 0, profiles: 0 });

/**
 * A target whose app.notes commits inserts; the reply to the first can be
 * lost. Answers only cleanup's exact statements, as `management.read` returns
 * them (the JSON-parsed `result`); `answer(sql)` overrides one answer.
 */
function rowsTarget({ loseFirstReply = true, readFails = false, answer = () => undefined } = {}) {
  const tables = { notes: [], orders: [] };
  let next = 1;
  let lost = !loseFirstReply;
  const own = (kind, runId) => tables[kind].filter((r) => r.title.startsWith(`hv${runId} `));
  const statements = [];
  const hosted = {
    rest: {
      async insert(_token, schema, name, row) {
        assert.deepEqual([schema, name], ['app', 'notes']);
        tables.notes.push({ id: next, title: row.title });
        next += 1;
        if (!lost) {
          lost = true;
          return { kind: 'failure', status: 0 };
        }
        return { kind: 'value', status: 201, value: [{ id: next - 1 }] };
      },
    },
    management: {
      async read(sql) {
        statements.push(sql);
        if (readFails) throw new Error('management unavailable');
        const override = answer(sql);
        if (override !== undefined) return override;
        for (const kind of ['notes', 'orders']) {
          for (const runId of ['r1', 'r2']) {
            if (sql === rowSql.ids(kind, runId)) return own(kind, runId).map((r) => r.id);
            if (sql === rowSql.count(kind, runId)) return own(kind, runId).length;
          }
        }
        if (sql.includes("'clients'")) return { ...KIT_ZERO };
        return 0;
      },
      async exec(sql) {
        statements.push(sql);
        for (const kind of ['notes', 'orders']) {
          for (const runId of ['r1', 'r2']) {
            if (sql === rowSql.remove(kind, runId)) {
              for (const r of own(kind, runId)) tables[kind].splice(tables[kind].indexOf(r), 1);
              return;
            }
          }
        }
        throw new Error(`unexpected statement ${sql}`);
      },
    },
  };
  return { table: tables.notes, tables, hosted, statements };
}

function rowsCtx(dir, hosted, actions, runId = 'r1') {
  return { hosted, runId, actions: new Set(actions), ledger: new Ledger(path.join(dir, 'ledger.jsonl')), observe: () => {} };
}

const settledShape = ({ foundByMarker, recoveredByMarker, deleted, remaining, reason }) => ({ foundByMarker, recoveredByMarker, deleted, remaining, reason });

test('a note whose insert answer was lost is found by its run marker, never reported as zero (L06-8)', async () => {
  const dir = tmp();
  const target = rowsTarget();
  const ctx = rowsCtx(dir, target.hosted, ['connect']);
  await assert.rejects(insertNote(ctx, 'rls_member', 'token'), (e) => e.stage === 'insert_note');
  assert.equal(await insertNote(ctx, 'rls_staff', 'token'), 2);
  target.table.push({ id: 99, title: rowTitle('r2', 'rls_member') }); // another run's note
  assert.deepEqual(ctx.ledger.outstanding().map((e) => [e.key, e.op, e.rowId ?? null]), [['rls_member', 'intent', null], ['rls_staff', 'created', 2]]);

  // Without cleanup_sql: both notes counted as residue, nothing marked removed.
  const noSql = await settleRows(ctx, 'notes');
  assert.deepEqual(noSql, { kind: 'notes', intents: 2, knownIds: 1, foundByMarker: 2, recoveredByMarker: 1, deleted: false, remaining: 2, reason: 'cleanup_sql_not_authorized' });
  assert.deepEqual(ctx.ledger.outstanding().map((e) => [e.key, e.op]), [['rls_member', 'residue'], ['rls_staff', 'residue']]);
  assert.equal(target.statements.filter((s) => s.startsWith('delete')).length, 0);

  // An unreadable target: unknown, not zero; still outstanding.
  const blind = rowsCtx(dir, rowsTarget({ readFails: true }).hosted, ['connect', 'cleanup_sql']);
  assert.deepEqual((({ remaining, reason }) => ({ remaining, reason }))(await settleRows(blind, 'notes')), { remaining: null, reason: 'unverified' });
  assert.equal(blind.ledger.outstanding().length, 2);

  // A cleanup rerun from a copy of the ledger with cleanup_sql: both deleted by marker, the other run's note kept.
  const rerunDir = tmp();
  fs.copyFileSync(path.join(dir, 'ledger.jsonl'), path.join(rerunDir, 'ledger.jsonl'));
  const rerun = rowsCtx(rerunDir, target.hosted, ['connect', 'cleanup_sql']);
  assert.deepEqual(settledShape(await settleRows(rerun, 'notes')), { foundByMarker: 2, recoveredByMarker: 1, deleted: true, remaining: 0, reason: null });
  assert.deepEqual(target.table, [{ id: 99, title: rowTitle('r2', 'rls_member') }]);
  assert.deepEqual(rerun.ledger.outstanding(), []);

  // A second rerun, every entry already removed: the target is still asked by marker, and the count it answers is the result.
  const before = target.statements.length;
  assert.deepEqual(settledShape(await settleRows(rerun, 'notes')), { foundByMarker: 0, recoveredByMarker: 0, deleted: false, remaining: 0, reason: null });
  assert.deepEqual(target.statements.slice(before), [rowSql.ids('notes', 'r1'), rowSql.count('notes', 'r1')]);

  // A marker row that reappears after that (a late commit): found, deleted, recounted; the other run's note kept.
  target.table.push({ id: 40, title: rowTitle('r1', 'rls_member') });
  assert.deepEqual(settledShape(await settleRows(rerun, 'notes')), { foundByMarker: 1, recoveredByMarker: 1, deleted: true, remaining: 0, reason: null });
  assert.deepEqual(target.table, [{ id: 99, title: rowTitle('r2', 'rls_member') }]);
  assert.deepEqual(rerun.ledger.outstanding(), []);
});

test('a null, false, text, array or other malformed count is unknown, never zero (L06-8, first reproduction)', async () => {
  assert.deepEqual([0, 3, Number.MAX_SAFE_INTEGER].map(knownCount), [0, 3, Number.MAX_SAFE_INTEGER]);
  for (const bad of [null, false, true, '', '0', '3', [], [0], {}, -1, 1.5, Number.NaN, Infinity, 2 ** 53]) {
    const dir = tmp();
    // A write-ahead note intent, the marker lookup answers [] and the count answers `bad`.
    const target = rowsTarget({ answer: (sql) => (sql === rowSql.count('notes', 'r1') ? bad : undefined) });
    const ctx = rowsCtx(dir, target.hosted, ['connect', 'cleanup_sql']);
    ctx.ledger.intent('notes', 'rls_member', {});
    const settled = await settleRows(ctx, 'notes');
    assert.deepEqual(settledShape(settled), { foundByMarker: 0, recoveredByMarker: 0, deleted: false, remaining: null, reason: 'unverified' }, `count answer ${JSON.stringify(bad)}`);
    assert.deepEqual(ctx.ledger.outstanding().map((e) => [e.key, e.op, e.reason]), [['rls_member', 'residue', 'unverified']]);
  }
  // A malformed id list is unknown too, and nothing is deleted on it.
  for (const bad of [null, false, 'x', [1, null], [1.5], [-1], {}]) {
    const target = rowsTarget({ answer: (sql) => (sql === rowSql.ids('notes', 'r1') ? bad : undefined) });
    target.table.push({ id: 7, title: rowTitle('r1', 'rls_member') });
    const ctx = rowsCtx(tmp(), target.hosted, ['connect', 'cleanup_sql']);
    assert.deepEqual(settledShape(await settleRows(ctx, 'notes')), { foundByMarker: null, recoveredByMarker: null, deleted: false, remaining: null, reason: 'unverified' });
    assert.equal(target.table.length, 1);
  }
});

test('marker rows are counted with no ledger entry of their kind; another run is untouched (L06-8, second reproduction)', async () => {
  const dir = tmp();
  const target = rowsTarget();
  target.table.push({ id: 17, title: rowTitle('r1', 'rls_member') }, { id: 99, title: rowTitle('r2', 'rls_member') });
  target.tables.orders.push({ id: 5, title: rowTitle('r1', 'ord_own_order') }, { id: 6, title: rowTitle('r2', 'ord_own_order') });
  const ctx = rowsCtx(dir, target.hosted, ['connect']);
  assert.deepEqual(ctx.ledger.outstanding(), []);

  // Without cleanup_sql: reported, nothing deleted, recorded as unledgered residue.
  for (const kind of ['notes', 'orders']) {
    assert.deepEqual(settledShape(await settleRows(ctx, kind)), { foundByMarker: 1, recoveredByMarker: 1, deleted: false, remaining: 1, reason: 'cleanup_sql_not_authorized' });
  }
  assert.ok(target.statements.includes(rowSql.ids('notes', 'r1')) && target.statements.includes(rowSql.ids('orders', 'r1')));
  assert.equal(target.statements.filter((s) => s.startsWith('delete')).length, 0);
  assert.deepEqual(ctx.ledger.outstanding().map((e) => [e.kind, e.key, e.op, e.reason]),
    [['notes', 'unledgered', 'residue', 'cleanup_sql_not_authorized'], ['orders', 'unledgered', 'residue', 'cleanup_sql_not_authorized']]);

  // With cleanup_sql: deleted and recounted; the other run's rows kept; the residue entries settle.
  const sql = rowsCtx(dir, target.hosted, ['connect', 'cleanup_sql']);
  for (const kind of ['notes', 'orders']) {
    assert.deepEqual(settledShape(await settleRows(sql, kind)), { foundByMarker: 1, recoveredByMarker: 1, deleted: true, remaining: 0, reason: null });
  }
  assert.deepEqual(target.table, [{ id: 99, title: rowTitle('r2', 'rls_member') }]);
  assert.deepEqual(target.tables.orders, [{ id: 6, title: rowTitle('r2', 'ord_own_order') }]);
  assert.deepEqual(sql.ledger.outstanding(), []);

  // A delete whose recount is malformed is unknown, not zero.
  const garbled = rowsTarget({ answer: (s) => (s === rowSql.count('notes', 'r1') ? null : undefined) });
  garbled.table.push({ id: 18, title: rowTitle('r1', 'rls_member') });
  const after = await settleRows(rowsCtx(tmp(), garbled.hosted, ['connect', 'cleanup_sql']), 'notes');
  assert.deepEqual(settledShape(after), { foundByMarker: 1, recoveredByMarker: 1, deleted: true, remaining: null, reason: 'unverified' });
});

test('C.rows_reported fails on an unknown row count and passes only on a counted zero (L06-8)', async () => {
  const run = async (hosted, actions, ledgerLines) => {
    const dir = tmp();
    const ctx = rowsCtx(dir, hosted, actions);
    for (const [op, key, data] of ledgerLines) ctx.ledger.write(op, 'notes', key, data);
    const cases = CASES.filter((c) => c.procedure === 'cleanup');
    const state = {};
    const { records } = await runProcedures({
      procedures: cleanupProcedures, ctx: { ...ctx, ids: {}, descriptor: {}, state }, selection: null,
      capabilities: { publishable_key: true, secret_key: true, management_token: true }, actions: ctx.actions, hosted: false,
      evidence: new Evidence(path.join(dir, 'ev'), new Redactor()), cases,
    });
    const at = (id) => ({ status: records.get(id).rehearsal?.status, reason: records.get(id).rehearsal?.reason, outer: records.get(id).status });
    return { ...at('C.rows_reported'), rows: state.residue?.rows ?? null, ledger: ctx.ledger };
  };
  const all = ['connect', 'create_users', 'cleanup_sql'];
  const lost = [['intent', 'rls_member', {}]];
  const pick = ({ status, reason, outer }) => ({ status, reason, outer });
  const blind = rowsTarget({ readFails: true });
  assert.deepEqual(pick(await run(blind.hosted, all, lost)), { status: 'failed', reason: 'assertion_failed', outer: 'not_run' });
  const target = rowsTarget();
  target.table.push({ id: 5, title: rowTitle('r1', 'rls_member') });
  assert.deepEqual(pick(await run(target.hosted, all, lost)), { status: 'passed', reason: null, outer: 'not_run' });
  assert.deepEqual(target.table, []);

  // First reproduction through the case: a null count answer fails it, and the intent stays outstanding.
  for (const bad of [null, false, '0', []]) {
    const nulled = rowsTarget({ answer: (sql) => (sql === rowSql.count('notes', 'r1') ? bad : undefined) });
    const r = await run(nulled.hosted, all, lost);
    assert.deepEqual({ ...pick(r), rows: r.rows }, { status: 'failed', reason: 'assertion_failed', outer: 'not_run', rows: { notes: null, orders: 0 } });
    assert.deepEqual(r.ledger.outstanding().map((e) => [e.key, e.op]), [['rls_member', 'residue']]);
  }

  // Second reproduction through the case: an empty ledger with a late marker row. Deleted with cleanup_sql; reported without.
  const late = rowsTarget();
  late.table.push({ id: 17, title: rowTitle('r1', 'late') });
  const unauthorised = await run(late.hosted, ['connect', 'create_users'], []);
  assert.deepEqual({ ...pick(unauthorised), rows: unauthorised.rows }, { status: 'passed', reason: null, outer: 'not_run', rows: { notes: 1, orders: 0 } });
  assert.equal(late.table.length, 1);
  assert.equal(late.statements.filter((s) => s.startsWith('delete')).length, 0);
  const settled = await run(late.hosted, all, []);
  assert.deepEqual({ ...pick(settled), rows: settled.rows }, { status: 'passed', reason: null, outer: 'not_run', rows: { notes: 0, orders: 0 } });
  assert.deepEqual(late.table, []);
  // With cleanup_sql, a marker row the delete could not clear fails the case.
  const stuck = rowsTarget({ answer: (sql) => (sql === rowSql.count('notes', 'r1') ? 1 : undefined) });
  stuck.table.push({ id: 17, title: rowTitle('r1', 'late') });
  assert.deepEqual(pick(await run(stuck.hosted, all, [])), { status: 'failed', reason: 'assertion_failed', outer: 'not_run' });
});

test('C.catalog_restored and the kit residue hold a malformed count to unknown, never zero (L06-8)', async () => {
  const run = async (answer) => {
    const dir = tmp();
    const ctx = rowsCtx(dir, rowsTarget({ answer }).hosted, ['connect', 'create_users', 'cleanup_sql']);
    const { records } = await runProcedures({
      procedures: cleanupProcedures, ctx: { ...ctx, ids: {}, descriptor: {}, state: {} }, selection: null,
      capabilities: { publishable_key: true, secret_key: true, management_token: true }, actions: ctx.actions, hosted: false,
      evidence: new Evidence(path.join(dir, 'ev'), new Redactor()), cases: CASES.filter((c) => c.procedure === 'cleanup'),
    });
    return ['C.catalog_restored', 'C.rows_reported'].map((id) => records.get(id).rehearsal?.status);
  };
  assert.deepEqual(await run(() => undefined), ['passed', 'passed']);
  for (const bad of [null, false, '0', []]) {
    assert.deepEqual(await run((sql) => (sql === GRANT_VIOLATIONS_SQL ? bad : undefined)), ['failed', 'passed'], `grant count ${JSON.stringify(bad)}`);
    assert.deepEqual(await run((sql) => (sql.includes('hv\\_fault\\_') ? bad : undefined)), ['failed', 'passed'], `fault schema count ${JSON.stringify(bad)}`);
    assert.deepEqual(await run((sql) => (sql.includes("'clients'") ? { ...KIT_ZERO, enrollments: bad } : undefined)), ['passed', 'failed'], `kit count ${JSON.stringify(bad)}`);
  }
  assert.deepEqual(await run((sql) => (sql.includes("'clients'") ? [] : undefined)), ['passed', 'failed']);
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
