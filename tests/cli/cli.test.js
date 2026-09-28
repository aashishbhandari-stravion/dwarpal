// auth-kit executable: parsing, exit statuses, stdout/stderr contract,
// redaction, request-id recovery hints and bounded listing, run as a real
// child process against the loopback fixture with scripted SQL answers. The
// end-to-end flow against the real migration is in sql-flow.test.js.

import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { canonicalModelJson, sha256Hex, validateModel, validateClientConfig } from '../../packages/core/index.js';
import { createFakeSupabase, SECRET_KEY, jsonResponse } from '../server/support/fake-supabase.js';
import { createMemoryMfa } from '../server/support/memory-mfa.js';
import { runCli, baseEnv } from './support.js';

const MODEL = {
  client: 'studio',
  roles: { owner: { manages_members: true, permissions: ['members:manage', 'MODELVALUEMARKER'] }, member: { self_assignable: true, permissions: [] } },
  permissions: { 'members:manage': 'manage', MODELVALUEMARKER: 'x' },
};

// Hooks live in a describe block: Node 22.0.0 does not run file-level
// before() hooks ahead of file-level tests.
describe('auth-kit executable', () => {
  let fake;
  let dir;

  before(async () => {
    fake = await createFakeSupabase();
    await fake.listen();
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dwl3-cli-'));
    fs.writeFileSync(path.join(dir, 'auth-model.json'), JSON.stringify(MODEL));
  });

  after(async () => {
    await fake.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  function reset() {
    fake.hooks.clear();
    fake.calls.length = 0;
    fake.rpc = async () => jsonResponse(500, { code: 'XX000', message: `database said ${SECRET_KEY}` });
  }

  test('usage errors exit 2 without touching the network; --help exits 0', async () => {
    reset();
    const env = baseEnv(fake);
    assert.equal((await runCli([], { env })).code, 2);
    assert.equal((await runCli(['--help'], { env })).code, 0);
    assert.equal((await runCli(['doctor', '--help'], { env })).code, 0);
    for (const args of [
      ['bogus'],
      ['register-client', '--client', 'a', '--client', 'b', '--name', 'n', '--signup', 'open'],
      ['register-client', '--client'],
      ['register-client', 'positional'],
      ['register-client', '--unknown', 'x'],
      ['register-client', '--client', 'a', '--name', 'n'],
      ['apply-model', '--dry-run=yes'],
      ['bootstrap-manager', '--client', 'a', '--role', 'r'],
      ['bootstrap-manager', '--client', 'a', '--role', 'r', '--user-id', 'u', '--email', 'e@example.test'],
      ['bootstrap-manager', '--client', 'a', '--role', 'r', '--user-id', '00000000-0000-4000-8000-000000000001', '--invite'],
      ['doctor', '--probe-email', 'x@example.test'],
      ['apply-model', '--model', path.join(dir, 'missing.json')],
      ['apply-model', '--client', 'other', '--model', path.join(dir, 'auth-model.json')],
    ]) {
      const result = await runCli(args, { env, cwd: dir });
      assert.equal(result.code, 2, `${args.join(' ')} -> ${result.code}\n${result.stderr}`);
    }
    assert.equal(fake.calls.length, 0);
  });

  test('missing credentials exit 5 and say what is missing, never what was set', async () => {
    reset();
    const result = await runCli(['export-model', '--client', 'studio'], { env: { PATH: process.env.PATH } });
    assert.equal(result.code, 5);
    assert.match(result.stderr, /SUPABASE_URL and SUPABASE_SECRET_KEY/);
    const pub = await runCli(['export-model', '--client', 'studio'], { env: { ...baseEnv(fake), SUPABASE_SECRET_KEY: 'sb_publishable_x' } });
    assert.equal(pub.code, 2);
    assert.equal(pub.json.error, 'config_invalid');
  });

  test('--env-path supplies credentials, environment values win, and the file is never echoed', async () => {
    reset();
    fake.rpc = async ({ args }) => jsonResponse(200, { result: 'registered', client_id: args.client_id, state: 'registered' });
    const envFile = path.join(dir, 'operator.env');
    fs.writeFileSync(envFile, `SUPABASE_URL=${fake.origin}\nSUPABASE_SECRET_KEY=${SECRET_KEY}\n`);
    const result = await runCli(['register-client', '--client', 'studio', '--name', 'Studio', '--signup', 'open', '--env-path', envFile], { env: { PATH: process.env.PATH } });
    assert.equal(result.code, 0, result.stderr);
    assert.deepEqual(result.json, { result: 'registered', clientId: 'studio', state: 'registered' });
    const wrong = await runCli(['register-client', '--client', 'studio', '--name', 'Studio', '--signup', 'open', '--env-path', envFile],
      { env: { PATH: process.env.PATH, SUPABASE_URL: 'https://abc.supabase.co' } });
    assert.notEqual(wrong.code, 0, 'the environment value wins over the file');
    assert.equal((await runCli(['register-client', '--env-path', path.join(dir, 'nope.env')], { env: { PATH: process.env.PATH } })).code, 2);
  });

  test('failures: unavailable exits 3, a lost write exits 4 with the same-id hint, and peer text never appears', async () => {
    reset();
    const env = baseEnv(fake);
    const read = await runCli(['export-model', '--client', 'studio'], { env });
    assert.equal(read.code, 3);
    assert.equal(read.json.error, 'unavailable');
    assert.ok(!read.stdout.includes('database said'));
    fake.hooks.set('rpc', async () => { throw new Error('drop the connection'); });
    const id = '00000000-0000-4000-8000-0000000000d1';
    const write = await runCli(['revoke-manager', '--client', 'studio', '--role', 'owner', '--user-id', id, '--request-id', id], { env });
    assert.equal(write.code, 4);
    assert.equal(write.json.error, 'outcome_unknown');
    assert.match(write.stderr, /same --request-id/);
  });

  test('apply-model: generated request id is printed first; dry run needs none; refusals show positions and ids only', async () => {
    reset();
    const env = baseEnv(fake);
    const hash = await sha256Hex(canonicalModelJson(MODEL));
    const seen = [];
    fake.rpc = async ({ args }) => {
      seen.push(args);
      return args.dry_run
        ? jsonResponse(200, { result: 'dry_run', model_hash: hash, changed: true, diff: [], refusals: [] })
        : jsonResponse(200, { result: 'applied', model_hash: hash, diff: [] });
    };
    const dry = await runCli(['apply-model', '--dry-run'], { env, cwd: dir });
    assert.equal(dry.code, 0, dry.stderr);
    assert.equal(dry.json.result, 'dry_run');
    assert.equal(seen[0].request_id, null);
    const applied = await runCli(['apply-model', '--model', 'auth-model.json'], { env, cwd: dir });
    assert.equal(applied.code, 0);
    const printed = /request id ([0-9a-f-]{36})/.exec(applied.stderr)?.[1];
    assert.equal(printed, seen[1].request_id);
    const holder = '00000000-0000-4000-8000-0000000000e1';
    fake.rpc = async () => jsonResponse(400, { code: 'DW001', message: 'model_refused', details: JSON.stringify({ refusals: [{ rule: 'promotes_holders', role: 'MODELVALUEMARKER', holders: [holder] }] }) });
    const refused = await runCli(['apply-model', '--request-id', holder], { env, cwd: dir, forbidden: ['MODELVALUEMARKER'] });
    assert.equal(refused.code, 1);
    assert.deepEqual(refused.json.details.refusals, [{ rule: 'promotes_holders', role: 'roles.#?', holderCount: 1, holders: [holder] }]);
    fs.writeFileSync(path.join(dir, 'bad-model.json'), JSON.stringify({ client: 'studio', roles: { MODELVALUEMARKER: { permissions: ['MODELVALUEMARKER'] } }, permissions: {} }));
    const invalid = await runCli(['apply-model', '--model', 'bad-model.json', '--dry-run'], { env, cwd: dir, forbidden: ['MODELVALUEMARKER'] });
    assert.equal(invalid.code, 1);
    assert.equal(invalid.json.error, 'model_invalid');
    assert.ok(invalid.json.details.issues.length > 0);
  });

  test('export-model prints the canonical file text byte for byte, or refuses when no model is applied', async () => {
    reset();
    const env = baseEnv(fake);
    const text = canonicalModelJson(MODEL);
    fake.rpc = async () => jsonResponse(200, { client_id: 'studio', model_json: text, model_hash: await sha256Hex(text), last_applied_hash: 'a'.repeat(64) });
    const result = await runCli(['export-model', '--client', 'studio'], { env });
    assert.equal(result.code, 0);
    assert.equal(result.stdout, `${text}\n`);
    assert.match(result.stderr, /changed outside apply-model/);
    fake.rpc = async () => jsonResponse(200, { client_id: 'studio', model_json: null, model_hash: null, last_applied_hash: null });
    const none = await runCli(['export-model', '--client', 'studio'], { env });
    assert.equal(none.code, 1);
    assert.equal(none.stdout, '');
  });

  test('bootstrap-manager --email: ambiguity, incomplete listing and invite are reported without echoing the address', async () => {
    reset();
    const env = baseEnv(fake);
    fake.rpc = async ({ args }) => jsonResponse(200, { result: 'granted', user_id: args.user_id, client_id: args.client_id, role_key: args.role_key });
    fake.users.clear();
    fake.addUser({ email: 'twin-marker@example.test' });
    fake.addUser({ email: 'twin-marker@example.test' });
    const forbidden = ['twin-marker', 'invitee-marker'];
    const args = ['bootstrap-manager', '--client', 'studio', '--role', 'owner', '--request-id', '00000000-0000-4000-8000-0000000000f1'];
    const ambiguous = await runCli([...args, '--email', 'twin-marker@example.test'], { env, forbidden });
    assert.equal(ambiguous.code, 1);
    assert.equal(ambiguous.json.error, 'ambiguous_user');
    fake.hooks.set('admin_list_users', async ({ url }) => jsonResponse(200, { users: Array.from({ length: Number(url.searchParams.get('per_page')) }, () => ({ id: crypto.randomUUID(), email: 'x@example.test', email_confirmed_at: '2026-01-01T00:00:00Z' })) }));
    const capped = await runCli([...args, '--email', 'twin-marker@example.test'], { env, forbidden });
    assert.equal(capped.code, 1);
    assert.equal(capped.json.error, 'lookup_incomplete');
    assert.match(capped.stderr, /--user-id/);
    assert.equal(fake.callsTo('admin_list_users').length, 1 + 10);
    fake.hooks.clear();
    const invited = await runCli([...args, '--email', 'invitee-marker@example.test', '--invite'], { env, forbidden });
    assert.equal(invited.code, 1);
    assert.equal(invited.json.result, 'setup_pending');
    assert.match(invited.stderr, new RegExp(`--user-id ${invited.json.userId}`));
    assert.equal(fake.callsTo('rpc').length, 0, 'nothing bootstrapped');
  });

  test('mfa-reset through the CLI: completes, replays without Auth, and reports in-progress with its hint', async () => {
    reset();
    const env = baseEnv(fake);
    const sql = createMemoryMfa();
    fake.rpc = sql.handle;
    const user = fake.addUser();
    fake.addFactor(user);
    const r = '00000000-0000-4000-8000-0000000000a9';
    const done = await runCli(['mfa-reset', '--user-id', user, '--request-id', r], { env });
    assert.equal(done.code, 0, done.stderr);
    assert.equal(done.json.result, 'reset');
    const admin = fake.adminCalls().length;
    const replay = await runCli(['mfa-reset', '--user-id', user, '--request-id', r], { env });
    assert.equal(replay.json.outcome, 'completed');
    assert.equal(fake.adminCalls().length, admin);
    const other = '00000000-0000-4000-8000-0000000000aa';
    fake.hooks.set('list_factors', async () => { throw new Error('crash'); });
    assert.equal((await runCli(['mfa-reset', '--user-id', user, '--request-id', other], { env })).code, 3);
    fake.hooks.clear();
    const busy = await runCli(['mfa-reset', '--user-id', user, '--request-id', other], { env });
    assert.equal(busy.code, 1);
    assert.equal(busy.json.error, 'request_in_progress');
    assert.match(busy.stderr, /120 seconds/);
    const generated = await runCli(['mfa-reset', '--user-id', user], { env });
    assert.match(generated.stderr, /request id [0-9a-f-]{36}/);
  });

  test('migrate and doctor without Management API access: exit 5, SQL-editor path, and no claimed probe', async () => {
    reset();
    const env = baseEnv(fake, { management: false });
    const migrate = await runCli(['migrate'], { env });
    assert.equal(migrate.code, 5);
    assert.equal(migrate.json.error, 'prerequisite_missing');
    assert.match(migrate.stderr, /SQL editor/);
    const text = canonicalModelJson(MODEL);
    const hash = await sha256Hex(text);
    fake.rpc = async () => jsonResponse(200, { client_id: 'studio', model_json: text, model_hash: hash, last_applied_hash: hash });
    const doctor = await runCli(['doctor', '--client', 'studio'], { env });
    assert.equal(doctor.code, 5);
    assert.equal(doctor.json.status, 'incomplete');
    assert.ok(doctor.json.checks.filter((c) => c.mode === 'catalog' && c.id !== 'model_drift').every((c) => c.status === 'not_run'));
    assert.match(doctor.stderr, /no actor probe ran/);
    const noPassword = await runCli(['doctor', '--probe', '--probe-email', 'p@example.test'], { env: { ...env, AUTH_KIT_PROBE_PASSWORD: '' } });
    assert.equal(noPassword.code, 5);
  });

  test('init writes valid skeletons without values and never overwrites', async () => {
    reset();
    const target = fs.mkdtempSync(path.join(os.tmpdir(), 'dwl3-init-'));
    try {
      const first = await runCli(['init', '--dir', target], { env: { PATH: process.env.PATH } });
      assert.equal(first.code, 0);
      assert.deepEqual(first.json.files.map((f) => f.result), ['written', 'written', 'written']);
      validateModel(JSON.parse(fs.readFileSync(path.join(target, 'auth-model.json'), 'utf8')));
      validateClientConfig(JSON.parse(fs.readFileSync(path.join(target, 'auth-kit.config.json'), 'utf8')));
      const envExample = fs.readFileSync(path.join(target, '.env.example'), 'utf8');
      assert.ok(envExample.split('\n').filter((l) => l && !l.startsWith('#')).every((l) => l.endsWith('=')), 'names only');
      fs.writeFileSync(path.join(target, 'auth-model.json'), 'mine');
      const second = await runCli(['init', '--dir', target], { env: { PATH: process.env.PATH } });
      assert.deepEqual(second.json.files.map((f) => f.result), ['exists_unchanged', 'exists_unchanged', 'exists_unchanged']);
      assert.equal(fs.readFileSync(path.join(target, 'auth-model.json'), 'utf8'), 'mine');
    } finally {
      fs.rmSync(target, { recursive: true, force: true });
    }
  });
});
