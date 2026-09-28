// Operator client: credential separation, refusal and failure mapping,
// strict result shapes, model and export parity, redaction of refusal
// details, and bootstrap-manager lookup (L32). SQL answers here are
// scripted; sql/operator.test.js runs the same calls against the migration.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createOperatorClient, OperatorError, OPERATOR_ERROR_CODES, RECOVERY } from '../../packages/server/operator.js';
import { AUTH_ERROR_CODES, canonicalModelJson, modelHash, sha256Hex } from '../../packages/core/index.js';
import { createFakeSupabase, SECRET_KEY, PUBLISHABLE_KEY, jsonResponse } from './support/fake-supabase.js';

const REQ = '00000000-0000-4000-8000-0000000000b1';
const MODEL = {
  client: 'studio',
  roles: {
    owner: { manages_members: true, permissions: ['members:manage', 'SECRET-PERMISSION-VALUE'] },
    member: { self_assignable: true, permissions: [] },
  },
  permissions: { 'members:manage': 'manage', 'SECRET-PERMISSION-VALUE': 'model value marker' },
};

async function setup(options = {}) {
  const fake = await createFakeSupabase();
  const client = createOperatorClient({ supabaseUrl: fake.origin, secretKey: SECRET_KEY, fetch: fake.fetch, rpcTimeoutMs: 300, adminTimeoutMs: 300, ...options });
  return { fake, client };
}

async function rejectsWith(promise, code, check) {
  return assert.rejects(promise, (error) => {
    assert.ok(error instanceof OperatorError, `expected OperatorError, got ${error?.name}: ${error?.message}`);
    assert.equal(error.code, code);
    check?.(error);
    return true;
  });
}

test('the operator set is closed and separate from the consumer AuthError set', () => {
  assert.throws(() => new OperatorError('not_a_code'), TypeError);
  for (const code of ['request_in_progress', 'run_superseded', 'lease_expired', 'lookup_incomplete', 'unknown_client', 'model_refused']) {
    assert.ok(OPERATOR_ERROR_CODES.includes(code));
    assert.ok(!AUTH_ERROR_CODES.includes(code), `${code} must not enter the consumer set`);
  }
});

test('no operator message claims that nothing changed; outcome_unknown always carries a recovery tag', () => {
  for (const code of OPERATOR_ERROR_CODES) {
    const error = code === 'outcome_unknown' ? new OperatorError(code, { recovery: RECOVERY[0] }) : new OperatorError(code);
    assert.doesNotMatch(error.message, /nothing (was )?changed|unchanged|no change|rolled back/i, code);
  }
  assert.throws(() => new OperatorError('outcome_unknown', { stage: 'x' }), TypeError);
  assert.throws(() => new OperatorError('unavailable', { recovery: 'hope' }), TypeError);
});

test('construction needs a secret key; a publishable key or garbage is refused without echo', () => {
  const warnings = [];
  const legacy = `x.${Buffer.from(JSON.stringify({ role: 'service_role' })).toString('base64url')}.y`;
  createOperatorClient({ supabaseUrl: 'https://abc.supabase.co', secretKey: legacy, onWarning: (w) => warnings.push(w) });
  assert.deepEqual(warnings, ['legacy_service_role_key']);
  const anonJwt = `x.${Buffer.from(JSON.stringify({ role: 'anon' })).toString('base64url')}.y`;
  for (const [options, path] of [
    [{ secretKey: PUBLISHABLE_KEY }, 'secretKey'],
    [{ secretKey: anonJwt }, 'secretKey'],
    [{ secretKey: 'sb_secret_' }, 'secretKey'],
    [{ publishableKey: SECRET_KEY }, 'publishableKey'],
    [{ supabaseUrl: 'http://abc.supabase.co' }, 'supabaseUrl'],
    [{ adminTimeoutMs: 20_001 }, 'adminTimeoutMs'],
    [{ management: { token: 'bad token with spaces' } }, 'management.token'],
  ]) {
    assert.throws(() => createOperatorClient({ supabaseUrl: 'https://abc.supabase.co', secretKey: SECRET_KEY, ...options }), (error) => {
      assert.equal(error.code, 'config_invalid');
      assert.equal(error.details.issues[0].path, path);
      assert.ok(!JSON.stringify(error).includes('PUBLISHABLEMARKER'));
      return true;
    });
  }
  // A custom domain without a project ref cannot use the Management API.
  assert.throws(() => createOperatorClient({ supabaseUrl: 'https://auth.example.test', secretKey: SECRET_KEY, management: { token: 'sbp_x' } }), (e) => e.code === 'prerequisite_missing');
});

test('every operator call is made with the secret key as the service role, never a user token', async () => {
  const { fake, client } = await setup();
  fake.rpc = async ({ fn, args, actor }) => {
    assert.equal(actor.role, 'service_role');
    assert.equal(fn, 'register_client');
    return jsonResponse(200, { result: 'registered', client_id: args.client_id, state: 'registered' });
  };
  assert.deepEqual({ ...(await client.registerClient({ clientId: '', displayName: 'Empty id', signupPolicy: 'closed' })) },
    { result: 'registered', clientId: '', state: 'registered' });
  assert.equal(fake.callsTo('rpc')[0].credential, 'secret');
  assert.equal(typeof client.resolveSession, 'undefined');
  for (const name of Object.keys(client)) assert.ok(!/token/i.test(name) || name === 'checkConfig');
});

test('refusals map to operator codes; unexpected refusals, reads and writes fail as unavailable or outcome_unknown', async () => {
  const { fake, client } = await setup();
  const args = { clientId: 'studio', roleKey: 'owner', userId: REQ, requestId: REQ };
  for (const code of ['last_manager', 'unknown_client', 'unknown_role', 'not_manager_role', 'request_conflict', 'invalid_argument']) {
    fake.rpc = async () => jsonResponse(400, { code: 'DW001', message: code, details: 'raw detail SHOULD NOT LEAK' });
    await rejectsWith(client.revokeManager(args), code, (e) => assert.ok(!JSON.stringify(e).includes('LEAK')));
  }
  fake.rpc = async () => jsonResponse(400, { code: 'DW001', message: 'request_in_progress' });
  await rejectsWith(client.revokeManager(args), 'unavailable', (e) => assert.equal(e.details.reason, 'unexpected_refusal'));
  for (const handler of [
    async () => jsonResponse(500, { code: 'XX000', message: 'internal' }),
    async () => jsonResponse(400, { code: '0A000', message: 'auth_kit writes require READ COMMITTED isolation' }),
    async () => { throw new TypeError('reset'); },
    () => new Promise(() => {}),
  ]) {
    fake.rpc = handler;
    await rejectsWith(client.revokeManager(args), 'outcome_unknown', (e) => {
      assert.ok(!JSON.stringify(e).includes('READ COMMITTED'));
      assert.equal(e.details.recovery, 'rerun_same_request_id');
    });
    await rejectsWith(client.exportModel('studio'), 'unavailable');
  }
  // A 2xx the client cannot accept may follow a committed write.
  for (const body of [
    { result: 'revoked', user_id: REQ, client_id: 'other', role_key: 'owner' },
    { result: 'granted', user_id: REQ, client_id: 'studio', role_key: 'owner' },
    { result: 'revoked', user_id: REQ, client_id: 'studio' },
  ]) {
    fake.rpc = async () => jsonResponse(200, body);
    await rejectsWith(client.revokeManager(args), 'outcome_unknown', (e) => {
      assert.deepEqual({ ...e.details }, { stage: 'revoke_manager', reason: 'malformed', recovery: 'rerun_same_request_id' });
    });
  }
});

test('an accepted write followed by a malformed or lost answer is outcome_unknown with a truthful recovery, never "unchanged"', async () => {
  const { fake, client } = await setup();
  const accepted = [];
  const accept = (answer) => async ({ fn, args }) => {
    accepted.push(fn);
    return answer(args);
  };
  const register = { clientId: 'studio', displayName: 'Studio', signupPolicy: 'open' };
  for (const answer of [
    (args) => jsonResponse(200, { result: 'registered', client_id: args.client_id, state: 'unexpected' }),
    () => new Response('not json', { status: 200 }),
    () => { throw new TypeError('lost after commit'); },
    () => jsonResponse(503, {}),
  ]) {
    fake.rpc = accept(answer);
    await rejectsWith(client.registerClient(register), 'outcome_unknown', (e) => {
      assert.equal(e.details.stage, 'register_client');
      assert.equal(e.details.recovery, 'rerun_same_arguments', 'register_client has no request id');
      assert.doesNotMatch(e.message, /nothing|unchanged/i);
    });
  }
  assert.deepEqual(accepted, Array(4).fill('register_client'), 'each write was sent');
  // Request-bearing writes: the same id returns the stored result.
  fake.rpc = accept(() => jsonResponse(200, { result: 'applied', model_hash: 'f'.repeat(64) }));
  await rejectsWith(client.applyModel(MODEL, { requestId: REQ }), 'outcome_unknown', (e) => {
    assert.deepEqual({ ...e.details }, { stage: 'apply_model', reason: 'malformed', recovery: 'rerun_same_request_id' });
  });
  const target = fake.addUser();
  fake.rpc = accept(() => jsonResponse(200, { result: 'granted', user_id: target, client_id: 'studio' }));
  await rejectsWith(client.bootstrapManager({ clientId: 'studio', roleKey: 'owner', requestId: REQ, userId: target }), 'outcome_unknown',
    (e) => assert.equal(e.details.recovery, 'rerun_same_request_id'));
  // A dry run writes nothing: its malformed answer is a plain read failure.
  fake.rpc = async () => jsonResponse(200, { result: 'dry_run' });
  await rejectsWith(client.applyModel(MODEL, { dryRun: true }), 'unavailable', (e) => assert.equal(e.details.recovery, undefined));
});

test('apply-model: local validation first, hash parity with core, sanitized refusals and issues', async () => {
  const { fake, client } = await setup();
  await rejectsWith(client.applyModel({ client: 'studio', roles: {}, permissions: {} }, { requestId: REQ }), 'model_invalid', (e) => {
    assert.ok(e.details.issues.length > 0);
  });
  assert.equal(fake.calls.length, 0);
  await rejectsWith(client.applyModel(MODEL, {}), 'invalid_argument');
  const hash = await modelHash(MODEL);
  fake.rpc = async ({ args }) => {
    assert.equal(args.request_id, args.dry_run ? null : REQ);
    return args.dry_run
      ? jsonResponse(200, { result: 'dry_run', model_hash: hash, changed: true, diff: [{ kind: 'role_added', role: 'member' }], refusals: [] })
      : jsonResponse(200, { result: 'applied', model_hash: hash, diff: [] });
  };
  const dry = await client.applyModel(MODEL, { dryRun: true });
  assert.equal(dry.hashMatchesFile, true);
  assert.equal(dry.changed, true);
  assert.equal((await client.applyModel(MODEL, { requestId: REQ })).result, 'applied');
  fake.rpc = async () => jsonResponse(200, { result: 'applied', model_hash: 'f'.repeat(64), diff: [] });
  assert.equal((await client.applyModel(MODEL, { requestId: REQ })).hashMatchesFile, false);
  const holder = '00000000-0000-4000-8000-0000000000c1';
  fake.rpc = async () => jsonResponse(400, { code: 'DW001', message: 'model_refused', details: JSON.stringify({ refusals: [
    { rule: 'role_held', role: 'owner', holders: [holder, 'not-a-uuid'] }, { rule: 'no_manager_would_remain' },
  ] }) });
  await rejectsWith(client.applyModel(MODEL, { requestId: REQ }), 'model_refused', (e) => {
    assert.deepEqual(e.details.refusals, [{ rule: 'role_held', role: 'roles.#1', holderCount: 1, holders: [holder] }, { rule: 'no_manager_would_remain' }]);
    assert.ok(!JSON.stringify(e).includes('owner'));
  });
  fake.rpc = async () => jsonResponse(400, { code: 'DW001', message: 'model_invalid', details: JSON.stringify({ issues: [
    { path: 'roles.#0.permissions[1]', rule: 'undeclared_permission' }, { path: 'SECRET-PERMISSION-VALUE', rule: 'x' }, { path: 'roles', rule: 'Not A Rule' },
  ] }) });
  await rejectsWith(client.applyModel(MODEL, { requestId: REQ }), 'model_invalid', (e) => {
    assert.deepEqual(e.details.issues, [{ path: 'roles.#0.permissions[1]', rule: 'undeclared_permission' }]);
  });
});

test('export-model returns the canonical file text only when it is exactly canonical and hashes to model_hash', async () => {
  const { fake, client } = await setup();
  const text = canonicalModelJson(MODEL);
  const hash = await sha256Hex(text);
  fake.rpc = async () => jsonResponse(200, { client_id: 'studio', model_json: text, model_hash: hash, last_applied_hash: hash });
  const exported = await client.exportModel('studio');
  assert.equal(exported.modelJson, text);
  assert.equal(exported.modelHash, await modelHash(MODEL));
  // Non-canonical text is refused even when model_hash is that text's own digest.
  const pretty = JSON.stringify(JSON.parse(text), null, 2);
  for (const body of [
    { client_id: 'studio', model_json: pretty, model_hash: await sha256Hex(pretty), last_applied_hash: null },
    { client_id: 'studio', model_json: pretty, model_hash: hash, last_applied_hash: null },
    { client_id: 'studio', model_json: text, model_hash: 'a'.repeat(64), last_applied_hash: null },
    { client_id: 'other', model_json: text, model_hash: hash, last_applied_hash: null },
    { client_id: 'studio', model_json: JSON.parse(text), model_hash: hash, last_applied_hash: null },
    { client_id: 'studio', model_json: null, model_hash: hash, last_applied_hash: null },
  ]) {
    fake.rpc = async () => jsonResponse(200, body);
    await rejectsWith(client.exportModel('studio'), 'unavailable');
  }
  fake.rpc = async () => jsonResponse(200, { client_id: 'studio', model_json: null, model_hash: null, last_applied_hash: null });
  assert.equal((await client.exportModel('studio')).modelJson, null);
});

function usersWith(fake, count, extra = []) {
  for (let i = 0; i < count; i += 1) fake.addUser({ email: `filler-${i}@example.test` });
  for (const user of extra) fake.addUser(user);
}

test('L32 bootstrap-manager --email: unique confirmed match after a complete listing only', async () => {
  const { fake, client } = await setup();
  fake.rpc = async ({ args }) => jsonResponse(200, { result: 'granted', user_id: args.user_id, client_id: args.client_id, role_key: args.role_key });
  const target = fake.addUser({ email: 'Target@Example.test' });
  usersWith(fake, 1500);
  const done = await client.bootstrapManager({ clientId: 'studio', roleKey: 'owner', requestId: REQ, email: 'target@example.TEST' });
  assert.equal(done.userId, target);
  assert.deepEqual(fake.callsTo('admin_list_users').map((c) => c.search), ['?page=1&per_page=1000', '?page=2&per_page=1000']);
  assert.equal(fake.callsTo('admin_get_user').length, 1, 'the resolved id is verified with getUserById');
  const noEmailLeak = JSON.stringify(done);
  assert.ok(!noEmailLeak.toLowerCase().includes('target@'));
});

test('L32 an address that changed between the listing and getUserById is refused with zero RPC writes', async () => {
  const { fake, client } = await setup();
  const rpcCalls = [];
  fake.rpc = async ({ fn, args }) => {
    rpcCalls.push(fn);
    return jsonResponse(200, { result: 'granted', user_id: args.user_id, client_id: args.client_id, role_key: args.role_key });
  };
  const target = fake.addUser({ email: 'target@example.test' });
  const args = { clientId: 'studio', roleKey: 'owner', requestId: REQ, email: 'target@example.test' };
  for (const email of ['other@example.test', 'target@example.test.evil', null]) {
    // The listing still shows the requested address; the final read does not.
    fake.hooks.set('admin_get_user', async () => jsonResponse(200, {
      id: target, email, email_confirmed_at: '2026-01-01T00:00:00Z', is_anonymous: false,
    }));
    await rejectsWith(client.bootstrapManager(args), 'unknown_user', (e) => {
      assert.deepEqual({ ...e.details }, { stage: 'get_user', reason: 'email_changed' });
      assert.ok(!JSON.stringify(e).includes('example.test'));
    });
  }
  assert.deepEqual(rpcCalls, [], 'no bootstrap_manager write was sent');
  assert.equal(fake.callsTo('rpc').length, 0);
  // The same final read with the requested address (any case) grants.
  fake.hooks.set('admin_get_user', async () => jsonResponse(200, {
    id: target, email: 'TARGET@example.test', email_confirmed_at: '2026-01-01T00:00:00Z', is_anonymous: false,
  }));
  assert.equal((await client.bootstrapManager(args)).result, 'granted');
  assert.deepEqual(rpcCalls, ['bootstrap_manager']);
  // --user-id is canonical and needs no address.
  fake.hooks.set('admin_get_user', async () => jsonResponse(200, { id: target, email: null, email_confirmed_at: '2026-01-01T00:00:00Z' }));
  const { email: _unused, ...byId } = args;
  assert.equal((await client.bootstrapManager({ ...byId, userId: target })).result, 'granted');
});

test('L32 zero, two, unconfirmed-only and capped listings are refused and write nothing', async () => {
  const { fake, client } = await setup();
  fake.rpc = async () => assert.fail('no bootstrap may be attempted');
  fake.addUser({ email: 'twin@example.test' });
  fake.addUser({ email: 'TWIN@example.test' });
  fake.addUser({ email: 'pending@example.test', confirmed: false });
  const args = { clientId: 'studio', roleKey: 'owner', requestId: REQ };
  await rejectsWith(client.bootstrapManager({ ...args, email: 'nobody@example.test' }), 'unknown_user');
  await rejectsWith(client.bootstrapManager({ ...args, email: 'twin@example.test' }), 'ambiguous_user', (e) => assert.equal(e.details.matches, 2));
  await rejectsWith(client.bootstrapManager({ ...args, email: 'pending@example.test' }), 'email_unverified');
  // More than ten full pages: the scan stops at the cap and never claims uniqueness.
  const big = await setup();
  big.fake.rpc = async () => assert.fail('no bootstrap may be attempted');
  big.fake.addUser({ email: 'early@example.test' });
  usersWith(big.fake, 10_000);
  await rejectsWith(big.client.bootstrapManager({ ...args, email: 'early@example.test' }), 'lookup_incomplete', (e) => {
    assert.equal(e.details.reason, 'page_cap');
    assert.equal(e.details.pages, 10);
  });
  assert.equal(big.fake.callsTo('admin_list_users').length, 10);
  assert.equal(big.fake.callsTo('admin_get_user').length, 0);
});

test('L32 inconsistent listing signals and listing failures refuse', async () => {
  const { fake, client } = await setup();
  fake.addUser({ email: 'a@example.test' });
  const args = { clientId: 'studio', roleKey: 'owner', requestId: REQ, email: 'a@example.test' };
  fake.hooks.set('admin_list_users', async () => jsonResponse(200, { users: [] }, { link: '</admin/users?page=2&per_page=1000>; rel="next"' }));
  await rejectsWith(client.bootstrapManager(args), 'lookup_incomplete');
  fake.hooks.set('admin_list_users', async () => jsonResponse(200, { users: [] }, { 'x-total-count': '5' }));
  await rejectsWith(client.bootstrapManager(args), 'lookup_incomplete');
  fake.hooks.set('admin_list_users', async () => jsonResponse(500, {}));
  await rejectsWith(client.bootstrapManager(args), 'unavailable');
  fake.hooks.set('admin_list_users', async () => jsonResponse(200, { users: 'x' }));
  await rejectsWith(client.bootstrapManager(args), 'unavailable');
  assert.equal(fake.callsTo('rpc').length, 0);
});

test('L32 --user-id is verified with getUserById: unknown, anonymous and unconfirmed users are refused; confirmed succeeds', async () => {
  const { fake, client } = await setup();
  fake.rpc = async ({ args }) => jsonResponse(200, { result: 'already_member', user_id: args.user_id, client_id: args.client_id, role_key: args.role_key });
  const args = { clientId: 'studio', roleKey: 'owner', requestId: REQ };
  await rejectsWith(client.bootstrapManager({ ...args, userId: '00000000-0000-4000-8000-0000000000ff' }), 'unknown_user');
  await rejectsWith(client.bootstrapManager({ ...args, userId: fake.addUser({ anonymous: true }) }), 'unknown_user');
  await rejectsWith(client.bootstrapManager({ ...args, userId: fake.addUser({ confirmed: false }) }), 'email_unverified');
  assert.equal(fake.callsTo('rpc').length, 0);
  fake.hooks.set('admin_get_user', async () => jsonResponse(500, {}));
  await rejectsWith(client.bootstrapManager({ ...args, userId: fake.addUser() }), 'unavailable');
  fake.hooks.clear();
  assert.equal((await client.bootstrapManager({ ...args, userId: fake.addUser() })).result, 'already_member');
  await rejectsWith(client.bootstrapManager({ ...args }), 'invalid_argument');
  await rejectsWith(client.bootstrapManager({ ...args, userId: REQ, email: 'x@example.test' }), 'invalid_argument');
  await rejectsWith(client.bootstrapManager({ ...args, userId: REQ, invite: true }), 'invalid_argument');
});

test('--invite is explicit: only a complete listing with no such user sends one, and the result is setup_pending', async () => {
  const { fake, client } = await setup();
  fake.rpc = async () => assert.fail('no bootstrap before the invite is accepted');
  const args = { clientId: 'studio', roleKey: 'owner', requestId: REQ };
  await rejectsWith(client.bootstrapManager({ ...args, email: 'new@example.test' }), 'unknown_user');
  assert.equal(fake.callsTo('invite').length, 0, 'never invite implicitly');
  const pending = await client.bootstrapManager({ ...args, email: 'new@example.test', invite: true });
  assert.equal(pending.result, 'setup_pending');
  assert.equal(fake.users.get(pending.userId).email, 'new@example.test');
  assert.equal(fake.callsTo('invite').length, 1);
  // The invited, unconfirmed user is not invited again.
  await rejectsWith(client.bootstrapManager({ ...args, email: 'new@example.test', invite: true }), 'email_unverified');
  assert.equal(fake.callsTo('invite').length, 1);
  fake.hooks.set('invite', async () => { throw new TypeError('lost'); });
  await rejectsWith(client.bootstrapManager({ ...args, email: 'other@example.test', invite: true }), 'outcome_unknown');
});

test('an invite whose answer is lost, unreadable or a 5xx may have been sent: outcome_unknown, and the rerun invites no one twice', async () => {
  const { fake, client } = await setup();
  fake.rpc = async () => assert.fail('no bootstrap before the invite is accepted');
  const args = { clientId: 'studio', roleKey: 'owner', requestId: REQ, invite: true };
  const answers = [
    () => { throw new TypeError('lost after sending'); },
    () => jsonResponse(200, { id: 'not-a-uuid' }),
    () => new Response('<html>', { status: 200 }),
    () => jsonResponse(504, {}),
  ];
  for (const [index, answer] of answers.entries()) {
    const email = `accepted-${index}@example.test`;
    // Auth accepts the invitation, then the answer goes wrong.
    fake.hooks.set('invite', async ({ body }) => {
      fake.addUser({ email: body.email, confirmed: false });
      return answer();
    });
    await rejectsWith(client.bootstrapManager({ ...args, email }), 'outcome_unknown', (e) => {
      assert.equal(e.details.stage, 'invite');
      assert.equal(e.details.recovery, 'rerun_lookup_before_invite');
      assert.ok(!JSON.stringify(e).includes('accepted-'));
    });
    fake.hooks.clear();
    const invites = fake.callsTo('invite').length;
    await rejectsWith(client.bootstrapManager({ ...args, email }), 'email_unverified');
    assert.equal(fake.callsTo('invite').length, invites, 'the rerun finds the invited address and sends no second invitation');
  }
  // Auth's own refusal is not an unknown outcome.
  fake.hooks.set('invite', async () => jsonResponse(422, { code: 422, error_code: 'email_exists' }));
  await rejectsWith(client.bootstrapManager({ ...args, email: 'refused@example.test' }), 'unavailable');
});
