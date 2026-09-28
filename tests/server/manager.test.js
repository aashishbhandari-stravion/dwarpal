// Manager operations through the session server: the manager's own token
// and the fixed client id, a live session check before the write, the
// closed consumer error mapping for SQL refusals, and unavailable (retry
// with the same id) for any unknown outcome. The stored-result, conflict and
// cross-actor semantics against the real SQL are in sql/manager.test.js.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createAuthServer, AuthError } from '../../packages/server/index.js';
import { createFakeSupabase, PUBLISHABLE_KEY, SECRET_KEY, jsonResponse } from './support/fake-supabase.js';

const CLIENT = 'studio';

async function setup() {
  const fake = await createFakeSupabase();
  const server = createAuthServer({ supabaseUrl: fake.origin, publishableKey: PUBLISHABLE_KEY, clientId: CLIENT, fetch: fake.fetch, requestTimeoutMs: 300 });
  const managerId = fake.addUser();
  const { token, sessionId } = await fake.signIn(managerId);
  return { fake, server, managerId, token, sessionId };
}

function req(token) {
  return new Request('https://app.example.test/members', { method: 'POST', headers: { authorization: `Bearer ${token}` } });
}

async function rejects(promise, code) {
  await assert.rejects(promise, (error) => error instanceof AuthError && error.code === code);
}

const TARGET = '00000000-0000-4000-8000-00000000000a';
const REQUEST = '00000000-0000-4000-8000-0000000000aa';

test('grant and revoke run as the manager, for the configured client, and return the checked outcome', async () => {
  const { fake, server, token } = await setup();
  fake.rpc = async ({ fn, args, actor }) => {
    assert.equal(actor.role, 'authenticated');
    const result = fn === 'grant_membership' ? 'granted' : 'not_member';
    return jsonResponse(200, { result, user_id: args.user_id, client_id: args.client_id, role_key: args.role_key });
  };
  const granted = await server.grantMembership(TARGET.toUpperCase(), 'editor', REQUEST, req(token));
  assert.deepEqual({ ...granted }, { result: 'granted', userId: TARGET, clientId: CLIENT, roleKey: 'editor' });
  const revoked = await server.revokeMembership(TARGET, '', REQUEST, req(token));
  assert.deepEqual({ ...revoked }, { result: 'not_member', userId: TARGET, clientId: CLIENT, roleKey: '' });
  const rpcCalls = fake.callsTo('rpc');
  assert.deepEqual(rpcCalls.map((c) => c.body), [
    { user_id: TARGET, client_id: CLIENT, role_key: 'editor', request_id: REQUEST },
    { user_id: TARGET, client_id: CLIENT, role_key: '', request_id: REQUEST },
  ]);
  assert.ok(rpcCalls.every((c) => c.credential === 'user'), 'the manager token, never a service key');
  // Each write re-checked the session live first.
  assert.deepEqual(fake.calls.map((c) => c.route), ['jwks', 'user', 'rpc', 'user', 'rpc']);
  assert.ok(!JSON.stringify(fake.calls).includes(SECRET_KEY));
});

test('no token, a revoked session or a bad token stop before the write', async () => {
  const { fake, server, token, sessionId } = await setup();
  fake.rpc = async () => assert.fail('no write may be attempted');
  await rejects(server.grantMembership(TARGET, 'editor', REQUEST, new Request('https://x.test')), 'no_token');
  fake.sessions.get(sessionId).revoked = true;
  await rejects(server.grantMembership(TARGET, 'editor', REQUEST, req(token)), 'invalid_token');
  await rejects(server.revokeMembership(TARGET, 'editor', REQUEST, req('a.b.c')), 'invalid_token');
  assert.equal(fake.callsTo('rpc').length, 0);
});

test('invalid arguments are programming errors raised before any call', async () => {
  const { fake, server, token } = await setup();
  for (const args of [['nope', 'editor', REQUEST], [TARGET, 'a\u0000b', REQUEST], [TARGET, 'editor', 'nope'], [TARGET, 7, REQUEST]]) {
    await assert.rejects(server.grantMembership(...args, req(token)), TypeError);
  }
  assert.equal(fake.calls.length, 0);
});

test('SQL refusals map to the closed consumer set; unknown refusals and all other failures are unavailable', async () => {
  const { fake, server, token } = await setup();
  const mapping = [
    ['forbidden', 'forbidden'],
    ['mfa_required', 'mfa_required'],
    ['request_conflict', 'request_conflict'],
    ['email_unverified', 'email_unverified'],
    ['unknown_role', 'forbidden'],
    ['unknown_user', 'forbidden'],
    ['invalid_argument', 'unavailable'],
    ['last_manager', 'unavailable'],
    ['some_future_code', 'unavailable'],
  ];
  for (const [sqlCode, consumerCode] of mapping) {
    fake.rpc = async () => jsonResponse(400, { code: 'DW001', message: sqlCode, details: null, hint: null });
    await rejects(server.grantMembership(TARGET, 'editor', REQUEST, req(token)), consumerCode);
  }
  const failures = [
    async () => jsonResponse(500, { code: 'XX000', message: 'raw database text' }),
    async () => jsonResponse(400, { code: '23505', message: 'duplicate key' }),
    async () => jsonResponse(400, { code: 'DW001', message: 'Not A Code!' }),
    async () => jsonResponse(502, 'bad gateway'),
    async () => { throw new TypeError('socket hang up'); },
    () => new Promise(() => {}),
    async () => jsonResponse(200, { result: 'granted', user_id: TARGET, client_id: 'other', role_key: 'editor' }),
    async () => jsonResponse(200, { result: 'granted', user_id: TARGET, client_id: CLIENT, role_key: 'owner' }),
    async () => jsonResponse(200, { result: 'revoked', user_id: TARGET, client_id: CLIENT, role_key: 'editor' }),
    async () => jsonResponse(200, { result: 'granted', user_id: REQUEST, client_id: CLIENT, role_key: 'editor' }),
    async () => jsonResponse(200, { result: 'granted', user_id: TARGET, client_id: CLIENT, role_key: 'editor', extra: true }),
    async () => jsonResponse(200, null),
  ];
  for (const handler of failures) {
    fake.rpc = handler;
    await rejects(server.grantMembership(TARGET, 'editor', REQUEST, req(token)), 'unavailable');
  }
  fake.rpc = async () => jsonResponse(401, { code: 'PGRST301', message: 'JWT expired' });
  await rejects(server.grantMembership(TARGET, 'editor', REQUEST, req(token)), 'invalid_token');
});

test('an unknown outcome is retried with the same request id and returns the stored result', async () => {
  const { fake, server, token } = await setup();
  let committed = null;
  fake.rpc = async ({ args }) => {
    // First call commits, then the answer is lost; the retry reads the stored row.
    if (committed === null) {
      committed = { result: 'granted', user_id: args.user_id, client_id: args.client_id, role_key: args.role_key, id: args.request_id };
      throw new TypeError('connection reset after commit');
    }
    assert.equal(args.request_id, committed.id);
    const { id: _, ...stored } = committed;
    return jsonResponse(200, stored);
  };
  await rejects(server.grantMembership(TARGET, 'editor', REQUEST, req(token)), 'unavailable');
  assert.equal((await server.grantMembership(TARGET, 'editor', REQUEST, req(token))).result, 'granted');
});
