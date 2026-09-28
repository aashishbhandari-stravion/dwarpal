// createAuthServer / resolveSession: JWT verification, live Auth check, fresh
// same-client access read, fail-closed mapping and statelessness (design
// 4.1, D8, L25(a) unit part, L31). Supabase is the synthetic fixture in
// support/fake-supabase.js; nothing here is hosted evidence.

import { test, mock } from 'node:test';
import assert from 'node:assert/strict';
import { createAuthServer, AuthError, can, explain, requirePermission } from '../../packages/server/index.js';
import { createFakeSupabase, newSigningKey, PUBLISHABLE_KEY, SECRET_KEY, jsonResponse } from './support/fake-supabase.js';
import { accessSnapshot } from './support/snapshots.js';

const CLIENT = 'client-b';
const OTHER = 'client-a';

async function setup({ tolerance, timeoutMs } = {}) {
  const fake = await createFakeSupabase();
  const grants = new Map();
  fake.rpc = async ({ fn, args, actor }) => {
    if (fn !== 'effective_access') return jsonResponse(404, { code: 'PGRST202', message: 'x' });
    const roles = grants.get(`${actor.claims.sub}|${args.client_id}`) ?? [];
    return jsonResponse(200, accessSnapshot(args.client_id, roles, actor.claims.aal));
  };
  const server = createAuthServer({
    supabaseUrl: fake.origin, publishableKey: PUBLISHABLE_KEY, clientId: CLIENT, fetch: fake.fetch,
    ...(tolerance === undefined ? {} : { clockToleranceSeconds: tolerance }),
    ...(timeoutMs === undefined ? {} : { requestTimeoutMs: timeoutMs }),
  });
  return { fake, grants, server };
}

function req(token) {
  return new Request('https://app.example.test/api', { headers: token === undefined ? {} : { authorization: `Bearer ${token}` } });
}

async function rejects(promise, code) {
  await assert.rejects(promise, (error) => {
    assert.ok(error instanceof AuthError, `expected AuthError, got ${error?.name}: ${error?.message}`);
    assert.equal(error.code, code);
    return true;
  });
}

const staff = { role: 'staff', mfa: true, permissions: ['orders:read:any', 'orders:update:any'] };
const customer = { role: 'customer', selfAssignable: true, via: 'join', permissions: ['orders:read:own'] };
const manager = { role: 'admin', manages: true, mfa: true, permissions: ['members:manage', 'orders:read:any'] };

test('construction refuses a secret key, a bad URL and out-of-range options', async () => {
  const legacyService = `x.${Buffer.from(JSON.stringify({ role: 'service_role' })).toString('base64url')}.y`;
  for (const [options, path] of [
    [{ publishableKey: SECRET_KEY }, 'publishableKey'],
    [{ publishableKey: legacyService }, 'publishableKey'],
    [{ supabaseUrl: 'http://project.example.test' }, 'supabaseUrl'],
    [{ supabaseUrl: 'https://project.example.test/path' }, 'supabaseUrl'],
    [{ clientId: 'a\u0000b' }, 'clientId'],
    [{ clockToleranceSeconds: -1 }, 'clockToleranceSeconds'],
    [{ requestTimeoutMs: 0 }, 'requestTimeoutMs'],
  ]) {
    assert.throws(() => createAuthServer({ supabaseUrl: 'https://p.supabase.co', publishableKey: PUBLISHABLE_KEY, clientId: CLIENT, ...options }), (error) => {
      assert.equal(error.code, 'config_invalid');
      assert.ok(error.issues.some((issue) => issue.path === path), JSON.stringify(error.issues));
      assert.ok(!JSON.stringify(error).includes('SECRETMARKER'));
      return true;
    });
  }
  // The empty string is a literal client id, not an absent one.
  assert.equal(createAuthServer({ supabaseUrl: 'https://p.supabase.co', publishableKey: PUBLISHABLE_KEY, clientId: '' }).clientId, '');
});

test('no Authorization header resolves to null without any network call', async () => {
  const { fake, server } = await setup();
  assert.equal(await server.resolveSession(req()), null);
  assert.equal(await server.resolveSession({ headers: {} }), null);
  assert.equal(fake.calls.length, 0);
});

test('a malformed Authorization header is invalid_token, never anonymous', async () => {
  const { fake, server } = await setup();
  for (const value of ['Basic abc', 'Bearer', 'Bearer ', 'Bearer a.b.c extra', 'Bearer a.b.c, Bearer d.e.f', 'bearer\ta.b.c']) {
    await rejects(server.resolveSession(new Request('https://x.test', { headers: { authorization: value } })), 'invalid_token');
  }
  await rejects(server.resolveSession({ headers: { authorization: ['Bearer a.b.c', 'Bearer d.e.f'] } }), 'invalid_token');
  await assert.rejects(server.resolveSession({}), TypeError);
  assert.equal(fake.calls.length, 0);
});

test('a valid session verifies the token, checks Auth live and reads access for the configured client only', async () => {
  const { fake, grants, server } = await setup();
  const userId = fake.addUser({ providers: ['email', 'google', 'github'] });
  grants.set(`${userId}|${CLIENT}`, [customer]);
  grants.set(`${userId}|${OTHER}`, [manager]);
  const { token, sessionId } = await fake.signIn(userId);
  const principal = await server.resolveSession(req(token));
  assert.equal(principal.identity.userId, userId);
  assert.deepEqual(principal.identity.providers, ['email', 'google']);
  assert.equal(principal.identity.verifiedEmail, fake.users.get(userId).email);
  assert.equal(principal.session.id, sessionId);
  assert.equal(principal.session.aal, 'aal1');
  assert.deepEqual(principal.memberships.map((m) => [m.clientId, m.roleKey]), [[CLIENT, 'customer']]);
  assert.deepEqual(principal.access.permissions, ['orders:read:own']);
  assert.equal(principal.access.clientId, CLIENT);
  assert.ok(Object.isFrozen(principal) && Object.isFrozen(principal.access.permissions));
  // L31: the only access read names client B; client A is never mentioned.
  const rpcCalls = fake.callsTo('rpc');
  assert.equal(rpcCalls.length, 1);
  assert.deepEqual(rpcCalls[0].body, { client_id: CLIENT });
  assert.equal(rpcCalls[0].credential, 'user');
  assert.ok(!JSON.stringify(principal).includes(OTHER));
  assert.deepEqual(fake.calls.map((c) => c.route), ['jwks', 'user', 'rpc']);
});

test('metadata never grants: app and user metadata roles are ignored', async () => {
  const { fake, server } = await setup();
  const userId = fake.addUser();
  const { token } = await fake.signIn(userId, { claims: { app_metadata: { roles: ['admin'] }, user_metadata: { role: 'admin' } } });
  const principal = await server.resolveSession(req(token));
  assert.deepEqual(principal.access.roles, []);
  assert.equal(can(principal, 'orders:read:any'), false);
});

test('MFA withholding follows the verified aal (L26 unit part)', async () => {
  const { fake, grants, server } = await setup();
  const userId = fake.addUser();
  grants.set(`${userId}|${CLIENT}`, [customer, staff]);
  const low = await server.resolveSession(req((await fake.signIn(userId)).token));
  assert.equal(can(low, 'orders:read:any'), false);
  assert.deepEqual(explain(low, 'orders:read:any').withheld, [{ role: 'staff', reason: 'mfa_required' }]);
  assert.equal(requirePermission(low, 'orders:read:own'), low);
  assert.throws(() => requirePermission(low, 'orders:update:any'), (e) => e.code === 'mfa_required');
  const high = await server.resolveSession(req((await fake.signIn(userId, { aal: 'aal2' })).token));
  assert.equal(can(high, 'orders:read:any'), true);
});

test('stateless: every request re-checks Auth and re-reads access; only the JWKS is cached', async () => {
  const { fake, grants, server } = await setup();
  const userId = fake.addUser();
  grants.set(`${userId}|${CLIENT}`, [customer]);
  const { token, sessionId } = await fake.signIn(userId);
  assert.equal(can(await server.resolveSession(req(token)), 'orders:read:own'), true);
  // A membership revoke takes effect on the next request.
  grants.set(`${userId}|${CLIENT}`, []);
  assert.equal(can(await server.resolveSession(req(token)), 'orders:read:own'), false);
  // Sign-out takes effect on the next request with the same unexpired token (L25(a), fixture only).
  fake.sessions.get(sessionId).revoked = true;
  await rejects(server.resolveSession(req(token)), 'invalid_token');
  assert.equal(fake.callsTo('jwks').length, 1);
  assert.equal(fake.callsTo('user').length, 3);
  assert.equal(fake.callsTo('rpc').length, 2);
});

test('banned, deleted and anonymous users, and a mismatched Auth answer, are invalid_token before any access read', async () => {
  const { fake, server } = await setup();
  const banned = fake.addUser({ bannedUntil: '2999-01-01T00:00:00Z' });
  const deleted = fake.addUser();
  const other = fake.addUser();
  const bannedToken = (await fake.signIn(banned)).token;
  const deletedToken = (await fake.signIn(deleted)).token;
  fake.users.get(deleted).deleted = true;
  await rejects(server.resolveSession(req(bannedToken)), 'invalid_token');
  await rejects(server.resolveSession(req(deletedToken)), 'invalid_token');
  // Auth answering 200 with a ban still in force, an anonymous user or another user id.
  const liveToken = (await fake.signIn(other)).token;
  for (const patch of [{ banned_until: '2999-01-01T00:00:00Z' }, { is_anonymous: true }, { id: banned }]) {
    fake.hooks.set('user', async () => jsonResponse(200, { id: other, email: 'x@example.test', identities: [], ...patch }));
    await rejects(server.resolveSession(req(liveToken)), 'invalid_token');
  }
  assert.equal(fake.callsTo('rpc').length, 0);
});

test('Auth and PostgREST failures are unavailable, never an empty or stale principal', async () => {
  const { fake, grants, server } = await setup({ timeoutMs: 200 });
  const userId = fake.addUser();
  grants.set(`${userId}|${CLIENT}`, [customer]);
  const { token } = await fake.signIn(userId);
  await server.resolveSession(req(token));
  const hang = ({ call }) => new Promise((resolve, reject) => call.signal.addEventListener('abort', () => reject(new Error('aborted'))));
  const cases = [
    ['user', async () => jsonResponse(500, { msg: 'boom' })],
    ['user', async () => jsonResponse(429, { msg: 'slow down' })],
    ['user', async () => { throw new TypeError('fetch failed'); }],
    ['user', hang],
    ['user', async () => new Response('not json', { status: 200 })],
    ['user', async () => jsonResponse(200, [])],
    ['rpc', async () => jsonResponse(500, { code: 'XX000', message: 'internal' })],
    ['rpc', async () => jsonResponse(400, { code: 'DW001', message: 'forbidden' })],
    ['rpc', async () => jsonResponse(503, {})],
    ['rpc', async () => jsonResponse(406, { code: 'PGRST106', message: 'schema' })],
    ['rpc', hang],
    ['rpc', async () => new Response('{', { status: 200 })],
    ['rpc', async () => new Response('x'.repeat(5 * 1024 * 1024), { status: 200 })],
  ];
  for (const [route, hook] of cases) {
    fake.hooks.clear();
    fake.hooks.set(route, hook);
    await rejects(server.resolveSession(req(token)), 'unavailable');
  }
  fake.hooks.clear();
  fake.hooks.set('rpc', async () => jsonResponse(401, { code: 'PGRST303', message: 'JWT expired' }));
  await rejects(server.resolveSession(req(token)), 'invalid_token');
});

test('a malformed, foreign or inconsistent access snapshot fails closed', async () => {
  const { fake, server } = await setup();
  const userId = fake.addUser();
  const { token } = await fake.signIn(userId);
  const good = accessSnapshot(CLIENT, [customer, staff], 'aal1');
  const mutations = [
    (s) => ({ ...s, client_id: OTHER }),
    (s) => ({ ...s, extra: 1 }),
    (s) => { const { mfa_pending: _, ...rest } = s; return rest; },
    (s) => ({ ...s, active_roles: ['customer', 'staff'] }),
    (s) => ({ ...s, permissions: ['orders:read:any', 'orders:read:own'] }),
    (s) => ({ ...s, mfa_pending: false }),
    (s) => ({ ...s, memberships: [{ ...s.memberships[0], client_id: OTHER }] }),
    (s) => ({ ...s, memberships: [{ ...s.memberships[0], flags: { ...s.memberships[0].flags, mfa_required: 'no' } }] }),
    (s) => ({ ...s, memberships: [s.memberships[0], s.memberships[0]] }),
    (s) => ({ ...s, memberships: [{ ...s.memberships[0], granted_via: 'metadata' }] }),
    (s) => ({ ...s, enrolled_at: 'yesterday' }),
    () => null,
    () => [],
  ];
  for (const mutate of mutations) {
    fake.hooks.set('rpc', async () => jsonResponse(200, mutate(structuredClone(good))));
    await rejects(server.resolveSession(req(token)), 'unavailable');
  }
  fake.hooks.set('rpc', async () => jsonResponse(200, good));
  assert.deepEqual((await server.resolveSession(req(token))).access.activeRoles, ['customer']);
});

test('JWT verification: time claims with the 5 s tolerance, issuer, audience and Supabase claims', async () => {
  const { fake, server } = await setup();
  fake.authLeewaySeconds = 10;
  const userId = fake.addUser();
  const now = Math.floor(Date.now() / 1000);
  const tokenWith = async (options) => {
    const sessionId = crypto.randomUUID();
    fake.sessions.set(sessionId, { userId, revoked: false });
    return fake.token({ userId, sessionId, ...options });
  };
  // Inside the tolerance: accepted.
  await server.resolveSession(req(await tokenWith({ iat: now - 60, exp: now - 3 })));
  await server.resolveSession(req(await tokenWith({ claims: { nbf: now + 3 } })));
  await server.resolveSession(req(await tokenWith({ iat: now + 3 })));
  await rejects(server.resolveSession(req(await tokenWith({ iat: now - 60, exp: now - 10 }))), 'expired');
  const invalid = [
    { claims: { nbf: now + 30 } },
    { iat: now + 30, exp: now + 1800 },
    { claims: { iss: 'https://other.example.test/auth/v1' } },
    { claims: { aud: 'anon' } },
    { claims: { is_anonymous: true } },
    { claims: { is_anonymous: undefined } },
    { claims: { aal: 'aal3' } },
    { claims: { aal: undefined } },
    { claims: { session_id: undefined } },
    { claims: { session_id: '' } },
    { claims: { role: 'service_role' } },
    { claims: { sub: 'not-a-uuid' } },
    { claims: { exp: undefined } },
    { claims: { iat: undefined } },
  ];
  for (const options of invalid) await rejects(server.resolveSession(req(await tokenWith(options))), 'invalid_token');
  assert.equal(fake.callsTo('user').length, 3, 'rejected tokens never reach Auth');
});

test('signatures: tampering, HS256 and unknown keys are invalid; rotation is picked up; JWKS failures are unavailable', async () => {
  const { fake, server } = await setup();
  const userId = fake.addUser();
  const { token } = await fake.signIn(userId);
  await server.resolveSession(req(token));
  const [h, p, s] = token.split('.');
  const flipped = `${h}.${p}.${s.slice(0, -2)}${s.at(-2) === 'A' ? 'B' : 'A'}${s.at(-1)}`;
  await rejects(server.resolveSession(req(flipped)), 'invalid_token');
  const forgedPayload = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(p, 'base64url')), sub: fake.addUser() })).toString('base64url');
  await rejects(server.resolveSession(req(`${h}.${forgedPayload}.${s}`)), 'invalid_token');
  const hs = { kid: crypto.randomUUID(), alg: 'HS256', privateKey: new TextEncoder().encode('0123456789abcdef0123456789abcdef') };
  await rejects(server.resolveSession(req(await fake.token({ userId, key: hs }))), 'invalid_token');
  const none = `${Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url')}.${p}.`;
  await rejects(server.resolveSession(req(none)), 'invalid_token');

  // A key that was never published: a fresh key set still lacks it.
  const rogue = await newSigningKey('ES256');
  const coldServer = createAuthServer({ supabaseUrl: fake.origin, publishableKey: PUBLISHABLE_KEY, clientId: CLIENT, fetch: fake.fetch });
  await rejects(coldServer.resolveSession(req(await fake.token({ userId, key: rogue }))), 'invalid_token');
  assert.equal(fake.callsTo('jwks').length, 2);

  // A fresh server whose key set cannot be fetched cannot judge any token.
  for (const hook of [async () => jsonResponse(500, {}), async () => { throw new TypeError('down'); }, async () => new Response('nope', { status: 200 })]) {
    const cold = createAuthServer({ supabaseUrl: fake.origin, publishableKey: PUBLISHABLE_KEY, clientId: CLIENT, fetch: fake.fetch });
    fake.hooks.set('jwks', hook);
    await rejects(cold.resolveSession(req(token)), 'unavailable');
  }
});

test('a JWKS endpoint that never answers is abandoned at its deadline', async () => {
  const { fake } = await setup();
  const userId = fake.addUser();
  const { token } = await fake.signIn(userId);
  const server = createAuthServer({ supabaseUrl: fake.origin, publishableKey: PUBLISHABLE_KEY, clientId: CLIENT, fetch: fake.fetch, requestTimeoutMs: 150 });
  fake.hooks.set('jwks', () => new Promise(() => {}));
  const started = performance.now();
  await rejects(server.resolveSession(req(token)), 'unavailable');
  assert.ok(performance.now() - started < 2_000);
});

test('an injected clock drives expiry: skew beyond tolerance is refused, inside it accepted', async () => {
  const fake = await createFakeSupabase();
  fake.rpc = async ({ args }) => jsonResponse(200, accessSnapshot(args.client_id, []));
  const userId = fake.addUser();
  const { token } = await fake.signIn(userId, { iat: 1_000_000, exp: 1_001_800 });
  fake.now = () => 1_001_000 * 1000;
  const at = (seconds) => createAuthServer({ supabaseUrl: fake.origin, publishableKey: PUBLISHABLE_KEY, clientId: CLIENT, fetch: fake.fetch, now: () => seconds * 1000 });
  await at(1_001_804).resolveSession(req(token));
  await rejects(at(1_001_806).resolveSession(req(token)), 'expired');
  await rejects(at(999_990).resolveSession(req(token)), 'invalid_token');
  await at(999_996).resolveSession(req(token));
});

test('key rotation: a new key id inside the JWKS cooldown is unavailable (retry), then accepted after one refetch', async (t) => {
  mock.timers.enable({ apis: ['Date'], now: Date.now() });
  t.after(() => mock.timers.reset());
  const { fake, grants, server } = await setup();
  const userId = fake.addUser();
  grants.set(`${userId}|${CLIENT}`, [customer]);
  await server.resolveSession(req((await fake.signIn(userId)).token));
  assert.equal(fake.callsTo('jwks').length, 1);
  const next = await newSigningKey('RS256');
  fake.keys.push(next);
  const rotated = (await fake.signIn(userId, { key: next })).token;
  await rejects(server.resolveSession(req(rotated)), 'unavailable');
  assert.equal(fake.callsTo('jwks').length, 1, 'no refetch storm inside the cooldown');
  mock.timers.tick(31_000);
  const principal = await server.resolveSession(req(rotated));
  assert.equal(principal.identity.userId, userId);
  assert.equal(fake.callsTo('jwks').length, 2);
  // The old key is withdrawn: after the cache ages out its tokens are refused.
  const oldToken = (await fake.signIn(userId)).token;
  fake.keys.shift();
  mock.timers.tick(601_000);
  await rejects(server.resolveSession(req(oldToken)), 'invalid_token');
});
