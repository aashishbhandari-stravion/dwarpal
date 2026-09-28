// The optional Hono middleware with a real Hono app (dev dependency): it sets
// c.var.principal, answers 401 for missing or rejected tokens and 503 when
// the kit cannot decide, and never lets a request through without a
// resolved principal.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Hono } from 'hono';
import { honoMiddleware } from '../../packages/server/hono.js';
import { createAuthServer, requirePermission, AuthError } from '../../packages/server/index.js';
import { createFakeSupabase, PUBLISHABLE_KEY, jsonResponse } from './support/fake-supabase.js';
import { accessSnapshot } from './support/snapshots.js';

async function setup() {
  const fake = await createFakeSupabase();
  fake.rpc = async ({ args, actor }) => jsonResponse(200, accessSnapshot(args.client_id, [{ role: 'reader', permissions: ['posts:read'] }], actor.claims.aal));
  const auth = createAuthServer({ supabaseUrl: fake.origin, publishableKey: PUBLISHABLE_KEY, clientId: 'studio', fetch: fake.fetch, requestTimeoutMs: 200 });
  let reached = 0;
  const app = new Hono();
  app.use('/api/*', honoMiddleware(auth));
  app.get('/api/posts', (c) => {
    reached += 1;
    const principal = c.var.principal;
    try {
      requirePermission(principal, c.req.query('key') ?? 'posts:read');
    } catch (error) {
      if (error instanceof AuthError) return c.json({ error: error.code }, 403);
      throw error;
    }
    return c.json({ user: principal.identity.userId });
  });
  return { fake, app, reached: () => reached };
}

test('sets c.var.principal for a live session', async () => {
  const { fake, app, reached } = await setup();
  const userId = fake.addUser();
  const { token } = await fake.signIn(userId);
  const res = await app.request('/api/posts', { headers: { authorization: `Bearer ${token}` } });
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { user: userId });
  const denied = await app.request('/api/posts?key=posts:delete', { headers: { authorization: `Bearer ${token}` } });
  assert.equal(denied.status, 403);
  assert.equal(reached(), 2);
});

test('401 for missing, malformed, expired or revoked tokens; 503 when unavailable; handler never reached', async () => {
  const { fake, app, reached } = await setup();
  const userId = fake.addUser();
  const live = await fake.signIn(userId);
  const expired = (await fake.signIn(userId, { iat: 1_000_000, exp: 1_000_100 })).token;
  assert.equal((await app.request('/api/posts')).status, 401);
  assert.deepEqual(await (await app.request('/api/posts')).json(), { error: 'no_token' });
  assert.equal((await app.request('/api/posts', { headers: { authorization: 'Basic x' } })).status, 401);
  const expiredRes = await app.request('/api/posts', { headers: { authorization: `Bearer ${expired}` } });
  assert.equal(expiredRes.status, 401);
  assert.deepEqual(await expiredRes.json(), { error: 'expired' });
  fake.hooks.set('user', async () => jsonResponse(500, { msg: 'down' }));
  const down = await app.request('/api/posts', { headers: { authorization: `Bearer ${live.token}` } });
  assert.equal(down.status, 503);
  assert.deepEqual(await down.json(), { error: 'unavailable' });
  fake.hooks.clear();
  fake.sessions.get(live.sessionId).revoked = true;
  const revoked = await app.request('/api/posts', { headers: { authorization: `Bearer ${live.token}` } });
  assert.equal(revoked.status, 401);
  assert.deepEqual(await revoked.json(), { error: 'invalid_token' });
  assert.equal(reached(), 0);
});

test('an auth server that throws something unexpected fails closed with 503', async () => {
  const app = new Hono();
  app.use('*', honoMiddleware({ resolveSession: async () => { throw new Error('bug'); } }));
  app.get('/', (c) => c.text('reached'));
  const res = await app.request('/');
  assert.equal(res.status, 503);
  assert.throws(() => honoMiddleware({}), TypeError);
});
