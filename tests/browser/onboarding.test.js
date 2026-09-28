// Verified-user onboarding order, join outcomes, safe join retry, revoked
// membership and fail-closed RPC answers (design 7; L4, L21, L27 browser part).
// SYNTHETIC: real supabase-js 2.117.2 over the scripted fixture in support/.

import test from 'node:test';
import assert from 'node:assert/strict';
import { setup, signedIn, reopen, openController, CLIENT_ID, MODEL_ROLES } from './support/env.js';
import { createScriptedSupabase } from './support/scripted-supabase.js';

const ONBOARDING = ['password_sign_in', 'get_user', 'ensure_profile', 'effective_access', 'join_client', 'effective_access'];

test('first sign-in runs ensure_profile, effective_access, join_client, effective_access in that order, then navigates', async () => {
  const { fixture, controller, tab } = await signedIn();
  assert.deepEqual(fixture.operations(), ONBOARDING);
  const view = controller.getView();
  assert.equal(view.state, 'signed_in');
  assert.deepEqual(view.principal.access.roles, ['member']);
  assert.deepEqual(tab.navigations, ['/app']);
  for (const request of fixture.requests.filter((r) => r.path.startsWith('/rest/'))) assert.equal(request.bearer, 'user');
});

test('an enrolled user signs in without join_client', async () => {
  const fixture = createScriptedSupabase();
  fixture.seedClient({ clientId: CLIENT_ID, roles: MODEL_ROLES });
  await signedIn({ fixture });
  const before = fixture.count('join_client');
  const again = await signedIn({ fixture, skipClient: true });
  assert.equal(fixture.count('join_client'), before, 'no join once enrolled_at is set');
  assert.equal(again.controller.getView().state, 'signed_in');
  assert.equal(fixture.snapshot().joinEvents, 1);
});

test('L4/L27: a join that commits but loses its answer shows setup_pending; the explicit retry never joins twice', async () => {
  const fixture = createScriptedSupabase();
  fixture.seedClient({ clientId: CLIENT_ID, roles: MODEL_ROLES });
  fixture.fault('join_client', 'lost_after_commit');
  const { controller } = await signedIn({ fixture });
  const pending = controller.getView();
  assert.deepEqual([pending.state, pending.setupReason, pending.canRetry], ['setup_pending', 'unavailable', true]);
  assert.equal(fixture.snapshot().joinEvents, 1, 'the write committed');
  const joinsBefore = fixture.count('join_client');
  for (let i = 0; i < 3; i += 1) await controller.retry();
  assert.equal(controller.getView().state, 'signed_in');
  assert.equal(fixture.count('join_client'), joinsBefore, 'enrolled_at is now set, so no further join is sent');
  assert.equal(fixture.snapshot().enrollments, 1);
  assert.equal(fixture.snapshot().joinEvents, 1, 'exactly one membership event');
  assert.deepEqual(fixture.snapshot().memberships, ['studio:member:join']);
});

test('L4: PostgREST briefly down on join gives setup_pending with an explicit retry and no automatic loop', async () => {
  const fixture = createScriptedSupabase();
  fixture.seedClient({ clientId: CLIENT_ID, roles: MODEL_ROLES });
  fixture.fault('join_client', 'http_503');
  const { controller } = await signedIn({ fixture });
  assert.equal(controller.getView().state, 'setup_pending');
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal(fixture.count('join_client'), 1, 'nothing retries by itself');
  const view = await controller.retry();
  assert.equal(view.state, 'signed_in');
  assert.equal(fixture.count('join_client'), 2);
  assert.equal(fixture.snapshot().joinEvents, 1);
});

test('L21: unknown_client and no_default_role are setup_pending with retry; nothing is written', async () => {
  const unknown = await signedIn({ skipClient: true });
  assert.deepEqual([unknown.controller.getView().state, unknown.controller.getView().setupReason], ['setup_pending', 'unknown_client']);
  assert.equal(unknown.controller.getView().canRetry, true);
  assert.equal(unknown.fixture.snapshot().enrollments, 0);

  const fixture = createScriptedSupabase();
  fixture.seedClient({ clientId: CLIENT_ID, roles: { staff: MODEL_ROLES.staff } });
  const noRole = await signedIn({ fixture, skipClient: true });
  assert.deepEqual([noRole.controller.getView().state, noRole.controller.getView().setupReason], ['setup_pending', 'no_default_role']);
  assert.equal(fixture.snapshot().enrollments, 0);

  // The operator finishes setup; the user's explicit retry then enrolls.
  fixture.seedClient({ clientId: CLIENT_ID, roles: MODEL_ROLES });
  assert.equal((await noRole.controller.retry()).state, 'signed_in');
  assert.equal(fixture.snapshot().enrollments, 1);
});

test('L21: a closed client is no_access with no retry and no further join', async () => {
  const fixture = createScriptedSupabase();
  fixture.seedClient({ clientId: CLIENT_ID, signupPolicy: 'closed', roles: MODEL_ROLES });
  const { controller } = await signedIn({ fixture, skipClient: true });
  const view = controller.getView();
  assert.deepEqual([view.state, view.canRetry, view.setupReason], ['no_access', false, null]);
  await controller.retry();
  assert.equal(fixture.count('join_client'), 1);
  assert.equal(fixture.snapshot().enrollments, 0);
});

test('L27: a manager revoke stays revoked: later sign-ins show no_access and never re-grant', async () => {
  const fixture = createScriptedSupabase();
  fixture.seedClient({ clientId: CLIENT_ID, roles: MODEL_ROLES });
  const first = await signedIn({ fixture });
  fixture.revoke(first.userId, CLIENT_ID, 'member');
  const again = await signedIn({ fixture, skipClient: true });
  const view = again.controller.getView();
  assert.equal(view.state, 'no_access');
  assert.deepEqual(view.principal.access.roles, []);
  assert.deepEqual(again.tab.navigations, [], 'no navigation to a protected page');
  assert.deepEqual(fixture.snapshot().memberships, []);
  assert.equal(fixture.snapshot().joinEvents, 1);
  assert.equal(fixture.count('join_client'), 1, 'the enrolled user is not joined again');
});

test('an unavailable or unreadable RPC answer never becomes a sign-in', async () => {
  const cases = [
    ['ensure_profile', 'http_503', 'error'],
    ['ensure_profile', 'transport_loss', 'offline'],
    ['ensure_profile', 'malformed', 'error'],
    ['effective_access', 'http_503', 'error'],
    ['effective_access', 'transport_loss', 'offline'],
    ['effective_access', 'malformed', 'error'],
    ['get_user', 'http_503', 'error'],
    ['get_user', 'transport_loss', 'offline'],
    // supabase-js reports an unparseable 2xx Auth body as a transport
    // failure (status 0), so the kit shows it as offline; still fail closed.
    ['get_user', 'malformed', 'offline'],
  ];
  for (const [operation, mode, state] of cases) {
    const fixture = createScriptedSupabase();
    fixture.seedClient({ clientId: CLIENT_ID, roles: MODEL_ROLES });
    fixture.fault(operation, mode);
    const { controller, tab } = await signedIn({ fixture });
    const view = controller.getView();
    assert.equal(view.state, state, `${operation} ${mode}`);
    assert.equal(view.principal, null);
    assert.equal(controller.getPrincipal(), null);
    assert.equal(view.canRetry, true);
    assert.deepEqual(tab.navigations, []);
    assert.equal((await controller.retry()).state, 'signed_in', `${operation} ${mode} recovers on explicit retry`);
  }
});

test('an access answer for another client, with a disagreeing active set or unknown join result, fails closed', async () => {
  const tamper = [
    (body) => ({ ...body, client_id: 'other' }),
    (body) => ({ ...body, active_roles: ['member', 'staff'] }),
    (body) => ({ ...body, mfa_pending: !body.mfa_pending }),
    (body) => ({ ...body, extra: 1 }),
    () => [],
    () => null,
  ];
  for (const change of tamper) {
    const fixture = createScriptedSupabase();
    fixture.seedClient({ clientId: CLIENT_ID, roles: MODEL_ROLES });
    const { controller, tab } = await signedIn({ fixture: wrapRpc(fixture, 'effective_access', change) });
    assert.deepEqual([controller.getView().state, controller.getView().error], ['error', 'unavailable']);
    assert.deepEqual(tab.navigations, []);
  }
  for (const result of ['granted', null, 'ENROLLED']) {
    const fixture = createScriptedSupabase();
    fixture.seedClient({ clientId: CLIENT_ID, roles: MODEL_ROLES });
    const { controller } = await signedIn({ fixture: wrapRpc(fixture, 'join_client', () => ({ result })) });
    assert.deepEqual([controller.getView().state, controller.getView().error], ['error', 'unavailable'], String(result));
  }
});

test('a DW001 refusal from an RPC is not success; other SQL errors are not refusals', async () => {
  const fixture = createScriptedSupabase();
  fixture.seedClient({ clientId: CLIENT_ID, roles: MODEL_ROLES });
  const refused = wrapRpcResponse(fixture, 'ensure_profile', () => new Response(JSON.stringify({ code: 'DW001', message: 'forbidden' }), { status: 400 }));
  const { controller } = await signedIn({ fixture: refused });
  assert.deepEqual([controller.getView().state, controller.getView().error], ['error', 'unavailable']);
  const joinFixture = createScriptedSupabase();
  joinFixture.seedClient({ clientId: CLIENT_ID, roles: MODEL_ROLES });
  const sqlError = wrapRpcResponse(joinFixture, 'join_client', () => new Response(JSON.stringify({ code: '40001', message: 'could not serialize' }), { status: 500 }));
  const joined = await signedIn({ fixture: sqlError });
  assert.deepEqual([joined.controller.getView().state, joined.controller.getView().setupReason], ['setup_pending', 'unavailable']);
});

test('join_client email_unverified returns to the verification screen', async () => {
  const fixture = createScriptedSupabase();
  fixture.seedClient({ clientId: CLIENT_ID, roles: MODEL_ROLES });
  const unverified = wrapRpc(fixture, 'join_client', () => ({ result: 'email_unverified' }));
  const { controller } = await signedIn({ fixture: unverified });
  const view = controller.getView();
  assert.deepEqual([view.screen, view.state, view.error], ['verify', 'error', 'email_unverified']);
});

test('a session signed out globally from another browser is ended locally on the next page load', async () => {
  const first = await signedIn();
  const elsewhere = await signedIn({ fixture: first.fixture, skipClient: true });
  await elsewhere.controller.signOut();
  assert.ok(first.tab.localStorage.keys().length > 0, 'this browser still holds its session');
  const later = openController(reopen(first.tab, '/account/mfa'), first.fixture);
  const view = await later.start();
  assert.deepEqual([view.screen, view.state, view.error], ['signIn', 'error', 'session_ended']);
  assert.deepEqual(first.tab.localStorage.keys(), [], 'the stale session is removed from this browser');
  assert.equal(first.fixture.count('ensure_profile'), 2, 'no RPC for the ended session');
});

test('a hung Auth answer ends as offline at the request deadline instead of waiting forever', async () => {
  const fixture = createScriptedSupabase();
  fixture.seedClient({ clientId: CLIENT_ID, roles: MODEL_ROLES });
  fixture.seedUser({ email: 'h@example.test' });
  const { controller } = await setup('/account/sign-in', { fixture, options: { requestTimeoutMs: 50 } });
  fixture.fault('password_sign_in', 'hang');
  const started = Date.now();
  const view = await controller.signIn({ email: 'h@example.test', password: 'correct horse battery' });
  assert.equal(view.state, 'offline');
  assert.ok(Date.now() - started < 1500);
});

// Rewrites one RPC's JSON answer while keeping the fixture's side effects.
function wrapRpc(fixture, name, change) {
  return wrapRpcResponse(fixture, name, async (response) => {
    const body = await response.json();
    return new Response(JSON.stringify(change(body)), { status: 200, headers: { 'content-type': 'application/json' } });
  });
}

function wrapRpcResponse(fixture, name, replace) {
  return {
    ...fixture,
    fetch: async (input, init) => {
      const response = await fixture.fetch(input, init);
      return new URL(input).pathname === `/rest/v1/rpc/${name}` ? replace(response) : response;
    },
  };
}
