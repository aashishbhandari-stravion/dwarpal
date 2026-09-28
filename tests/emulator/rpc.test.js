// auth_kit RPC contract of the development fixture through the pinned
// @supabase/supabase-js 2.117.2 PostgREST client: the integrated SQL wrappers'
// argument names, JSON results, order of checks, DW001 refusals, aal
// activation, durable enrollment, request-id semantics and client isolation.
// Synthetic fixture evidence only; the SQL suite proves the real functions.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { FIXTURE_CLIENT_ID, FIXTURE_MODEL, fixturePrincipal } from '@briqvent/dwarpal/testing';
import {
  PASSWORD, client, clientSnapshot, liveStudio, raiseToAal2, randomUuid, raw, signedIn, start, studioModel,
} from './support.js';

const refusal = (result, code) => {
  assert.equal(result.status, 400);
  assert.equal(result.data, null);
  assert.deepEqual(result.error, { code: 'DW001', details: null, hint: null, message: code });
};
const sansTime = (snapshot) => ({ ...snapshot, httpRequests: undefined });

test('ensure_profile and effective_access: exact wrapper shapes; the profile upsert is idempotent', async (t) => {
  const emulator = await start(t);
  emulator.controls.seedClient({ clientId: 'studio', signupPolicy: 'open', model: studioModel() });
  const { kit, userId } = await signedIn(emulator, 'shape@example.test');
  const first = await kit.rpc('ensure_profile');
  assert.equal(first.status, 200);
  assert.deepEqual(Object.keys(first.data).sort(), ['contact_email', 'contact_phone', 'display_name', 'updated_at', 'user_id']);
  assert.equal(first.data.user_id, userId);
  assert.match(first.data.updated_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/);
  assert.deepEqual((await kit.rpc('ensure_profile')).data, first.data);
  assert.equal(emulator.controls.snapshot().counts.profiles, 1);

  const access = await kit.rpc('effective_access', { client_id: 'studio' });
  assert.deepEqual(access.data, { client_id: 'studio', enrolled_at: null, memberships: [], active_roles: [], permissions: [], mfa_pending: false });
  const viaGet = await kit.rpc('effective_access', { client_id: 'studio' }, { get: true });
  assert.deepEqual(viaGet.data, access.data, 'the stable function also answers GET');

  const joined = await kit.rpc('join_client', { client_id: 'studio' });
  assert.deepEqual(Object.keys(joined.data).sort(), ['enrolled_at', 'granted_roles', 'result']);
  assert.deepEqual(joined.data.granted_roles, ['member', 'reader']);
  const after = (await kit.rpc('effective_access', { client_id: 'studio' })).data;
  assert.equal(after.enrolled_at, joined.data.enrolled_at);
  assert.deepEqual(after.memberships[0], {
    role_key: 'member', flags: { self_assignable: true, manages_members: false, mfa_required: false },
    granted_at: joined.data.enrolled_at, granted_via: 'join', permissions: ['records:read:own'],
  });
  assert.deepEqual(after.active_roles, ['member', 'reader']);
  assert.deepEqual(after.permissions, ['files:read:own', 'records:read:own']);
});

test('join_client outcome matrix (F7, L21): outcomes that write nothing, then enrolled, then already_enrolled', async (t) => {
  const emulator = await start(t);
  const { controls } = emulator;
  controls.seedClient({ clientId: 'studio', signupPolicy: 'open', model: studioModel() });
  controls.seedClient({ clientId: 'club', signupPolicy: 'closed', model: studioModel('club') });
  const noDefault = studioModel('no-default');
  for (const role of Object.values(noDefault.roles)) role.self_assignable = false;
  controls.seedClient({ clientId: 'no-default', signupPolicy: 'open', model: noDefault });
  controls.seedClient({ clientId: 'bare', signupPolicy: 'open', model: null });
  const { kit, userId } = await signedIn(emulator, 'joiner@example.test');
  const before = sansTime(controls.snapshot());

  controls.setEmailConfirmed({ userId, confirmed: false });
  assert.deepEqual((await kit.rpc('join_client', { client_id: 'studio' })).data, { result: 'email_unverified' });
  controls.setEmailConfirmed({ userId, confirmed: true });
  assert.deepEqual((await kit.rpc('join_client', { client_id: 'nowhere' })).data, { result: 'unknown_client' });
  assert.deepEqual((await kit.rpc('join_client', { client_id: 'club' })).data, { result: 'closed' });
  assert.deepEqual((await kit.rpc('join_client', { client_id: 'no-default' })).data, { result: 'no_default_role' });
  assert.deepEqual((await kit.rpc('join_client', { client_id: 'bare' })).data, { result: 'no_default_role' });
  refusal(await kit.rpc('join_client', { client_id: null }), 'invalid_argument');
  assert.deepEqual(sansTime(controls.snapshot()), before, 'none of these outcomes writes anything');

  const enrolled = (await kit.rpc('join_client', { client_id: 'studio' })).data;
  assert.equal(enrolled.result, 'enrolled');
  const once = clientSnapshot(emulator);
  assert.equal(once.enrollments.length, 1);
  assert.deepEqual(once.events.map((e) => [e.action, e.roleKey, e.actorKind, e.actorUserId, e.requestId]),
    [['join', 'member', 'user', userId, null], ['join', 'reader', 'user', userId, null]]);
  assert.equal(once.requestLog.length, 0, 'join_client has no request id and no request log row (R1)');
  const retry = (await kit.rpc('join_client', { client_id: 'studio' })).data;
  assert.deepEqual(retry, { result: 'already_enrolled', enrolled_at: enrolled.enrolled_at });
  assert.deepEqual(clientSnapshot(emulator), once, 'a retry writes nothing');

  // The empty string is a literal client id, not a wildcard.
  controls.seedClient({ clientId: '', signupPolicy: 'open', model: studioModel('') });
  assert.equal((await kit.rpc('join_client', { client_id: '' })).data.result, 'enrolled');
  assert.equal(clientSnapshot(emulator).enrollments.length, 1);
});

test('L27: a revoked membership is never silently re-granted by a later sign-in or join; only a manager grant restores it', async (t) => {
  const emulator = await start(t);
  const { steward } = await liveStudio(emulator);
  const { factorId } = steward;
  await raiseToAal2(emulator, steward.supabase, factorId);
  const user = await signedIn(emulator, 'durable@example.test');
  await user.kit.rpc('join_client', { client_id: 'studio' });

  const revoked = await steward.kit.rpc('revoke_membership', { user_id: user.userId, client_id: 'studio', role_key: 'member', request_id: randomUuid() });
  assert.equal(revoked.data.result, 'revoked');
  emulator.controls.setMembership({ userId: user.userId, clientId: 'studio', roleKey: 'reader', present: false });

  const again = client(emulator);
  await again.auth.signInWithPassword({ email: 'durable@example.test', password: PASSWORD });
  const kit = again.schema('auth_kit');
  const access = (await kit.rpc('effective_access', { client_id: 'studio' })).data;
  assert.notEqual(access.enrolled_at, null, 'the enrollment marker survives revocation');
  assert.deepEqual(access.memberships, []);
  assert.equal((await kit.rpc('join_client', { client_id: 'studio' })).data.result, 'already_enrolled');
  assert.deepEqual((await kit.rpc('effective_access', { client_id: 'studio' })).data.memberships, []);

  const regrant = await steward.kit.rpc('grant_membership', { user_id: user.userId, client_id: 'studio', role_key: 'member', request_id: randomUuid() });
  assert.equal(regrant.data.result, 'granted');
  const restored = (await kit.rpc('effective_access', { client_id: 'studio' })).data.memberships;
  assert.deepEqual(restored.map((m) => [m.role_key, m.granted_via]), [['member', 'manager']]);
  assert.deepEqual(clientSnapshot(emulator).events.map((e) => `${e.action}:${e.roleKey}`),
    ['bootstrap:steward', 'join:member', 'join:reader', 'revoke:member', 'grant:member']);
});

test('a role a manager granted before the first join is not granted twice', async (t) => {
  const emulator = await start(t);
  await liveStudio(emulator);
  const convener = await signedIn(emulator, 'convener@example.test');
  emulator.controls.setMembership({ userId: convener.userId, clientId: 'studio', roleKey: 'convener', present: true });
  const user = await signedIn(emulator, 'early@example.test');
  await convener.kit.rpc('grant_membership', { user_id: user.userId, client_id: 'studio', role_key: 'member', request_id: randomUuid() });
  const joined = (await user.kit.rpc('join_client', { client_id: 'studio' })).data;
  assert.deepEqual(joined.granted_roles, ['reader']);
  const memberships = (await user.kit.rpc('effective_access', { client_id: 'studio' })).data.memberships;
  assert.deepEqual(memberships.map((m) => `${m.role_key}:${m.granted_via}`), ['member:manager', 'reader:join']);
});

test('aal activation matches core evaluation of the shared fixture model at aal1 and aal2 (L14, L20)', async (t) => {
  const emulator = await start(t);
  const holders = [['patron'], ['clerk'], ['patron', 'clerk'], ['lead'], ['coordinator'], ['lead', 'coordinator'], []];
  const manager = emulator.controls.seedUser({ email: 'bootstrap@example.test', password: PASSWORD });
  emulator.controls.seedClient({ clientId: FIXTURE_CLIENT_ID, signupPolicy: 'open', model: FIXTURE_MODEL, state: 'live', managerUserId: manager.userId, managerRoleKey: 'coordinator' });
  for (const [index, roles] of holders.entries()) {
    const user = await signedIn(emulator, `holder-${index}@example.test`, { aal: 'aal2' });
    await user.kit.rpc('join_client', { client_id: FIXTURE_CLIENT_ID });
    emulator.controls.setMembership({ userId: user.userId, clientId: FIXTURE_CLIENT_ID, roleKey: 'patron', present: false });
    for (const roleKey of roles) emulator.controls.setMembership({ userId: user.userId, clientId: FIXTURE_CLIENT_ID, roleKey, present: true });
    for (const aal of ['aal1', 'aal2']) {
      if (aal === 'aal2') await raiseToAal2(emulator, user.supabase, user.factorId);
      const access = (await user.kit.rpc('effective_access', { client_id: FIXTURE_CLIENT_ID })).data;
      const expected = fixturePrincipal({ roles, aal, userId: user.userId }).access;
      const label = `${roles.join('+') || 'none'} at ${aal}`;
      assert.deepEqual(access.memberships.map((m) => m.role_key), expected.roles, label);
      assert.deepEqual(access.active_roles, expected.activeRoles, label);
      assert.deepEqual(access.permissions, expected.permissions, label);
      assert.equal(access.mfa_pending, expected.mfaPending, label);
    }
  }
});

test('manager grant/revoke: request-id replay, conflict, cross-actor reuse and no-op outcomes (L30)', async (t) => {
  const emulator = await start(t);
  await liveStudio(emulator);
  const convener = await signedIn(emulator, 'convener@example.test');
  const second = await signedIn(emulator, 'second@example.test');
  for (const manager of [convener, second]) emulator.controls.setMembership({ userId: manager.userId, clientId: 'studio', roleKey: 'convener', present: true });
  const target = await signedIn(emulator, 'target@example.test');
  const id = randomUuid();
  const args = { user_id: target.userId.toUpperCase(), client_id: 'studio', role_key: 'curator', request_id: id };

  const granted = await convener.kit.rpc('grant_membership', args);
  assert.deepEqual(granted.data, { result: 'granted', user_id: target.userId, client_id: 'studio', role_key: 'curator' });
  const once = clientSnapshot(emulator);
  assert.equal(once.events.at(-1).actorUserId, convener.userId);
  assert.equal(once.events.at(-1).requestId, id);
  assert.deepEqual((await convener.kit.rpc('grant_membership', args)).data, granted.data, 'same id and payload: the stored result');
  assert.deepEqual(clientSnapshot(emulator), once, 'a replay writes nothing');
  refusal(await convener.kit.rpc('grant_membership', { ...args, role_key: 'member' }), 'request_conflict');
  refusal(await convener.kit.rpc('revoke_membership', args), 'request_conflict');
  refusal(await second.kit.rpc('grant_membership', args), 'request_conflict');
  assert.deepEqual(clientSnapshot(emulator), once);

  const noop = await convener.kit.rpc('grant_membership', { ...args, request_id: randomUuid() });
  assert.equal(noop.data.result, 'already_member');
  const afterNoop = clientSnapshot(emulator);
  assert.equal(afterNoop.events.length, once.events.length, 'a no-op writes no event');
  assert.equal(afterNoop.requestLog.length, once.requestLog.length + 1, 'but does record its request id');

  const revokeId = randomUuid();
  assert.equal((await convener.kit.rpc('revoke_membership', { ...args, request_id: revokeId })).data.result, 'revoked');
  assert.equal((await convener.kit.rpc('revoke_membership', { ...args, request_id: revokeId })).data.result, 'revoked');
  assert.equal((await convener.kit.rpc('revoke_membership', { ...args, request_id: randomUuid() })).data.result, 'not_member');
  assert.deepEqual(clientSnapshot(emulator).events.slice(-2).map((e) => e.action), ['grant', 'revoke']);
});

test('manager authority and target rules refuse with DW001 and write nothing (L19, L34 subset)', async (t) => {
  const emulator = await start(t);
  const { steward } = await liveStudio(emulator);
  const plain = await signedIn(emulator, 'plain@example.test');
  await plain.kit.rpc('join_client', { client_id: 'studio' });
  const pending = emulator.controls.seedUser({ email: 'pending@example.test', password: PASSWORD, confirmed: false });
  const target = await signedIn(emulator, 'target@example.test');
  const grant = (actor, overrides = {}) => actor.kit.rpc('grant_membership', {
    user_id: target.userId, client_id: 'studio', role_key: 'curator', request_id: randomUuid(), ...overrides,
  });
  const before = clientSnapshot(emulator);

  refusal(await grant(steward), 'mfa_required');
  refusal(await grant(plain), 'forbidden');
  await raiseToAal2(emulator, steward.supabase, steward.factorId);
  refusal(await grant(steward, { role_key: 'convener' }), 'forbidden');
  refusal(await grant(steward, { role_key: 'ghost' }), 'unknown_role');
  refusal(await grant(steward, { user_id: randomUuid() }), 'unknown_user');
  refusal(await grant(steward, { user_id: pending.userId }), 'email_unverified');
  refusal(await grant(steward, { user_id: steward.userId }), 'forbidden');
  refusal(await grant(steward, { role_key: null }), 'invalid_argument');
  refusal(await steward.kit.rpc('revoke_membership', { user_id: steward.userId, client_id: 'studio', role_key: 'steward', request_id: randomUuid() }), 'forbidden');
  assert.deepEqual(clientSnapshot(emulator), before, 'refusals write neither events nor request log rows');

  const badUuid = await grant(steward, { user_id: 'not-a-uuid' });
  assert.equal(badUuid.status, 400);
  assert.equal(badUuid.error.code, '22P02', 'a type error is a database failure, not a kit refusal');
  assert.equal((await grant(steward)).data.result, 'granted');
});

test('client isolation: a manager of one client is nobody in another; access names the requested client only', async (t) => {
  const emulator = await start(t);
  const { steward } = await liveStudio(emulator, 'alpha');
  await liveStudio(emulator, 'beta');
  await raiseToAal2(emulator, steward.supabase, steward.factorId);
  const user = await signedIn(emulator, 'cross@example.test');
  await user.kit.rpc('join_client', { client_id: 'alpha' });

  refusal(await steward.kit.rpc('grant_membership', { user_id: user.userId, client_id: 'beta', role_key: 'curator', request_id: randomUuid() }), 'forbidden');
  const beta = (await user.kit.rpc('effective_access', { client_id: 'beta' })).data;
  assert.deepEqual(beta, { client_id: 'beta', enrolled_at: null, memberships: [], active_roles: [], permissions: [], mfa_pending: false });
  assert.equal(clientSnapshot(emulator, 'beta').enrollments.length, 0);
  const stewardBeta = (await steward.kit.rpc('effective_access', { client_id: 'beta' })).data;
  assert.deepEqual(stewardBeta.memberships, [], "alpha's manager holds nothing in beta");

  const elsewhere = await start(t);
  const foreignToken = (await user.supabase.auth.getSession()).data.session.access_token;
  const foreign = await raw(elsewhere, '/rest/v1/rpc/effective_access', {
    method: 'POST', body: { client_id: 'alpha' }, headers: { authorization: `Bearer ${foreignToken}`, 'content-profile': 'auth_kit' },
  });
  assert.equal(foreign.status, 401, 'a token signed by another fixture instance is refused');
  assert.equal((await foreign.json()).code, 'PGRST301');
});

test('PostgREST surface: schema routing, private schema, operator functions, anon, argument matching and text rules', async (t) => {
  const emulator = await start(t);
  emulator.controls.seedClient({ clientId: 'studio', signupPolicy: 'open', model: studioModel() });
  const { supabase, kit } = await signedIn(emulator, 'surface@example.test');
  const publicSchema = await supabase.rpc('join_client', { client_id: 'studio' });
  assert.equal(publicSchema.status, 404);
  assert.equal(publicSchema.error.code, 'PGRST202');
  const privateSchema = await supabase.schema('auth_kit_private').rpc('join_client_impl', { p_client_id: 'studio' });
  assert.equal(privateSchema.status, 406);
  assert.equal(privateSchema.error.code, 'PGRST106');
  const operator = await kit.rpc('bootstrap_manager', { user_id: randomUuid(), client_id: 'studio', role_key: 'steward', request_id: randomUuid() });
  assert.equal(operator.status, 403);
  assert.equal(operator.error.code, '42501');
  assert.equal((await kit.rpc('no_such_function')).error.code, 'PGRST202');
  assert.equal((await kit.rpc('join_client', { client_id: 'studio', extra: 1 })).error.code, 'PGRST202');
  assert.equal((await kit.rpc('join_client', {})).error.code, 'PGRST202');
  const getVolatile = await kit.rpc('join_client', { client_id: 'studio' }, { get: true });
  assert.equal(getVolatile.status, 405);
  const nul = await kit.rpc('effective_access', { client_id: 'a\u0000b' });
  assert.equal(nul.error.code, '22P05');
  const surrogate = await kit.rpc('effective_access', { client_id: '\ud800' });
  assert.equal(surrogate.error.code, '22P02');
  assert.equal(emulator.controls.snapshot().counts.enrollments, 0);

  const anon = client(emulator).schema('auth_kit');
  for (const fn of ['ensure_profile', 'join_client', 'effective_access']) {
    const result = await anon.rpc(fn, fn === 'ensure_profile' ? {} : { client_id: 'studio' });
    assert.equal(result.status, 401, fn);
    assert.equal(result.error.code, '42501', fn);
  }
});

test('L27 concurrency: many simultaneous first joins produce one enrollment and one event per role', async (t) => {
  const emulator = await start(t);
  emulator.controls.seedClient({ clientId: 'studio', signupPolicy: 'open', model: studioModel() });
  const { kit } = await signedIn(emulator, 'racer@example.test');
  const results = await Promise.all(Array.from({ length: 12 }, () => kit.rpc('join_client', { client_id: 'studio' })));
  const outcomes = results.map((r) => r.data.result).sort();
  assert.deepEqual(outcomes, ['already_enrolled', ...Array(10).fill('already_enrolled'), 'enrolled'].sort());
  const snapshot = clientSnapshot(emulator);
  assert.equal(snapshot.enrollments.length, 1);
  assert.equal(snapshot.memberships.length, 2);
  assert.equal(snapshot.events.length, 2);
});

test('concurrent grants with one request id: one membership, one event, one stored result', async (t) => {
  const emulator = await start(t);
  await liveStudio(emulator);
  const convener = await signedIn(emulator, 'convener@example.test');
  emulator.controls.setMembership({ userId: convener.userId, clientId: 'studio', roleKey: 'convener', present: true });
  const target = await signedIn(emulator, 'target@example.test');
  const args = { user_id: target.userId, client_id: 'studio', role_key: 'curator', request_id: randomUuid() };
  const results = await Promise.all(Array.from({ length: 8 }, () => convener.kit.rpc('grant_membership', args)));
  assert.ok(results.every((r) => r.data?.result === 'granted'));
  const snapshot = clientSnapshot(emulator);
  assert.equal(snapshot.events.filter((e) => e.action === 'grant').length, 1);
  assert.equal(snapshot.requestLog.length, 1);
});
