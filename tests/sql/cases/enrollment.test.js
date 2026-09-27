// Enrollment matrix (L27, I12): once per user and client, durable revokes,
// outcomes for unknown/closed/unconfirmed/no-default clients, concurrent first
// joins on real sessions, and rollback after the enrollment insert.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { withDatabase, actors, dbError, lit } from '../harness/db.js';
import {
  exampleModel, register, applyModel, bootstrap, grant, revoke, join, snapshot, events,
} from '../harness/kit.js';

async function studio(db, { policy = 'open' } = {}) {
  await register(db, 'studio', { policy });
  await applyModel(db, 'studio', exampleModel('studio'));
  const steward = await db.createUser();
  await bootstrap(db, steward, 'studio', 'steward');
  return actors.user(steward);
}

async function memberships(db, user, client = 'studio') {
  const rows = await db.rows(`select role_key, granted_via from auth_kit_private.memberships
                               where user_id = ${lit(user)} and client_id = ${lit(client)} order by role_key`);
  return rows.map((r) => `${r.role_key}:${r.granted_via}`);
}

test('first join enrolls once with every self-assignable role and one join event per role', () => withDatabase(async (db) => {
  await studio(db);
  const user = await db.createUser();
  const result = await join(db, user, 'studio');
  assert.equal(result.result, 'enrolled');
  assert.deepEqual(result.granted_roles, ['member', 'reader']);
  assert.match(result.enrolled_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/);
  assert.deepEqual(await memberships(db, user), ['member:join', 'reader:join']);
  assert.equal(await db.count('auth_kit_private.enrollments', `user_id = ${lit(user)}`), 1);
  const joins = await events(db, `user_id = ${lit(user)}`);
  assert.deepEqual(joins.map((e) => [e.action, e.role_key, e.result, e.actor_kind, e.actor_user_id, e.request_id]), [
    ['join', 'member', 'enrolled', 'user', user, null], ['join', 'reader', 'enrolled', 'user', user, null],
  ]);
  // join_client carries no request id and writes no request_log row.
  assert.equal(await db.count('auth_kit_private.request_log', `client_id = 'studio' and operation not in ('apply_model', 'bootstrap_manager')`), 0);
}));

test('retry and sign-in after a manager revoke: already_enrolled, nothing re-granted; only a manager grant restores', () => withDatabase(async (db) => {
  const steward = await studio(db);
  const user = await db.createUser();
  await join(db, user, 'studio');
  const before = await snapshot(db);
  const retry = await join(db, user, 'studio');
  assert.equal(retry.result, 'already_enrolled');
  assert.deepEqual(await snapshot(db), before);

  await revoke(db, steward, user, 'studio', 'member');
  const afterRevoke = await snapshot(db);
  assert.equal((await join(db, user, 'studio')).result, 'already_enrolled');
  assert.deepEqual(await snapshot(db), afterRevoke);
  assert.deepEqual(await memberships(db, user), ['reader:join']);

  assert.equal((await grant(db, steward, user, 'studio', 'member')).result, 'granted');
  assert.deepEqual(await memberships(db, user), ['member:manager', 'reader:join']);
  const all = await events(db, `user_id = ${lit(user)}`);
  assert.deepEqual(all.map((e) => `${e.action}:${e.role_key}`), ['join:member', 'join:reader', 'revoke:member', 'grant:member']);
}));

test('outcomes that write nothing: unconfirmed email (auth.users, not the JWT), unknown client, closed, no default role', () => withDatabase(async (db) => {
  await studio(db);
  await register(db, 'closed-club', { policy: 'closed' });
  await applyModel(db, 'closed-club', exampleModel('closed-club'));
  await register(db, 'no-default');
  const invite = exampleModel('no-default');
  for (const role of Object.values(invite.roles)) role.self_assignable = false;
  await applyModel(db, 'no-default', invite);
  await register(db, 'bare');

  const unconfirmed = await db.createUser({ confirmed: false });
  const confirmed = await db.createUser();
  const before = await snapshot(db);
  // The JWT claims a verified email; the kit reads auth.users instead.
  const lying = actors.user(unconfirmed, 'aal1', { email: 'x@example.test', email_verified: true, user_metadata: { email_verified: true } });
  assert.deepEqual(await db.call(lying, 'auth_kit.join_client', { client_id: 'studio' }), { result: 'email_unverified' });
  assert.deepEqual(await join(db, confirmed, 'nowhere'), { result: 'unknown_client' });
  assert.deepEqual(await join(db, confirmed, 'closed-club'), { result: 'closed' });
  assert.deepEqual(await join(db, confirmed, 'no-default'), { result: 'no_default_role' });
  assert.deepEqual(await join(db, confirmed, 'bare'), { result: 'no_default_role' });
  // A user id with no auth.users row is not confirmed either.
  assert.deepEqual(await join(db, '00000000-0000-4000-8000-00000000dead', 'studio'), { result: 'email_unverified' });
  assert.deepEqual(await snapshot(db), before);

  // no_default_role left nothing behind, so the join succeeds once a role exists.
  await applyModel(db, 'bare', exampleModel('bare'));
  assert.equal((await join(db, confirmed, 'bare')).result, 'enrolled');
  // Confirmation later makes the earlier refusal retryable too.
  await db.admin.query(`update auth.users set email_confirmed_at = now() where id = ${lit(unconfirmed)}`);
  assert.equal((await join(db, unconfirmed, 'studio')).result, 'enrolled');
}));

test('two concurrent first joins serialise on the client lock: one enrollment, one event per role', () => withDatabase(async (db) => {
  await studio(db);
  const user = await db.createUser();
  const first = await db.session(actors.user(user));
  const second = await db.session(actors.user(user));
  await first.begin();
  assert.equal((await first.call('auth_kit.join_client', { client_id: 'studio' })).result, 'enrolled');
  await second.begin();
  const pending = second.call('auth_kit.join_client', { client_id: 'studio' });
  await db.waitForAdvisoryWait(second.pid);
  await first.commit();
  assert.equal((await pending).result, 'already_enrolled');
  await second.commit();
  assert.equal(await db.count('auth_kit_private.enrollments', `user_id = ${lit(user)}`), 1);
  assert.equal(await db.count('auth_kit_private.memberships', `user_id = ${lit(user)}`), 2);
  assert.equal(await db.count('auth_kit_private.membership_events', `user_id = ${lit(user)} and action = 'join'`), 2);
}));

test('a join that fails after the enrollment insert leaves no enrollment; the next join enrolls (injected faults)', () => withDatabase(async (db) => {
  await studio(db);
  await db.installFaults();
  const user = await db.createUser();
  const before = await snapshot(db);
  for (const table of ['memberships', 'membership_events', 'enrollments']) {
    const error = await dbError(db.call(actors.user(user), 'auth_kit.join_client', { client_id: 'studio' },
      { settings: [['dwarpal_test.fail_on', table]] }), 'DT001');
    assert.match(error.message, new RegExp(table));
    assert.deepEqual(await snapshot(db), before, `after fault on ${table}`);
  }
  assert.equal((await join(db, user, 'studio')).result, 'enrolled');
  assert.equal(await db.count('auth_kit_private.enrollments', `user_id = ${lit(user)}`), 1);
}));

test('a self-assignable role added later reaches future joiners only; the dry run says so', () => withDatabase(async (db) => {
  await studio(db);
  const early = await db.createUser();
  await join(db, early, 'studio');
  const next = exampleModel('studio');
  next.permissions['news:read'] = '';
  next.roles.subscriber = { self_assignable: true, permissions: ['news:read'] };
  const dry = await applyModel(db, 'studio', next, { dryRun: true });
  assert.deepEqual(dry.diff.find((d) => d.kind === 'role_added'), { kind: 'role_added', role: 'subscriber', reach: 'future_joiners' });
  await applyModel(db, 'studio', next);
  assert.deepEqual(await memberships(db, early), ['member:join', 'reader:join']);
  assert.equal((await join(db, early, 'studio')).result, 'already_enrolled');
  const late = await db.createUser();
  assert.deepEqual((await join(db, late, 'studio')).granted_roles, ['member', 'reader', 'subscriber']);
}));

test('a role granted by a manager before the first join is not granted twice', () => withDatabase(async (db) => {
  const steward = await studio(db);
  const user = await db.createUser();
  await grant(db, steward, user, 'studio', 'member');
  const result = await join(db, user, 'studio');
  assert.equal(result.result, 'enrolled');
  assert.deepEqual(result.granted_roles, ['reader']);
  assert.deepEqual(await memberships(db, user), ['member:manager', 'reader:join']);
  assert.equal(await db.count('auth_kit_private.membership_events', `user_id = ${lit(user)} and action = 'join'`), 1);
  const row = await db.rows(`select granted_roles from auth_kit_private.enrollments where user_id = ${lit(user)}`);
  assert.equal(row[0].granted_roles, '{reader}');
}));

test('enrollment is per client: the empty-string client is its own client; anon cannot join', () => withDatabase(async (db) => {
  await studio(db);
  await register(db, '');
  await applyModel(db, '', exampleModel(''));
  const user = await db.createUser();
  assert.equal((await join(db, user, '')).result, 'enrolled');
  assert.equal((await join(db, user, 'studio')).result, 'enrolled');
  assert.equal((await join(db, user, '')).result, 'already_enrolled');
  assert.equal(await db.count('auth_kit_private.enrollments', `user_id = ${lit(user)}`), 2);
  await dbError(db.call(actors.anon(), 'auth_kit.join_client', { client_id: 'studio' }), '42501');
}));
