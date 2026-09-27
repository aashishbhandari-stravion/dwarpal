// Per-client serialisation (I9): a write that waited on the client lock
// re-reads authority, model and holders afterwards. Each race holds the first
// transaction open on a real session, proves the second is blocked on the
// advisory lock through pg_locks, then commits and checks the second outcome.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { withDatabase, actors, uuid, dbError, lit, sqlArg, jsonLit } from '../harness/db.js';
import { service, exampleModel, register, applyModel, bootstrap, grant, join, snapshot } from '../harness/kit.js';

async function setup(db) {
  await register(db, 'studio');
  await applyModel(db, 'studio', exampleModel('studio'));
  const steward = await db.createUser();
  const steward2 = await db.createUser();
  await bootstrap(db, steward, 'studio', 'steward');
  await bootstrap(db, steward2, 'studio', 'steward');
  return { steward, steward2, target: await db.createUser() };
}

const modelArg = (model) => sqlArg(jsonLit(JSON.stringify(model)));

/** First holds the lock inside an open transaction; second must block, then sees first's commit. */
async function race(db, first, second) {
  const a = await db.session(first.actor);
  const b = await db.session(second.actor);
  await a.begin();
  const resultA = await first.run(a);
  await b.begin();
  const pending = second.run(b).then((value) => ({ value }), (error) => ({ error }));
  await db.waitForAdvisoryWait(b.pid);
  await a.commit();
  const outcome = await pending;
  await (outcome.error ? b.rollback() : b.commit());
  return { resultA, outcome };
}

const grantBy = (user, target, role) => ({
  actor: actors.user(user),
  run: (s) => s.call('auth_kit.grant_membership', { user_id: target, client_id: 'studio', role_key: role, request_id: uuid() }),
});
const operator = (fn, args) => ({ actor: service, run: (s) => s.call(fn, args) });

test('a manager revoked while its grant waits on the lock is refused after the wait', () => withDatabase(async (db) => {
  const c = await setup(db);
  const before = await snapshot(db);
  const { resultA, outcome } = await race(db,
    operator('auth_kit.revoke_manager', { user_id: c.steward, client_id: 'studio', role_key: 'steward', request_id: uuid() }),
    grantBy(c.steward, c.target, 'editor'));
  assert.equal(resultA.result, 'revoked');
  assert.equal(outcome.error?.message, 'forbidden');
  assert.equal(await db.count('auth_kit_private.memberships', `user_id = ${lit(c.target)}`), 0);
  const after = await snapshot(db);
  assert.equal(after['auth_kit_private.request_log'].length, before['auth_kit_private.request_log'].length + 1);
}));

test('a manager role made MFA-required while the grant waits yields mfa_required after the wait', () => withDatabase(async (db) => {
  const c = await setup(db);
  const model = exampleModel('studio');
  model.roles.steward.mfa_required = true;
  const { outcome } = await race(db,
    operator('auth_kit.apply_model', { client_id: 'studio', model: modelArg(model), request_id: uuid() }),
    grantBy(c.steward, c.target, 'editor'));
  assert.equal(outcome.error?.message, 'mfa_required');
}));

test('a role removed by a model change while a grant of it waits: unknown_role after the wait', () => withDatabase(async (db) => {
  const c = await setup(db);
  const model = exampleModel('studio');
  delete model.roles.editor;
  const { outcome } = await race(db,
    operator('auth_kit.apply_model', { client_id: 'studio', model: modelArg(model), request_id: uuid() }),
    grantBy(c.steward, c.target, 'editor'));
  assert.equal(outcome.error?.message, 'unknown_role');
}));

test('a model change waiting behind a grant sees the new holder: role_held and promotes_holders refusals', () => withDatabase(async (db) => {
  const c = await setup(db);
  const removal = exampleModel('studio');
  delete removal.roles.editor;
  const first = await race(db, grantBy(c.steward, c.target, 'editor'),
    operator('auth_kit.apply_model', { client_id: 'studio', model: modelArg(removal), request_id: uuid() }));
  assert.equal(first.outcome.error?.message, 'model_refused');
  assert.deepEqual(JSON.parse(first.outcome.error.detail).refusals, [{ rule: 'role_held', role: 'editor', holders: [c.target] }]);

  const other = await db.createUser();
  const promotion = exampleModel('studio');
  promotion.roles.reader.self_assignable = false;
  promotion.roles.reader.manages_members = true;
  const second = await race(db, grantBy(c.steward, other, 'reader'),
    operator('auth_kit.apply_model', { client_id: 'studio', model: modelArg(promotion), request_id: uuid() }));
  assert.equal(second.outcome.error?.message, 'model_refused');
  assert.deepEqual(JSON.parse(second.outcome.error.detail).refusals, [{ rule: 'promotes_holders', role: 'reader', holders: [other] }]);
}));

test('two concurrent revoke_manager calls for the last two managers: the second is last_manager', () => withDatabase(async (db) => {
  const c = await setup(db);
  const { resultA, outcome } = await race(db,
    operator('auth_kit.revoke_manager', { user_id: c.steward, client_id: 'studio', role_key: 'steward', request_id: uuid() }),
    operator('auth_kit.revoke_manager', { user_id: c.steward2, client_id: 'studio', role_key: 'steward', request_id: uuid() }));
  assert.equal(resultA.result, 'revoked');
  assert.equal(outcome.error?.message, 'last_manager');
  assert.equal(await db.count('auth_kit_private.memberships', "client_id = 'studio' and role_key = 'steward'"), 1);
}));

test('a join waiting behind a model change receives the self-assignable role that change added', () => withDatabase(async (db) => {
  await setup(db);
  const model = exampleModel('studio');
  model.permissions['news:read'] = '';
  model.roles.subscriber = { self_assignable: true, permissions: ['news:read'] };
  const user = await db.createUser();
  const { outcome } = await race(db,
    operator('auth_kit.apply_model', { client_id: 'studio', model: modelArg(model), request_id: uuid() }),
    { actor: actors.user(user), run: (s) => s.call('auth_kit.join_client', { client_id: 'studio' }) });
  assert.deepEqual(outcome.value.granted_roles, ['member', 'reader', 'subscriber']);
}));

test('reads take no lock: effective_access and the helpers answer while a write holds the client lock', () => withDatabase(async (db) => {
  const c = await setup(db);
  const member = await db.createUser();
  await join(db, member, 'studio');
  const writer = await db.session(service);
  await writer.begin();
  await writer.call('auth_kit.apply_model', { client_id: 'studio', model: modelArg(exampleModel('studio')), request_id: uuid() });
  const reader = actors.user(member);
  const accessResult = await db.call(reader, 'auth_kit.effective_access', { client_id: 'studio' });
  assert.deepEqual(accessResult.active_roles, ['member', 'reader']);
  assert.equal(await db.call(reader, 'auth_kit.has_permission', { client_id: 'studio', permission_key: 'posts:read' }), true);
  await writer.commit();
  assert.ok(c.steward);
}));

test('writes refuse REPEATABLE READ and SERIALIZABLE, whose snapshot could predate the lock wait', () => withDatabase(async (db) => {
  const c = await setup(db);
  const member = await db.createUser();
  const calls = [
    [actors.user(c.steward), 'auth_kit.grant_membership', { user_id: c.target, client_id: 'studio', role_key: 'editor', request_id: uuid() }],
    [actors.user(c.steward), 'auth_kit.revoke_membership', { user_id: c.target, client_id: 'studio', role_key: 'editor', request_id: uuid() }],
    [actors.user(member), 'auth_kit.join_client', { client_id: 'studio' }],
    [service, 'auth_kit.bootstrap_manager', { user_id: c.target, client_id: 'studio', role_key: 'owner', request_id: uuid() }],
    [service, 'auth_kit.revoke_manager', { user_id: c.steward2, client_id: 'studio', role_key: 'steward', request_id: uuid() }],
    [service, 'auth_kit.apply_model', { client_id: 'studio', model: modelArg(exampleModel('studio')), request_id: uuid() }],
    [service, 'auth_kit.register_client', { client_id: 'studio', display_name: 'x', signup_policy: 'open' }],
    [service, 'auth_kit.mfa_reset_begin', { user_id: member, request_id: uuid() }],
  ];
  const before = await snapshot(db);
  for (const level of ['repeatable read', 'serializable']) {
    for (const [actor, fn, args] of calls) {
      const session = await db.session(actor);
      await session.connection.query(`begin isolation level ${level}`);
      if (actor.role !== 'postgres') {
        await session.connection.query(`select set_config('role', ${lit(actor.role)}, true), set_config('request.jwt.claims', ${lit(JSON.stringify(actor.claims))}, true)`);
      }
      const error = await dbError(session.call(fn, args), '0A000');
      assert.match(error.message, /READ COMMITTED/, `${level} ${fn}`);
      await session.rollback();
    }
  }
  assert.deepEqual(await snapshot(db), before);
}));
