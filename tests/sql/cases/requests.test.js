// Request ids (L30): every request-bearing command, first called with a
// mutating and with a no-op payload, then replayed with the same and with a
// changed payload, reused by another actor, another client and another
// operation, and collided concurrently on real sessions. A replay returns the
// stored result and writes nothing; anything else is request_conflict.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { withDatabase, actors, uuid, refusal, dbError, lit, sqlArg, jsonLit } from '../harness/db.js';
import {
  service, exampleModel, register, applyModel, bootstrap, revokeManager, grant, revoke, join, snapshot, requestRow, mfaBegin,
} from '../harness/kit.js';

/** Fresh state: two clients with one active manager each, a member and a second manager. */
async function setup(db) {
  const ctx = {};
  for (const client of ['studio', 'other']) {
    await register(db, client);
    await applyModel(db, client, exampleModel(client));
  }
  ctx.steward = await db.createUser();
  ctx.steward2 = await db.createUser();
  ctx.otherSteward = await db.createUser();
  await bootstrap(db, ctx.steward, 'studio', 'steward');
  await bootstrap(db, ctx.steward2, 'studio', 'steward');
  await bootstrap(db, ctx.otherSteward, 'other', 'steward');
  ctx.member = await db.createUser();
  await join(db, ctx.member, 'studio');
  await join(db, ctx.member, 'other');
  ctx.fresh = await db.createUser();
  return ctx;
}

const changedModel = (client) => {
  const m = exampleModel(client);
  m.permissions['posts:read'] = 'read posts';
  return m;
};
const otherModel = (client) => {
  const m = exampleModel(client);
  delete m.roles.reader;
  return m;
};

// Each command: how to call it as (actor, client, payload, id), a mutating
// and a no-op payload, a changed payload, and the event table it writes.
const COMMANDS = [
  {
    name: 'grant_membership', manager: true, events: 'auth_kit_private.membership_events',
    call: (db, c, actor, client, p, id) => grant(db, actor, p.user, client, p.role, id),
    mutating: (c) => ({ user: c.fresh, role: 'editor' }), noop: (c) => ({ user: c.member, role: 'member' }),
    changed: (c, p) => ({ ...p, role: 'reader' === p.role ? 'editor' : 'reader' }),
  },
  {
    name: 'revoke_membership', manager: true, events: 'auth_kit_private.membership_events',
    call: (db, c, actor, client, p, id) => revoke(db, actor, p.user, client, p.role, id),
    mutating: (c) => ({ user: c.member, role: 'member' }), noop: (c) => ({ user: c.fresh, role: 'member' }),
    changed: (c, p) => ({ ...p, role: 'editor' }),
  },
  {
    name: 'bootstrap_manager', manager: false, events: 'auth_kit_private.membership_events',
    call: (db, c, actor, client, p, id) => bootstrap(db, p.user, client, p.role, id),
    mutating: (c) => ({ user: c.fresh, role: 'steward' }), noop: (c) => ({ user: c.steward, role: 'steward' }),
    changed: (c, p) => ({ ...p, role: 'owner' }),
  },
  {
    name: 'revoke_manager', manager: false, events: 'auth_kit_private.membership_events',
    call: (db, c, actor, client, p, id) => revokeManager(db, p.user, client, p.role, id),
    mutating: (c) => ({ user: c.steward2, role: 'steward' }), noop: (c) => ({ user: c.fresh, role: 'steward' }),
    changed: (c, p) => ({ ...p, role: 'owner' }),
  },
  {
    name: 'apply_model', manager: false, events: 'auth_kit_private.model_events',
    call: (db, c, actor, client, p, id) => applyModel(db, client, p.model(client), { requestId: id }),
    mutating: () => ({ model: changedModel }), noop: () => ({ model: exampleModel }),
    changed: () => ({ model: otherModel }),
  },
];

for (const command of COMMANDS) {
  for (const kind of ['mutating', 'noop']) {
    test(`L30 ${command.name}, ${kind === 'noop' ? 'no-op' : 'mutating'} first call: replay, changed payload, other actor/client/operation`, () => withDatabase(async (db) => {
      const c = await setup(db);
      const actor = actors.user(c.steward);
      const payload = command[kind](c);
      const id = uuid();
      const events = () => db.count(command.events);
      const eventsBefore = await events();
      const logBefore = await db.count('auth_kit_private.request_log');
      const first = await command.call(db, c, actor, 'studio', payload, id);
      assert.equal(await events(), eventsBefore + (kind === 'mutating' ? 1 : 0), 'event rows after the first call');
      assert.equal(await db.count('auth_kit_private.request_log'), logBefore + 1, 'one request_log row, even for a no-op');
      const row = await requestRow(db, id);
      assert.deepEqual(row.result, first);
      assert.equal(row.state, 'completed');
      assert.equal(row.client_id, 'studio');
      assert.equal(row.actor_id, command.manager ? c.steward : 'operator');
      if (kind === 'noop') assert.match(first.result, /^(already_member|not_member|unchanged)$/);

      const settled = await snapshot(db);
      // Nth retry with the same payload: the stored result, nothing written.
      for (let i = 0; i < 3; i += 1) assert.deepEqual(await command.call(db, c, actor, 'studio', payload, id), first);
      await refusal(command.call(db, c, actor, 'studio', command.changed(c, payload), id), 'request_conflict');
      if (command.manager) {
        // The actor is in the fingerprint: another manager cannot replay this id.
        await refusal(command.call(db, c, actors.user(c.steward2), 'studio', payload, id), 'request_conflict');
      }
      const otherActor = command.manager ? actors.user(c.otherSteward) : actor;
      await refusal(command.call(db, c, otherActor, 'other', payload, id), 'request_conflict');
      // Another operation cannot claim the id either, including the project-wide MFA reset.
      const crossOp = COMMANDS.find((other) => other.name !== command.name && other.manager === command.manager);
      await refusal(crossOp.call(db, c, actor, 'studio', crossOp.mutating(c), id), 'request_conflict');
      await refusal(mfaBegin(db, c.member, id), 'request_conflict');
      assert.deepEqual(await snapshot(db), settled, 'no replay or conflict wrote anything');
    }));
  }
}

test('join_client and register_client are not request-bearing: idempotent on their natural keys, no request_log row', () => withDatabase(async (db) => {
  await register(db, 'studio');
  await register(db, 'studio');
  await applyModel(db, 'studio', exampleModel('studio'));
  const user = await db.createUser();
  await join(db, user, 'studio');
  await join(db, user, 'studio');
  const rows = await db.rows('select operation, count(*) as n from auth_kit_private.request_log group by operation');
  assert.deepEqual(rows, [{ operation: 'apply_model', n: '1' }]);
}));

test('a refused call binds nothing: the same id succeeds once the refusal no longer applies', () => withDatabase(async (db) => {
  const c = await setup(db);
  const owner = await db.createUser();
  await bootstrap(db, owner, 'studio', 'owner');
  const id = uuid();
  await refusal(grant(db, actors.user(owner, 'aal1'), c.fresh, 'studio', 'editor', id), 'mfa_required');
  assert.equal(await requestRow(db, id), null);
  assert.equal((await grant(db, actors.user(owner, 'aal2'), c.fresh, 'studio', 'editor', id)).result, 'granted');
}));

test('a database failure is never a success: injected failures surface as errors, persist nothing, and the id stays usable', () => withDatabase(async (db) => {
  const c = await setup(db);
  await db.installFaults();
  const id = uuid();
  const before = await snapshot(db);
  for (const table of ['memberships', 'membership_events', 'request_log']) {
    const error = await dbError(db.call(actors.user(c.steward), 'auth_kit.grant_membership',
      { user_id: c.fresh, client_id: 'studio', role_key: 'editor', request_id: id }, { settings: [['dwarpal_test.fail_on', table]] }), 'DT001');
    assert.notEqual(error.code, 'DW001');
    assert.deepEqual(await snapshot(db), before, table);
  }
  assert.equal((await grant(db, actors.user(c.steward), c.fresh, 'studio', 'editor', id)).result, 'granted');
}));

async function holdAndCollide(db, first, second) {
  const a = await db.session(first.actor);
  const b = await db.session(second.actor);
  await a.begin();
  const resultA = await first.run(a);
  await b.begin();
  const pendingB = second.run(b).then((value) => ({ value }), (error) => ({ error }));
  await db.waitForAdvisoryWait(b.pid);
  if (first.rollback) await a.rollback();
  else await a.commit();
  const outcomeB = await pendingB;
  await (outcomeB.error ? b.rollback() : b.commit());
  return { resultA, outcomeB };
}

const grantCall = (user, client, role, id) => (s) => s.call('auth_kit.grant_membership', { user_id: user, client_id: client, role_key: role, request_id: id });

test('concurrent same id, same payload: the waiter gets the stored result; one row, one event', () => withDatabase(async (db) => {
  const c = await setup(db);
  const id = uuid();
  const manager = actors.user(c.steward);
  const { resultA, outcomeB } = await holdAndCollide(db,
    { actor: manager, run: grantCall(c.fresh, 'studio', 'editor', id) },
    { actor: manager, run: grantCall(c.fresh, 'studio', 'editor', id) });
  assert.equal(resultA.result, 'granted');
  assert.deepEqual(outcomeB.value, resultA);
  assert.equal(await db.count('auth_kit_private.membership_events', `request_id = ${lit(id)}`), 1);
  assert.equal(await db.count('auth_kit_private.request_log', `request_id = ${lit(id)}`), 1);
}));

test('concurrent same id, changed payload or other actor: request_conflict after the wait, nothing written', () => withDatabase(async (db) => {
  const c = await setup(db);
  for (const [label, secondActor, role] of [['changed payload', c.steward, 'reader'], ['other actor', c.steward2, 'editor']]) {
    const id = uuid();
    const { outcomeB } = await holdAndCollide(db,
      { actor: actors.user(c.steward), run: grantCall(c.fresh, 'studio', 'editor', id) },
      { actor: actors.user(secondActor), run: grantCall(c.fresh, 'studio', role, id) });
    assert.equal(outcomeB.error?.code, 'DW001', label);
    assert.equal(outcomeB.error.message, 'request_conflict', label);
    assert.equal(await db.count('auth_kit_private.membership_events', `request_id = ${lit(id)}`), 1, label);
    await revoke(db, actors.user(c.steward), c.fresh, 'studio', 'editor');
  }
}));

test('concurrent first use of one id under two different client locks: request_conflict, never a key violation', () => withDatabase(async (db) => {
  const c = await setup(db);
  const id = uuid();
  const { resultA, outcomeB } = await holdAndCollide(db,
    { actor: actors.user(c.steward), run: grantCall(c.fresh, 'studio', 'editor', id) },
    { actor: actors.user(c.otherSteward), run: grantCall(c.fresh, 'other', 'editor', id) });
  assert.equal(resultA.result, 'granted');
  assert.equal(outcomeB.error?.code, 'DW001', `got ${outcomeB.error?.code} ${outcomeB.error?.message}`);
  assert.equal(outcomeB.error.message, 'request_conflict');
  assert.equal(await db.count('auth_kit_private.memberships', `user_id = ${lit(c.fresh)} and client_id = 'other'`), 0);

  // If the first holder rolls back, the waiter's call is the first use and succeeds.
  const id2 = uuid();
  const rolled = await holdAndCollide(db,
    { actor: actors.user(c.steward), run: grantCall(c.fresh, 'studio', 'reader', id2), rollback: true },
    { actor: actors.user(c.otherSteward), run: grantCall(c.fresh, 'other', 'editor', id2) });
  assert.equal(rolled.outcomeB.value?.result, 'granted');
  assert.equal((await requestRow(db, id2)).client_id, 'other');
}));

test('concurrent first use of one id by a client write and a project-wide MFA reset: request_conflict', () => withDatabase(async (db) => {
  const c = await setup(db);
  const id = uuid();
  const { outcomeB } = await holdAndCollide(db,
    { actor: service, run: (s) => s.call('auth_kit.apply_model', { client_id: 'studio', model: sqlArg(jsonLit(JSON.stringify(changedModel('studio')))), request_id: id }) },
    { actor: service, run: (s) => s.call('auth_kit.mfa_reset_begin', { user_id: c.member, request_id: id }) });
  assert.equal(outcomeB.error?.message, 'request_conflict');
  assert.equal((await requestRow(db, id)).operation, 'apply_model');
}));
