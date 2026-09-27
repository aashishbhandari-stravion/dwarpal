// Project-wide MFA reset claim (design 4.7, L35 SQL parts). SQL never
// calls Auth: here "Auth work" is only the ordering of begin / note / finish.
// Lease expiry is simulated by moving started_at back 121 s as the superuser;
// the CLI's monotonic 100 s deadline and 20 s call timeout are lane 03 and
// hosted gates and are not exercised here.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { withDatabase, actors, uuid, refusal, dbError, lit } from '../harness/db.js';
import { service, exampleModel, register, applyModel, bootstrap, grant, mfaBegin, mfaNote, mfaFinish, snapshot, requestRow, events } from '../harness/kit.js';

const F1 = '11111111-1111-4111-8111-111111111111';
const F2 = '22222222-2222-4222-8222-222222222222';

async function expire(db, requestId) {
  await db.admin.query(`update auth_kit_private.request_log set started_at = started_at - interval '121 seconds' where request_id = ${lit(requestId)}`);
}

async function mfaEvents(db, requestId) {
  return events(db, `action = 'mfa_reset' and request_id = ${lit(requestId)}`);
}

test('L35(a): reserve before any factor work, note, finish: one completed row and one project-wide event', () => withDatabase(async (db) => {
  const user = await db.createUser();
  const id = uuid();
  const begin = await mfaBegin(db, user, id);
  assert.equal(begin.outcome, 'proceed');
  assert.match(begin.run_token, /^[0-9a-f-]{36}$/);
  assert.equal(begin.factors_seen, null);
  // The pending row exists before the runner lists factors.
  const pending = await requestRow(db, id);
  assert.equal(pending.state, 'pending');
  assert.equal(pending.client_id, null);
  assert.equal(pending.operation, 'mfa_reset');
  assert.equal(pending.actor_id, 'operator');
  assert.equal(pending.user_id, user);
  assert.equal(pending.run_token, begin.run_token);
  assert.equal(pending.factors_seen, null);
  assert.deepEqual(await mfaNote(db, id, begin.run_token, [F1]), { factors_seen: [F1] });
  const result = await mfaFinish(db, id, begin.run_token, [F1]);
  assert.deepEqual(result, { result: 'reset', factors_seen: [F1], factors_deleted: [F1] });
  const done = await requestRow(db, id);
  assert.equal(done.state, 'completed');
  assert.equal(done.run_token, begin.run_token);
  assert.deepEqual(done.result, result);
  const [event] = await mfaEvents(db, id);
  assert.deepEqual([event.client_id, event.role_key, event.user_id, event.actor_kind, event.result, event.payload_hash],
    [null, null, user, 'operator', 'reset', done.payload_hash]);
}));

test('L35(b)(c): retry after success returns the stored result; the same id for another user conflicts; nothing written', () => withDatabase(async (db) => {
  const user = await db.createUser();
  const other = await db.createUser();
  const id = uuid();
  const { run_token: token } = await mfaBegin(db, user, id);
  await mfaNote(db, id, token, [F1, F2]);
  const result = await mfaFinish(db, id, token, [F1, F2]);
  const before = await snapshot(db);
  for (let i = 0; i < 3; i += 1) assert.deepEqual(await mfaBegin(db, user, id), { outcome: 'completed', result });
  await refusal(mfaBegin(db, other, id), 'request_conflict');
  assert.deepEqual(await snapshot(db), before);
}));

test('L35(d): two concurrent begins for the same id: one proceeds, the other waits and gets request_in_progress', () => withDatabase(async (db) => {
  const user = await db.createUser();
  const id = uuid();
  const a = await db.session(service);
  const b = await db.session(service);
  await a.begin();
  assert.equal((await a.call('auth_kit.mfa_reset_begin', { user_id: user, request_id: id })).outcome, 'proceed');
  await b.begin();
  const pending = b.call('auth_kit.mfa_reset_begin', { user_id: user, request_id: id }).then((v) => ({ v }), (e) => ({ e }));
  await db.waitForAdvisoryWait(b.pid);
  await a.commit();
  const outcome = await pending;
  await b.rollback();
  assert.equal(outcome.e?.message, 'request_in_progress');
  assert.equal(await db.count('auth_kit_private.request_log', `request_id = ${lit(id)}`), 1);
  // A later begin inside the lease is refused the same way.
  await refusal(mfaBegin(db, user, id), 'request_in_progress');
}));

test('L35(e): crash after deleting one of two factors; inside the lease in progress, after it resume keeps the original list', () => withDatabase(async (db) => {
  const user = await db.createUser();
  const id = uuid();
  const first = await mfaBegin(db, user, id);
  await mfaNote(db, id, first.run_token, [F2, F1]);
  // (crash: F1 was deleted, finish never ran)
  await refusal(mfaBegin(db, user, id), 'request_in_progress');
  await expire(db, id);
  const resumed = await mfaBegin(db, user, id);
  assert.equal(resumed.outcome, 'resume');
  assert.notEqual(resumed.run_token, first.run_token);
  assert.deepEqual(resumed.factors_seen, [F1, F2]);
  // A resumed run's note never replaces the recorded list.
  assert.deepEqual(await mfaNote(db, id, resumed.run_token, [F2]), { factors_seen: [F1, F2] });
  const result = await mfaFinish(db, id, resumed.run_token, [F1, F2]);
  assert.deepEqual(result, { result: 'reset', factors_seen: [F1, F2], factors_deleted: [F1, F2] });
  assert.equal((await mfaEvents(db, id)).length, 1);
  const rows = await db.rows(`select count(*) as n from auth_kit_private.request_log where operation = 'mfa_reset' and factors_seen = '{}'`);
  assert.equal(rows[0].n, '0');
}));

test('L35(f): crash before note; resume after the lease has no list, then notes and completes normally', () => withDatabase(async (db) => {
  const user = await db.createUser();
  const id = uuid();
  await mfaBegin(db, user, id);
  await expire(db, id);
  const resumed = await mfaBegin(db, user, id);
  assert.equal(resumed.outcome, 'resume');
  assert.equal(resumed.factors_seen, null);
  await mfaNote(db, id, resumed.run_token, [F1]);
  assert.equal((await mfaFinish(db, id, resumed.run_token, [F1])).result, 'reset');
}));

test('L35(g): two retries just after the lease: one atomic takeover, the other request_in_progress; one row, one event', () => withDatabase(async (db) => {
  const user = await db.createUser();
  const id = uuid();
  const first = await mfaBegin(db, user, id);
  await mfaNote(db, id, first.run_token, [F1, F2]);
  await expire(db, id);
  const a = await db.session(service);
  const b = await db.session(service);
  await a.begin();
  const takeover = await a.call('auth_kit.mfa_reset_begin', { user_id: user, request_id: id });
  await b.begin();
  const pending = b.call('auth_kit.mfa_reset_begin', { user_id: user, request_id: id }).then((v) => ({ v }), (e) => ({ e }));
  await db.waitForAdvisoryWait(b.pid);
  await a.commit();
  const second = await pending;
  await b.rollback();
  assert.equal(takeover.outcome, 'resume');
  assert.equal(second.e?.message, 'request_in_progress');
  await mfaFinish(db, id, takeover.run_token, [F1, F2]);
  assert.equal(await db.count('auth_kit_private.request_log', `request_id = ${lit(id)} and state = 'completed'`), 1);
  assert.equal((await mfaEvents(db, id)).length, 1);
}));

test('L35(h): a superseded runner is fenced by its token before any state check, before and after the takeover completes', () => withDatabase(async (db) => {
  const user = await db.createUser();
  const id = uuid();
  const original = await mfaBegin(db, user, id);
  await mfaNote(db, id, original.run_token, [F1, F2]);
  await expire(db, id);
  const takeover = await mfaBegin(db, user, id);
  // Superseded while the takeover is still pending.
  let before = await snapshot(db);
  await refusal(mfaNote(db, id, original.run_token, [F2]), 'run_superseded');
  await refusal(mfaFinish(db, id, original.run_token, [F2]), 'run_superseded');
  assert.deepEqual(await snapshot(db), before);
  const result = await mfaFinish(db, id, takeover.run_token, [F1, F2]);
  assert.equal(result.result, 'reset');
  // After completion the stale runner still learns only that it was superseded,
  // not request_conflict and not the stored result.
  before = await snapshot(db);
  await refusal(mfaNote(db, id, original.run_token, [F1, F2]), 'run_superseded');
  await refusal(mfaFinish(db, id, original.run_token, [F1, F2]), 'run_superseded');
  assert.deepEqual(await snapshot(db), before);
  assert.equal((await mfaEvents(db, id)).length, 1);
  assert.equal((await requestRow(db, id)).run_token, takeover.run_token);
}));

test('claim holder retries: own finish returns the stored result; note after finish conflicts; finish needs a recorded list', () => withDatabase(async (db) => {
  const user = await db.createUser();
  const id = uuid();
  const { run_token: token } = await mfaBegin(db, user, id);
  // Finish before note: the audit never claims a list it did not record.
  await refusal(mfaFinish(db, id, token, []), 'request_conflict');
  await mfaNote(db, id, token, [F1]);
  // Only recorded factors can have been deleted.
  await refusal(mfaFinish(db, id, token, [F2]), 'invalid_argument');
  const result = await mfaFinish(db, id, token, [F1]);
  const before = await snapshot(db);
  assert.deepEqual(await mfaFinish(db, id, token, [F1]), result);
  assert.deepEqual(await mfaFinish(db, id, token, []), result);
  await refusal(mfaNote(db, id, token, [F1]), 'request_conflict');
  assert.deepEqual(await snapshot(db), before);
  assert.equal((await mfaEvents(db, id)).length, 1);
}));

test('no factors: an empty recorded list completes as no_factors', () => withDatabase(async (db) => {
  const user = await db.createUser();
  const id = uuid();
  const { run_token: token } = await mfaBegin(db, user, id);
  await mfaNote(db, id, token, []);
  assert.deepEqual(await mfaFinish(db, id, token, []), { result: 'no_factors', factors_seen: [], factors_deleted: [] });
  assert.equal((await mfaEvents(db, id))[0].result, 'no_factors');
}));

test('unknown ids and ids of other operations: note/finish conflict; nulls are invalid', () => withDatabase(async (db) => {
  const user = await db.createUser();
  await refusal(mfaNote(db, uuid(), uuid(), [F1]), 'request_conflict');
  await refusal(mfaFinish(db, uuid(), uuid(), [F1]), 'request_conflict');
  // An id bound by a client-scoped command (here on the empty-string client)
  // is not an MFA reset: the empty client is never the null project scope.
  await register(db, '');
  await applyModel(db, '', exampleModel(''));
  const steward = await db.createUser();
  const bootstrapId = uuid();
  await bootstrap(db, steward, '', 'steward', bootstrapId);
  assert.equal((await requestRow(db, bootstrapId)).client_id, '');
  await refusal(mfaBegin(db, user, bootstrapId), 'request_conflict');
  await refusal(mfaNote(db, bootstrapId, uuid(), [F1]), 'request_conflict');
  await refusal(mfaFinish(db, bootstrapId, uuid(), [F1]), 'request_conflict');
  const grantId = uuid();
  await grant(db, actors.user(steward), await db.createUser(), '', 'editor', grantId);
  await refusal(mfaBegin(db, user, grantId), 'request_conflict');
  await refusal(db.call(service, 'auth_kit.mfa_reset_note', { request_id: uuid(), run_token: uuid(), factor_ids: { sql: `array['${F1}', null]::uuid[]` } }), 'invalid_argument');
  await refusal(mfaBegin(db, null, uuid()), 'invalid_argument');
}));

test('a failure while finishing leaves the claim pending with its token and list; the retry completes once', () => withDatabase(async (db) => {
  await db.installFaults();
  const user = await db.createUser();
  const id = uuid();
  const { run_token: token } = await mfaBegin(db, user, id);
  await mfaNote(db, id, token, [F1]);
  const before = await snapshot(db);
  await dbError(db.call(service, 'auth_kit.mfa_reset_finish', { request_id: id, run_token: token, factors_deleted: { sql: `array['${F1}']::uuid[]` } },
    { settings: [['dwarpal_test.fail_on', 'membership_events']] }), 'DT001');
  assert.deepEqual(await snapshot(db), before);
  assert.equal((await mfaFinish(db, id, token, [F1])).result, 'reset');
  assert.equal((await mfaEvents(db, id)).length, 1);
  // A failed takeover leaves the old claim intact.
  const id2 = uuid();
  const first = await mfaBegin(db, user, id2);
  await expire(db, id2);
  await dbError(db.call(service, 'auth_kit.mfa_reset_begin', { user_id: user, request_id: id2 }, { settings: [['dwarpal_test.fail_on', 'request_log']] }), 'DT001');
  assert.equal((await requestRow(db, id2)).run_token, first.run_token);
}));

test('the claim time is taken after the locks, not at transaction start', () => withDatabase(async (db) => {
  const user = await db.createUser();
  const id = uuid();
  const session = await db.session(service);
  await session.begin();
  // A transaction that started a second before begin was called.
  await session.query('select pg_sleep(1.1)');
  await session.call('auth_kit.mfa_reset_begin', { user_id: user, request_id: id });
  const gap = await session.query(`select extract(epoch from (started_at - now()))::float8 from auth_kit_private.request_log where request_id = ${lit(id)}`);
  await session.commit();
  assert.ok(gap >= 1, `started_at - transaction start = ${gap} s`);
}));

test('MFA reset is operator-only', () => withDatabase(async (db) => {
  const user = await db.createUser();
  for (const actor of [actors.user(user, 'aal2'), actors.anon()]) {
    await dbError(db.call(actor, 'auth_kit.mfa_reset_begin', { user_id: user, request_id: uuid() }), '42501');
    await dbError(db.call(actor, 'auth_kit.mfa_reset_note', { request_id: uuid(), run_token: uuid(), factor_ids: { sql: "'{}'::uuid[]" } }), '42501');
    await dbError(db.call(actor, 'auth_kit.mfa_reset_finish', { request_id: uuid(), run_token: uuid(), factors_deleted: { sql: "'{}'::uuid[]" } }), '42501');
  }
  assert.equal(await db.count('auth_kit_private.request_log'), 0);
}));
