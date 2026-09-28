// L35 (a)–(i) with the operator runner against the real mfa_reset_* SQL
// functions: fixture Auth admin API (factor list/delete), fake monotonic
// clock, lease expiry simulated by moving started_at back as the SQL gates
// do. The claim, fencing and audit rows are PostgreSQL's. Not hosted
// evidence: real Auth timing and lease passage are Lane 06.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { withDatabase, uuid, lit } from '../../sql/harness/db.js';
import { requestRow, events, snapshot } from '../../sql/harness/kit.js';
import { createOperatorClient, OperatorError } from '../../../packages/server/operator.js';
import { createFakeSupabase, SECRET_KEY } from '../support/fake-supabase.js';
import { pgRpc, addUser } from '../support/pg-bridge.js';

async function stack(db) {
  const fake = await createFakeSupabase();
  fake.rpc = pgRpc(db);
  const operator = (name) => {
    let t = 5_000;
    const clock = { now: () => t, advance: (ms) => { t += ms; } };
    const fetchAs = (input, init = {}) => fake.fetch(input, { ...init, headers: { ...init.headers, 'x-runner': name } });
    return { clock, client: createOperatorClient({ supabaseUrl: fake.origin, secretKey: SECRET_KEY, fetch: fetchAs, monotonicNow: clock.now }) };
  };
  return { fake, operator };
}

const runner = (ctx) => ctx.request.headers.get('x-runner');

function gate() {
  let open;
  const promise = new Promise((resolve) => { open = resolve; });
  return { promise, open };
}

async function expire(db, requestId) {
  await db.admin.query(`update auth_kit_private.request_log set started_at = started_at - interval '121 seconds' where request_id = ${lit(requestId)}`);
}

async function mfaEvents(db, requestId) {
  return events(db, `action = 'mfa_reset' and request_id = ${lit(requestId)}`);
}

async function rejectsWith(promise, code) {
  await assert.rejects(promise, (error) => {
    assert.ok(error instanceof OperatorError, `expected ${code}, got ${error?.name} ${error?.code ?? error?.message}`);
    assert.equal(error.code, code);
    return true;
  });
}

test('L35(a)(b)(c) complete, replay without Auth, and conflict for another user before Auth', async () => {
  await withDatabase(async (db) => {
    const { fake, operator } = await stack(db);
    const u = await addUser(fake, db);
    const u2 = await addUser(fake, db);
    const f = fake.addFactor(u);
    const f2 = fake.addFactor(u2);
    const r = uuid();
    fake.hooks.set('list_factors', async () => {
      const row = await requestRow(db, r);
      assert.equal(row.state, 'pending');
      assert.equal(row.factors_seen, null);
      return undefined;
    });
    const done = await operator('A').client.mfaReset({ userId: u, requestId: r });
    assert.equal(done.result, 'reset');
    const row = await requestRow(db, r);
    assert.equal(row.state, 'completed');
    assert.deepEqual(row.factors_seen, [f]);
    assert.deepEqual(row.result, { result: 'reset', factors_seen: [f], factors_deleted: [f] });
    const ev = await mfaEvents(db, r);
    assert.equal(ev.length, 1);
    assert.equal(ev[0].client_id, null);
    assert.equal(ev[0].actor_kind, 'operator');

    fake.hooks.clear();
    const adminBefore = fake.adminCalls().length;
    const state = await snapshot(db);
    const replay = await operator('B').client.mfaReset({ userId: u, requestId: r });
    assert.equal(replay.outcome, 'completed');
    assert.deepEqual([...replay.factorsDeleted], [f]);
    await rejectsWith(operator('C').client.mfaReset({ userId: u2, requestId: r }), 'request_conflict');
    assert.equal(fake.adminCalls().length, adminBefore, 'no admin call on replay or conflict');
    assert.deepEqual(await snapshot(db), state, 'nothing written');
    assert.ok(fake.users.get(u2).factors.has(f2));
  });
});

test('L35(d) a concurrent run is request_in_progress before any admin call', async () => {
  await withDatabase(async (db) => {
    const { fake, operator } = await stack(db);
    const u = await addUser(fake, db);
    fake.addFactor(u);
    const r = uuid();
    const hold = gate();
    const entered = gate();
    fake.hooks.set('list_factors', async (ctx) => {
      if (runner(ctx) === 'A') { entered.open(); await hold.promise; }
      return undefined;
    });
    const a = operator('A').client.mfaReset({ userId: u, requestId: r });
    await entered.promise;
    await rejectsWith(operator('B').client.mfaReset({ userId: u, requestId: r }), 'request_in_progress');
    assert.equal(fake.adminCalls().length, 1);
    hold.open();
    assert.equal((await a).result, 'reset');
    assert.equal((await mfaEvents(db, r)).length, 1);
  });
});

test('L35(e)(g) crash after the first deletion; in-progress in the lease; two retries after it, one claim, one event', async () => {
  await withDatabase(async (db) => {
    const { fake, operator } = await stack(db);
    const u = await addUser(fake, db);
    const ordered = [fake.addFactor(u), fake.addFactor(u)].sort();
    const r = uuid();
    let deletes = 0;
    fake.hooks.set('delete_factor', async () => {
      deletes += 1;
      if (deletes === 2) throw new TypeError('crash');
      return undefined;
    });
    await rejectsWith(operator('A').client.mfaReset({ userId: u, requestId: r }), 'unavailable');
    let row = await requestRow(db, r);
    assert.equal(row.state, 'pending');
    assert.deepEqual(row.factors_seen, ordered);
    fake.hooks.clear();
    await rejectsWith(operator('B').client.mfaReset({ userId: u, requestId: r }), 'request_in_progress');
    await expire(db, r);
    const hold = gate();
    const entered = gate();
    fake.hooks.set('delete_factor', async (ctx) => {
      if (runner(ctx) === 'C') { entered.open(); await hold.promise; }
      return undefined;
    });
    const c = operator('C').client.mfaReset({ userId: u, requestId: r });
    await entered.promise;
    const tokenC = (await requestRow(db, r)).run_token;
    const adminBefore = fake.adminCalls().length;
    await rejectsWith(operator('D').client.mfaReset({ userId: u, requestId: r }), 'request_in_progress');
    assert.equal(fake.adminCalls().length, adminBefore);
    hold.open();
    const resumed = await c;
    assert.equal(resumed.outcome, 'resume');
    assert.deepEqual([...resumed.factorsSeen], ordered);
    assert.deepEqual([...resumed.factorsDeleted], ordered);
    row = await requestRow(db, r);
    assert.equal(row.state, 'completed');
    assert.equal(row.run_token, tokenC);
    assert.equal((await mfaEvents(db, r)).length, 1);
    assert.equal(fake.callsTo('list_factors').length, 1, 'the resumed run used the recorded list');
  });
});

test('L35(f) crash before note: resume lists, notes and completes', async () => {
  await withDatabase(async (db) => {
    const { fake, operator } = await stack(db);
    const u = await addUser(fake, db);
    const f = fake.addFactor(u);
    const r = uuid();
    fake.hooks.set('list_factors', async () => { throw new TypeError('crash'); });
    await rejectsWith(operator('A').client.mfaReset({ userId: u, requestId: r }), 'unavailable');
    assert.equal((await requestRow(db, r)).factors_seen, null);
    fake.hooks.clear();
    await expire(db, r);
    const resumed = await operator('B').client.mfaReset({ userId: u, requestId: r });
    assert.equal(resumed.outcome, 'resume');
    assert.deepEqual([...resumed.factorsSeen], [f]);
    assert.equal((await mfaEvents(db, r)).length, 1);
  });
});

test('L35(h) the original runner wakes after a completed takeover: not-found delete, run_superseded note and finish, nothing written', async () => {
  await withDatabase(async (db) => {
    const { fake, operator } = await stack(db);
    const u = await addUser(fake, db);
    const [f1, f2] = [fake.addFactor(u), fake.addFactor(u)].sort();
    const r = uuid();
    const hold = gate();
    const paused = gate();
    let aDeletes = 0;
    fake.hooks.set('delete_factor', async (ctx) => {
      if (runner(ctx) === 'A' && (aDeletes += 1) === 2) { paused.open(); await hold.promise; }
      return undefined;
    });
    const a = operator('A').client.mfaReset({ userId: u, requestId: r });
    await paused.promise;
    const tokenA = (await requestRow(db, r)).run_token;
    await expire(db, r);
    const b = await operator('B').client.mfaReset({ userId: u, requestId: r });
    assert.equal(b.result, 'reset');
    const completed = await snapshot(db);
    hold.open();
    await rejectsWith(a, 'run_superseded');
    // A's late note is refused as superseded too (token before state).
    const note = await fake.fetch(`${fake.origin}/rest/v1/rpc/mfa_reset_note`, {
      method: 'POST',
      headers: { apikey: SECRET_KEY, Authorization: `Bearer ${SECRET_KEY}`, 'Content-Profile': 'auth_kit', 'Content-Type': 'application/json' },
      body: JSON.stringify({ request_id: r, run_token: tokenA, factor_ids: [f1] }),
    });
    const noteBody = await note.json();
    assert.equal(noteBody.code, 'DW001');
    assert.equal(noteBody.message, 'run_superseded');
    assert.deepEqual(await snapshot(db), completed, 'the superseded runner wrote nothing');
    const row = await requestRow(db, r);
    assert.notEqual(row.run_token, tokenA);
    assert.deepEqual(row.result.factors_deleted, [f1, f2]);
    assert.equal((await mfaEvents(db, r)).length, 1);
    assert.equal(fake.callsTo('delete_factor').filter((c) => c.path.endsWith(f2)).length, 2);
  });
});

test('L35(i) the claim age reaches 101 s between listFactors and the first deletion: lease_expired, then a resumed completion', async () => {
  await withDatabase(async (db) => {
    const { fake, operator } = await stack(db);
    const u = await addUser(fake, db);
    const ordered = [fake.addFactor(u), fake.addFactor(u)].sort();
    const r = uuid();
    const a = operator('A');
    fake.hooks.set('list_factors', async () => { a.clock.advance(101_000); return undefined; });
    await rejectsWith(a.client.mfaReset({ userId: u, requestId: r }), 'lease_expired');
    assert.equal(fake.callsTo('delete_factor').length, 0);
    const row = await requestRow(db, r);
    assert.equal(row.state, 'pending');
    assert.deepEqual(row.factors_seen, ordered);
    fake.hooks.clear();
    await rejectsWith(operator('B').client.mfaReset({ userId: u, requestId: r }), 'request_in_progress');
    await expire(db, r);
    const resumed = await operator('C').client.mfaReset({ userId: u, requestId: r });
    assert.deepEqual([...resumed.factorsDeleted], ordered);
    assert.equal((await mfaEvents(db, r)).length, 1);
    assert.equal(fake.users.get(u).factors.size, 0);
  });
});

test('a user without factors completes as no_factors with empty lists', async () => {
  await withDatabase(async (db) => {
    const { fake, operator } = await stack(db);
    const u = await addUser(fake, db);
    const r = uuid();
    const done = await operator('A').client.mfaReset({ userId: u, requestId: r });
    assert.equal(done.result, 'no_factors');
    assert.equal(fake.callsTo('delete_factor').length, 0);
    assert.equal((await mfaEvents(db, r))[0].result, 'no_factors');
  });
});
