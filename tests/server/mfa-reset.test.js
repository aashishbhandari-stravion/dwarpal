// mfaReset runner, L35 (a)–(i) at unit level: a mocked Auth admin API (the
// fixture's factor endpoints), an in-memory mirror of the SQL claim
// functions, a fake monotonic clock and injected timers. The same scenarios
// run against the real SQL functions in sql/mfa-reset.test.js. Neither is
// hosted evidence: real Auth deadlines and lease passage are Lane 06.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createOperatorClient, OperatorError } from '../../packages/server/operator.js';
import { createFakeSupabase, SECRET_KEY, jsonResponse } from './support/fake-supabase.js';
import { createMemoryMfa } from './support/memory-mfa.js';

const R = '00000000-0000-4000-8000-0000000000a1';

function manualClock(start = 1_000) {
  let t = start;
  return { now: () => t, advance: (ms) => { t += ms; } };
}

async function setup() {
  const fake = await createFakeSupabase();
  const sql = createMemoryMfa();
  fake.rpc = sql.handle;
  const operator = (name = 'A', { clock = manualClock(), timers } = {}) => {
    const fetchAs = (input, init = {}) => fake.fetch(input, { ...init, headers: { ...init.headers, 'x-runner': name } });
    return { clock, client: createOperatorClient({ supabaseUrl: fake.origin, secretKey: SECRET_KEY, fetch: fetchAs, monotonicNow: clock.now, ...(timers ? { timers } : {}) }) };
  };
  return { fake, sql, operator };
}

function runner(ctx) {
  return ctx.request.headers.get('x-runner');
}

async function rejectsWith(promise, code, check) {
  return assert.rejects(promise, (error) => {
    assert.ok(error instanceof OperatorError, `expected OperatorError, got ${error?.name}: ${error?.message}`);
    assert.equal(error.code, code);
    check?.(error);
    return true;
  });
}

// After begin, every failure says how to converge: the same request id.
function sameId(error) {
  assert.equal(error.details.recovery, 'rerun_same_request_id');
  assert.doesNotMatch(error.message, /nothing|unchanged/i);
}

function gate() {
  let open;
  const promise = new Promise((resolve) => { open = resolve; });
  return { promise, open };
}

test('L35(a) reserve before Auth, then complete with the recorded list and one event', async () => {
  const { fake, sql, operator } = await setup();
  const u = fake.addUser();
  const f = fake.addFactor(u);
  fake.addFactor(u, { status: 'unverified' });
  fake.addFactor(u, { type: 'phone' });
  fake.hooks.set('list_factors', async () => {
    const row = sql.rows.get(R);
    assert.equal(row?.state, 'pending', 'a pending row exists before listFactors');
    assert.equal(row.factorsSeen, null);
    return undefined;
  });
  const result = await operator().client.mfaReset({ userId: u, requestId: R });
  assert.deepEqual({ ...result, factorsSeen: [...result.factorsSeen], factorsDeleted: [...result.factorsDeleted] },
    { outcome: 'proceed', replayed: false, result: 'reset', factorsSeen: [f], factorsDeleted: [f] });
  assert.equal(sql.rows.get(R).state, 'completed');
  assert.equal(sql.events.length, 1);
  assert.equal(fake.users.get(u).factors.size, 2, 'only the verified TOTP factor is deleted');
  assert.deepEqual(sql.calls, ['mfa_reset_begin', 'mfa_reset_note', 'mfa_reset_finish']);
  assert.deepEqual(fake.adminCalls().map((c) => c.route), ['list_factors', 'delete_factor']);
  assert.ok(fake.adminCalls().every((c) => c.credential === 'secret'));
});

test('L35(b) a retry after success returns the stored result with no admin call and no write', async () => {
  const { fake, sql, operator } = await setup();
  const u = fake.addUser();
  fake.addFactor(u);
  await operator().client.mfaReset({ userId: u, requestId: R });
  const before = fake.adminCalls().length;
  const replay = await operator('B').client.mfaReset({ userId: u, requestId: R });
  assert.equal(replay.outcome, 'completed');
  assert.equal(replay.replayed, true);
  assert.equal(replay.result, 'reset');
  assert.equal(fake.adminCalls().length, before);
  assert.equal(sql.events.length, 1);
});

test('L35(c) the same id for another user is request_conflict before any admin call', async () => {
  const { fake, sql, operator } = await setup();
  const u = fake.addUser();
  const u2 = fake.addUser();
  fake.addFactor(u);
  const f2 = fake.addFactor(u2);
  await operator().client.mfaReset({ userId: u, requestId: R });
  const before = fake.adminCalls().length;
  await rejectsWith(operator('B').client.mfaReset({ userId: u2, requestId: R }), 'request_conflict');
  assert.equal(fake.adminCalls().length, before);
  assert.ok(fake.users.get(u2).factors.has(f2));
  assert.equal(sql.events.length, 1);
});

test('L35(d) a concurrent run with the same id is request_in_progress before any admin call', async () => {
  const { fake, sql, operator } = await setup();
  const u = fake.addUser();
  fake.addFactor(u);
  const hold = gate();
  const entered = gate();
  fake.hooks.set('list_factors', async (ctx) => {
    if (runner(ctx) === 'A') {
      entered.open();
      await hold.promise;
    }
    return undefined;
  });
  const first = operator('A').client.mfaReset({ userId: u, requestId: R });
  await entered.promise;
  await rejectsWith(operator('B').client.mfaReset({ userId: u, requestId: R }), 'request_in_progress');
  assert.ok(fake.adminCalls().every((c) => c.route === 'list_factors'), 'B made no admin call');
  hold.open();
  assert.equal((await first).result, 'reset');
  assert.equal(sql.events.length, 1);
});

test('L35(e) crash after the first of two deletions: in-progress inside the lease, resume with the original list after it', async () => {
  const { fake, sql, operator } = await setup();
  const u = fake.addUser();
  const f1 = fake.addFactor(u);
  const f2 = fake.addFactor(u);
  const ordered = [f1, f2].sort();
  let deletes = 0;
  fake.hooks.set('delete_factor', async () => {
    deletes += 1;
    if (deletes === 2) throw new TypeError('crash');
    return undefined;
  });
  // The crashed delete may have been applied.
  await rejectsWith(operator('A').client.mfaReset({ userId: u, requestId: R }), 'outcome_unknown', sameId);
  assert.deepEqual(sql.rows.get(R).factorsSeen, ordered);
  assert.equal(sql.rows.get(R).state, 'pending');
  fake.hooks.clear();
  const adminBefore = fake.adminCalls().length;
  await rejectsWith(operator('B').client.mfaReset({ userId: u, requestId: R }), 'request_in_progress');
  assert.equal(fake.adminCalls().length, adminBefore);
  sql.expire(R);
  const resumed = await operator('C').client.mfaReset({ userId: u, requestId: R });
  assert.equal(resumed.outcome, 'resume');
  assert.deepEqual([...resumed.factorsSeen], ordered);
  assert.deepEqual([...resumed.factorsDeleted], ordered, "the first factor's not-found counts as deleted");
  assert.equal(resumed.result, 'reset');
  assert.equal(fake.users.get(u).factors.size, 0);
  // The resumed run did not list again: it used the recorded list.
  assert.equal(fake.callsTo('list_factors').length, 1);
  assert.equal(sql.events.length, 1);
});

test('L35(f) crash before note: resume with no recorded list lists, notes and completes', async () => {
  const { fake, sql, operator } = await setup();
  const u = fake.addUser();
  const f = fake.addFactor(u);
  fake.hooks.set('list_factors', async () => jsonResponse(503, { msg: 'unavailable' }));
  // A failed read, but the claim is reserved: the same id resumes it.
  await rejectsWith(operator('A').client.mfaReset({ userId: u, requestId: R }), 'unavailable', sameId);
  assert.equal(sql.rows.get(R).factorsSeen, null);
  fake.hooks.clear();
  sql.expire(R);
  const resumed = await operator('B').client.mfaReset({ userId: u, requestId: R });
  assert.equal(resumed.outcome, 'resume');
  assert.deepEqual([...resumed.factorsSeen], [f]);
  assert.equal(resumed.result, 'reset');
  assert.equal(sql.events.length, 1);
});

test('L35(g) two retries just after the lease: one claims and completes, the other is refused before Auth', async () => {
  const { fake, sql, operator } = await setup();
  const u = fake.addUser();
  fake.addFactor(u);
  fake.addFactor(u);
  let deletes = 0;
  fake.hooks.set('delete_factor', async () => {
    deletes += 1;
    if (deletes === 2) throw new TypeError('crash');
    return undefined;
  });
  // The crashed delete may have been applied.
  await rejectsWith(operator('A').client.mfaReset({ userId: u, requestId: R }), 'outcome_unknown', sameId);
  sql.expire(R);
  const hold = gate();
  const entered = gate();
  fake.hooks.set('delete_factor', async (ctx) => {
    if (runner(ctx) === 'B') {
      entered.open();
      await hold.promise;
    }
    return undefined;
  });
  const b = operator('B').client.mfaReset({ userId: u, requestId: R });
  await entered.promise;
  const tokenB = sql.rows.get(R).token;
  const callsBefore = fake.adminCalls().length;
  await rejectsWith(operator('C').client.mfaReset({ userId: u, requestId: R }), 'request_in_progress');
  assert.equal(fake.adminCalls().length, callsBefore, 'the second retry never reached Auth');
  hold.open();
  assert.equal((await b).outcome, 'resume');
  assert.equal(sql.rows.get(R).state, 'completed');
  assert.equal(sql.rows.get(R).token, tokenB);
  assert.equal(sql.events.length, 1);
});

test('L35(h) a superseded runner that wakes after a takeover completed gets run_superseded, never a stored success', async () => {
  const { fake, sql, operator } = await setup();
  const u = fake.addUser();
  const [f1, f2] = [fake.addFactor(u), fake.addFactor(u)].sort();
  const hold = gate();
  const paused = gate();
  let aDeletes = 0;
  fake.hooks.set('delete_factor', async (ctx) => {
    if (runner(ctx) === 'A') {
      aDeletes += 1;
      if (aDeletes === 2) {
        // A is inside its second admin call when its lease passes to B.
        paused.open();
        await hold.promise;
      }
    }
    return undefined;
  });
  const a = operator('A').client.mfaReset({ userId: u, requestId: R });
  await paused.promise;
  const tokenA = sql.rows.get(R).token;
  sql.expire(R);
  const b = await operator('B').client.mfaReset({ userId: u, requestId: R });
  assert.equal(b.outcome, 'resume');
  assert.equal(b.result, 'reset');
  const tokenB = sql.rows.get(R).token;
  assert.notEqual(tokenA, tokenB);
  hold.open();
  await rejectsWith(a, 'run_superseded');
  // A's late delete saw not-found; its finish wrote nothing.
  const lateDelete = fake.callsTo('delete_factor').filter((c) => c.path.endsWith(f2));
  assert.equal(lateDelete.length, 2);
  // A's note with its stale token is refused the same way (token before state).
  const note = await fake.fetch(`${fake.origin}/rest/v1/rpc/mfa_reset_note`, {
    method: 'POST',
    headers: { apikey: SECRET_KEY, Authorization: `Bearer ${SECRET_KEY}`, 'Content-Profile': 'auth_kit', 'Content-Type': 'application/json' },
    body: JSON.stringify({ request_id: R, run_token: tokenA, factor_ids: [f1] }),
  });
  assert.equal((await note.json()).message, 'run_superseded');
  assert.equal(sql.events.length, 1);
  assert.equal(sql.events[0].token, tokenB);
  assert.equal(sql.rows.get(R).token, tokenB);
  assert.deepEqual(sql.rows.get(R).result.factors_deleted, [f1, f2]);
});

test('L35(i) claim age past 100 s before the first deletion stops with lease_expired; the retry resumes and completes', async () => {
  const { fake, sql, operator } = await setup();
  const u = fake.addUser();
  const f1 = fake.addFactor(u);
  const f2 = fake.addFactor(u);
  const a = operator('A');
  fake.hooks.set('list_factors', async () => {
    a.clock.advance(101_000);
    return undefined;
  });
  await rejectsWith(a.client.mfaReset({ userId: u, requestId: R }), 'lease_expired');
  assert.equal(fake.callsTo('delete_factor').length, 0, 'no admin call after the deadline');
  assert.equal(sql.rows.get(R).state, 'pending');
  assert.deepEqual(sql.rows.get(R).factorsSeen, [f1, f2].sort());
  fake.hooks.clear();
  await rejectsWith(operator('B').client.mfaReset({ userId: u, requestId: R }), 'request_in_progress');
  sql.expire(R);
  const resumed = await operator('C').client.mfaReset({ userId: u, requestId: R });
  assert.equal(resumed.outcome, 'resume');
  assert.deepEqual([...resumed.factorsDeleted], [f1, f2].sort());
  assert.equal(sql.events.length, 1);
});

test('the pre-call deadline is strict at 100 s on the monotonic clock', async () => {
  for (const [age, allowed] of [[99_999, true], [100_000, false]]) {
    const { fake, operator } = await setup();
    const u = fake.addUser();
    fake.addFactor(u);
    const a = operator('A');
    fake.hooks.set('list_factors', async () => {
      a.clock.advance(age);
      return undefined;
    });
    const run = a.client.mfaReset({ userId: u, requestId: R });
    if (allowed) assert.equal((await run).result, 'reset');
    else await rejectsWith(run, 'lease_expired');
  }
});

test('every admin call gets its own 20 s abort deadline, and firing it stops the run with the row pending', async () => {
  const { fake, sql, operator } = await setup();
  const u = fake.addUser();
  fake.addFactor(u);
  fake.addFactor(u);
  const timers = [];
  const fakeTimers = {
    setTimeout: (fn, ms) => { const t = { fn, ms, cleared: false }; timers.push(t); return t; },
    clearTimeout: (t) => { if (t) t.cleared = true; },
  };
  const signals = [];
  let deleteCalls = 0;
  fake.hooks.set('list_factors', async (ctx) => { signals.push(ctx.call.signal); return undefined; });
  fake.hooks.set('delete_factor', async (ctx) => {
    signals.push(ctx.call.signal);
    deleteCalls += 1;
    if (deleteCalls === 2) {
      // This call hangs; its own deadline must abort it.
      const pending = timers.at(-1);
      assert.equal(pending.ms, 20_000);
      assert.equal(ctx.call.signal.aborted, false);
      queueMicrotask(() => pending.fn());
      return new Promise(() => {});
    }
    return undefined;
  });
  const { client } = operator('A', { timers: fakeTimers });
  // The abandoned delete may still have been applied.
  await rejectsWith(client.mfaReset({ userId: u, requestId: R }), 'outcome_unknown', sameId);
  // One 20 s timer per call (begin, list, note, delete, delete), each separate.
  assert.deepEqual(timers.map((t) => t.ms), [20_000, 20_000, 20_000, 20_000, 20_000]);
  assert.equal(new Set(signals).size, 3);
  assert.equal(signals.at(-1).aborted, true, 'the hung call observed its abort');
  assert.equal(signals[0].aborted, false);
  assert.equal(sql.rows.get(R).state, 'pending');
  assert.equal(sql.calls.includes('mfa_reset_finish'), false);
});

test('a real hung admin call is abandoned at the configured deadline even if fetch ignores its signal', async () => {
  const fake = await createFakeSupabase();
  const sql = createMemoryMfa();
  fake.rpc = sql.handle;
  const u = fake.addUser();
  fake.addFactor(u);
  fake.hooks.set('list_factors', () => new Promise(() => {}));
  const client = createOperatorClient({ supabaseUrl: fake.origin, secretKey: SECRET_KEY, fetch: fake.fetch, adminTimeoutMs: 150 });
  const started = performance.now();
  await rejectsWith(client.mfaReset({ userId: u, requestId: R }), 'unavailable');
  const elapsed = performance.now() - started;
  assert.ok(elapsed >= 140 && elapsed < 2_000, `elapsed ${elapsed}`);
});

test('only factor-not-found counts as deleted; a missing user or other answer stops the run', async () => {
  const { fake, sql, operator } = await setup();
  const u = fake.addUser();
  fake.addFactor(u);
  fake.hooks.set('delete_factor', async () => jsonResponse(404, { code: 404, error_code: 'user_not_found', msg: 'User not found' }));
  await rejectsWith(operator().client.mfaReset({ userId: u, requestId: R }), 'unavailable');
  fake.hooks.set('delete_factor', async () => jsonResponse(404, { code: 404, msg: 'Not found' }));
  sql.expire(R);
  await rejectsWith(operator('B').client.mfaReset({ userId: u, requestId: R }), 'unavailable');
  assert.equal(sql.rows.get(R).state, 'pending');
  assert.equal(sql.events.length, 0);
});

test('a lost answer to begin, note or finish is outcome_unknown; the rerun with the same id converges', async () => {
  const { fake, sql, operator } = await setup();
  const u = fake.addUser();
  fake.addFactor(u);
  fake.hooks.set('rpc', async (ctx) => {
    if (ctx.body && ctx.call.path.endsWith('mfa_reset_finish')) {
      await sql.handle({ fn: 'mfa_reset_finish', args: ctx.body, actor: { role: 'service_role' } });
      throw new TypeError('answer lost after commit');
    }
    return undefined;
  });
  await rejectsWith(operator('A').client.mfaReset({ userId: u, requestId: R }), 'outcome_unknown');
  fake.hooks.clear();
  const replay = await operator('B').client.mfaReset({ userId: u, requestId: R });
  assert.equal(replay.outcome, 'completed');
  assert.equal(sql.events.length, 1);
  await rejectsWith(operator('C').client.mfaReset({ userId: 'nope', requestId: R }), 'invalid_argument');
});

test('malformed claim answers are outcome_unknown (the claim may be reserved) and stop before Auth', async () => {
  const { fake, operator } = await setup();
  const u = fake.addUser();
  for (const body of [
    { outcome: 'proceed', run_token: 'not-a-uuid', factors_seen: null },
    { outcome: 'proceed', run_token: R, factors_seen: [R] },
    { outcome: 'resume', run_token: R },
    { outcome: 'completed', result: { result: 'reset', factors_seen: [], factors_deleted: [], extra: 1 } },
    { outcome: 'maybe' },
  ]) {
    fake.rpc = async () => jsonResponse(200, body);
    await rejectsWith(operator().client.mfaReset({ userId: u, requestId: R }), 'outcome_unknown', (e) => {
      sameId(e);
      assert.equal(e.details.stage, 'mfa_reset_begin');
    });
  }
  assert.equal(fake.adminCalls().length, 0);
});

test('a factor deletion Auth applied but whose answer was lost, unreadable or a 5xx is outcome_unknown; the same id converges', async () => {
  for (const answer of [
    () => { throw new TypeError('lost after delete'); },
    () => new Response('<html>', { status: 502 }),
    () => jsonResponse(500, {}),
  ]) {
    const { fake, sql, operator } = await setup();
    const u = fake.addUser();
    const f = fake.addFactor(u);
    fake.hooks.set('delete_factor', async ({ match }) => {
      fake.users.get(match[1]).factors.delete(match[2]);
      return answer();
    });
    await rejectsWith(operator('A').client.mfaReset({ userId: u, requestId: R }), 'outcome_unknown', (e) => {
      sameId(e);
      assert.equal(e.details.stage, 'delete_factor');
    });
    assert.equal(fake.users.get(u).factors.size, 0, 'Auth applied the deletion');
    assert.equal(sql.rows.get(R).state, 'pending');
    fake.hooks.clear();
    sql.expire(R);
    const resumed = await operator('B').client.mfaReset({ userId: u, requestId: R });
    assert.deepEqual([resumed.outcome, resumed.result, [...resumed.factorsDeleted]], ['resume', 'reset', [f]]);
    assert.equal(sql.events.length, 1);
  }
});
