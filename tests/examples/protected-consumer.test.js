// The generic protected Node consumer (examples/protected-consumer) against the
// real server library and the synthetic loopback fixture: the own/any guard
// with the consumer's own SQLite links, the literal L26 sequence, a revoked
// role (L6), another client's user (L12), a historical contact email without a
// link (L16), live session revocation on the Node path (L25a), request-id
// semantics on manager writes, and fail-closed behaviour when the consumer's
// store or Supabase is unavailable. Fixture evidence only; no hosted Supabase
// is involved.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { chmod, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { join, dirname } from 'node:path';
import { consumerWorld, loadModel, raiseToAal2, CLIENT_ID } from './support/consumer-world.js';
import { signedIn } from '../emulator/support.js';
import { createStore, StoreUnavailableError } from '../../examples/protected-consumer/store.js';

const seed = (store) => {
  store.createRecord({ id: 'r-mine', title: 'Linked to the member' });
  store.createRecord({ id: 'r-other', title: 'Linked to nobody' });
};

test('requests without a valid bearer token get 401 and never reach the store', async (t) => {
  const w = await consumerWorld(t);
  seed(w.store);
  const none = await w.call(null, 'GET', '/records');
  assert.equal(none.status, 401);
  assert.deepEqual(none.body, { error: 'no_token' });
  assert.equal(none.headers.get('www-authenticate'), 'Bearer');
  assert.equal(none.headers.get('cache-control'), 'no-store');
  const garbage = await w.call(null, 'GET', '/records/r-mine', { rawToken: 'not.a.jwt' });
  assert.equal(garbage.status, 401);
  assert.equal(garbage.body.error, 'invalid_token');
  assert.equal((await w.call(null, 'GET', '/health')).status, 200);
  assert.deepEqual(w.store.events(), []);
});

test('L26: customer plus MFA-required staff at aal1 — the literal own/any sequence', async (t) => {
  const w = await consumerWorld(t);
  seed(w.store);
  const user = await w.member('both@example.test', { aal: 'aal2' });
  // The manager grants the MFA-required staff role through the consumer's own endpoint.
  const granted = await w.call(w.manager, 'PUT', `/members/${user.userId}/roles/staff`, { headers: { 'idempotency-key': randomUUID() } });
  assert.deepEqual([granted.status, granted.body], [200, { result: 'granted' }]);
  assert.equal((await w.call(w.manager, 'PUT', `/records/r-mine/links/${user.userId}`)).body.result, 'linked');

  // aal1: staff is withheld. (i) another record: forbidden, and the page is told MFA would help.
  const other = await w.call(user, 'GET', '/records/r-other');
  assert.equal(other.status, 403);
  assert.deepEqual(other.body, { error: 'forbidden', withheld: ['staff'] });
  // (ii) the linked record: own permission plus the consumer's link.
  const mine = await w.call(user, 'GET', '/records/r-mine');
  assert.deepEqual([mine.status, mine.body.id], [200, 'r-mine']);
  assert.deepEqual((await w.call(user, 'GET', '/records')).body.records.map((r) => r.id), ['r-mine']);

  // aal2: the broad key becomes active, so both records succeed.
  await raiseToAal2(w.emulator, user.supabase, user.factorId);
  assert.equal((await w.call(user, 'GET', '/records/r-other')).status, 200);
  assert.equal((await w.call(user, 'GET', '/records/r-mine')).status, 200);
  assert.deepEqual((await w.call(user, 'GET', '/records')).body.records.map((r) => r.id), ['r-mine', 'r-other']);
});

test('an absent record and an unlinked record look the same to a caller without the broad key', async (t) => {
  const w = await consumerWorld(t);
  seed(w.store);
  const plain = await w.member('plain@example.test');
  const unlinked = await w.call(plain, 'GET', '/records/r-other');
  const absent = await w.call(plain, 'GET', '/records/r-missing');
  assert.deepEqual([unlinked.status, unlinked.body], [403, { error: 'forbidden' }]);
  assert.deepEqual([absent.status, absent.body], [403, { error: 'forbidden' }]);
  assert.equal(unlinked.text, absent.text);
  // The broad reader can tell them apart: 404 for an absent record.
  assert.equal((await w.call(w.manager, 'GET', '/records/r-missing')).status, 404);
  assert.equal((await w.call(w.manager, 'GET', '/records/r-other')).status, 200);
  assert.deepEqual((await w.call(plain, 'GET', '/records')).body, { records: [] });
});

test('L16: a verified email equal to a historical contact grants no records without a link row', async (t) => {
  const w = await consumerWorld(t);
  w.store.createRecord({ id: 'r-history', title: 'Old enquiry', contactEmail: 'contact@example.test' });
  const owner = await w.member('contact@example.test');
  assert.deepEqual((await w.call(owner, 'GET', '/records')).body, { records: [] });
  assert.deepEqual((await w.call(owner, 'GET', '/records/r-history')).body, { error: 'forbidden' });
  // Only an explicit link, made by staff, opens it; the record never exposes the contact address.
  assert.equal((await w.call(w.manager, 'PUT', `/records/r-history/links/${owner.userId}`)).body.result, 'linked');
  const opened = await w.call(owner, 'GET', '/records/r-history');
  assert.deepEqual([opened.status, opened.body], [200, { id: 'r-history', title: 'Old enquiry' }]);
});

test('L12: a user who belongs to another client only is refused here', async (t) => {
  const w = await consumerWorld(t);
  seed(w.store);
  w.emulator.controls.seedClient({ clientId: 'other-client', signupPolicy: 'open', model: { ...(await loadModel()), client: 'other-client' } });
  const stranger = await signedIn(w.emulator, 'stranger@example.test');
  assert.equal((await stranger.kit.rpc('join_client', { client_id: 'other-client' })).error, null);
  for (const path of ['/records', '/records/r-mine']) {
    const r = await w.call(stranger, 'GET', path);
    assert.deepEqual([r.status, r.body], [403, { error: 'forbidden' }], path);
  }
  assert.equal((await w.call(stranger, 'PUT', '/records/r-mine/links/someone')).status, 403);
});

test('links are idempotent, audited once, and need the broad link permission', async (t) => {
  const w = await consumerWorld(t);
  seed(w.store);
  const plain = await w.member('link@example.test');
  assert.equal((await w.call(plain, 'PUT', `/records/r-mine/links/${plain.userId}`)).status, 403, 'a member cannot link themselves');
  for (const expected of ['linked', 'already_linked', 'already_linked']) {
    const r = await w.call(w.manager, 'PUT', `/records/r-mine/links/${plain.userId}`);
    assert.deepEqual([r.status, r.body.result], [200, expected]);
  }
  assert.equal(w.store.events().length, 1, 'the retries wrote no further events');
  assert.equal((await w.call(plain, 'GET', '/records/r-mine')).status, 200);
  for (const expected of ['unlinked', 'not_linked']) {
    assert.equal((await w.call(w.manager, 'DELETE', `/records/r-mine/links/${plain.userId}`)).body.result, expected);
  }
  assert.equal((await w.call(plain, 'GET', '/records/r-mine')).status, 403, 'an unlink takes effect on the next request');
  assert.deepEqual(w.store.events().map((e) => e.action), ['link', 'unlink']);
  assert.equal((await w.call(w.manager, 'PUT', `/records/nope/links/${plain.userId}`)).status, 404);
  assert.equal((await w.call(w.manager, 'GET', '/records/bad%20segment')).status, 404);
});

test('L25a: a signed-out token is refused on the very next request', async (t) => {
  const w = await consumerWorld(t);
  seed(w.store);
  const user = await w.member('leaving@example.test');
  const token = await w.token(user);
  assert.equal((await w.call(null, 'GET', '/records', { rawToken: token })).status, 200);
  await user.supabase.auth.signOut();
  const after = await w.call(null, 'GET', '/records', { rawToken: token });
  assert.deepEqual([after.status, after.body.error], [401, 'invalid_token']);
});

test('manager writes: request-id replay, conflict, missing key and non-manager refusal', async (t) => {
  const w = await consumerWorld(t);
  const one = await w.member('one@example.test');
  const two = await w.member('two@example.test');
  const id = randomUUID();
  const first = await w.call(w.manager, 'PUT', `/members/${one.userId}/roles/staff`, { headers: { 'idempotency-key': id } });
  const replay = await w.call(w.manager, 'PUT', `/members/${one.userId}/roles/staff`, { headers: { 'idempotency-key': id } });
  assert.deepEqual([first.body, replay.body], [{ result: 'granted' }, { result: 'granted' }]);
  const grants = w.emulator.controls.snapshot().clients[0].events.filter((e) => e.action === 'grant');
  assert.equal(grants.length, 1, 'the replay wrote no second event');
  const conflict = await w.call(w.manager, 'PUT', `/members/${two.userId}/roles/staff`, { headers: { 'idempotency-key': id } });
  assert.deepEqual([conflict.status, conflict.body], [409, { error: 'request_conflict' }]);
  assert.equal((await w.call(w.manager, 'PUT', `/members/${two.userId}/roles/staff`)).status, 400);
  assert.equal((await w.call(one, 'PUT', `/members/${two.userId}/roles/staff`, { headers: { 'idempotency-key': randomUUID() } })).status, 403, 'a non-manager cannot grant');
  const revoked = await w.call(w.manager, 'DELETE', `/members/${one.userId}/roles/staff`, { headers: { 'idempotency-key': randomUUID() } });
  assert.deepEqual([revoked.status, revoked.body.result], [200, 'revoked']);
});

test('L6: a role revoked by a manager stops working on the very next request, with the same token', async (t) => {
  const w = await consumerWorld(t);
  seed(w.store);
  const staffer = await w.member('staffer@example.test', { aal: 'aal2' });
  assert.equal((await w.call(w.manager, 'PUT', `/members/${staffer.userId}/roles/staff`, { headers: { 'idempotency-key': randomUUID() } })).status, 200);
  await raiseToAal2(w.emulator, staffer.supabase, staffer.factorId);
  assert.equal((await w.call(staffer, 'GET', '/records/r-other')).status, 200);
  assert.equal((await w.call(w.manager, 'DELETE', `/members/${staffer.userId}/roles/staff`, { headers: { 'idempotency-key': randomUUID() } })).status, 200);
  const after = await w.call(staffer, 'GET', '/records/r-other');
  assert.deepEqual([after.status, after.body], [403, { error: 'forbidden' }]);
});

test('fail closed: Supabase unavailable gives 503 with no data, and the next request recovers', async (t) => {
  const w = await consumerWorld(t);
  seed(w.store);
  w.emulator.controls.setFault({ operation: 'effective_access', mode: 'http_503' });
  const down = await w.call(w.manager, 'GET', '/records');
  assert.deepEqual([down.status, down.body], [503, { error: 'unavailable' }]);
  assert.equal((await w.call(w.manager, 'GET', '/records')).status, 200);
});

test('fail closed: an unreadable or locked consumer store gives 503, never a guessed answer', async (t) => {
  const w = await consumerWorld(t, { busyTimeoutMs: 50 });
  seed(w.store);
  const plain = await w.member('locked@example.test');

  // A writer in another process holds the lock: writes wait out the busy timeout and fail,
  // reads (WAL) still answer, and the failed write left nothing behind.
  const other = new DatabaseSync(w.file);
  other.exec('pragma busy_timeout = 50; begin immediate');
  const blocked = await w.call(w.manager, 'PUT', `/records/r-mine/links/${plain.userId}`);
  assert.deepEqual([blocked.status, blocked.body], [503, { error: 'unavailable' }]);
  assert.equal((await w.call(w.manager, 'GET', '/records')).status, 200);
  assert.deepEqual(w.store.events(), []);
  other.exec('rollback');
  other.close();
  // The retry after the lock is gone succeeds exactly once.
  assert.equal((await w.call(w.manager, 'PUT', `/records/r-mine/links/${plain.userId}`)).body.result, 'linked');
  assert.equal(w.store.events().length, 1);

  // The store closes under the running server (file gone, disk error, shutdown): 503, not 403 or 200.
  w.store.close();
  const gone = await w.call(plain, 'GET', '/records/r-mine');
  assert.deepEqual([gone.status, gone.body], [503, { error: 'unavailable' }]);
  assert.equal((await w.call(null, 'GET', '/records')).status, 401, 'authentication still comes first');
});

test('a store that cannot be opened refuses to start', async (t) => {
  const w = await consumerWorld(t);
  const junk = join(dirname(w.file), 'junk.sqlite');
  await writeFile(junk, 'this is not a database file, but it is long enough to be read as a header'.repeat(20));
  assert.throws(() => createStore(junk), StoreUnavailableError);
  // File permissions do not bind the superuser, so this case only runs for an ordinary account.
  if (process.getuid?.() !== 0) {
    const locked = join(dirname(w.file), 'locked.sqlite');
    await writeFile(locked, '');
    await chmod(locked, 0o000);
    try {
      assert.throws(() => createStore(locked), StoreUnavailableError);
    } finally {
      await chmod(locked, 0o600);
    }
  }
  assert.throws(() => createStore(join(dirname(w.file), 'missing-dir', 'x.sqlite')), StoreUnavailableError);
});

test('answers carry no token, key or provider text, and the model names only generic keys', async (t) => {
  const w = await consumerWorld(t);
  seed(w.store);
  const user = await w.member('leak@example.test');
  const token = await w.token(user);
  for (const path of ['/records', '/records/r-other', '/records/r-mine']) {
    const r = await w.call(user, 'GET', path);
    assert.ok(!r.text.includes(token) && !r.text.includes('sb_'), 'no credential in the body');
    assert.equal(r.headers.get('cache-control'), 'no-store');
  }
  const model = await loadModel();
  assert.equal(model.client, CLIENT_ID);
  assert.ok(!/creditone|order|lead/i.test(JSON.stringify(model)), 'the generic example carries no consumer-specific keys');
});
