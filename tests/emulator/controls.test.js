// In-process fixture controls: argument validation, core model validation,
// detached snapshots and redaction of every secret the fixture handles.
// Synthetic fixture evidence only.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isAuthError } from '@briqvent/dwarpal';
import { PASSWORD, client, clientSnapshot, randomUuid, raw, signedIn, start, studioModel } from './support.js';

test('seedClient validates the model with core and the live-client manager invariant', async (t) => {
  const { controls } = await start(t);
  const manager = controls.seedUser({ email: 'boss@example.test', password: PASSWORD });
  const unconfirmed = controls.seedUser({ email: 'unsure@example.test', password: PASSWORD, confirmed: false });
  const modelError = (fn) => assert.throws(fn, (error) => isAuthError(error) && error.code === 'model_invalid');
  const selfManager = studioModel();
  selfManager.roles.member.manages_members = true;
  modelError(() => controls.seedClient({ clientId: 'studio', signupPolicy: 'open', model: selfManager }));
  modelError(() => controls.seedClient({ clientId: 'other', signupPolicy: 'open', model: studioModel() }));
  modelError(() => controls.seedClient({ clientId: 'studio', signupPolicy: 'open', model: { client: 'studio', roles: {}, permissions: {} } }));
  const typeError = (input, pattern) => assert.throws(() => controls.seedClient(input), (error) => error instanceof TypeError && pattern.test(error.message));
  const base = { clientId: 'studio', signupPolicy: 'open', model: studioModel() };
  typeError({ ...base, signupPolicy: 'invite' }, /signupPolicy/);
  typeError({ ...base, state: 'retired' }, /state/);
  typeError({ ...base, clientId: 'a\u0000b' }, /opaque clientId/);
  typeError({ ...base, state: 'live' }, /previously seeded manager/);
  typeError({ ...base, state: 'live', managerUserId: randomUuid(), managerRoleKey: 'steward' }, /previously seeded manager/);
  typeError({ ...base, state: 'live', managerUserId: unconfirmed.userId, managerRoleKey: 'steward' }, /confirmed/);
  typeError({ ...base, state: 'live', managerUserId: manager.userId, managerRoleKey: 'member' }, /manages_members/);
  typeError({ ...base, managerUserId: manager.userId, managerRoleKey: 'steward' }, /only a live client/);
  typeError({ ...base, model: null, state: 'live', managerUserId: manager.userId, managerRoleKey: 'steward' }, /needs a model/);
  typeError({ ...base, roles: {} }, /does not accept/);
  assert.deepEqual(controls.seedClient({ ...base, state: 'live', managerUserId: manager.userId, managerRoleKey: 'steward' }), { clientId: 'studio' });
  typeError(base, /already seeded/);
  const live = controls.snapshot().clients[0];
  assert.equal(live.state, 'live');
  assert.deepEqual(live.memberships, [{ userId: manager.userId, roleKey: 'steward', grantedVia: 'operator', grantedBy: null }]);
  assert.deepEqual(live.events.map((e) => [e.action, e.actorKind]), [['bootstrap', 'operator']]);
});

test('seedUser, issueLink, setMembership, advanceTime, totpCode and setOAuthAccount reject bad input explicitly', async (t) => {
  const { controls } = await start(t);
  const rejects = (fn, pattern) => assert.throws(fn, (error) => error instanceof TypeError && pattern.test(error.message));
  rejects(() => controls.seedUser({ email: 'not-an-email', password: PASSWORD }), /valid email/);
  rejects(() => controls.seedUser({ email: 'short@example.test', password: '12345' }), /password/);
  rejects(() => controls.seedUser({ email: 'long@example.test', password: 'x'.repeat(73) }), /password/);
  rejects(() => controls.seedUser({ email: 'aal@example.test', password: PASSWORD, aal: 'aal3' }), /aal/);
  rejects(() => controls.seedUser({ email: 'flag@example.test', password: PASSWORD, confirmed: 'yes' }), /confirmed/);
  const { userId } = controls.seedUser({ email: 'Case@Example.test', password: PASSWORD });
  rejects(() => controls.seedUser({ email: 'case@example.TEST', password: PASSWORD }), /already seeded/);
  rejects(() => controls.issueLink({ type: 'magiclink', email: 'case@example.test' }), /type/);
  rejects(() => controls.issueLink({ type: 'email', email: 'ghost@example.test' }), /no seeded/);
  controls.seedClient({ clientId: 'studio', signupPolicy: 'open', model: studioModel() });
  rejects(() => controls.setMembership({ userId: randomUuid(), clientId: 'studio', roleKey: 'member', present: true }), /unknown user/);
  rejects(() => controls.setMembership({ userId, clientId: 'elsewhere', roleKey: 'member', present: true }), /unknown client/);
  rejects(() => controls.setMembership({ userId, clientId: 'studio', roleKey: 'ghost', present: true }), /unknown role/);
  rejects(() => controls.setMembership({ userId, clientId: 'studio', roleKey: 'member', present: 1 }), /boolean/);
  for (const ms of [-1, Number.NaN, Number.POSITIVE_INFINITY, '5', null]) rejects(() => controls.advanceTime(ms), /finite nonnegative/);
  rejects(() => controls.totpCode({ factorId: randomUuid() }), /unknown factor/);
  rejects(() => controls.setOAuthAccount({ email: 'nope' }), /valid email/);
  rejects(() => controls.setEmailConfirmed({ userId: randomUuid(), confirmed: false }), /unknown user/);
  const before = controls.snapshot().now;
  controls.advanceTime(0);
  controls.advanceTime(1500);
  assert.equal(Date.parse(controls.snapshot().now) - Date.parse(before), 1500);
});

test('setMembership keeps the enrollment ledger and writes no events; the clock is fixed unless advanced', async (t) => {
  const emulator = await start(t, { now: Date.parse('2026-03-01T10:00:00Z') });
  emulator.controls.seedClient({ clientId: 'studio', signupPolicy: 'open', model: studioModel() });
  const { kit, userId } = await signedIn(emulator, 'ledger@example.test');
  const joined = (await kit.rpc('join_client', { client_id: 'studio' })).data;
  assert.equal(joined.enrolled_at, '2026-03-01T10:00:00.000000Z');
  const before = clientSnapshot(emulator);
  assert.deepEqual(emulator.controls.setMembership({ userId, clientId: 'studio', roleKey: 'member', present: false }), { changed: true });
  assert.deepEqual(emulator.controls.setMembership({ userId, clientId: 'studio', roleKey: 'member', present: false }), { changed: false });
  assert.deepEqual(emulator.controls.setMembership({ userId, clientId: 'studio', roleKey: 'curator', present: true }), { changed: true });
  const after = clientSnapshot(emulator);
  assert.deepEqual(after.enrollments, before.enrollments);
  assert.deepEqual(after.events, before.events);
  assert.deepEqual(after.memberships.map((m) => m.roleKey).sort(), ['curator', 'reader']);
  assert.equal(emulator.controls.snapshot().now, '2026-03-01T10:00:00.000000Z');
});

test('snapshot is detached: changing a returned snapshot changes nothing in the fixture', async (t) => {
  const emulator = await start(t);
  emulator.controls.seedClient({ clientId: 'studio', signupPolicy: 'open', model: studioModel() });
  const { kit } = await signedIn(emulator, 'detached@example.test');
  await kit.rpc('join_client', { client_id: 'studio' });
  const first = emulator.controls.snapshot();
  first.clients[0].enrollments.length = 0;
  first.clients[0].memberships[0].roleKey = 'steward';
  first.users[0].confirmed = false;
  first.counts.enrollments = 99;
  const second = emulator.controls.snapshot();
  assert.equal(second.clients[0].enrollments.length, 1);
  assert.equal(second.clients[0].memberships[0].roleKey, 'member');
  assert.equal(second.users[0].confirmed, true);
  assert.equal(second.counts.enrollments, 1);
  assert.equal(second.synthetic, true);
});

test('redaction: snapshots, logs and error bodies never carry passwords, link hashes, tokens, factor secrets or request bodies', async (t) => {
  const entries = [];
  const emulator = await start(t, { log: (entry) => entries.push(entry) });
  const secrets = [PASSWORD, 'Canary-Password-77', 'canary-value-in-a-body'];
  emulator.controls.seedClient({ clientId: 'studio', signupPolicy: 'open', model: studioModel() });
  const signup = client(emulator);
  await signup.auth.signUp({ email: 'canary@example.test', password: 'Canary-Password-77', options: { data: { note: 'canary-value-in-a-body' } } });
  const { tokenHash } = emulator.controls.issueLink({ type: 'email', email: 'canary@example.test' });
  secrets.push(tokenHash);
  const verified = await signup.auth.verifyOtp({ type: 'email', token_hash: tokenHash });
  secrets.push(verified.data.session.access_token, verified.data.session.refresh_token);
  const enrolled = await signup.auth.mfa.enroll({ factorType: 'totp', friendlyName: 'canary' });
  secrets.push(enrolled.data.totp.secret);
  const { kit } = await signedIn(emulator, 'second@example.test');
  await kit.rpc('join_client', { client_id: 'studio' });
  const recovery = emulator.controls.issueLink({ type: 'recovery', email: 'second@example.test' });
  secrets.push(recovery.tokenHash);

  const errorBodies = [];
  for (const [path, init] of [
    ['/auth/v1/signup', { method: 'POST', body: { email: 'canary-value-in-a-body', password: PASSWORD } }],
    ['/auth/v1/verify', { method: 'POST', body: { type: 'email', token_hash: tokenHash } }],
    ['/auth/v1/token?grant_type=password', { method: 'POST', body: { email: 'canary@example.test', password: 'Canary-Password-77-wrong' } }],
    ['/auth/v1/user', { headers: { authorization: `Bearer ${verified.data.session.access_token}x` } }],
    ['/rest/v1/rpc/grant_membership', { method: 'POST', headers: { 'content-profile': 'auth_kit', authorization: `Bearer ${verified.data.session.access_token}` },
      body: { user_id: 'canary-value-in-a-body', client_id: 'studio', role_key: 'member', request_id: randomUuid() } }],
    ['/rest/v1/rpc/join_client', { method: 'POST', headers: { 'content-profile': 'auth_kit', authorization: `Bearer ${verified.data.session.access_token}` },
      body: { client_id: 'studio', 'canary-value-in-a-body': 1 } }],
  ]) {
    errorBodies.push(await (await raw(emulator, path, init)).text());
  }
  const snapshotText = JSON.stringify(emulator.controls.snapshot());
  const logText = JSON.stringify(entries);
  for (const secret of secrets) {
    assert.ok(!snapshotText.includes(secret), 'snapshot leaks a secret');
    assert.ok(!logText.includes(secret), 'log leaks a secret');
    for (const body of errorBodies) assert.ok(!body.includes(secret), 'an error body echoes request data');
  }
  assert.ok(!snapshotText.includes(emulator.publishableKey));
  assert.ok(!logText.includes('@example.test'), 'log entries carry no addresses');
  assert.ok(entries.length > 10);
  for (const entry of entries) {
    assert.deepEqual(Object.keys(entry).filter((k) => !['method', 'route', 'operation', 'status', 'fault'].includes(k)), []);
    assert.match(entry.route, /^[a-z_]+$/);
  }
});

test('a throwing logger never changes an answer', async (t) => {
  const emulator = await start(t, { log: () => { throw new Error('logger down'); } });
  assert.equal((await raw(emulator, '/auth/v1/settings')).status, 200);
});
