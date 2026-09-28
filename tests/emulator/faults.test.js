// One-shot fault controls of the development fixture, seen through the pinned
// @supabase/supabase-js 2.117.2 client: what each mode leaves behind and how
// retries converge. Synthetic fixture evidence only.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PASSWORD, client, clientSnapshot, liveStudio, raiseToAal2, randomUuid, signedIn, start, studioModel } from './support.js';

async function studio(t) {
  const emulator = await start(t);
  emulator.controls.seedClient({ clientId: 'studio', signupPolicy: 'open', model: studioModel() });
  return emulator;
}

const join = (kit) => kit.rpc('join_client', { client_id: 'studio' });

test('setFault validates operation and mode, replaces a pending fault and is consumed by exactly one request', async (t) => {
  const emulator = await studio(t);
  const { controls } = emulator;
  assert.throws(() => controls.setFault({ operation: 'drop_table', mode: 'http_503' }), /unsupported operation/);
  assert.throws(() => controls.setFault({ operation: 'join_client', mode: 'slow' }), /unsupported mode/);
  assert.throws(() => controls.setFault({ operation: 'effective_access', mode: 'lost_after_commit' }), /writing operation/);
  assert.throws(() => controls.setFault({ operation: 'join_client', mode: 'http_503', extra: true }), /does not accept/);
  controls.setFault({ operation: 'join_client', mode: 'transport_loss' });
  controls.setFault({ operation: 'join_client', mode: 'http_503' });
  assert.deepEqual(controls.snapshot().pendingFaults, [{ operation: 'join_client', mode: 'http_503' }]);
  const { kit } = await signedIn(emulator, 'once@example.test');
  assert.equal((await join(kit)).status, 503);
  assert.deepEqual(controls.snapshot().pendingFaults, []);
  assert.equal((await join(kit)).data.result, 'enrolled');
});

test('L4: 503, transport loss and failure before commit write nothing; N retries give one enrollment and one event per role', async (t) => {
  const emulator = await studio(t);
  const { kit } = await signedIn(emulator, 'retry@example.test');

  emulator.controls.setFault({ operation: 'join_client', mode: 'http_503' });
  const unavailable = await join(kit);
  assert.equal(unavailable.status, 503);
  assert.notEqual(unavailable.error?.code, 'DW001', 'an outage never looks like a kit refusal');

  emulator.controls.setFault({ operation: 'join_client', mode: 'transport_loss' });
  const lost = await join(kit);
  assert.equal(lost.status, 0);
  assert.equal(lost.data, null);

  emulator.controls.setFault({ operation: 'join_client', mode: 'failed_before_commit' });
  const failed = await join(kit);
  assert.equal(failed.status, 500);
  assert.equal(failed.error.code, 'XX000');
  assert.equal(clientSnapshot(emulator).enrollments.length, 0, 'nothing committed by any of the three');

  emulator.controls.setFault({ operation: 'join_client', mode: 'lost_after_commit' });
  const committed = await join(kit);
  assert.equal(committed.status, 0, 'the caller cannot tell a lost answer from a lost request');
  assert.equal(clientSnapshot(emulator).enrollments.length, 1, 'but the write was applied once');

  for (let attempt = 0; attempt < 3; attempt += 1) assert.equal((await join(kit)).data.result, 'already_enrolled');
  const snapshot = clientSnapshot(emulator);
  assert.equal(snapshot.enrollments.length, 1);
  assert.deepEqual(snapshot.memberships.map((m) => m.roleKey).sort(), ['member', 'reader']);
  assert.equal(snapshot.events.length, 2);
});

test('L27 injected failure: a join that fails before commit leaves no enrollment; the next join enrolls', async (t) => {
  const emulator = await studio(t);
  const { kit } = await signedIn(emulator, 'injected@example.test');
  emulator.controls.setFault({ operation: 'join_client', mode: 'failed_before_commit' });
  assert.equal((await join(kit)).status, 500);
  const access = (await kit.rpc('effective_access', { client_id: 'studio' })).data;
  assert.equal(access.enrolled_at, null);
  assert.equal((await join(kit)).data.result, 'enrolled');
});

test('a grant whose answer is lost after commit is safe to retry with the same request id', async (t) => {
  const emulator = await start(t);
  await liveStudio(emulator);
  const convener = await signedIn(emulator, 'convener@example.test');
  emulator.controls.setMembership({ userId: convener.userId, clientId: 'studio', roleKey: 'convener', present: true });
  const target = await signedIn(emulator, 'target@example.test');
  const args = { user_id: target.userId, client_id: 'studio', role_key: 'member', request_id: randomUuid() };
  emulator.controls.setFault({ operation: 'grant_membership', mode: 'lost_after_commit' });
  assert.equal((await convener.kit.rpc('grant_membership', args)).status, 0);
  const retried = await convener.kit.rpc('grant_membership', args);
  assert.equal(retried.data.result, 'granted', 'the stored result, not already_member');
  const snapshot = clientSnapshot(emulator);
  assert.equal(snapshot.events.filter((e) => e.action === 'grant').length, 1);
  assert.equal(snapshot.requestLog.length, 1);

  emulator.controls.setFault({ operation: 'revoke_membership', mode: 'http_503' });
  assert.equal((await convener.kit.rpc('revoke_membership', { ...args, request_id: randomUuid() })).status, 503);
  assert.equal(clientSnapshot(emulator).memberships.some((m) => m.userId === target.userId), true);
});

test('effective_access faults: POST sees the 503; supabase-js retries a GET read once the one-shot fault is spent', async (t) => {
  const emulator = await studio(t);
  const { kit } = await signedIn(emulator, 'reader@example.test');
  emulator.controls.setFault({ operation: 'effective_access', mode: 'http_503' });
  assert.equal((await kit.rpc('effective_access', { client_id: 'studio' })).status, 503);
  emulator.controls.setFault({ operation: 'effective_access', mode: 'transport_loss' });
  assert.equal((await kit.rpc('effective_access', { client_id: 'studio' })).status, 0);
  emulator.controls.setFault({ operation: 'ensure_profile', mode: 'failed_before_commit' });
  assert.equal((await kit.rpc('ensure_profile')).status, 500);
  assert.equal(emulator.controls.snapshot().counts.profiles, 0);

  emulator.controls.setFault({ operation: 'effective_access', mode: 'http_503' });
  const viaGet = await kit.rpc('effective_access', { client_id: 'studio' }, { get: true });
  assert.equal(viaGet.status, 200, 'postgrest-js retries idempotent GETs on 503 (client behaviour, recorded)');
  assert.equal(emulator.controls.snapshot().httpRequests.effective_access, 4);
});

test('Auth faults: 503 and transport loss change nothing; a lost verify answer leaves the link used and the address confirmed', async (t) => {
  const emulator = await start(t);
  emulator.controls.seedUser({ email: 'auth-fault@example.test', password: PASSWORD, confirmed: false });
  const supabase = client(emulator);
  const { tokenHash } = emulator.controls.issueLink({ type: 'email', email: 'auth-fault@example.test' });

  emulator.controls.setFault({ operation: 'verify_email', mode: 'http_503' });
  const outage = await supabase.auth.verifyOtp({ type: 'email', token_hash: tokenHash });
  assert.equal(outage.error.name, 'AuthRetryableFetchError');
  assert.equal(outage.error.status, 503);
  emulator.controls.setFault({ operation: 'verify_email', mode: 'transport_loss' });
  assert.equal((await supabase.auth.verifyOtp({ type: 'email', token_hash: tokenHash })).error.status, 0);
  assert.equal(emulator.controls.snapshot().counts.linksUsed, 0, 'the link survives both');

  emulator.controls.setFault({ operation: 'verify_email', mode: 'lost_after_commit' });
  const lost = await supabase.auth.verifyOtp({ type: 'email', token_hash: tokenHash });
  assert.equal(lost.error.name, 'AuthRetryableFetchError');
  assert.equal(lost.data.session, null);
  const snapshot = emulator.controls.snapshot();
  assert.equal(snapshot.counts.linksUsed, 1);
  assert.equal(snapshot.users[0].confirmed, true);
  assert.equal((await supabase.auth.verifyOtp({ type: 'email', token_hash: tokenHash })).error.code, 'otp_expired');
  assert.equal((await supabase.auth.signInWithPassword({ email: 'auth-fault@example.test', password: PASSWORD })).error, null,
    'the confirmed user can still sign in with a password');
});

test('password, recovery and sign-up faults: nothing written on outage; a lost sign-up converges to the neutral answer', async (t) => {
  const emulator = await start(t);
  emulator.controls.seedUser({ email: 'known@example.test', password: PASSWORD });
  emulator.controls.setFault({ operation: 'password_sign_in', mode: 'http_503' });
  const outage = await client(emulator).auth.signInWithPassword({ email: 'known@example.test', password: PASSWORD });
  assert.equal(outage.error.status, 503);
  assert.equal(emulator.controls.snapshot().counts.activeSessions, 0);

  emulator.controls.setFault({ operation: 'recovery_request', mode: 'transport_loss' });
  assert.equal((await client(emulator).auth.resetPasswordForEmail('known@example.test')).error.status, 0);
  assert.equal(emulator.controls.snapshot().counts.mailsSent, 0);

  emulator.controls.setFault({ operation: 'signup', mode: 'lost_after_commit' });
  assert.equal((await client(emulator).auth.signUp({ email: 'fresh@example.test', password: PASSWORD })).error.status, 0);
  const retry = await client(emulator).auth.signUp({ email: 'fresh@example.test', password: PASSWORD });
  assert.equal(retry.error, null);
  assert.equal(retry.data.session, null);
  assert.equal(emulator.controls.snapshot().users.filter((u) => u.email === 'fresh@example.test').length, 1);
});

test('L13: a password update that fails keeps the old password; the retry succeeds', async (t) => {
  const emulator = await start(t);
  emulator.controls.seedUser({ email: 'reset@example.test', password: PASSWORD });
  const supabase = client(emulator);
  const { tokenHash } = emulator.controls.issueLink({ type: 'recovery', email: 'reset@example.test' });
  assert.equal((await supabase.auth.verifyOtp({ type: 'recovery', token_hash: tokenHash })).error, null);
  for (const mode of ['http_503', 'failed_before_commit', 'transport_loss']) {
    emulator.controls.setFault({ operation: 'update_password', mode });
    const failed = await supabase.auth.updateUser({ password: 'replacement-password' });
    assert.notEqual(failed.error, null, mode);
    assert.equal((await client(emulator).auth.signInWithPassword({ email: 'reset@example.test', password: PASSWORD })).error, null, mode);
  }
  assert.equal((await supabase.auth.updateUser({ password: 'replacement-password' })).error, null);
});

test('sign-out faults: transport loss revokes nothing; a lost answer after commit has revoked every session', async (t) => {
  const emulator = await start(t);
  const { supabase } = await signedIn(emulator, 'leaving@example.test');
  const other = client(emulator);
  await other.auth.signInWithPassword({ email: 'leaving@example.test', password: PASSWORD });

  emulator.controls.setFault({ operation: 'global_sign_out', mode: 'transport_loss' });
  const lost = await supabase.auth.signOut();
  assert.equal(lost.error.status, 0);
  assert.equal((await supabase.auth.getSession()).data.session, null, 'supabase-js clears its local session anyway');
  assert.equal(emulator.controls.snapshot().counts.activeSessions, 2, 'the fixture revoked nothing');

  emulator.controls.setFault({ operation: 'global_sign_out', mode: 'lost_after_commit' });
  assert.equal((await other.auth.signOut()).error.status, 0);
  assert.equal(emulator.controls.snapshot().counts.activeSessions, 0);
});

test('OAuth and MFA faults: an exchange outage keeps the code usable; a lost MFA verify has raised the session', async (t) => {
  const emulator = await start(t);
  emulator.controls.setOAuthAccount({ email: 'oauth-fault@example.test' });
  const supabase = client(emulator);
  const started = await supabase.auth.signInWithOAuth({ provider: 'google', options: { redirectTo: 'http://127.0.0.1:9/cb', skipBrowserRedirect: true } });
  const code = new URL((await fetch(started.data.url, { redirect: 'manual' })).headers.get('location')).searchParams.get('code');
  emulator.controls.setFault({ operation: 'oauth_exchange', mode: 'http_503' });
  const outage = await supabase.auth.exchangeCodeForSession(code);
  assert.equal(outage.error.status, 503);
  // supabase-js drops its verifier after any exchange attempt, so the retry needs a fresh start.
  const again = await supabase.auth.signInWithOAuth({ provider: 'google', options: { redirectTo: 'http://127.0.0.1:9/cb', skipBrowserRedirect: true } });
  const secondCode = new URL((await fetch(again.data.url, { redirect: 'manual' })).headers.get('location')).searchParams.get('code');
  assert.equal((await supabase.auth.exchangeCodeForSession(secondCode)).error, null);

  const staff = await signedIn(emulator, 'mfa-fault@example.test', { aal: 'aal2' });
  const challenge = await staff.supabase.auth.mfa.challenge({ factorId: staff.factorId });
  emulator.controls.setFault({ operation: 'mfa_verify', mode: 'lost_after_commit' });
  const lost = await staff.supabase.auth.mfa.verify({ factorId: staff.factorId, challengeId: challenge.data.id, code: emulator.controls.totpCode({ factorId: staff.factorId }) });
  assert.notEqual(lost.error, null);
  const level = await staff.supabase.auth.mfa.getAuthenticatorAssuranceLevel();
  assert.equal(level.data.currentLevel, 'aal1', 'the client still holds its aal1 token');
  await raiseToAal2(emulator, staff.supabase, staff.factorId);

  emulator.controls.setFault({ operation: 'mfa_enroll', mode: 'lost_after_commit' });
  assert.notEqual((await staff.supabase.auth.mfa.enroll({ factorType: 'totp', friendlyName: 'spare' })).error, null);
  const retry = await staff.supabase.auth.mfa.enroll({ factorType: 'totp', friendlyName: 'spare' });
  assert.equal(retry.error.code, 'mfa_factor_name_conflict', 'the lost enrolment exists; a retry with the same name conflicts');
});
