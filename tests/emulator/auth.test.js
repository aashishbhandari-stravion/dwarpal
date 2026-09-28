// Auth subset of the development fixture, exercised through the pinned
// @supabase/supabase-js 2.117.2 client. Synthetic fixture evidence only.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createLocalJWKSet, jwtVerify, decodeJwt } from 'jose';
import { PASSWORD, client, raiseToAal2, raw, signedIn, start } from './support.js';
import { totpCode, totpMatches } from '../../packages/emulator/lib/crypto.js';

const counts = (emulator) => emulator.controls.snapshot().counts;
const userOf = (emulator, email) => emulator.controls.snapshot().users.find((u) => u.email === email);

test('sign-up needs confirmation: no session, one mail; a clicked email link signs in once and a second click is refused', async (t) => {
  const emulator = await start(t);
  const supabase = client(emulator);
  const signUp = await supabase.auth.signUp({ email: 'New.Person@Example.test', password: PASSWORD });
  assert.equal(signUp.error, null);
  assert.equal(signUp.data.session, null);
  assert.equal(signUp.data.user.email, 'new.person@example.test');
  assert.equal(userOf(emulator, 'new.person@example.test').confirmed, false);
  assert.equal(counts(emulator).mailsSent, 1);

  const early = await supabase.auth.signInWithPassword({ email: 'new.person@example.test', password: PASSWORD });
  assert.equal(early.error.status, 400);
  assert.equal(early.error.code, 'email_not_confirmed');

  const { tokenHash } = emulator.controls.issueLink({ type: 'email', email: 'new.person@example.test' });
  assert.match(tokenHash, /^[0-9a-f]{56}$/);
  const verified = await supabase.auth.verifyOtp({ type: 'email', token_hash: tokenHash });
  assert.equal(verified.error, null);
  assert.equal(verified.data.session.user.email, 'new.person@example.test');
  assert.equal(decodeJwt(verified.data.session.access_token).aal, 'aal1');
  assert.equal(userOf(emulator, 'new.person@example.test').confirmed, true);
  assert.equal(counts(emulator).activeSessions, 1);

  const second = await client(emulator).auth.verifyOtp({ type: 'email', token_hash: tokenHash });
  assert.equal(second.error.status, 403);
  assert.equal(second.error.code, 'otp_expired');
  assert.equal(second.data.session, null);
  assert.equal(counts(emulator).activeSessions, 1, 'no second session from a reused link');
});

test('L1: sign-up for an existing address answers neutrally and writes no user, profile or membership', async (t) => {
  const emulator = await start(t);
  const confirmed = emulator.controls.seedUser({ email: 'taken@example.test', password: PASSWORD });
  emulator.controls.seedUser({ email: 'pending@example.test', password: PASSWORD, confirmed: false });
  const before = emulator.controls.snapshot();

  const again = await client(emulator).auth.signUp({ email: 'taken@example.test', password: 'another-password' });
  assert.equal(again.error, null);
  assert.equal(again.data.session, null);
  assert.equal(again.data.user.email, 'taken@example.test');
  assert.notEqual(again.data.user.id, confirmed.userId, 'the neutral answer never names the real user');
  const after = emulator.controls.snapshot();
  assert.deepEqual(after.users, before.users);
  assert.deepEqual(after.profiles, before.profiles);
  assert.equal(after.counts.mailsSent, before.counts.mailsSent);
  const stillOld = await client(emulator).auth.signInWithPassword({ email: 'taken@example.test', password: PASSWORD });
  assert.equal(stillOld.error, null, 'the password is not replaced');

  // An unconfirmed address receives the confirmation mail again; older links stop working.
  const old = emulator.controls.issueLink({ type: 'email', email: 'pending@example.test' });
  const resent = await client(emulator).auth.signUp({ email: 'pending@example.test', password: PASSWORD });
  assert.equal(resent.error, null);
  assert.equal(resent.data.session, null);
  assert.equal(counts(emulator).mailsSent, before.counts.mailsSent + 1);
  assert.equal(counts(emulator).users, before.counts.users);
  const stale = await client(emulator).auth.verifyOtp({ type: 'email', token_hash: old.tokenHash });
  assert.equal(stale.error.code, 'otp_expired');
});

test('L2: issuing or prefetching a link never consumes it; superseded, expired and wrong-type links are refused', async (t) => {
  const emulator = await start(t, { linkTtlSeconds: 600 });
  emulator.controls.seedUser({ email: 'link@example.test', password: PASSWORD, confirmed: false });
  const first = emulator.controls.issueLink({ type: 'email', email: 'link@example.test' });
  // A mail client or scanner fetching the page does not reach Auth; a stray GET to Auth is not a verification.
  for (const method of ['GET', 'HEAD']) {
    const response = await raw(emulator, `/auth/v1/verify?token_hash=${first.tokenHash}&type=email`, { method });
    assert.equal(response.status, 404);
  }
  assert.equal(counts(emulator).linksUsed, 0);
  const resend = await client(emulator).auth.resend({ type: 'signup', email: 'link@example.test' });
  assert.equal(resend.error, null);
  assert.equal((await client(emulator).auth.verifyOtp({ type: 'email', token_hash: first.tokenHash })).error.code, 'otp_expired',
    'a resent mail supersedes the older link');

  const second = emulator.controls.issueLink({ type: 'email', email: 'link@example.test' });
  const wrongType = await client(emulator).auth.verifyOtp({ type: 'recovery', token_hash: second.tokenHash });
  assert.equal(wrongType.error.code, 'otp_expired');
  emulator.controls.advanceTime(600_000);
  const expired = await client(emulator).auth.verifyOtp({ type: 'email', token_hash: second.tokenHash });
  assert.equal(expired.error.code, 'otp_expired');
  assert.equal(userOf(emulator, 'link@example.test').confirmed, false);

  const third = emulator.controls.issueLink({ type: 'email', email: 'link@example.test' });
  emulator.controls.advanceTime(599_999);
  assert.equal((await client(emulator).auth.verifyOtp({ type: 'email', token_hash: third.tokenHash })).error, null);
  assert.equal(counts(emulator).linksUsed, 1);
});

test('password sign-in: unknown address and wrong password get the same refusal', async (t) => {
  const emulator = await start(t);
  emulator.controls.seedUser({ email: 'pw@example.test', password: PASSWORD });
  const wrong = await client(emulator).auth.signInWithPassword({ email: 'pw@example.test', password: 'not-the-password' });
  const unknown = await client(emulator).auth.signInWithPassword({ email: 'nobody@example.test', password: PASSWORD });
  for (const result of [wrong, unknown]) {
    assert.equal(result.error.status, 400);
    assert.equal(result.error.code, 'invalid_credentials');
    assert.equal(result.error.message, 'Invalid login credentials');
  }
  assert.equal(counts(emulator).activeSessions, 0);
});

test('recovery: neutral request, one-use recovery link, password update rules, old password stops working', async (t) => {
  const emulator = await start(t);
  emulator.controls.seedUser({ email: 'forgot@example.test', password: PASSWORD });
  const unknown = await client(emulator).auth.resetPasswordForEmail('nobody@example.test', { redirectTo: 'http://127.0.0.1:1/account/reset' });
  assert.equal(unknown.error, null);
  assert.equal(counts(emulator).mailsSent, 0, 'no mail for an unknown address, same answer');
  assert.equal((await client(emulator).auth.resetPasswordForEmail('forgot@example.test')).error, null);
  assert.equal(counts(emulator).mailsSent, 1);

  const supabase = client(emulator);
  const { tokenHash } = emulator.controls.issueLink({ type: 'recovery', email: 'forgot@example.test' });
  const emailTyped = await client(emulator).auth.verifyOtp({ type: 'email', token_hash: tokenHash });
  assert.equal(emailTyped.error.code, 'otp_expired', 'a recovery link is not an email link');
  const recovery = emulator.controls.issueLink({ type: 'recovery', email: 'forgot@example.test' });
  const verified = await supabase.auth.verifyOtp({ type: 'recovery', token_hash: recovery.tokenHash });
  assert.equal(verified.error, null);
  assert.equal(decodeJwt(verified.data.session.access_token).amr[0].method, 'recovery');

  const same = await supabase.auth.updateUser({ password: PASSWORD });
  assert.equal(same.error.status, 422);
  assert.equal(same.error.code, 'same_password');
  const weak = await supabase.auth.updateUser({ password: '123' });
  assert.equal(weak.error.code, 'weak_password');
  assert.deepEqual(weak.error.reasons, ['length']);
  const long = await supabase.auth.updateUser({ password: 'x'.repeat(73) });
  assert.equal(long.error.status, 422);
  assert.equal((await supabase.auth.updateUser({ password: 'a-new-fixture-password' })).error, null);

  assert.equal((await client(emulator).auth.signInWithPassword({ email: 'forgot@example.test', password: PASSWORD })).error.code, 'invalid_credentials');
  assert.equal((await client(emulator).auth.signInWithPassword({ email: 'forgot@example.test', password: 'a-new-fixture-password' })).error, null);
  const reused = await client(emulator).auth.verifyOtp({ type: 'recovery', token_hash: recovery.tokenHash });
  assert.equal(reused.error.code, 'otp_expired');
});

test('session, user and refresh: rotation, reuse refusal, and tokens that verify against the published JWKS', async (t) => {
  const emulator = await start(t);
  const { supabase, userId } = await signedIn(emulator, 'session@example.test');
  const { data: { session } } = await supabase.auth.getSession();
  assert.equal(session.token_type, 'bearer');
  assert.equal(session.expires_in, 3600);
  const user = await supabase.auth.getUser();
  assert.equal(user.error, null);
  assert.equal(user.data.user.id, userId);

  const jwks = await (await raw(emulator, '/auth/v1/.well-known/jwks.json', { headers: { apikey: undefined } })).json();
  const { payload, protectedHeader } = await jwtVerify(session.access_token, createLocalJWKSet(jwks), {
    issuer: `${emulator.origin}/auth/v1`, audience: 'authenticated', algorithms: ['ES256'],
    currentDate: new Date(Date.parse(emulator.controls.snapshot().now)),
  });
  assert.equal(protectedHeader.alg, 'ES256');
  assert.equal(payload.sub, userId);
  assert.equal(payload.role, 'authenticated');
  assert.equal(typeof payload.session_id, 'string');

  const refreshed = await supabase.auth.refreshSession();
  assert.equal(refreshed.error, null);
  assert.notEqual(refreshed.data.session.refresh_token, session.refresh_token);
  assert.equal(decodeJwt(refreshed.data.session.access_token).session_id, payload.session_id);
  const reuse = await raw(emulator, '/auth/v1/token?grant_type=refresh_token', { method: 'POST', body: { refresh_token: session.refresh_token } });
  assert.equal(reuse.status, 400);
  assert.equal((await reuse.json()).code, 'refresh_token_already_used');
  const unknown = await raw(emulator, '/auth/v1/token?grant_type=refresh_token', { method: 'POST', body: { refresh_token: 'nope' } });
  assert.equal((await unknown.json()).code, 'refresh_token_not_found');
});

test('global sign-out revokes every session of the user; PostgREST still honours an unexpired token until it expires (L25b)', async (t) => {
  const emulator = await start(t, { accessTokenTtlSeconds: 600 });
  const first = await signedIn(emulator, 'out@example.test');
  const second = client(emulator);
  assert.equal((await second.auth.signInWithPassword({ email: 'out@example.test', password: PASSWORD })).error, null);
  const other = await signedIn(emulator, 'bystander@example.test');
  const secondToken = (await second.auth.getSession()).data.session.access_token;
  assert.equal(counts(emulator).activeSessions, 3);

  assert.equal((await first.supabase.auth.signOut()).error, null);
  assert.equal((await first.supabase.auth.getSession()).data.session, null);
  assert.equal(counts(emulator).activeSessions, 1, "only the bystander's session remains");
  const afterUser = await second.auth.getUser();
  assert.equal(afterUser.error.name, 'AuthSessionMissingError');
  assert.equal((await other.supabase.auth.getUser()).error, null);

  const postgrest = () => raw(emulator, '/rest/v1/rpc/ensure_profile', {
    method: 'POST', body: {}, headers: { authorization: `Bearer ${secondToken}`, 'content-profile': 'auth_kit' },
  });
  assert.equal((await postgrest()).status, 200, 'PostgREST checks signature and expiry, not the Auth session');
  emulator.controls.advanceTime(600_000);
  const expired = await postgrest();
  assert.equal(expired.status, 401);
  assert.equal((await expired.json()).code, 'PGRST303');
});

test('local sign-out revokes only the current session', async (t) => {
  const emulator = await start(t);
  const first = await signedIn(emulator, 'local@example.test');
  const second = client(emulator);
  await second.auth.signInWithPassword({ email: 'local@example.test', password: PASSWORD });
  assert.equal((await first.supabase.auth.signOut({ scope: 'local' })).error, null);
  assert.equal((await second.auth.getUser()).error, null);
  assert.equal(counts(emulator).activeSessions, 1);
});

async function startGoogle(supabase, redirectTo) {
  const started = await supabase.auth.signInWithOAuth({ provider: 'google', options: { redirectTo, skipBrowserRedirect: true } });
  assert.equal(started.error, null);
  const response = await fetch(started.data.url, { redirect: 'manual' });
  assert.equal(response.status, 303);
  return new URL(response.headers.get('location'));
}

test('Google OAuth: synthetic consent returns a PKCE-bound code to a loopback callback; the code works once', async (t) => {
  const emulator = await start(t, { siteUrl: 'http://127.0.0.1:9/site' });
  emulator.controls.setOAuthAccount({ email: 'Google.User@example.test' });
  const supabase = client(emulator);
  const callback = await startGoogle(supabase, 'http://127.0.0.1:9/account/callback?next=%2Forders');
  assert.equal(callback.origin, 'http://127.0.0.1:9');
  assert.equal(callback.pathname, '/account/callback');
  assert.equal(callback.searchParams.get('next'), '/orders');
  const code = callback.searchParams.get('code');
  assert.ok(code);

  const exchanged = await supabase.auth.exchangeCodeForSession(code);
  assert.equal(exchanged.error, null);
  assert.equal(exchanged.data.session.user.email, 'google.user@example.test');
  assert.deepEqual(userOf(emulator, 'google.user@example.test').providers, ['google']);
  assert.equal(decodeJwt(exchanged.data.session.access_token).amr[0].method, 'oauth');

  const again = await raw(emulator, '/auth/v1/token?grant_type=pkce', { method: 'POST', body: { auth_code: code, code_verifier: 'v'.repeat(64) } });
  assert.equal(again.status, 404);
  assert.equal((await again.json()).code, 'flow_state_not_found');

  const offsite = await startGoogle(client(emulator), 'https://evil.example/steal');
  assert.equal(`${offsite.origin}${offsite.pathname}`, 'http://127.0.0.1:9/site', 'a non-loopback redirect falls back to the site URL');
});

test('L3: two PKCE starts; a code only exchanges with its own verifier and a wrong verifier leaves the flow usable', async (t) => {
  const emulator = await start(t);
  emulator.controls.setOAuthAccount({ email: 'pkce@example.test' });
  const flowClient = client(emulator, { experimental: { appendPkceFlowIdToRedirects: true } });
  const first = await startGoogle(flowClient, 'http://127.0.0.1:9/callback');
  const second = await startGoogle(flowClient, 'http://127.0.0.1:9/callback');
  const firstFlow = first.searchParams.get('sb_flow_id');
  assert.ok(firstFlow, 'the flow id added by supabase-js survives the redirect');
  assert.notEqual(firstFlow, second.searchParams.get('sb_flow_id'));
  const a = await flowClient.auth.exchangeCodeForSession(first.searchParams.get('code'), { flowId: firstFlow });
  assert.equal(a.error, null);
  const b = await flowClient.auth.exchangeCodeForSession(second.searchParams.get('code'), { flowId: second.searchParams.get('sb_flow_id') });
  assert.equal(b.error, null);

  // Without per-flow ids the client uses its latest verifier: the older flow's code is refused.
  const legacy = client(emulator);
  const older = await startGoogle(legacy, 'http://127.0.0.1:9/callback');
  await startGoogle(legacy, 'http://127.0.0.1:9/callback');
  const crossed = await legacy.auth.exchangeCodeForSession(older.searchParams.get('code'));
  assert.equal(crossed.error.status, 403);
  assert.equal(crossed.error.code, 'bad_code_verifier');
  assert.equal(crossed.data.session, null);
  assert.equal(emulator.controls.snapshot().counts.activeSessions, 2);
});

test('L8: denied consent returns an error and no code, creates no user; an expired flow is refused', async (t) => {
  const emulator = await start(t);
  const denied = await startGoogle(client(emulator), 'http://127.0.0.1:9/callback');
  assert.equal(denied.searchParams.get('error'), 'access_denied');
  assert.equal(denied.searchParams.get('code'), null);
  assert.equal(counts(emulator).users, 0);

  emulator.controls.setOAuthAccount({ email: 'slow@example.test' });
  const supabase = client(emulator);
  const callback = await startGoogle(supabase, 'http://127.0.0.1:9/callback');
  emulator.controls.advanceTime(300_000);
  const late = await supabase.auth.exchangeCodeForSession(callback.searchParams.get('code'));
  assert.equal(late.error.code, 'flow_state_expired');

  const implicit = await fetch(`${emulator.origin}/auth/v1/authorize?provider=google&redirect_to=http%3A%2F%2F127.0.0.1%3A9%2F`, { redirect: 'manual' });
  assert.equal(implicit.status, 400, 'only the PKCE flow is emulated');
  const github = await fetch(`${emulator.origin}/auth/v1/authorize?provider=github`, { redirect: 'manual' });
  assert.equal(github.status, 400);
});

test('TOTP: enrol, challenge and verify raise the session to aal2; wrong, expired and reused challenges are refused', async (t) => {
  const emulator = await start(t);
  const { supabase, userId } = await signedIn(emulator, 'mfa@example.test');
  const enrolled = await supabase.auth.mfa.enroll({ factorType: 'totp', friendlyName: 'phone' });
  assert.equal(enrolled.error, null);
  assert.match(enrolled.data.totp.qr_code, /^data:image\/svg\+xml;utf-8,<svg/);
  assert.match(enrolled.data.totp.uri, /^otpauth:\/\/totp\//);
  const factorId = enrolled.data.id;
  assert.equal(emulator.controls.snapshot().users.find((u) => u.userId === userId).factors[0].status, 'unverified');
  assert.equal((await supabase.auth.mfa.enroll({ factorType: 'totp', friendlyName: 'phone' })).error.code, 'mfa_factor_name_conflict');

  const challenge = await supabase.auth.mfa.challenge({ factorId });
  const code = emulator.controls.totpCode({ factorId });
  const wrong = String((Number(code) + 500_000) % 1_000_000).padStart(6, '0');
  const bad = await supabase.auth.mfa.verify({ factorId, challengeId: challenge.data.id, code: wrong });
  assert.equal(bad.error.code, 'mfa_verification_failed');
  const good = await supabase.auth.mfa.verify({ factorId, challengeId: challenge.data.id, code });
  assert.equal(good.error, null);
  const claims = decodeJwt(good.data.access_token);
  assert.equal(claims.aal, 'aal2');
  assert.equal(claims.amr[0].method, 'totp');
  const level = await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
  assert.deepEqual([level.data.currentLevel, level.data.nextLevel], ['aal2', 'aal2']);
  const reused = await supabase.auth.mfa.verify({ factorId, challengeId: challenge.data.id, code });
  assert.equal(reused.error.code, 'mfa_challenge_expired');

  const late = await supabase.auth.mfa.challenge({ factorId });
  emulator.controls.advanceTime(300_000);
  const expired = await supabase.auth.mfa.verify({ factorId, challengeId: late.data.id, code: emulator.controls.totpCode({ factorId }) });
  assert.equal(expired.error.code, 'mfa_challenge_expired');
});

test('TOTP at fixture clock 0: a valid code verifies; a wrong code is refused without raising AAL or consuming the challenge', async (t) => {
  const emulator = await start(t, { now: 0 });
  const { supabase, userId } = await signedIn(emulator, 'epoch@example.test');
  const enrolled = await supabase.auth.mfa.enroll({ factorType: 'totp', friendlyName: 'phone' });
  assert.equal(enrolled.error, null);
  const factorId = enrolled.data.id;
  const secret = enrolled.data.totp.secret;
  const code = emulator.controls.totpCode({ factorId });
  assert.equal(code, totpCode(secret, 0));
  // At step 0 the window is steps 0 and 1; one of three distinct codes is outside it.
  const window = new Set([totpCode(secret, 0, 0), totpCode(secret, 0, 1)]);
  const wrong = ['000000', '111111', '222222'].find((candidate) => !window.has(candidate));

  const challenge = await supabase.auth.mfa.challenge({ factorId });
  assert.equal(challenge.error, null);
  const bad = await supabase.auth.mfa.verify({ factorId, challengeId: challenge.data.id, code: wrong });
  assert.equal(bad.error.status, 422);
  assert.equal(bad.error.code, 'mfa_verification_failed');
  const session = (await supabase.auth.getSession()).data.session;
  assert.equal(decodeJwt(session.access_token).aal, 'aal1');
  const level = await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
  assert.equal(level.data.currentLevel, 'aal1');
  assert.equal(emulator.controls.snapshot().users.find((u) => u.userId === userId).factors[0].status, 'unverified');

  const good = await supabase.auth.mfa.verify({ factorId, challengeId: challenge.data.id, code });
  assert.equal(good.error, null, 'the refused attempt left the challenge usable');
  assert.equal(decodeJwt(good.data.access_token).aal, 'aal2');
  assert.equal(emulator.controls.snapshot().users.find((u) => u.userId === userId).factors[0].status, 'verified');
});

test('TOTP codes follow RFC 6238; the window is the current step and one either side, without steps before the epoch', () => {
  const rfcSecret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'; // ASCII "12345678901234567890"
  assert.equal(totpCode(rfcSecret, 59_000), '287082');
  assert.equal(totpCode(rfcSecret, 1_111_111_109_000), '081804');
  const code = (step) => totpCode(rfcSecret, step * 30_000);
  for (const at of [0, 29_999]) {
    assert.equal(totpMatches(rfcSecret, at, code(0)), true);
    assert.equal(totpMatches(rfcSecret, at, code(1)), true);
    assert.equal(totpMatches(rfcSecret, at, code(2)), code(2) === code(0) || code(2) === code(1));
  }
  for (const step of [0, 1, 2]) assert.equal(totpMatches(rfcSecret, 30_000, code(step)), true, `step ${step} is inside the window at step 1`);
  assert.equal(totpMatches(rfcSecret, 30_000, code(3)), [0, 1, 2].some((s) => code(s) === code(3)));
});

test('a user seeded at aal2 signs in at aal1 with aal2 next; a new factor then needs aal2 first', async (t) => {
  const emulator = await start(t);
  const { supabase, factorId } = await signedIn(emulator, 'staff@example.test', { aal: 'aal2' });
  const level = await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
  assert.deepEqual([level.data.currentLevel, level.data.nextLevel], ['aal1', 'aal2']);
  const blocked = await supabase.auth.mfa.enroll({ factorType: 'totp', friendlyName: 'second' });
  assert.equal(blocked.error.code, 'insufficient_aal');
  const other = await signedIn(emulator, 'other@example.test');
  const foreign = await other.supabase.auth.mfa.challenge({ factorId });
  assert.equal(foreign.error.code, 'mfa_factor_not_found', "another user's factor is not reachable");
  await raiseToAal2(emulator, supabase, factorId);
  assert.equal((await supabase.auth.mfa.enroll({ factorType: 'totp', friendlyName: 'second' })).error, null);
});
