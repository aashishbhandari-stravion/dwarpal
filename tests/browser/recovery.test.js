// Password recovery with the recovery_pending lock (v0.3 flow carried; L13).
// SYNTHETIC: real supabase-js 2.117.2 over the scripted fixture in support/.

import test from 'node:test';
import assert from 'node:assert/strict';
import { setup, reopen, openController, CLIENT_ID, MODEL_ROLES, SITE } from './support/env.js';
import { createScriptedSupabase, TOTP_CODE } from './support/scripted-supabase.js';

function fixtureWithUser(email = 'r@example.test') {
  const fixture = createScriptedSupabase();
  fixture.seedClient({ clientId: CLIENT_ID, roles: MODEL_ROLES });
  const userId = fixture.seedUser({ email });
  return { fixture, userId, email };
}

async function openRecoveryLink(fixture, email) {
  const tokenHash = fixture.issueLink(email, 'recovery');
  const context = await setup(`/account/reset?token_hash=${tokenHash}&type=recovery`, { fixture });
  return { ...context, tokenHash };
}

function markerOf(tab) {
  const key = tab.localStorage.keys().find((k) => k.endsWith(':recovery'));
  return key ? JSON.parse(tab.localStorage.getItem(key)) : null;
}

test('forgot answers a neutral `sent` for known and unknown addresses', async () => {
  const { fixture, email } = fixtureWithUser();
  const { controller } = await setup('/account/forgot', { fixture });
  assert.equal((await controller.requestRecovery({ email })).state, 'sent');
  assert.equal((await controller.requestRecovery({ email: 'nobody@example.test' })).state, 'sent');
  assert.equal((await controller.requestRecovery({ email: 'bad' })).error, 'invalid_input');
  assert.equal(fixture.count('recovery_request'), 2);
});

test('the recovery link verifies only on click, then holds the reset screen with a pending marker', async () => {
  const { fixture, email, userId } = fixtureWithUser();
  const { controller, tab } = await openRecoveryLink(fixture, email);
  assert.equal(fixture.count('verify_recovery'), 0);
  assert.equal(markerOf(tab), null, 'no marker before the click');
  assert.equal(tab.href, `${SITE}/account/reset`);
  const view = await controller.confirmLink();
  assert.deepEqual([view.screen, view.state, view.recoveryPending], ['reset', 'idle', true]);
  assert.deepEqual(markerOf(tab), { v: 1, phase: 'pending', userId });
  assert.equal(fixture.count('ensure_profile'), 0, 'no onboarding in a recovery session');
});

test('L13: a failed password update keeps recovery_pending and the reset screen; every other kit page returns to it', async () => {
  const { fixture, email } = fixtureWithUser();
  const { controller, tab } = await openRecoveryLink(fixture, email);
  await controller.confirmLink();
  fixture.fault('update_password', 'http_503');
  const failed = await controller.updatePassword({ password: 'a brand new secret' });
  assert.deepEqual([failed.screen, failed.state, failed.error, failed.recoveryPending], ['reset', 'error', 'unavailable', true]);
  assert.equal(markerOf(tab).phase, 'pending');
  assert.equal((await controller.updatePassword({ password: 'short' })).error, 'weak_password');
  assert.equal(markerOf(tab).phase, 'pending');

  for (const path of ['/account/sign-in', '/account/sign-up', '/account/mfa', '/account/verify?token_hash=x&type=email', '/account/callback?code=x', '/somewhere/else']) {
    const other = openController(reopen(tab, path, { newTab: true }), fixture);
    const view = await other.start();
    assert.deepEqual([view.screen, view.recoveryPending], ['reset', true], path);
    for (const action of [() => other.signIn({ email, password: 'correct horse battery' }), () => other.startGoogle(), () => other.signUp({ email: 'x@example.test', password: 'long enough' }), () => other.confirmLink(), () => other.requestRecovery({ email })]) {
      assert.equal((await action()).screen, 'reset', path);
    }
  }
  assert.equal(fixture.count('password_sign_in'), 0);
  assert.equal(fixture.count('oauth_exchange'), 0);
  assert.equal(fixture.count('ensure_profile'), 0);

  const done = await controller.updatePassword({ password: 'a brand new secret' });
  assert.equal(done.state, 'signed_in');
  assert.equal(markerOf(tab), null);
  assert.equal(fixture.count('ensure_profile'), 1);
});

test('L13: sign-out releases a pending recovery and clears the marker even when Auth is unreachable', async () => {
  const { fixture, email } = fixtureWithUser();
  const { controller, tab } = await openRecoveryLink(fixture, email);
  await controller.confirmLink();
  fixture.fault('global_sign_out', 'transport_loss');
  const view = await controller.signOut();
  assert.deepEqual(view.signOut, { remote: 'unconfirmed', local: 'cleared' });
  assert.equal(markerOf(tab), null);
  const later = openController(reopen(tab, '/account/sign-in'), fixture);
  assert.deepEqual([(await later.start()).screen, later.getView().recoveryPending], ['signIn', false]);
});

test('the marker is written before verification: a page that dies after Auth answered still opens on the reset screen', async () => {
  const { fixture, email } = fixtureWithUser();
  const tokenHash = fixture.issueLink(email, 'recovery');
  const { tab, controller } = await setup(`/account/reset?token_hash=${tokenHash}&type=recovery`, { fixture });
  // The session save succeeds but the marker update after it fails, as if
  // the page were gone: storage refuses writes to the marker key only.
  const original = tab.localStorage.setItem.bind(tab.localStorage);
  tab.localStorage.setItem = (key, value) => {
    if (key.endsWith(':recovery') && JSON.parse(value).phase === 'pending') throw new Error('page gone');
    original(key, value);
  };
  await controller.confirmLink();
  tab.localStorage.setItem = original;
  assert.equal(markerOf(tab).phase, 'verifying');
  const next = openController(reopen(tab, '/account/sign-in'), fixture);
  const view = await next.start();
  assert.deepEqual([view.screen, view.recoveryPending], ['reset', true]);
  assert.equal(fixture.count('ensure_profile'), 0);
});

test('a refused or lost recovery verification restores the previous marker state and issues no session', async () => {
  const { fixture, email } = fixtureWithUser();
  const { controller, tab } = await setup('/account/reset?token_hash=pkce_unknown&type=recovery', { fixture });
  assert.equal((await controller.confirmLink()).state, 'expired_link');
  assert.equal(markerOf(tab), null);

  const lost = await openRecoveryLink(fixture, email);
  fixture.fault('verify_recovery', 'transport_loss');
  const view = await lost.controller.confirmLink();
  assert.deepEqual([view.state, view.canRetry], ['offline', true]);
  assert.equal(markerOf(lost.tab), null);
  const retried = await lost.controller.retry();
  assert.deepEqual([retried.screen, retried.recoveryPending], ['reset', true], 'nothing was consumed, so the retry succeeds');
});

test('a marker without a session is dropped on the next pass; a damaged marker counts as pending', async () => {
  const { fixture, email } = fixtureWithUser();
  const { controller, tab } = await openRecoveryLink(fixture, email);
  await controller.confirmLink();
  const key = tab.localStorage.keys().find((k) => k.endsWith(':recovery'));
  tab.localStorage.setItem(key, '{not json');
  const damaged = openController(reopen(tab, '/account/sign-in'), fixture);
  assert.equal((await damaged.start()).screen, 'reset');

  const sessionKey = tab.localStorage.keys().find((k) => k.endsWith(':auth'));
  tab.localStorage.removeItem(sessionKey);
  const orphan = openController(reopen(tab, '/account/sign-in'), fixture);
  assert.deepEqual([(await orphan.start()).screen, orphan.getView().recoveryPending], ['signIn', false]);
  assert.equal(markerOf(tab), null);
});

test('an MFA user must pass the challenge before the recovery password update, and stays on reset meanwhile', async () => {
  const { fixture, email, userId } = fixtureWithUser();
  fixture.seedFactor(userId);
  const { controller, tab } = await openRecoveryLink(fixture, email);
  await controller.confirmLink();
  const challenged = await controller.updatePassword({ password: 'a brand new secret' });
  assert.deepEqual([challenged.state, challenged.mfa.mode, challenged.recoveryPending], ['mfa_challenge', 'challenge', true]);
  const back = await controller.verifyMfa({ code: TOTP_CODE });
  assert.deepEqual([back.screen, back.recoveryPending], ['reset', true]);
  assert.equal(markerOf(tab).phase, 'pending');
  assert.equal((await controller.updatePassword({ password: 'a brand new secret' })).state, 'signed_in');
  assert.equal(markerOf(tab), null);
});
