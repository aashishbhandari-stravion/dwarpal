// Sign-up, click-only e-mail verification and resend (design 7; L1, L2).
// SYNTHETIC: real supabase-js 2.117.2 over the scripted fixture in support/.

import test from 'node:test';
import assert from 'node:assert/strict';
import { setup, reopen, openController, baseConfig, CLIENT_ID, MODEL_ROLES, SITE } from './support/env.js';
import { createScriptedSupabase } from './support/scripted-supabase.js';

function fixtureWithClient() {
  const fixture = createScriptedSupabase();
  fixture.seedClient({ clientId: CLIENT_ID, roles: MODEL_ROLES });
  return fixture;
}

test('L1: sign-up answers the same neutral `sent` for a new and an existing address, writing nothing for the existing one', async () => {
  const fixture = fixtureWithClient();
  fixture.seedUser({ email: 'taken@example.test' });
  const fresh = await setup('/account/sign-up', { fixture });
  const first = await fresh.controller.signUp({ email: 'new@example.test', password: 'long enough' });
  const before = fixture.snapshot();
  const again = await setup('/account/sign-up', { fixture });
  const second = await again.controller.signUp({ email: 'taken@example.test', password: 'long enough' });
  assert.deepEqual([first.state, first.screen, first.error], ['sent', 'signUp', null]);
  assert.deepEqual([second.state, second.screen, second.error], ['sent', 'signUp', null]);
  assert.deepEqual(fixture.snapshot(), before, 'the existing address changes nothing');
  assert.equal(fixture.snapshot().memberships.length, 0, 'sign-up alone never enrolls');
  assert.equal(fixture.count('join_client'), 0);
});

test('sign-up refuses locally when self sign-up or e-mail is disabled, without a request', async () => {
  for (const config of [baseConfig({ selfSignup: false }), baseConfig({ providers: { email: false, google: true } })]) {
    const { controller, fixture } = await setup('/account/sign-up', { config });
    const view = await controller.signUp({ email: 'a@example.test', password: 'long enough' });
    assert.deepEqual([view.state, view.error], ['error', 'method_disabled']);
    assert.equal(fixture.count('signup'), 0);
  }
});

test('sign-up input and weak-password errors are specific; offline is offline', async () => {
  const fixture = fixtureWithClient();
  const { controller } = await setup('/account/sign-up', { fixture });
  assert.equal((await controller.signUp({ email: 'not-an-address', password: 'long enough' })).error, 'invalid_input');
  assert.equal((await controller.signUp({ email: 'a@example.test', password: '' })).error, 'invalid_input');
  assert.equal((await controller.signUp({ email: 'a@example.test', password: 'short' })).error, 'weak_password');
  fixture.fault('signup', 'transport_loss');
  assert.equal((await controller.signUp({ email: 'b@example.test', password: 'long enough' })).state, 'offline');
  fixture.fault('signup', 'http_503');
  assert.deepEqual(pick(await controller.signUp({ email: 'b@example.test', password: 'long enough' })), ['error', 'unavailable']);
});

test('L2: opening a verification link verifies nothing; only the click does, the address is stripped at once', async () => {
  const fixture = fixtureWithClient();
  fixture.seedUser({ email: 'v@example.test', confirmed: false });
  const tokenHash = fixture.issueLink('v@example.test', 'email');
  const { controller, tab } = await setup(`/account/verify?token_hash=${tokenHash}&type=email`, { fixture });
  assert.deepEqual([controller.getView().state, controller.getView().link], ['idle', true]);
  assert.equal(fixture.count('verify_email'), 0, 'no verification on load or prefetch');
  assert.equal(tab.href, `${SITE}/account/verify`, 'token_hash and type are removed from the address');
  assert.ok(!tab.replaced.some((href) => href.includes(tokenHash)));

  const view = await controller.confirmLink();
  assert.equal(view.state, 'signed_in');
  assert.equal(fixture.count('verify_email'), 1);
  assert.deepEqual(fixture.snapshot().memberships, ['studio:member:join']);
});

test('L2: a second click on the same page sends nothing and reports already_used; a second page load gets expired_link', async () => {
  const fixture = fixtureWithClient();
  fixture.seedUser({ email: 'v@example.test', confirmed: false });
  const tokenHash = fixture.issueLink('v@example.test', 'email');
  const { controller, tab } = await setup(`/account/verify?token_hash=${tokenHash}&type=email`, { fixture, options: { autoNavigate: false } });
  const [a, b] = await Promise.all([controller.confirmLink(), controller.confirmLink()]);
  assert.equal(fixture.count('verify_email'), 1, 'a double click sends one request');
  assert.equal(a.state, 'signed_in');
  assert.equal(b.state, 'submitting', 'the second call returned the view of the running action');
  assert.equal((await controller.confirmLink()).state, 'already_used');
  assert.equal(fixture.count('verify_email'), 1);

  const second = openController(reopen(tab, `/account/verify?token_hash=${tokenHash}&type=email`, { newTab: true }), fixture);
  await second.start();
  const view = await second.confirmLink();
  assert.equal(view.state, 'expired_link');
  assert.equal(fixture.count('verify_email'), 2);
  assert.equal(fixture.snapshot().liveSessions, 1, 'no second session from a reused link');
});

test('L2: a lost verification answer is retried with the same token; Auth then refuses it and the page says already_used', async () => {
  const fixture = fixtureWithClient();
  fixture.seedUser({ email: 'v@example.test', confirmed: false });
  const tokenHash = fixture.issueLink('v@example.test', 'email');
  const { controller } = await setup(`/account/verify?token_hash=${tokenHash}&type=email`, { fixture });
  fixture.fault('verify_email', 'lost_after_commit');
  const lost = await controller.confirmLink();
  assert.deepEqual([lost.state, lost.canRetry, lost.link], ['offline', true, true]);
  const retried = await controller.retry();
  assert.equal(retried.state, 'already_used');
  assert.equal(fixture.count('verify_email'), 2);
  assert.equal(fixture.count('join_client'), 0, 'no session, no onboarding');
});

test('an expired, unknown or wrong-type link is expired_link; a missing or repeated token is refused without a request', async () => {
  const fixture = fixtureWithClient();
  const unknown = await setup('/account/verify?token_hash=pkce_unknown&type=email', { fixture });
  assert.equal((await unknown.controller.confirmLink()).state, 'expired_link');
  for (const query of ['token_hash=abc&type=recovery', 'token_hash=abc', 'token_hash=a&token_hash=b&type=email', 'token_hash=&type=email']) {
    const page = await setup(`/account/verify?${query}`, { fixture });
    assert.equal(page.controller.getView().state, 'expired_link', query);
    assert.equal((await page.controller.confirmLink()).state, 'expired_link', query);
  }
  assert.equal(fixture.count('verify_email'), 1);
});

test('the verify page returns to the sign-up return path stored by this tab; another tab uses the default', async () => {
  const fixture = fixtureWithClient();
  const signup = await setup('/account/sign-up?next=%2Fapp%2Forders', { fixture });
  await signup.controller.signUp({ email: 'n@example.test', password: 'long enough' });
  const tokenHash = fixture.latestLink('n@example.test', 'email');
  const sameTab = openController(reopen(signup.tab, `/account/verify?token_hash=${tokenHash}&type=email`), fixture);
  await sameTab.start();
  assert.equal((await sameTab.confirmLink()).next, '/app/orders');

  fixture.seedUser({ email: 'm@example.test', confirmed: false });
  const other = fixture.issueLink('m@example.test', 'email');
  const otherTab = openController(reopen(signup.tab, `/account/verify?token_hash=${other}&type=email`, { newTab: true }), fixture);
  await otherTab.start();
  assert.equal((await otherTab.confirmLink()).next, '/app');
});

test('unverified password sign-in shows email_unverified; resend honours the countdown', async () => {
  let now = 1_000_000;
  const fixture = fixtureWithClient();
  fixture.seedUser({ email: 'u@example.test', confirmed: false });
  const { controller } = await setup('/account/sign-in', { fixture, options: { now: () => now } });
  const view = await controller.signIn({ email: 'u@example.test', password: 'correct horse battery' });
  assert.deepEqual(pick(view), ['error', 'email_unverified']);
  const sent = await controller.resendConfirmation();
  assert.equal(sent.state, 'sent');
  assert.equal(sent.resendAvailableAt, now + 60_000);
  now += 30_000;
  await controller.resendConfirmation();
  assert.equal(fixture.count('resend'), 1, 'inside the countdown nothing is sent');
  now += 31_000;
  await controller.resendConfirmation();
  assert.equal(fixture.count('resend'), 2);
});

function pick(view) {
  return [view.state, view.error];
}

test('start() reads the address once; a second call re-checks the session and keeps the page state', async () => {
  const fixture = fixtureWithClient();
  fixture.seedUser({ email: 'v@example.test', confirmed: false });
  const tokenHash = fixture.issueLink('v@example.test', 'email');
  const { controller } = await setup(`/account/verify?token_hash=${tokenHash}&type=email`, { fixture, options: { autoNavigate: false } });
  assert.equal((await controller.start()).link, true, 'the stripped link is still waiting for its click');
  assert.equal((await controller.confirmLink()).state, 'signed_in');
  assert.equal((await controller.start()).state, 'signed_in', 'a consumed link is not shown again');
  assert.equal(fixture.count('verify_email'), 1);
});
