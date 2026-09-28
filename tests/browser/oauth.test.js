// Google sign-in with per-flow PKCE, exact callback handling and `next`
// (v0.3 5.7/5.9 carried; L3, L8, L11). SYNTHETIC: real supabase-js 2.117.2
// over the scripted fixture in support/; the provider round trip is simulated.

import test from 'node:test';
import assert from 'node:assert/strict';
import { setup, reopen, openController, baseConfig, CLIENT_ID, MODEL_ROLES, SITE, FakeStorage, createTab } from './support/env.js';
import { createScriptedSupabase, ORIGIN } from './support/scripted-supabase.js';

function fixtureWithClient() {
  const fixture = createScriptedSupabase();
  fixture.seedClient({ clientId: CLIENT_ID, roles: MODEL_ROLES });
  return fixture;
}

async function startGoogle(fixture, path = '/account/sign-in', tab) {
  const context = await setup(path, { fixture, tab });
  await context.controller.startGoogle();
  const authorize = context.tab.navigations.at(-1);
  return { ...context, authorize };
}

async function landOnCallback(tab, fixture, callbackUrl, options) {
  const page = createTab(callbackUrl, { localStorage: tab.localStorage, sessionStorage: tab.sessionStorage });
  const controller = openController(page, fixture, baseConfig(), options);
  const view = await controller.start();
  return { page, controller, view };
}

test('start builds an exact-callback authorize URL on the configured project, without skip_http_redirect or a flow parameter', async () => {
  const fixture = fixtureWithClient();
  const { authorize, tab } = await startGoogle(fixture);
  const url = new URL(authorize);
  assert.equal(url.origin, ORIGIN);
  assert.equal(url.pathname, '/auth/v1/authorize');
  assert.equal(url.searchParams.get('provider'), 'google');
  assert.equal(url.searchParams.get('redirect_to'), `${SITE}/account/callback`, 'exact allow-listed callback, no query');
  assert.equal(url.searchParams.get('code_challenge_method'), 's256');
  assert.equal(url.searchParams.has('skip_http_redirect'), false);
  assert.equal(fixture.requests.length, 0, 'starting makes no request');
  assert.ok(tab.sessionStorage.keys().some((key) => key.endsWith('-code-verifier')), 'the verifier is in this tab only');
  assert.ok(!tab.localStorage.keys().some((key) => key.endsWith('-code-verifier')));
});

test('a completed callback exchanges this flow, strips the code and returns to the flow return path', async () => {
  const fixture = fixtureWithClient();
  const { authorize, tab } = await startGoogle(fixture, '/account/sign-in?next=%2Fapp%2Forders');
  const callback = fixture.completeGoogle(authorize);
  const { page, view } = await landOnCallback(tab, fixture, callback);
  assert.equal(view.state, 'signed_in');
  assert.equal(view.next, '/app/orders');
  assert.equal(page.href, `${SITE}/account/callback`, 'code is gone from the address');
  assert.deepEqual(page.navigations, ['/app/orders']);
  assert.equal(fixture.count('oauth_exchange'), 1);
  assert.ok(!page.sessionStorage.keys().some((key) => key.endsWith('-code-verifier') && !key.endsWith('flows-code-verifier')), 'verifier consumed');
});

test('L3: overlapping starts in two tabs each complete with their own verifier', async () => {
  const fixture = fixtureWithClient();
  const localStorage = new FakeStorage();
  const tabA = createTab(`${SITE}/account/sign-in`, { localStorage });
  const tabB = createTab(`${SITE}/account/sign-in`, { localStorage });
  const a = await startGoogle(fixture, undefined, tabA);
  const b = await startGoogle(fixture, undefined, tabB);
  const callbackB = fixture.completeGoogle(b.authorize, { email: 'b@example.test' });
  const callbackA = fixture.completeGoogle(a.authorize, { email: 'a@example.test' });
  const doneB = await landOnCallback(tabB, fixture, callbackB, { autoNavigate: false });
  const doneA = await landOnCallback(tabA, fixture, callbackA, { autoNavigate: false });
  assert.equal(doneB.view.state, 'signed_in');
  assert.equal(doneA.view.state, 'signed_in');
  assert.equal(fixture.count('oauth_exchange'), 2);
});

test('L3: two starts in one tab: the first flow callback is refused with a fresh start, nothing is stored', async () => {
  const fixture = fixtureWithClient();
  const first = await startGoogle(fixture);
  const secondController = openController(reopen(first.tab, '/account/sign-in'), fixture);
  await secondController.start();
  await secondController.startGoogle();
  const firstCallback = fixture.completeGoogle(first.authorize);
  const { view, page } = await landOnCallback(first.tab, fixture, firstCallback);
  assert.deepEqual([view.screen, view.state, view.error], ['callback', 'error', 'provider_unavailable']);
  assert.equal(page.localStorage.keys().filter((key) => key.endsWith(':auth')).length, 0, 'no session stored');
  assert.equal(fixture.snapshot().liveSessions, 0);
  assert.equal(page.sessionStorage.keys().filter((key) => key.endsWith(':flow')).length, 0, 'the flow is abandoned');
  // A fresh start works.
  const retry = await startGoogle(fixture, '/account/sign-in', reopen(page, '/account/sign-in'));
  const ok = await landOnCallback(retry.tab, fixture, fixture.completeGoogle(retry.authorize));
  assert.equal(ok.view.state, 'signed_in');
});

test('L8: a callback without code, with a provider error, or in a tab without the flow stores nothing', async () => {
  const fixture = fixtureWithClient();
  const { authorize, tab } = await startGoogle(fixture);
  const denied = await landOnCallback(tab, fixture, fixture.completeGoogle(authorize, { deny: true }));
  assert.deepEqual([denied.view.state, denied.view.error], ['error', 'provider_unavailable']);
  assert.equal(denied.page.href, `${SITE}/account/callback`, 'provider error text is stripped');

  const bare = await landOnCallback(tab, fixture, `${SITE}/account/callback`);
  assert.equal(bare.view.error, 'provider_unavailable');

  const fresh = await startGoogle(fixture, '/account/sign-in', reopen(tab, '/account/sign-in'));
  const callback = fixture.completeGoogle(fresh.authorize);
  const otherTab = createTab(callback, { localStorage: tab.localStorage });
  const foreign = openController(otherTab, fixture);
  assert.equal((await foreign.start()).error, 'provider_unavailable');
  assert.equal(fixture.count('oauth_exchange'), 0, 'no exchange without this tab\'s flow');
  assert.equal(fixture.snapshot().liveSessions, 0);
});

test('a stale flow (past its lifetime, or dated in the future after a clock change) is refused before any exchange', async () => {
  for (const shift of [11 * 60 * 1000, -60 * 1000]) {
    const fixture = fixtureWithClient();
    let now = 5_000_000;
    const context = await setup('/account/sign-in', { fixture, options: { now: () => now } });
    await context.controller.startGoogle();
    const callback = fixture.completeGoogle(context.tab.navigations.at(-1));
    now += shift;
    const { view } = await landOnCallback(context.tab, fixture, callback, { now: () => now });
    assert.equal(view.error, 'provider_unavailable', `shift ${shift}`);
    assert.equal(fixture.count('oauth_exchange'), 0);
  }
});

test('an exchange refused by Auth or lost in transport is provider_unavailable with a fresh start', async () => {
  for (const mode of ['http_503', 'transport_loss']) {
    const fixture = fixtureWithClient();
    const { authorize, tab } = await startGoogle(fixture);
    fixture.fault('oauth_exchange', mode);
    const { view } = await landOnCallback(tab, fixture, fixture.completeGoogle(authorize));
    assert.deepEqual([view.state, view.error], ['error', 'provider_unavailable'], mode);
    assert.equal(tab.sessionStorage.keys().filter((key) => key.endsWith(':flow')).length, 0);
  }
  const fixture = fixtureWithClient();
  const { authorize, tab } = await startGoogle(fixture);
  const reused = fixture.completeGoogle(authorize);
  assert.equal((await landOnCallback(tab, fixture, reused)).view.state, 'signed_in');
  // The same callback address again (history, reload): its code is spent.
  assert.equal((await landOnCallback(tab, fixture, reused)).view.error, 'provider_unavailable');
});

test('L11: `next` abuse always falls back to the client default', async () => {
  const hostile = [
    'https://evil.example/app', '//evil.example/app', '/\\evil.example', '/app%2F..', '/app/../admin', '/app#x',
    ' /app', '/app\u0000', 'javascript:alert(1)', '/unlisted', '/APP', `/${'a'.repeat(3000)}`,
  ];
  for (const next of hostile) {
    const fixture = fixtureWithClient();
    fixture.seedUser({ email: 'n@example.test' });
    const { controller, tab } = await setup(`/account/sign-in?next=${encodeURIComponent(next)}`, { fixture });
    await controller.signIn({ email: 'n@example.test', password: 'correct horse battery' });
    assert.deepEqual(tab.navigations, ['/app'], JSON.stringify(next));
  }
  const fixture = fixtureWithClient();
  fixture.seedUser({ email: 'n@example.test' });
  const repeated = await setup('/account/sign-in?next=%2Fapp%2Forders&next=%2Fapp%2Forders', { fixture });
  await repeated.controller.signIn({ email: 'n@example.test', password: 'correct horse battery' });
  assert.deepEqual(repeated.tab.navigations, ['/app'], 'a repeated next is ambiguous');
});

test('a tampered stored return path is re-validated on use', async () => {
  const fixture = fixtureWithClient();
  const { authorize, tab } = await startGoogle(fixture, '/account/sign-in?next=%2Fapp%2Forders');
  const key = tab.sessionStorage.keys().find((k) => k.endsWith(':flow'));
  const record = JSON.parse(tab.sessionStorage.getItem(key));
  tab.sessionStorage.setItem(key, JSON.stringify({ ...record, next: 'https://evil.example/' }));
  const { view } = await landOnCallback(tab, fixture, fixture.completeGoogle(authorize));
  assert.equal(view.next, '/app');
});

test('Google is refused locally when the provider is disabled', async () => {
  const { controller, tab, fixture } = await setup('/account/sign-in', { config: baseConfig({ providers: { email: true, google: false } }) });
  const view = await controller.startGoogle();
  assert.deepEqual([view.state, view.error], ['error', 'method_disabled']);
  assert.deepEqual(tab.navigations, []);
  assert.equal(fixture.requests.length, 0);
});
