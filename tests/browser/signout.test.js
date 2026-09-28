// Global sign-out that clears local state even when Auth fails (v0.3 5.9
// carried). SYNTHETIC: real supabase-js 2.117.2 over the scripted fixture in support/.

import test from 'node:test';
import assert from 'node:assert/strict';
import { signedIn, setup, reopen, openController, CLIENT_ID, MODEL_ROLES } from './support/env.js';
import { createScriptedSupabase } from './support/scripted-supabase.js';

function kitKeys(tab) {
  return [...tab.localStorage.keys(), ...tab.sessionStorage.keys()].filter((key) => key.startsWith('dwarpal:'));
}

test('global sign-out revokes every session of the user and clears this browser', async () => {
  const first = await signedIn();
  await signedIn({ fixture: first.fixture, skipClient: true });
  assert.equal(first.fixture.snapshot().liveSessions, 2);
  const view = await first.controller.signOut();
  assert.deepEqual([view.screen, view.state], ['signOut', 'idle']);
  assert.deepEqual(view.signOut, { remote: 'revoked', local: 'cleared' });
  assert.equal(first.fixture.snapshot().liveSessions, 0, 'scope global');
  assert.deepEqual(kitKeys(first.tab), []);
  assert.equal(first.controller.getPrincipal(), null);
});

test('sign-out clears local state when Auth is unreachable, errors or hangs, and says the remote half is unconfirmed', async () => {
  for (const mode of ['transport_loss', 'http_503', 'hang']) {
    const { controller, fixture, tab } = await signedIn({ controller: { requestTimeoutMs: 100 } });
    fixture.fault('global_sign_out', mode);
    const view = await controller.signOut();
    assert.deepEqual(view.signOut, { remote: 'unconfirmed', local: 'cleared' }, mode);
    assert.deepEqual(kitKeys(tab), [], mode);
    const later = openController(reopen(tab, '/account/sign-in'), fixture);
    assert.deepEqual([(await later.start()).state, later.getPrincipal()], ['idle', null], `${mode}: no session survives`);
    assert.equal(fixture.snapshot().liveSessions, 1, `${mode}: the server session is still live, as reported`);
  }
});

test('sign-out without a session asks Auth nothing', async () => {
  const { controller, fixture } = await setup('/account/sign-out');
  const view = await controller.signOut();
  assert.deepEqual(view.signOut, { remote: 'skipped', local: 'cleared' });
  assert.equal(fixture.count('global_sign_out'), 0);
});

test('a storage that refuses removal is reported as a failed local clear, never as success', async () => {
  const { controller, tab } = await signedIn();
  tab.localStorage.failRemove = true;
  const view = await controller.signOut();
  // supabase-js throws from its own storage removal after Auth answered, so
  // the kit cannot confirm the remote half either; it claims neither.
  assert.deepEqual(view.signOut, { remote: 'unconfirmed', local: 'failed' });
  assert.ok(tab.localStorage.keys().some((key) => key.endsWith(':auth')), 'the session is still stored');
  const resumed = await controller.start();
  assert.deepEqual([resumed.state, resumed.principal], ['idle', null], 'this page never resumes the session it failed to remove');
  tab.localStorage.failRemove = false;
});

test('sign-out during a running sign-in wins: the late session is wiped and the page stays signed out', async () => {
  const fixture = createScriptedSupabase();
  fixture.seedClient({ clientId: CLIENT_ID, roles: MODEL_ROLES });
  fixture.seedUser({ email: 'late@example.test' });
  const { tab } = await setup('/account/sign-in', { fixture, start: false });
  let release;
  const gate = new Promise((resolve) => { release = resolve; });
  const slowFetch = fixture.fetch;
  fixture.fetch = async (input, init) => {
    if (String(input).includes('grant_type=password')) await gate;
    return slowFetch(input, init);
  };
  const late = openController(tab, fixture);
  await late.start();
  const signingIn = late.signIn({ email: 'late@example.test', password: 'correct horse battery' });
  const signingOut = late.signOut();
  // Signed out already; a new action is refused until the running one ends.
  assert.equal((await late.signIn({ email: 'late@example.test', password: 'other' })).state, 'idle');
  release();
  const [inView, outView] = await Promise.all([signingIn, signingOut]);
  assert.equal(outView.state, 'idle');
  assert.equal(late.getView().state, 'idle', 'the late sign-in result was dropped');
  assert.notEqual(inView.state, 'signed_in');
  assert.deepEqual(kitKeys(tab), [], 'the session saved by the late answer was wiped');
  assert.equal(fixture.count('ensure_profile'), 0);
  assert.equal(fixture.count('password_sign_in'), 1, 'the action tried during sign-out sent nothing');
});
