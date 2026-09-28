// MFA challenge, enrolment, aal2 refresh and withheld-role presentation
// (design 5.10, 7; L14, L20). SYNTHETIC: real supabase-js 2.117.2 over the
// scripted fixture in support/; TOTP is a fixed synthetic code.

import test from 'node:test';
import assert from 'node:assert/strict';
import { setup, CLIENT_ID, MODEL_ROLES } from './support/env.js';
import { createScriptedSupabase, TOTP_CODE, TOTP_SECRET } from './support/scripted-supabase.js';

async function staffUser({ factor = false, controller } = {}) {
  const fixture = createScriptedSupabase();
  fixture.seedClient({ clientId: CLIENT_ID, roles: MODEL_ROLES });
  const userId = fixture.seedUser({ email: 'staff@example.test' });
  if (factor) fixture.seedFactor(userId);
  const context = await setup('/account/sign-in', { fixture, options: controller });
  await context.controller.signIn({ email: 'staff@example.test', password: 'correct horse battery' });
  // Enrolled as member through the join, staff granted by a manager.
  if (!factor) fixture.grant(userId, CLIENT_ID, 'staff');
  return { ...context, fixture, userId };
}

test('L20: an aal1 member+staff sees staff withheld and is sent to MFA enrolment, not signed in', async () => {
  const { controller, fixture, tab } = await staffUser();
  const view = await controller.start();
  assert.deepEqual([view.screen, view.state, view.mfa.mode, view.mfa.enrolment], ['mfa', 'mfa_enrol', 'enrol', null]);
  assert.deepEqual(view.principal.access.activeRoles, ['member']);
  assert.deepEqual(view.withheldRoles, ['staff']);
  assert.deepEqual(view.principal.access.permissions, ['orders:read:own']);
  assert.equal(view.principal.access.mfaPending, true);
  assert.equal(fixture.count('mfa_enroll'), 0, 'no factor is created until the user asks');
  assert.deepEqual(tab.navigations, ['/app'], 'only the first, member-only pass navigated');
});

test('L14: enrol, verify, refreshed aal2 session; the reread activates the withheld role', async () => {
  const { controller, fixture } = await staffUser();
  await controller.start();
  const enrol = await controller.startMfaEnrol();
  assert.equal(enrol.mfa.enrolment.secret, TOTP_SECRET);
  assert.ok(enrol.mfa.enrolment.qrCode.startsWith('data:image/svg+xml'));
  await controller.startMfaEnrol();
  assert.equal(fixture.count('mfa_enroll'), 1, 'one factor per page');
  assert.equal((await controller.verifyMfa({ code: '000000' })).error, 'mfa_invalid_code');
  assert.equal((await controller.verifyMfa({ code: '12' })).error, 'invalid_input');
  const done = await controller.verifyMfa({ code: TOTP_CODE });
  assert.equal(done.state, 'signed_in');
  assert.equal(done.principal.session.aal, 'aal2');
  assert.deepEqual(done.principal.access.activeRoles, ['member', 'staff']);
  assert.deepEqual(done.withheldRoles, []);
  assert.equal(fixture.count('mfa_enroll'), 1);
});

test('an enrolled factor is challenged before any RPC at sign-in', async () => {
  const { controller, fixture } = await staffUser({ factor: true });
  const view = controller.getView();
  assert.deepEqual([view.state, view.mfa.mode], ['mfa_challenge', 'challenge']);
  assert.equal(fixture.count('ensure_profile'), 0);
  const done = await controller.verifyMfa({ code: TOTP_CODE });
  assert.equal(done.state, 'signed_in');
  assert.equal(done.principal.session.aal, 'aal2');
});

test('L14: when the verify answer still carries aal1, the kit refreshes once before rereading access', async () => {
  const fixture = createScriptedSupabase();
  fixture.seedClient({ clientId: CLIENT_ID, roles: MODEL_ROLES });
  const userId = fixture.seedUser({ email: 's@example.test' });
  fixture.seedFactor(userId);
  fixture.setVerifyTokenAal('aal1');
  const { controller } = await setup('/account/sign-in', { fixture });
  await controller.signIn({ email: 's@example.test', password: 'correct horse battery' });
  const done = await controller.verifyMfa({ code: TOTP_CODE });
  assert.equal(done.state, 'signed_in');
  assert.equal(done.principal.session.aal, 'aal2');
  assert.equal(fixture.count('refresh'), 1);
});

test('a failed aal2 refresh never shows the user as signed in', async () => {
  const fixture = createScriptedSupabase();
  fixture.seedClient({ clientId: CLIENT_ID, roles: MODEL_ROLES });
  const userId = fixture.seedUser({ email: 's@example.test' });
  fixture.seedFactor(userId);
  fixture.setVerifyTokenAal('aal1');
  const { controller } = await setup('/account/sign-in', { fixture });
  await controller.signIn({ email: 's@example.test', password: 'correct horse battery' });
  // A 503 would be retried by supabase-js itself; Auth refusing is final.
  fixture.fault('refresh', 'refused');
  const view = await controller.verifyMfa({ code: TOTP_CODE });
  assert.deepEqual([view.state, view.error, view.principal], ['error', 'unavailable', null]);
});

test('enrolment is skippable only when the host marks it optional; withheld roles stay withheld', async () => {
  const strict = await staffUser();
  await strict.controller.start();
  assert.equal((await strict.controller.skipMfaEnrol()).state, 'mfa_enrol');

  const optional = await staffUser({ controller: { mfaEnrolOptional: true } });
  const view = await optional.controller.start();
  assert.equal(view.mfa.optional, true);
  const skipped = await optional.controller.skipMfaEnrol();
  assert.equal(skipped.state, 'signed_in');
  assert.deepEqual(skipped.withheldRoles, ['staff']);
  assert.deepEqual(skipped.principal.access.permissions, ['orders:read:own']);
});

test('MFA transport and service failures keep the MFA screen with a specific state', async () => {
  const { controller, fixture } = await staffUser({ factor: true });
  fixture.fault('mfa_challenge', 'transport_loss');
  const offline = await controller.verifyMfa({ code: TOTP_CODE });
  assert.deepEqual([offline.screen, offline.state, offline.mfa.mode], ['mfa', 'offline', 'challenge']);
  fixture.fault('mfa_verify', 'http_503');
  assert.deepEqual([(await controller.verifyMfa({ code: TOTP_CODE })).error], ['unavailable']);
  assert.equal((await controller.verifyMfa({ code: TOTP_CODE })).state, 'signed_in');
});
