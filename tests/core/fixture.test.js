import { test } from 'node:test';
import assert from 'node:assert/strict';
import { validateModel } from '@briqvent/dwarpal';
import {
  FIXTURE_MODEL,
  FIXTURE_USER_IDS,
  fixturePrincipal,
  fixturePrincipals,
} from '@briqvent/dwarpal/testing';

function assertDeepFrozen(value, path = '$') {
  if (value === null || typeof value !== 'object') return;
  assert.ok(Object.isFrozen(value), `${path} is not frozen`);
  for (const [key, child] of Object.entries(value)) assertDeepFrozen(child, `${path}.${key}`);
}

test('shared fixtures are deeply frozen and mutation throws', () => {
  assertDeepFrozen(FIXTURE_MODEL);
  assertDeepFrozen(FIXTURE_USER_IDS);
  assertDeepFrozen(fixturePrincipals);
  assert.throws(() => { fixturePrincipals.patron.access.permissions.push('people:manage'); }, TypeError);
  assert.throws(() => { fixturePrincipals.patron.session.aal = 'aal2'; }, TypeError);
  assert.throws(() => { FIXTURE_MODEL.roles.patron.manages_members = true; }, TypeError);
  assert.throws(() => { fixturePrincipals.extra = {}; }, TypeError);
});

test('fixturePrincipal returns detached objects: no shared references between calls or with the model', () => {
  const a = fixturePrincipal({ roles: ['clerk'] });
  const b = fixturePrincipal({ roles: ['clerk'] });
  assert.notEqual(a, b);
  assert.deepEqual(a, b);
  assert.notEqual(a.access.permissions, b.access.permissions);
  assert.notEqual(a.memberships[0].permissions, FIXTURE_MODEL.roles.clerk.permissions);
  const clone = structuredClone(a);
  clone.access.permissions.push('people:manage');
  assert.ok(!a.access.permissions.includes('people:manage'));
  assert.ok(!fixturePrincipals.clerkAal1.access.permissions.includes('people:manage'));
});

test('fixture model is a valid canonical model with no reserved-flag conflicts', () => {
  assert.deepEqual(validateModel(structuredClone(FIXTURE_MODEL)), FIXTURE_MODEL);
  for (const role of Object.values(FIXTURE_MODEL.roles)) {
    assert.ok(!(role.self_assignable && role.manages_members));
  }
});

test('fixturePrincipal rejects unknown roles and non-array input', () => {
  assert.throws(() => fixturePrincipal({ roles: ['superuser'] }), TypeError);
  assert.throws(() => fixturePrincipal({ roles: 'patron' }), TypeError);
});

test('named principals match the documented role and MFA matrix', () => {
  const summary = Object.fromEntries(
    Object.entries(fixturePrincipals).map(([name, p]) => [name, [p.session.aal, p.access.roles.join('+'), p.access.activeRoles.join('+'), p.access.mfaPending]]),
  );
  assert.deepEqual(summary, {
    patron: ['aal1', 'patron', 'patron', false],
    otherPatron: ['aal1', 'patron', 'patron', false],
    clerkAal1: ['aal1', 'clerk', '', true],
    clerkAal2: ['aal2', 'clerk', 'clerk', false],
    patronClerkAal1: ['aal1', 'clerk+patron', 'patron', true],
    patronClerkAal2: ['aal2', 'clerk+patron', 'clerk+patron', false],
    leadAal1: ['aal1', 'lead', '', true],
    leadAal2: ['aal2', 'lead', 'lead', false],
    coordinator: ['aal1', 'coordinator', 'coordinator', false],
    leadCoordinatorAal1: ['aal1', 'coordinator+lead', 'coordinator', true],
    enrolledNoRoles: ['aal1', '', '', false],
    notEnrolled: ['aal1', '', '', false],
  });
  assert.equal(fixturePrincipals.notEnrolled.access.enrolledAt, null);
});
