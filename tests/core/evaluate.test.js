import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  AuthError,
  can,
  canAll,
  canAny,
  explain,
  requirePermission,
  requireRole,
  requireMfa,
} from '@briqvent/dwarpal';
import { fixturePrincipals as P, fixturePrincipal, FIXTURE_MODEL } from '@briqvent/dwarpal/testing';

const code = (c) => (err) => err instanceof AuthError && err.code === c;

test('active/withheld union: patron plus MFA clerk at aal1 keeps only patron keys (L20)', () => {
  const p = P.patronClerkAal1;
  assert.deepEqual(p.access.roles, ['clerk', 'patron']);
  assert.deepEqual(p.access.activeRoles, ['patron']);
  assert.deepEqual(p.access.permissions, ['files:upload:own', 'records:read:own']);
  assert.equal(p.access.mfaPending, true);
  assert.equal(can(p, 'records:read:own'), true);
  assert.equal(can(p, 'records:read:any'), false);
  assert.deepEqual(explain(p, 'files:upload:any'), {
    allowed: false,
    via: [],
    withheld: [{ role: 'clerk', reason: 'mfa_required' }],
  });
});

test('active/withheld union: at aal2 the union covers both roles', () => {
  const p = P.patronClerkAal2;
  assert.deepEqual(p.access.activeRoles, ['clerk', 'patron']);
  assert.equal(p.access.mfaPending, false);
  const expected = new Set([...FIXTURE_MODEL.roles.patron.permissions, ...FIXTURE_MODEL.roles.clerk.permissions]);
  assert.deepEqual(new Set(p.access.permissions), expected);
  assert.deepEqual(explain(p, 'records:read:any'), { allowed: true, via: ['clerk'], withheld: [] });
});

test('requirePermission: mfa_required only when a withheld role would grant the key', () => {
  assert.throws(() => requirePermission(P.clerkAal1, 'records:read:any'), code('mfa_required'));
  assert.throws(() => requirePermission(P.clerkAal1, 'tasks:assign:any'), code('forbidden'));
  assert.equal(requirePermission(P.clerkAal2, 'records:read:any'), P.clerkAal2);
  assert.throws(() => requirePermission(P.patron, 'records:read:any'), code('forbidden'));
});

test('mixed manager roles (L34): U1 via coordinator with lead withheld, U2 aal1 mfa_required, U3 granted, U2 aal2 granted', () => {
  const u1 = P.leadCoordinatorAal1;
  assert.equal(can(u1, 'people:manage'), true);
  assert.deepEqual(explain(u1, 'people:manage'), {
    allowed: true,
    via: ['coordinator'],
    withheld: [{ role: 'lead', reason: 'mfa_required' }],
  });
  assert.equal(requireRole(u1, 'coordinator'), u1);
  assert.throws(() => requireRole(u1, 'lead'), code('mfa_required'));

  assert.throws(() => requirePermission(P.leadAal1, 'people:manage'), code('mfa_required'));
  assert.equal(requirePermission(P.coordinator, 'people:manage'), P.coordinator);
  assert.equal(requirePermission(P.leadAal2, 'people:manage'), P.leadAal2);
  assert.throws(() => requirePermission(P.clerkAal2, 'people:manage'), code('forbidden'));
  assert.throws(() => requirePermission(P.patron, 'people:manage'), code('forbidden'));
});

test('unknown and unmapped keys are not granted and have no grantor (L24)', () => {
  for (const key of ['nope:read:any', 'reports:export:any', 'RECORDS:READ:ANY', 'records:read:any ']) {
    assert.equal(can(P.leadAal2, key), false, key);
    assert.deepEqual(explain(P.leadAal2, key), { allowed: false, via: [], withheld: [] });
    assert.throws(() => requirePermission(P.leadAal2, key), code('forbidden'));
  }
});

test('canAll / canAny: matrices, empty and malformed lists fail closed', () => {
  assert.equal(canAll(P.clerkAal2, ['records:read:any', 'records:update:any']), true);
  assert.equal(canAll(P.clerkAal2, ['records:read:any', 'people:manage']), false);
  assert.equal(canAny(P.clerkAal1, ['records:read:any', 'people:manage']), false);
  assert.equal(canAny(P.patronClerkAal1, ['records:read:any', 'records:read:own']), true);
  for (const bad of [[], null, undefined, 'records:read:own', [''], [1], ['records:read:own', null]]) {
    assert.equal(canAll(P.patron, bad), false);
    assert.equal(canAny(P.patron, bad), false);
  }
});

test('role helper activation: requireRole uses activeRoles, never display roles', () => {
  assert.throws(() => requireRole(P.clerkAal1, 'clerk'), code('mfa_required'));
  assert.equal(requireRole(P.clerkAal2, 'clerk'), P.clerkAal2);
  assert.equal(requireRole(P.patronClerkAal1, ['clerk', 'patron']), P.patronClerkAal1);
  assert.throws(() => requireRole(P.patron, 'lead'), code('forbidden'));
  assert.throws(() => requireRole(P.patron, []), code('forbidden'));
  assert.throws(() => requireRole(P.patron, ''), code('forbidden'));
  // A forged principal listing a display role without activating it gets nothing.
  const forged = structuredClone(P.patron);
  forged.access.roles.push('lead');
  assert.throws(() => requireRole(forged, 'lead'), code('forbidden'));
  assert.equal(can(forged, 'people:manage'), false);
});

test('requireMfa follows the session assurance level', () => {
  assert.throws(() => requireMfa(P.patron), code('mfa_required'));
  assert.equal(requireMfa(P.leadAal2), P.leadAal2);
  assert.throws(() => requireMfa({}), code('forbidden'));
});

test('missing or malformed principals fail closed', () => {
  for (const helper of [(p) => requirePermission(p, 'records:read:own'), (p) => requireRole(p, 'patron'), requireMfa]) {
    assert.throws(() => helper(null), code('no_token'));
    assert.throws(() => helper(undefined), code('no_token'));
  }
  for (const bad of [{}, 'x', 42, { access: {} }, { access: { roles: [], activeRoles: ['patron'], permissions: ['records:read:own'] } }]) {
    assert.equal(can(bad, 'records:read:own'), false);
    assert.deepEqual(explain(bad, 'records:read:own'), { allowed: false, via: [], withheld: [] });
    assert.throws(() => requirePermission(bad, 'records:read:own'), code('forbidden'));
    assert.throws(() => requireRole(bad, 'patron'), code('forbidden'));
  }
  assert.equal(can(P.patron, undefined), false);
  assert.equal(can(P.patron, ''), false);
  assert.equal(can(P.patron, ['records:read:own']), false);
});

test('explain never invents provenance when per-role keys are absent', () => {
  const bare = structuredClone(P.patronClerkAal1);
  for (const m of bare.memberships) delete m.permissions;
  assert.deepEqual(explain(bare, 'records:read:own'), { allowed: true, via: [], withheld: [] });
  assert.deepEqual(explain(bare, 'records:read:any'), { allowed: false, via: [], withheld: [] });
  // Without provenance the helper cannot claim MFA would help.
  assert.throws(() => requirePermission(bare, 'records:read:any'), code('forbidden'));
  // Provenance never grants: a membership listing a key absent from access.permissions.
  const inflated = structuredClone(P.patron);
  inflated.memberships[0].permissions.push('people:manage');
  assert.deepEqual(explain(inflated, 'people:manage'), { allowed: false, via: [], withheld: [] });
  assert.throws(() => requirePermission(inflated, 'people:manage'), code('forbidden'));
});

// Consumer guard from contract 4.3 with the fixture's own/any keys.
function readRecord(principal, record) {
  if (!can(principal, 'records:read:any')) {
    requirePermission(principal, 'records:read:own');
    if (record.ownerId !== principal.identity.userId) throw new AuthError('forbidden');
  }
  return record;
}

test('own/any consumer guard (L26): patron plus clerk at aal1, then aal2', () => {
  const p = P.patronClerkAal1;
  const own = { id: 'r1', ownerId: p.identity.userId };
  const other = { id: 'r2', ownerId: P.otherPatron.identity.userId };
  assert.throws(() => readRecord(p, other), code('forbidden'));
  assert.deepEqual(explain(p, 'records:read:any').withheld, [{ role: 'clerk', reason: 'mfa_required' }]);
  assert.equal(readRecord(p, own), own);
  const p2 = P.patronClerkAal2;
  assert.equal(readRecord(p2, other), other);
  assert.equal(readRecord(p2, { ownerId: p2.identity.userId }).ownerId, p2.identity.userId);
});

test('own/any consumer guard: negatives for each principal', () => {
  const record = { ownerId: P.otherPatron.identity.userId };
  assert.throws(() => readRecord(P.patron, record), code('forbidden'));
  // The clerk's broad key is withheld and it holds no own key: the guard says
  // forbidden, while explain tells the page that MFA would unlock the broad branch.
  assert.throws(() => readRecord(P.clerkAal1, record), code('forbidden'));
  assert.deepEqual(explain(P.clerkAal1, 'records:read:any').withheld, [{ role: 'clerk', reason: 'mfa_required' }]);
  assert.throws(() => readRecord(P.enrolledNoRoles, record), code('forbidden'));
  assert.throws(() => readRecord(P.notEnrolled, record), code('forbidden'));
  assert.throws(() => readRecord(null, record), code('no_token'));
  assert.equal(readRecord(P.clerkAal2, record), record);
});

test('self-scoped key predicate: target must equal the principal', () => {
  const assign = (principal, targetUserId) => {
    if (can(principal, 'tasks:assign:any')) return true;
    requirePermission(principal, 'tasks:assign:self');
    if (targetUserId !== principal.identity.userId) throw new AuthError('forbidden');
    return true;
  };
  assert.equal(assign(P.clerkAal2, P.clerkAal2.identity.userId), true);
  assert.throws(() => assign(P.clerkAal2, P.patron.identity.userId), code('forbidden'));
  assert.throws(() => assign(P.clerkAal1, P.clerkAal1.identity.userId), code('mfa_required'));
  assert.equal(assign(P.leadAal2, P.patron.identity.userId), true);
  assert.throws(() => assign(P.patron, P.patron.identity.userId), code('forbidden'));
});

test('client scoping: a principal carries only its configured client', () => {
  for (const p of Object.values(P)) {
    assert.equal(p.access.clientId, 'fixture-client');
    for (const m of p.memberships) assert.equal(m.clientId, 'fixture-client');
  }
  const p = fixturePrincipal({ roles: ['patron'] });
  assert.equal(can(p, 'records:read:own'), true);
});
