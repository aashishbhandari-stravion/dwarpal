import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AuthError, createPrincipal, can, explain, requirePermission } from '@briqvent/dwarpal';
import { FIXTURE_CLIENT_ID, FIXTURE_OTHER_CLIENT_ID } from '@briqvent/dwarpal/testing';

const unavailable = (err) => err instanceof AuthError && err.code === 'unavailable';
const USER = '11111111-1111-4111-8111-111111111111';
const T = '2026-02-01T10:00:00Z';

function row(overrides = {}) {
  return {
    clientId: 'client-b',
    roleKey: 'member',
    flags: { selfAssignable: true, managesMembers: false, mfaRequired: false },
    grantedAt: T,
    grantedVia: 'join',
    permissions: ['items:read:own'],
    ...overrides,
  };
}

function snapshot(overrides = {}) {
  return {
    clientId: 'client-b',
    identity: { userId: USER, verifiedEmail: 'someone@example.test', providers: ['email'] },
    session: { id: 'session-1', aal: 'aal1', issuedAt: T, expiresAt: T, checkedAt: T },
    enrolledAt: T,
    memberships: [row()],
    ...overrides,
  };
}

test('createPrincipal derives access from the snapshot and freezes it', () => {
  const p = createPrincipal(snapshot({
    memberships: [
      row(),
      row({ roleKey: 'desk', flags: { selfAssignable: false, managesMembers: false, mfaRequired: true }, grantedVia: 'manager', permissions: ['items:read:any', 'items:read:any'] }),
    ],
  }));
  assert.deepEqual(p.access, {
    clientId: 'client-b',
    enrolledAt: T,
    roles: ['desk', 'member'],
    activeRoles: ['member'],
    permissions: ['items:read:own'],
    mfaPending: true,
  });
  assert.deepEqual(p.memberships.map((m) => m.permissions), [['items:read:any'], ['items:read:own']]);
  assert.ok(Object.isFrozen(p) && Object.isFrozen(p.access.permissions) && Object.isFrozen(p.memberships[0].flags));
  assert.throws(() => { 'use strict'; p.access.permissions.push('x'); }, TypeError);
});

test('manager of A and customer of B, resolved for B, mentions B only (L31)', () => {
  const p = createPrincipal(snapshot());
  assert.equal(p.access.clientId, 'client-b');
  assert.deepEqual(p.memberships.map((m) => m.clientId), ['client-b']);
  assert.ok(!JSON.stringify(p).includes('client-a'));
  // A row for another client in the same read means the read was not scoped: fail closed.
  const leaked = snapshot({ memberships: [row(), row({ clientId: 'client-a', roleKey: 'boss', flags: { selfAssignable: false, managesMembers: true, mfaRequired: false }, grantedVia: 'operator' })] });
  assert.throws(() => createPrincipal(leaked), unavailable);
  assert.throws(() => createPrincipal(snapshot({ clientId: FIXTURE_CLIENT_ID, memberships: [row({ clientId: FIXTURE_OTHER_CLIENT_ID })] })), unavailable);
});

test('enrolled with no memberships and never enrolled are distinct, both grant nothing', () => {
  const revoked = createPrincipal(snapshot({ memberships: [] }));
  assert.equal(revoked.access.enrolledAt, T);
  assert.deepEqual(revoked.access.permissions, []);
  assert.equal(revoked.access.mfaPending, false);
  const fresh = createPrincipal(snapshot({ memberships: [], enrolledAt: null }));
  assert.equal(fresh.access.enrolledAt, null);
});

test('invalid external shapes and booleans fail closed with unavailable', () => {
  const cases = {
    notObject: null,
    extraTopLevel: { ...snapshot(), cached: true },
    numberClient: snapshot({ clientId: 5 }),
    nulClient: snapshot({ clientId: 'b\u0000', memberships: [row({ clientId: 'b\u0000' })] }),
    badEnrolled: snapshot({ enrolledAt: 'yesterday' }),
    badUser: snapshot({ identity: { userId: 'not-a-uuid', verifiedEmail: null, providers: [] } }),
    badProvider: snapshot({ identity: { userId: USER, verifiedEmail: null, providers: ['github'] } }),
    dupProvider: snapshot({ identity: { userId: USER, verifiedEmail: null, providers: ['email', 'email'] } }),
    identityExtra: snapshot({ identity: { userId: USER, verifiedEmail: null, providers: [], appMetadata: { role: 'boss' } } }),
    unknownAal: snapshot({ session: { id: 's', aal: 'aal3', issuedAt: T, expiresAt: T, checkedAt: T } }),
    missingAal: snapshot({ session: { id: 's', issuedAt: T, expiresAt: T, checkedAt: T } }),
    badTime: snapshot({ session: { id: 's', aal: 'aal1', issuedAt: '2026-13-45T99:00:00Z', expiresAt: T, checkedAt: T } }),
    stringFlag: snapshot({ memberships: [row({ flags: { selfAssignable: true, managesMembers: false, mfaRequired: 'false' } })] }),
    numberFlag: snapshot({ memberships: [row({ flags: { selfAssignable: true, managesMembers: 0, mfaRequired: false } })] }),
    missingFlag: snapshot({ memberships: [row({ flags: { selfAssignable: true, managesMembers: false } })] }),
    extraFlag: snapshot({ memberships: [row({ flags: { selfAssignable: true, managesMembers: false, mfaRequired: false, superuser: true } })] }),
    missingPermissions: snapshot({ memberships: [row({ permissions: undefined })] }),
    numberPermission: snapshot({ memberships: [row({ permissions: [7] })] }),
    nulPermission: snapshot({ memberships: [row({ permissions: ['a\u0000b'] })] }),
    surrogatePermission: snapshot({ memberships: [row({ permissions: ['\udc00'] })] }),
    missingRole: snapshot({ memberships: [row({ roleKey: undefined })] }),
    surrogateRole: snapshot({ memberships: [row({ roleKey: '\ud800' })] }),
    badVia: snapshot({ memberships: [row({ grantedVia: 'self' })] }),
    dupRole: snapshot({ memberships: [row(), row()] }),
    membershipsNotArray: snapshot({ memberships: {} }),
  };
  for (const [name, input] of Object.entries(cases)) {
    assert.throws(() => createPrincipal(input), unavailable, name);
  }
});

test('sparse arrays in a snapshot give unavailable, never a native error', () => {
  const holes = (values, extra = 1) => {
    const out = [...values];
    out.length += extra;
    return out;
  };
  const cases = {
    memberships: snapshot({ memberships: holes([row()]) }),
    allHoleMemberships: snapshot({ memberships: Array(2) }),
    rowPermissions: snapshot({ memberships: [row({ permissions: holes(['items:read:own']) })] }),
    providers: snapshot({ identity: { userId: USER, verifiedEmail: null, providers: holes(['email']) } }),
  };
  for (const [name, input] of Object.entries(cases)) {
    assert.throws(() => createPrincipal(input), unavailable, name);
  }
  assert.deepEqual(createPrincipal(snapshot({ memberships: [] })).access.roles, []);
  assert.deepEqual(createPrincipal(snapshot({ memberships: [row({ permissions: [] })] })).access.permissions, []);
});

test('snapshot keys are opaque like model keys', () => {
  const p = createPrincipal(snapshot({
    clientId: 'shop/eu 1',
    memberships: [row({ clientId: 'shop/eu 1', roleKey: 'constructor', permissions: ['invoice/read', 'façade:lire'] })],
  }));
  assert.deepEqual(p.access.roles, ['constructor']);
  assert.deepEqual(p.access.permissions, ['façade:lire', 'invoice/read']);
});

test('empty client, role and permission keys are literal keys in a scoped snapshot', () => {
  const p = createPrincipal(snapshot({ clientId: '', memberships: [row({ clientId: '', roleKey: '', permissions: ['items:read:own', ''] })] }));
  assert.equal(p.access.clientId, '');
  assert.deepEqual(p.access.roles, ['']);
  assert.deepEqual(p.access.activeRoles, ['']);
  assert.deepEqual(p.access.permissions, ['', 'items:read:own']);
  assert.equal(can(p, ''), true);
  // Exact client equality: '' is neither a wildcard nor a match for another id.
  assert.throws(() => createPrincipal(snapshot({ memberships: [row({ clientId: '' })] })), unavailable);
  assert.throws(() => createPrincipal(snapshot({ clientId: '' })), unavailable);
});

test('an empty permission follows activation: withheld at aal1, granted at aal2, denied when absent', () => {
  const mfaRow = row({ roleKey: 'desk', flags: { selfAssignable: false, managesMembers: false, mfaRequired: true }, grantedVia: 'manager', permissions: [''] });
  const mfaCode = (err) => err instanceof AuthError && err.code === 'mfa_required';
  const forbidden = (err) => err instanceof AuthError && err.code === 'forbidden';

  const aal1 = createPrincipal(snapshot({ memberships: [row(), mfaRow] }));
  assert.deepEqual(aal1.access.permissions, ['items:read:own']);
  assert.equal(aal1.access.mfaPending, true);
  assert.equal(can(aal1, ''), false);
  assert.deepEqual(explain(aal1, ''), { allowed: false, via: [], withheld: [{ role: 'desk', reason: 'mfa_required' }] });
  assert.throws(() => requirePermission(aal1, ''), mfaCode);

  const aal2 = createPrincipal(snapshot({ session: { id: 'session-1', aal: 'aal2', issuedAt: T, expiresAt: T, checkedAt: T }, memberships: [row(), mfaRow] }));
  assert.deepEqual(aal2.access.permissions, ['', 'items:read:own']);
  assert.deepEqual(explain(aal2, ''), { allowed: true, via: ['desk'], withheld: [] });
  assert.equal(requirePermission(aal2, ''), aal2);

  const absent = createPrincipal(snapshot());
  assert.equal(can(absent, ''), false);
  assert.deepEqual(explain(absent, ''), { allowed: false, via: [], withheld: [] });
  assert.throws(() => requirePermission(absent, ''), forbidden);
});
