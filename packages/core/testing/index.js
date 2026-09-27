// Shared synthetic evaluation fixture, exported as @briqvent/dwarpal/testing so
// consumers test their guards against the same principals the kit tests with.
// Every value here is synthetic: no real users, clients or credentials.
// Everything returned is deeply frozen; fixturePrincipal() builds a fresh
// object on every call.

import { createPrincipal } from '../principal.js';
import { validateModel } from '../model.js';
import { deepFreeze } from '../shape.js';

export const FIXTURE_CLIENT_ID = 'fixture-client';
export const FIXTURE_OTHER_CLIENT_ID = 'fixture-other-client';

/**
 * Four roles cover the evaluation cases: `lead` (manages members, needs MFA),
 * `coordinator` (manages members, no MFA), `clerk` (needs MFA) and `patron`
 * (self-assignable). `reports:export:any` is declared but mapped to no role.
 */
export const FIXTURE_MODEL = validateModel({
  client: FIXTURE_CLIENT_ID,
  roles: {
    lead: {
      manages_members: true,
      mfa_required: true,
      permissions: ['people:manage', 'records:read:any', 'records:update:any', 'tasks:assign:any', 'tasks:assign:self'],
    },
    coordinator: {
      manages_members: true,
      permissions: ['people:manage', 'records:read:any'],
    },
    clerk: {
      mfa_required: true,
      permissions: ['records:read:any', 'records:update:any', 'files:upload:any', 'tasks:assign:self'],
    },
    patron: {
      self_assignable: true,
      permissions: ['records:read:own', 'files:upload:own'],
    },
  },
  permissions: {
    'people:manage': 'grant and revoke non-manager roles',
    'records:read:own': "read records linked to the principal's own user id",
    'records:read:any': 'read any record',
    'records:update:any': 'update any record',
    'files:upload:own': 'upload to an own record',
    'files:upload:any': 'upload to any record',
    'tasks:assign:self': 'assign a task to oneself',
    'tasks:assign:any': 'assign a task to any member',
    'reports:export:any': 'export reports',
  },
});

export const FIXTURE_USER_IDS = deepFreeze({
  patron: '00000000-0000-4000-8000-000000000001',
  otherPatron: '00000000-0000-4000-8000-000000000002',
  clerk: '00000000-0000-4000-8000-000000000003',
  patronClerk: '00000000-0000-4000-8000-000000000004',
  lead: '00000000-0000-4000-8000-000000000005',
  coordinator: '00000000-0000-4000-8000-000000000006',
  leadCoordinator: '00000000-0000-4000-8000-000000000007',
  enrolledNoRoles: '00000000-0000-4000-8000-000000000008',
  notEnrolled: '00000000-0000-4000-8000-000000000009',
});

const GRANTED_VIA = { lead: 'operator', coordinator: 'operator', clerk: 'manager', patron: 'join' };
const T0 = '2026-01-01T00:00:00.000Z';

/**
 * Builds a fresh, deeply frozen principal for FIXTURE_CLIENT_ID holding
 * `roles` from FIXTURE_MODEL, through the same createPrincipal the server uses.
 * @param {{ roles: string[], aal?: 'aal1' | 'aal2', userId?: string, enrolledAt?: string | null }} options
 */
export function fixturePrincipal({ roles, aal = 'aal1', userId = FIXTURE_USER_IDS.patron, enrolledAt = T0 }) {
  if (!Array.isArray(roles)) throw new TypeError('fixturePrincipal: roles must be an array.');
  const memberships = roles.map((roleKey) => {
    const role = FIXTURE_MODEL.roles[roleKey];
    if (!role) throw new TypeError('fixturePrincipal: unknown fixture role.');
    return {
      clientId: FIXTURE_CLIENT_ID,
      roleKey,
      flags: { selfAssignable: role.self_assignable, managesMembers: role.manages_members, mfaRequired: role.mfa_required },
      grantedAt: T0,
      grantedVia: GRANTED_VIA[roleKey],
      permissions: [...role.permissions],
    };
  });
  return createPrincipal({
    clientId: FIXTURE_CLIENT_ID,
    identity: { userId, verifiedEmail: `user-${userId.slice(-4)}@example.test`, providers: ['email'] },
    session: {
      id: `fixture-session-${userId.slice(-4)}-${aal}`,
      aal,
      issuedAt: T0,
      expiresAt: '2026-01-01T00:30:00.000Z',
      checkedAt: '2026-01-01T00:00:01.000Z',
    },
    enrolledAt,
    memberships,
  });
}

const ids = FIXTURE_USER_IDS;

/** Named principals for the evaluation matrix. */
export const fixturePrincipals = deepFreeze({
  patron: fixturePrincipal({ roles: ['patron'], userId: ids.patron }),
  otherPatron: fixturePrincipal({ roles: ['patron'], userId: ids.otherPatron }),
  clerkAal1: fixturePrincipal({ roles: ['clerk'], userId: ids.clerk }),
  clerkAal2: fixturePrincipal({ roles: ['clerk'], aal: 'aal2', userId: ids.clerk }),
  patronClerkAal1: fixturePrincipal({ roles: ['patron', 'clerk'], userId: ids.patronClerk }),
  patronClerkAal2: fixturePrincipal({ roles: ['patron', 'clerk'], aal: 'aal2', userId: ids.patronClerk }),
  leadAal1: fixturePrincipal({ roles: ['lead'], userId: ids.lead }),
  leadAal2: fixturePrincipal({ roles: ['lead'], aal: 'aal2', userId: ids.lead }),
  coordinator: fixturePrincipal({ roles: ['coordinator'], userId: ids.coordinator }),
  leadCoordinatorAal1: fixturePrincipal({ roles: ['lead', 'coordinator'], userId: ids.leadCoordinator }),
  enrolledNoRoles: fixturePrincipal({ roles: [], userId: ids.enrolledNoRoles }),
  notEnrolled: fixturePrincipal({ roles: [], userId: ids.notEnrolled, enrolledAt: null }),
});
