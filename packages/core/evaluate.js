// Permission evaluation over a resolved Principal (contract 4.3). Decisions
// read only `access.permissions` and `access.activeRoles`; `access.roles` is
// display data and never grants anything. Inputs that are not a well-formed
// principal or key fail closed.

import { AuthError } from './errors.js';
import { isPlainObject, isOpaqueKey, isDenseArray, isStringArray } from './shape.js';

function readAccess(principal) {
  if (!isPlainObject(principal) || !isPlainObject(principal.access)) return null;
  const { roles, activeRoles, permissions } = principal.access;
  // Dense string arrays only: a hole is not a role or a key.
  if (!isStringArray(roles) || !isStringArray(activeRoles) || !isStringArray(permissions)) return null;
  // An active role that is not held is an impossible state: refuse it rather
  // than guess which list is right.
  if (!activeRoles.every((role) => roles.includes(role))) return null;
  return principal.access;
}

// Array methods skip holes, so a sparse list would be judged on fewer keys
// than it names; an all-hole list would be vacuously granted.
function hasKeys(keys) {
  return isDenseArray(keys) && keys.length > 0 && keys.every(isOpaqueKey);
}

/** True when an active role grants `key`. */
export function can(principal, key) {
  const access = readAccess(principal);
  return access !== null && isOpaqueKey(key) && access.permissions.includes(key);
}

/** True when every key is granted. An empty list is never granted. */
export function canAll(principal, keys) {
  return hasKeys(keys) && keys.every((key) => can(principal, key));
}

/** True when at least one key is granted. An empty list is never granted. */
export function canAny(principal, keys) {
  return hasKeys(keys) && keys.some((key) => can(principal, key));
}

/**
 * Names the roles behind a decision. Provenance comes from the per-role keys
 * carried on each membership by the same snapshot (`Membership.permissions`,
 * an additive optional field). A membership without that field contributes to
 * neither list: associations are never inferred.
 * @returns {{ allowed: boolean, via: string[], withheld: { role: string, reason: 'mfa_required' }[] }}
 */
export function explain(principal, key) {
  const allowed = can(principal, key);
  const access = readAccess(principal);
  if (access === null || !isOpaqueKey(key) || !isDenseArray(principal.memberships)) {
    return { allowed, via: [], withheld: [] };
  }
  const via = [];
  const withheld = [];
  for (const membership of principal.memberships) {
    if (!isPlainObject(membership) || typeof membership.roleKey !== 'string') continue;
    if (!isStringArray(membership.permissions) || !membership.permissions.includes(key)) continue;
    const role = membership.roleKey;
    if (!access.roles.includes(role)) continue;
    if (access.activeRoles.includes(role)) {
      if (allowed) via.push(role);
    } else if (membership.flags?.mfaRequired === true && principal.session?.aal !== 'aal2') {
      withheld.push({ role, reason: 'mfa_required' });
    }
  }
  return { allowed, via, withheld };
}

/**
 * Returns the principal when `key` is granted; otherwise throws
 * `mfa_required` if a held role withheld for lack of aal2 would grant it, or
 * `forbidden`. A missing principal throws `no_token`.
 */
export function requirePermission(principal, key) {
  requirePresent(principal);
  if (can(principal, key)) return principal;
  throw new AuthError(explain(principal, key).withheld.length > 0 ? 'mfa_required' : 'forbidden');
}

/**
 * Returns the principal when at least one of `roles` is active. Held roles
 * that are inactive for lack of aal2 produce `mfa_required`.
 * @param {unknown} principal
 * @param {string | string[]} roles
 */
export function requireRole(principal, roles) {
  requirePresent(principal);
  const wanted = typeof roles === 'string' ? [roles] : roles;
  const access = readAccess(principal);
  if (access === null || !hasKeys(wanted)) throw new AuthError('forbidden');
  if (wanted.some((role) => access.activeRoles.includes(role))) return principal;
  const withheld = principal.session?.aal !== 'aal2' && wanted.some((role) => {
    if (!access.roles.includes(role) || !isDenseArray(principal.memberships)) return false;
    const membership = principal.memberships.find((m) => isPlainObject(m) && m.roleKey === role);
    return membership?.flags?.mfaRequired === true;
  });
  throw new AuthError(withheld ? 'mfa_required' : 'forbidden');
}

/** Returns the principal when its session is aal2; otherwise throws `mfa_required`. */
export function requireMfa(principal) {
  requirePresent(principal);
  if (!isPlainObject(principal) || !isPlainObject(principal.session)) throw new AuthError('forbidden');
  if (principal.session.aal !== 'aal2') throw new AuthError('mfa_required');
  return principal;
}

function requirePresent(principal) {
  if (principal === null || principal === undefined) throw new AuthError('no_token');
}
