// Builds a Principal from one effective-access snapshot. Access is derived
// here, from the same rows that populate memberships, so the two views cannot
// disagree. Any malformed or foreign row fails closed with `unavailable`: the
// caller must never receive an empty, partial or cross-client principal.

import { AuthError } from './errors.js';
import {
  UUID_PATTERN,
  TIMESTAMP_PATTERN,
  isPlainObject,
  isOpaqueKey,
  isDenseArray,
  isStringArray,
  hasExtraKeys,
  own,
  deepFreeze,
  sortedUnique,
  compareCodeUnits,
} from './shape.js';

export const PROVIDERS = Object.freeze(['email', 'google']);
export const AAL_LEVELS = Object.freeze(['aal1', 'aal2']);
export const GRANTED_VIA = Object.freeze(['join', 'manager', 'operator']);

const MAX_MEMBERSHIPS = 256;
const MAX_ROLE_PERMISSIONS = 2048;

/**
 * @param {import('./index.js').PrincipalSnapshot} snapshot
 * @returns {import('./index.js').Principal}
 */
export function createPrincipal(snapshot) {
  if (!isPlainObject(snapshot)) fail();
  const { clientId, identity, session, enrolledAt, memberships } = ownFields(snapshot, ['clientId', 'identity', 'session', 'enrolledAt', 'memberships']);
  if (!isOpaqueKey(clientId)) fail();
  if (enrolledAt !== null && !isTimestamp(enrolledAt)) fail();

  const id = readIdentity(identity);
  const sess = readSession(session);
  if (!isDenseArray(memberships) || memberships.length > MAX_MEMBERSHIPS) fail();
  const rows = memberships.map((row) => readMembership(row, clientId));
  rows.sort((a, b) => compareCodeUnits(a.roleKey, b.roleKey));
  for (let i = 1; i < rows.length; i += 1) {
    if (rows[i].roleKey === rows[i - 1].roleKey) fail();
  }

  // A role is active when it needs no MFA or the session is aal2 (contract 4.3).
  const active = rows.filter((row) => !row.flags.mfaRequired || sess.aal === 'aal2');
  const access = {
    clientId,
    enrolledAt,
    roles: rows.map((row) => row.roleKey),
    activeRoles: active.map((row) => row.roleKey),
    permissions: sortedUnique(active.flatMap((row) => row.permissions)),
    mfaPending: active.length < rows.length,
  };
  return deepFreeze({ identity: id, memberships: rows, access, session: sess });
}

function readIdentity(value) {
  if (!isPlainObject(value)) fail();
  const { userId, verifiedEmail, providers } = ownFields(value, ['userId', 'verifiedEmail', 'providers']);
  if (typeof userId !== 'string' || !UUID_PATTERN.test(userId)) fail();
  if (verifiedEmail !== null && (typeof verifiedEmail !== 'string' || verifiedEmail === '' || verifiedEmail.length > 320)) fail();
  if (!isStringArray(providers) || !providers.every((p) => PROVIDERS.includes(p))) fail();
  if (new Set(providers).size !== providers.length) fail();
  return { userId: userId.toLowerCase(), verifiedEmail, providers: [...providers].sort(compareCodeUnits) };
}

function readSession(value) {
  if (!isPlainObject(value)) fail();
  const { id, aal, issuedAt, expiresAt, checkedAt } = ownFields(value, ['id', 'aal', 'issuedAt', 'expiresAt', 'checkedAt']);
  if (typeof id !== 'string' || id === '' || id.length > 128) fail();
  // An unknown assurance level is never treated as aal1 or aal2.
  if (!AAL_LEVELS.includes(aal)) fail();
  if (!isTimestamp(issuedAt) || !isTimestamp(expiresAt) || !isTimestamp(checkedAt)) fail();
  return { id, aal, issuedAt, expiresAt, checkedAt };
}

function readMembership(row, clientId) {
  if (!isPlainObject(row)) fail();
  const fields = ownFields(row, ['clientId', 'roleKey', 'flags', 'grantedAt', 'grantedVia', 'permissions']);
  // Principal is scoped to the configured client only; a row for any other
  // client means the read was not scoped and nothing from it can be trusted.
  if (fields.clientId !== clientId) fail();
  if (!isOpaqueKey(fields.roleKey)) fail();
  if (!isPlainObject(fields.flags)) fail();
  const { selfAssignable, managesMembers, mfaRequired } = ownFields(fields.flags, ['selfAssignable', 'managesMembers', 'mfaRequired']);
  if (typeof selfAssignable !== 'boolean' || typeof managesMembers !== 'boolean' || typeof mfaRequired !== 'boolean') fail();
  if (!isTimestamp(fields.grantedAt) || !GRANTED_VIA.includes(fields.grantedVia)) fail();
  const permissions = fields.permissions;
  if (!isStringArray(permissions) || permissions.length > MAX_ROLE_PERMISSIONS) fail();
  if (!permissions.every(isOpaqueKey)) fail();
  return {
    clientId,
    roleKey: fields.roleKey,
    flags: { selfAssignable, managesMembers, mfaRequired },
    grantedAt: fields.grantedAt,
    grantedVia: fields.grantedVia,
    permissions: sortedUnique(permissions),
  };
}

// Exactly the named own fields: any other key fails, and a missing name reads
// as undefined rather than as an inherited property.
function ownFields(object, names) {
  if (hasExtraKeys(object, names)) fail();
  const out = {};
  for (const name of names) out[name] = own(object, name);
  return out;
}

function isTimestamp(value) {
  return typeof value === 'string' && TIMESTAMP_PATTERN.test(value) && !Number.isNaN(Date.parse(value));
}

function fail() {
  throw new AuthError('unavailable');
}
