// Turns the two live reads of design 4.1 (steps 2 and 3) into a Principal.
//
// The Auth user answer supplies identity; the effective_access answer
// supplies memberships for the configured client. Both are external input:
// each field is checked against the exact wire shape, the access snapshot
// must name the configured client, and the SQL-computed active roles,
// permissions and mfa_pending must equal what core derives from the same
// rows and the verified token's aal. Any disagreement fails closed with
// `unavailable`; nothing is copied into a principal unchecked.

import { AuthError, createPrincipal } from '../../core/index.js';
import { isPlainObject, isOpaqueKey, isStringArray, hasExtraKeys, own, UUID_PATTERN } from '../../core/shape.js';

const ACCESS_FIELDS = ['client_id', 'enrolled_at', 'memberships', 'active_roles', 'permissions', 'mfa_pending'];
const MEMBERSHIP_FIELDS = ['role_key', 'flags', 'granted_at', 'granted_via', 'permissions'];
const FLAG_FIELDS = ['self_assignable', 'manages_members', 'mfa_required'];
const PROVIDERS = new Set(['email', 'google']);

function unavailable() {
  return new AuthError('unavailable');
}

function exactFields(value, names) {
  if (!isPlainObject(value) || hasExtraKeys(value, names) || !names.every((name) => Object.hasOwn(value, name))) {
    throw unavailable();
  }
  return value;
}

/**
 * Identity from GET /auth/v1/user. Providers come from the user's linked
 * identities (Auth's own table), never from user or app metadata.
 * @returns {{ userId: string, verifiedEmail: string | null, providers: string[] }}
 */
export function readAuthUser(user, expectedUserId, nowMs) {
  if (!isPlainObject(user)) throw unavailable();
  const id = own(user, 'id');
  if (typeof id !== 'string' || !UUID_PATTERN.test(id)) throw unavailable();
  // The token's subject and the user Auth returned for that token must agree.
  if (id.toLowerCase() !== expectedUserId) throw new AuthError('invalid_token');
  if (own(user, 'is_anonymous') === true) throw new AuthError('invalid_token');
  const bannedUntil = own(user, 'banned_until');
  if (typeof bannedUntil === 'string' && bannedUntil !== '') {
    const until = Date.parse(bannedUntil);
    if (Number.isNaN(until) || until > nowMs) throw new AuthError('invalid_token');
  }
  const email = own(user, 'email');
  const confirmedAt = own(user, 'email_confirmed_at');
  const confirmed = typeof confirmedAt === 'string' && confirmedAt !== '' && !Number.isNaN(Date.parse(confirmedAt));
  const verifiedEmail = confirmed && typeof email === 'string' && email !== '' && email.length <= 320 ? email : null;
  const identities = own(user, 'identities');
  const providers = new Set();
  if (identities !== undefined && identities !== null) {
    if (!Array.isArray(identities) || identities.length > 64) throw unavailable();
    for (const identity of identities) {
      if (!isPlainObject(identity)) throw unavailable();
      const provider = own(identity, 'provider');
      if (typeof provider !== 'string') throw unavailable();
      if (PROVIDERS.has(provider)) providers.add(provider);
    }
  }
  return { userId: expectedUserId, verifiedEmail, providers: [...providers] };
}

/**
 * @param {unknown} value the effective_access RPC result
 * @param {{ clientId: string, identity: object, session: object }} context
 */
export function principalFromAccess(value, { clientId, identity, session }) {
  const snapshot = exactFields(value, ACCESS_FIELDS);
  // A snapshot for any other client means the read was not the one requested.
  if (snapshot.client_id !== clientId) throw unavailable();
  if (!Array.isArray(snapshot.memberships)) throw unavailable();
  const memberships = snapshot.memberships.map((row) => {
    exactFields(row, MEMBERSHIP_FIELDS);
    const flags = exactFields(row.flags, FLAG_FIELDS);
    return {
      clientId,
      roleKey: row.role_key,
      flags: { selfAssignable: flags.self_assignable, managesMembers: flags.manages_members, mfaRequired: flags.mfa_required },
      grantedAt: row.granted_at,
      grantedVia: row.granted_via,
      permissions: row.permissions,
    };
  });
  // createPrincipal validates every remaining field and throws unavailable.
  const principal = createPrincipal({ clientId, identity, session, enrolledAt: snapshot.enrolled_at, memberships });
  const { access } = principal;
  if (!sameList(snapshot.active_roles, access.activeRoles) || !sameList(snapshot.permissions, access.permissions)
      || snapshot.mfa_pending !== access.mfaPending) {
    throw unavailable();
  }
  return principal;
}

// Both sides are sorted in UTF-16 code-unit order (SQL utf16_key, core
// compareCodeUnits), so equal sets are equal lists.
function sameList(wire, derived) {
  return isStringArray(wire) && wire.every(isOpaqueKey) && wire.length === derived.length
    && wire.every((item, index) => item === derived[index]);
}
