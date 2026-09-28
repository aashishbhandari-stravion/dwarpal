// PostgREST RPC into the exposed `auth_kit` schema: the five user wrappers of
// supabase/migrations/20260927000000_dwarpal_auth_kit.sql with the same
// argument names, JSON results, order of checks and refusals. A kit refusal is
// HTTP 400 with SQLSTATE DW001 and the refusal code as `message`, as PostgREST
// renders `raise ... using errcode = 'DW001'`; no other failure uses DW001.
// PostgREST checks the JWT signature and expiry only, never the Auth session,
// so a signed-out user's unexpired token still reaches these functions (L25b).

import { requestFingerprint } from '../../core/index.js';
import { UUID_PATTERN } from '../../core/shape.js';
import { isoMicro, membershipsOf, nowMs } from './store.js';

export const EXPOSED_SCHEMAS = ['public', 'graphql_public', 'auth_kit'];
const CLIENT_ARGS = [['client_id', 'text']];
const TARGET_ARGS = [['user_id', 'uuid'], ['client_id', 'text'], ['role_key', 'text'], ['request_id', 'uuid']];
export const USER_FUNCTIONS = Object.freeze({
  ensure_profile: { args: [], stable: false },
  join_client: { args: CLIENT_ARGS, stable: false },
  effective_access: { args: CLIENT_ARGS, stable: true },
  grant_membership: { args: TARGET_ARGS, stable: false },
  revoke_membership: { args: TARGET_ARGS, stable: false },
});
// Present in the real schema but executable by service_role only.
export const OPERATOR_FUNCTIONS = new Set([
  'register_client', 'apply_model', 'export_model', 'bootstrap_manager', 'revoke_manager',
  'mfa_reset_begin', 'mfa_reset_note', 'mfa_reset_finish',
]);

function pgError(status, code, message, details = null) {
  return { status, body: { code, details, hint: null, message } };
}

const refuse = (code) => pgError(400, 'DW001', code);
const value = (body) => ({ status: 200, body });

export function notFound(fn) {
  const name = Object.hasOwn(USER_FUNCTIONS, fn) ? `auth_kit.${fn}` : 'the requested function';
  return pgError(404, 'PGRST202', `Could not find ${name} with the given parameters in the schema cache`,
    'Searched the exposed schema for a function with exactly the given parameter names, but no matches were found in the schema cache.');
}

/** Resolves the database role from the Authorization header, as PostgREST would. */
export function resolveRole(ctx) {
  const header = ctx.request.headers.authorization;
  if (header === undefined) return { role: 'anon' };
  const match = typeof header === 'string' ? /^Bearer ([^\s]{1,16384})$/.exec(header) : null;
  if (match && match[1] === ctx.publishableKey) return { role: 'anon' };
  const claims = match ? ctx.signer.verify(match[1]) : null;
  if (!claims) return { error: pgError(401, 'PGRST301', 'JWT could not be decoded or verified') };
  if (typeof claims.exp !== 'number' || claims.exp <= Math.floor(nowMs(ctx.state) / 1000)) {
    return { error: pgError(401, 'PGRST303', 'JWT expired') };
  }
  if (claims.role !== 'authenticated' || typeof claims.sub !== 'string' || !UUID_PATTERN.test(claims.sub)) {
    return { error: pgError(401, 'PGRST301', 'JWT could not be decoded or verified') };
  }
  // Only the literal 'aal2' activates MFA-required roles; anything else is aal1.
  return { role: 'authenticated', userId: claims.sub.toLowerCase(), aal: claims.aal === 'aal2' ? 'aal2' : 'aal1' };
}

/** Converts JSON arguments to SQL values: text or uuid, with PostgreSQL's input errors. */
export function readArgs(fn, input) {
  const spec = USER_FUNCTIONS[fn].args;
  const names = Object.keys(input);
  if (names.length !== spec.length || spec.some(([name]) => !Object.hasOwn(input, name))) return { error: notFound(fn) };
  const args = {};
  for (const [name, type] of spec) {
    const raw = input[name];
    if (raw === null || raw === undefined) {
      args[name] = null;
    } else if (type === 'uuid') {
      if (typeof raw !== 'string' || !UUID_PATTERN.test(raw)) return { error: pgError(400, '22P02', 'invalid input syntax for type uuid') };
      args[name] = raw.toLowerCase();
    } else {
      const text = typeof raw === 'string' ? raw : typeof raw === 'object' ? JSON.stringify(raw) : String(raw);
      if (text.includes('\u0000')) return { error: pgError(400, '22P05', 'unsupported Unicode escape sequence', '\\u0000 cannot be converted to text.') };
      if (!text.isWellFormed()) return { error: pgError(400, '22P02', 'invalid input syntax for type json') };
      args[name] = text;
    }
  }
  return { args };
}

/**
 * Runs one user function. Request fingerprints are hashed first; everything
 * after that is synchronous, so each call is one serialised transaction.
 */
export async function callFunction(ctx, fn, actor, args) {
  let hash = null;
  if ((fn === 'grant_membership' || fn === 'revoke_membership') && Object.values(args).every((v) => v !== null)) {
    hash = await requestFingerprint({
      operation: fn, clientId: args.client_id, actorId: actor.userId,
      payload: { user_id: args.user_id, role_key: args.role_key },
    });
  }
  switch (fn) {
    case 'ensure_profile': return ensureProfile(ctx.state, actor);
    case 'join_client': return joinClient(ctx.state, actor, args.client_id);
    case 'effective_access': return effectiveAccess(ctx.state, actor, args.client_id);
    default: return changeMembership(ctx.state, fn, actor, args, hash);
  }
}

function ensureProfile(state, actor) {
  let profile = state.profiles.get(actor.userId);
  if (!profile) {
    profile = { updatedAt: nowMs(state) };
    state.profiles.set(actor.userId, profile);
  }
  return value({ user_id: actor.userId, display_name: null, contact_email: null, contact_phone: null, updated_at: isoMicro(profile.updatedAt) });
}

function sortedKeys(keys) {
  // JavaScript string order is UTF-16 code-unit order, the order SQL uses for keys.
  return [...keys].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}

function joinClient(state, actor, clientId) {
  if (clientId === null) return refuse('invalid_argument');
  // Confirmation comes from the user record (auth.users), never from the JWT.
  const user = state.users.get(actor.userId);
  if (!user || user.confirmedAt === null) return value({ result: 'email_unverified' });
  const client = state.clients.get(clientId);
  if (!client) return value({ result: 'unknown_client' });
  // Enrollment is once per user and client: an existing row ends the join
  // whatever memberships exist now, so a revoke stays durable.
  const enrollment = client.enrollments.get(actor.userId);
  if (enrollment) return value({ result: 'already_enrolled', enrolled_at: isoMicro(enrollment.enrolledAt) });
  if (client.signupPolicy === 'closed') return value({ result: 'closed' });
  const selfAssignable = sortedKeys([...client.roles.entries()].filter(([, role]) => role.self_assignable).map(([key]) => key));
  if (selfAssignable.length === 0) return value({ result: 'no_default_role' });
  const held = membershipsOf(client, actor.userId);
  // A role a manager granted before the first join is not granted twice.
  const granted = selfAssignable.filter((key) => !held.has(key));
  const at = nowMs(state);
  client.enrollments.set(actor.userId, { enrolledAt: at, grantedRoles: granted });
  for (const roleKey of granted) {
    held.set(roleKey, { grantedAt: at, grantedBy: null, grantedVia: 'join' });
    client.events.push({ action: 'join', result: 'enrolled', userId: actor.userId, roleKey, actorKind: 'user',
      actorUserId: actor.userId, requestId: null, at });
  }
  return value({ result: 'enrolled', enrolled_at: isoMicro(at), granted_roles: granted });
}

function effectiveAccess(state, actor, clientId) {
  if (clientId === null) return refuse('invalid_argument');
  const client = state.clients.get(clientId);
  const enrollment = client?.enrollments.get(actor.userId);
  const held = client?.memberships.get(actor.userId) ?? new Map();
  const rows = sortedKeys([...held.keys()].filter((key) => client.roles.has(key))).map((roleKey) => {
    const role = client.roles.get(roleKey);
    const row = held.get(roleKey);
    return {
      role_key: roleKey,
      flags: { self_assignable: role.self_assignable, manages_members: role.manages_members, mfa_required: role.mfa_required },
      granted_at: isoMicro(row.grantedAt),
      granted_via: row.grantedVia,
      permissions: sortedKeys(role.permissions),
      active: !role.mfa_required || actor.aal === 'aal2',
    };
  });
  const active = rows.filter((row) => row.active);
  return value({
    client_id: clientId,
    enrolled_at: enrollment ? isoMicro(enrollment.enrolledAt) : null,
    memberships: rows.map(({ active: _active, ...row }) => row),
    active_roles: active.map((row) => row.role_key),
    permissions: sortedKeys(new Set(active.flatMap((row) => row.permissions))),
    mfa_pending: rows.some((row) => !row.active),
  });
}

// grant_membership / revoke_membership, in the SQL order: arguments, request
// id, manager authority (after the "lock"), target role, target user, self.
function changeMembership(state, fn, actor, args, hash) {
  if (Object.values(args).some((v) => v === null)) return refuse('invalid_argument');
  const { user_id: userId, client_id: clientId, role_key: roleKey, request_id: requestId } = args;
  const stored = state.requestLog.get(requestId);
  if (stored) return stored.payloadHash === hash ? value(stored.result) : refuse('request_conflict');
  const client = state.clients.get(clientId);
  const authority = managerAuthority(client, actor);
  if (authority) return refuse(authority);
  const role = client.roles.get(roleKey);
  if (!role) return refuse('unknown_role');
  // Managers never create or remove managers; that stays with the operator.
  if (role.manages_members) return refuse('forbidden');
  if (fn === 'grant_membership') {
    const target = state.users.get(userId);
    if (!target) return refuse('unknown_user');
    if (target.confirmedAt === null) return refuse('email_unverified');
    if (userId === actor.userId) return refuse('forbidden');
  }
  const held = membershipsOf(client, userId);
  const at = nowMs(state);
  let changed;
  if (fn === 'grant_membership') {
    changed = !held.has(roleKey);
    if (changed) held.set(roleKey, { grantedAt: at, grantedBy: actor.userId, grantedVia: 'manager' });
  } else {
    changed = held.delete(roleKey);
  }
  const outcome = fn === 'grant_membership' ? (changed ? 'granted' : 'already_member') : (changed ? 'revoked' : 'not_member');
  const result = { result: outcome, user_id: userId, client_id: clientId, role_key: roleKey };
  if (changed) {
    client.events.push({ action: fn === 'grant_membership' ? 'grant' : 'revoke', result: outcome, userId, roleKey,
      actorKind: 'user', actorUserId: actor.userId, requestId, at });
  }
  state.requestLog.set(requestId, { payloadHash: hash, result, clientId, operation: fn, actorId: actor.userId, at });
  return value(result);
}

/** null when an active manages_members role is held; otherwise the refusal. */
function managerAuthority(client, actor) {
  const held = client?.memberships.get(actor.userId);
  const managerRoles = held ? [...held.keys()].map((key) => client.roles.get(key)).filter((role) => role?.manages_members) : [];
  if (managerRoles.length === 0) return 'forbidden';
  return managerRoles.some((role) => !role.mfa_required || actor.aal === 'aal2') ? null : 'mfa_required';
}
