// Stateless session resolution and manager operations (design 4.1, D8).
//
// Every authenticated call verifies the token (signature, issuer, audience,
// time claims and Supabase claims), asks Supabase Auth whether that user and
// session still exist (GET /auth/v1/user), and only then reads or writes
// through the exposed auth_kit wrappers with the same token. The client id
// is fixed at construction. Nothing about a user or session is cached: the
// only state held between requests is jose's JWKS public-key cache. The
// publishable key is the only credential this module accepts; a secret key
// is refused at construction.

import { AuthError } from '../core/index.js';
import { isOpaqueKey, UUID_PATTERN, deepFreeze } from '../core/shape.js';
import { DEFAULT_TIMERS, request, parseJson, TransportError } from './lib/http.js';
import { serverConfigIssues, projectOrigin } from './lib/keys.js';
import { createVerifier } from './lib/jwt.js';
import { readAuthUser, principalFromAccess } from './lib/access.js';
import { callRpc } from './lib/postgrest.js';

const MAX_USER_BYTES = 256 * 1024;
const BEARER = /^Bearer ([A-Za-z0-9_.-]+)$/i;

// Manager write refusals and the consumer error each becomes (design 4.1,
// closed AuthError set). `unknown_role` and `unknown_user` have no consumer
// code: the manager may not grant or revoke that target, so they read as
// forbidden. `invalid_argument` cannot arise from arguments validated here,
// so it, like any unlisted code, means the database and this library
// disagree and is reported as unavailable.
const MANAGER_REFUSALS = Object.freeze({
  forbidden: 'forbidden',
  mfa_required: 'mfa_required',
  request_conflict: 'request_conflict',
  email_unverified: 'email_unverified',
  unknown_role: 'forbidden',
  unknown_user: 'forbidden',
});
const MANAGER_RESULTS = Object.freeze({
  grant_membership: new Set(['granted', 'already_member']),
  revoke_membership: new Set(['revoked', 'not_member']),
});

/**
 * @param {{ supabaseUrl: string, publishableKey: string, clientId: string, clockToleranceSeconds?: number,
 *           fetch?: typeof fetch, requestTimeoutMs?: number, now?: () => number, timers?: object }} options
 */
export function createAuthServer(options) {
  if (options === null || typeof options !== 'object') throw new AuthError('config_invalid', { issues: [{ path: '$', rule: 'not_object' }] });
  const { supabaseUrl, publishableKey, clientId } = options;
  const issues = serverConfigIssues({ clientId, supabaseUrl, publishableKey });
  const tolerance = options.clockToleranceSeconds ?? 5;
  if (!Number.isFinite(tolerance) || tolerance < 0 || tolerance > 300) issues.push({ path: 'clockToleranceSeconds', rule: 'out_of_range' });
  const timeoutMs = options.requestTimeoutMs ?? 10_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120_000) issues.push({ path: 'requestTimeoutMs', rule: 'out_of_range' });
  if (options.fetch !== undefined && typeof options.fetch !== 'function') issues.push({ path: 'fetch', rule: 'type' });
  if (issues.length > 0) throw new AuthError('config_invalid', { issues });

  const origin = projectOrigin(supabaseUrl);
  const fetchImpl = options.fetch ?? globalThis.fetch;
  const now = options.now ?? Date.now;
  const timers = options.timers ?? DEFAULT_TIMERS;
  const verify = createVerifier({ origin, fetch: fetchImpl, timers, clockToleranceSeconds: tolerance, now, jwksTimeoutMs: Math.min(timeoutMs, 5_000) });

  async function liveUser(token, claims) {
    let response;
    try {
      response = await request(fetchImpl, `${origin}/auth/v1/user`, {
        headers: { apikey: publishableKey, Authorization: `Bearer ${token}`, Accept: 'application/json' },
        timeoutMs,
        maxBytes: MAX_USER_BYTES,
        timers,
      });
    } catch (error) {
      if (error instanceof TransportError) throw new AuthError('unavailable');
      throw error;
    }
    // Signed out, banned or deleted users and dead sessions are refused by
    // Auth with a 4xx; the token is then not a live session.
    if ([400, 401, 403, 404].includes(response.status)) throw new AuthError('invalid_token');
    if (response.status !== 200) throw new AuthError('unavailable');
    let user;
    try {
      user = parseJson(response.text);
    } catch {
      throw new AuthError('unavailable');
    }
    return readAuthUser(user, claims.sub, now());
  }

  async function authenticate(requestLike) {
    const token = bearerToken(requestLike);
    if (token === null) return null;
    const claims = await verify(token);
    const identity = await liveUser(token, claims);
    return { token, claims, identity };
  }

  function rpc(token, fn, args) {
    return callRpc({ fetch: fetchImpl, timers, origin, apikey: publishableKey, bearer: token, fn, args, timeoutMs });
  }

  async function resolveSession(requestLike) {
    const auth = await authenticate(requestLike);
    if (auth === null) return null;
    const outcome = await rpc(auth.token, 'effective_access', { client_id: clientId });
    if (outcome.kind !== 'value') {
      // PostgREST judged the token itself: it expired between the checks.
      if (outcome.kind === 'failure' && outcome.status === 401) throw new AuthError('invalid_token');
      throw new AuthError('unavailable');
    }
    const session = {
      id: auth.claims.sessionId,
      aal: auth.claims.aal,
      issuedAt: new Date(auth.claims.iat * 1000).toISOString(),
      expiresAt: new Date(auth.claims.exp * 1000).toISOString(),
      checkedAt: new Date(now()).toISOString(),
    };
    return principalFromAccess(outcome.value, { clientId, identity: auth.identity, session });
  }

  async function managerWrite(fn, userId, roleKey, requestId, requestLike) {
    const args = managerArgs(userId, roleKey, requestId);
    const auth = await authenticate(requestLike);
    if (auth === null) throw new AuthError('no_token');
    const outcome = await rpc(auth.token, fn, { user_id: args.userId, client_id: clientId, role_key: args.roleKey, request_id: args.requestId });
    if (outcome.kind === 'refusal') {
      const code = Object.hasOwn(MANAGER_REFUSALS, outcome.code) ? MANAGER_REFUSALS[outcome.code] : 'unavailable';
      throw new AuthError(code);
    }
    // A failure after the request was sent may hide a committed write:
    // retrying with the same request id returns the stored result.
    if (outcome.kind !== 'value') throw new AuthError(outcome.status === 401 ? 'invalid_token' : 'unavailable');
    return readManagerResult(outcome.value, MANAGER_RESULTS[fn], { ...args, clientId });
  }

  return Object.freeze({
    clientId,
    resolveSession,
    /** Grants a non-manager role as the manager whose token `request` carries. */
    grantMembership: (userId, roleKey, requestId, requestLike) => managerWrite('grant_membership', userId, roleKey, requestId, requestLike),
    /** Revokes a non-manager role as the manager whose token `request` carries. */
    revokeMembership: (userId, roleKey, requestId, requestLike) => managerWrite('revoke_membership', userId, roleKey, requestId, requestLike),
  });
}

/**
 * The bearer token of a Fetch API Request or a Node IncomingMessage, or null
 * when the request carries no Authorization header. A header that is present
 * but not exactly one bearer token is invalid, never anonymous.
 */
export function bearerToken(requestLike) {
  const headers = requestLike?.headers;
  let value;
  if (headers && typeof headers.get === 'function') value = headers.get('authorization');
  else if (headers && typeof headers === 'object') value = Object.hasOwn(headers, 'authorization') ? headers.authorization : undefined;
  else throw new TypeError('resolveSession: expected a Request or an incoming message with headers.');
  if (value === null || value === undefined) return null;
  if (typeof value !== 'string') throw new AuthError('invalid_token');
  const match = BEARER.exec(value);
  if (!match) throw new AuthError('invalid_token');
  return match[1];
}

function managerArgs(userId, roleKey, requestId) {
  if (typeof userId !== 'string' || !UUID_PATTERN.test(userId)) throw new TypeError('userId must be a UUID string.');
  if (!isOpaqueKey(roleKey)) throw new TypeError('roleKey must be a role key string.');
  if (typeof requestId !== 'string' || !UUID_PATTERN.test(requestId)) throw new TypeError('requestId must be a UUID string.');
  return { userId: userId.toLowerCase(), roleKey, requestId: requestId.toLowerCase() };
}

// The stored or fresh outcome must describe exactly the requested change.
function readManagerResult(value, results, expected) {
  const keys = ['result', 'user_id', 'client_id', 'role_key'];
  const ok = value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key))
    && results.has(value.result) && typeof value.user_id === 'string' && value.user_id.toLowerCase() === expected.userId
    && value.client_id === expected.clientId && value.role_key === expected.roleKey;
  if (!ok) throw new AuthError('unavailable');
  return deepFreeze({ result: value.result, userId: expected.userId, clientId: expected.clientId, roleKey: expected.roleKey });
}
