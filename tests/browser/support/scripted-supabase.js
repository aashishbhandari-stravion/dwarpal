// SYNTHETIC TEST FIXTURE. A scripted, in-memory stand-in for the Supabase Auth
// and PostgREST answers the browser kit consumes, exposed as a `fetch`
// function so the real pinned supabase-js runs unchanged on top of it. It is
// written against the browser/emulator interface contract and the migration's
// SQL semantics for the three exposed RPCs; it is not the development
// emulator (packages/emulator), not Supabase, and passing against it is not
// hosted evidence.
//
// It records every request (operation name, never bodies or tokens) and
// counts side effects (profiles, enrollments, memberships, events) so tests
// can assert once-only effects. One-shot faults per operation:
//   http_503        answer 503, apply nothing
//   refused         answer 400 with an Auth error code, apply nothing
//   transport_loss  reject the fetch, apply nothing
//   lost_after_commit apply the write, then reject the fetch
//   malformed       answer 200 with a non-JSON body
//   hang            never answer until the request is aborted

import { createHash, randomUUID } from 'node:crypto';

export const ORIGIN = 'http://127.0.0.1:54321';
export const PUBLISHABLE_KEY = 'sb_publishable_synthetic_fixture_key';
export const TOTP_CODE = '123456';
export const TOTP_SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DP';

const JSON_HEADERS = { 'content-type': 'application/json', 'x-supabase-api-version': '2024-01-01' };

export function createScriptedSupabase() {
  const users = new Map();
  const sessions = new Map();
  const refreshTokens = new Map();
  const links = new Map();
  const codes = new Map();
  const challenges = new Map();
  const clients = new Map();
  const profiles = new Map();
  const enrollments = new Map();
  const memberships = new Map();
  const events = [];
  const requests = [];
  const faults = new Map();
  let accessTtlSeconds = 3600;
  let verifyTokenAal = null;

  // ---- seeding --------------------------------------------------------------

  function seedUser({ email, password = 'correct horse battery', confirmed = true, providers = ['email'] }) {
    const id = randomUUID();
    users.set(id, {
      id,
      email,
      password,
      confirmedAt: confirmed ? new Date().toISOString() : null,
      identities: providers.map((provider) => ({ provider, id: randomUUID() })),
      factors: [],
    });
    return id;
  }

  function seedFactor(userId) {
    const factor = { id: randomUUID(), factor_type: 'totp', status: 'verified' };
    users.get(userId).factors.push(factor);
    return factor.id;
  }

  /** roles: { key: { selfAssignable, managesMembers, mfaRequired, permissions } } */
  function seedClient({ clientId, signupPolicy = 'open', roles = {} }) {
    clients.set(clientId, { clientId, signupPolicy, roles });
  }

  function grant(userId, clientId, roleKey, via = 'manager') {
    memberships.set(`${userId}|${clientId}|${roleKey}`, { userId, clientId, roleKey, grantedAt: new Date().toISOString(), grantedVia: via });
    events.push({ action: 'grant', userId, clientId, roleKey });
  }

  function revoke(userId, clientId, roleKey) {
    memberships.delete(`${userId}|${clientId}|${roleKey}`);
    events.push({ action: 'revoke', userId, clientId, roleKey });
  }

  function issueLink(email, type) {
    const user = findUser(email);
    const tokenHash = `pkce_${createHash('sha256').update(randomUUID()).digest('hex')}`;
    links.set(tokenHash, { type, userId: user.id, used: false });
    return tokenHash;
  }

  function latestLink(email, type) {
    const user = findUser(email);
    let latest = null;
    for (const [hash, link] of links) if (link.userId === user?.id && link.type === type && !link.used) latest = hash;
    return latest;
  }

  function fault(operation, mode) {
    faults.set(operation, mode);
  }

  // ---- OAuth provider round trip (browser navigation, outside fetch) --------

  /** Completes Google at the provider and returns the callback address Auth would redirect to. */
  function completeGoogle(authorizeUrl, { email = 'google.user@example.test', deny = false } = {}) {
    const url = new URL(authorizeUrl);
    if (url.origin !== ORIGIN || url.pathname !== '/auth/v1/authorize') throw new Error('not an authorize URL');
    const redirect = new URL(url.searchParams.get('redirect_to'));
    if (deny) {
      redirect.searchParams.set('error', 'access_denied');
      redirect.searchParams.set('error_description', 'The user denied access');
      return redirect.toString();
    }
    let user = findUser(email);
    if (!user) user = users.get(seedUser({ email, providers: ['google'] }));
    const code = randomUUID();
    codes.set(code, { userId: user.id, challenge: url.searchParams.get('code_challenge'), method: url.searchParams.get('code_challenge_method'), used: false });
    redirect.searchParams.set('code', code);
    return redirect.toString();
  }

  // ---- fetch ----------------------------------------------------------------

  async function fetchImpl(input, init = {}) {
    const url = new URL(typeof input === 'string' ? input : input.url);
    const method = (init.method ?? 'GET').toUpperCase();
    const body = init.body ? JSON.parse(init.body) : null;
    return runRoute(routeOf(method, url, body), url, method, init, body);
  }

  function routeOf(method, url, body) {
    const path = url.pathname;
    const grant = url.searchParams.get('grant_type');
    const table = [
      ['POST', '/auth/v1/signup', 'signup', signup],
      ['POST', '/auth/v1/token', grant === 'password' ? 'password_sign_in' : grant === 'pkce' ? 'oauth_exchange' : 'refresh', token],
      ['POST', '/auth/v1/verify', null, verify],
      ['POST', '/auth/v1/recover', 'recovery_request', recover],
      ['POST', '/auth/v1/resend', 'resend', resend],
      ['GET', '/auth/v1/user', 'get_user', getUser],
      ['PUT', '/auth/v1/user', 'update_password', updateUser],
      ['POST', '/auth/v1/logout', 'global_sign_out', logout],
      ['POST', '/auth/v1/factors', 'mfa_enroll', enroll],
      ['POST', '/rest/v1/rpc/ensure_profile', 'ensure_profile', ensureProfile],
      ['POST', '/rest/v1/rpc/effective_access', 'effective_access', effectiveAccess],
      ['POST', '/rest/v1/rpc/join_client', 'join_client', joinClient],
    ];
    for (const [m, p, operation, handler] of table) {
      if (m === method && p === path) {
        // verify is named by its link type so faults can target e-mail or recovery.
        if (p === '/auth/v1/verify') return { operation: body?.type === 'recovery' ? 'verify_recovery' : 'verify_email', handler };
        return { operation, handler };
      }
    }
    const factor = /^\/auth\/v1\/factors\/([^/]+)\/(challenge|verify)$/.exec(path);
    if (method === 'POST' && factor) {
      return factor[2] === 'challenge'
        ? { operation: 'mfa_challenge', handler: (req) => challenge(req, factor[1]) }
        : { operation: 'mfa_verify', handler: (req) => verifyFactor(req, factor[1]) };
    }
    return { operation: 'unknown', handler: () => json(404, { message: 'not found' }) };
  }

  async function runRoute(route, url, method, init, body) {
    const headers = new Headers(init.headers);
    requests.push({ operation: route.operation, method, path: url.pathname, bearer: bearerKind(headers) });
    if (headers.get('apikey') !== PUBLISHABLE_KEY) return json(401, { message: 'invalid apikey' });
    const mode = faults.get(route.operation);
    if (mode) faults.delete(route.operation);
    if (mode === 'transport_loss') throw new TypeError('fetch failed');
    if (mode === 'http_503') return json(503, { message: 'service unavailable' });
    if (mode === 'refused') return authError(400, 'refresh_token_not_found', 'Invalid Refresh Token');
    if (mode === 'malformed') return new Response('<html>gateway</html>', { status: 200, headers: { 'content-type': 'text/html' } });
    if (mode === 'hang') {
      return new Promise((_, reject) => {
        const fail = () => reject(new DOMException('aborted', 'AbortError'));
        if (init.signal?.aborted) fail();
        else init.signal?.addEventListener('abort', fail, { once: true });
      });
    }
    const response = route.handler({ url, headers, body });
    if (mode === 'lost_after_commit') throw new TypeError('fetch failed');
    return response;
  }

  // ---- Auth handlers --------------------------------------------------------

  function signup({ body }) {
    if (typeof body?.password !== 'string' || body.password.length < 6) {
      return authError(422, 'weak_password', 'Password should be at least 6 characters.', { weak_password: { reasons: ['length'] } });
    }
    const existing = findUser(body.email);
    if (existing) {
      // Auth's obfuscated answer for an existing address: a user-shaped body
      // with no identities and no session, and nothing written.
      return json(200, { id: randomUUID(), email: body.email, identities: [], aud: 'authenticated', role: 'authenticated' });
    }
    const id = seedUser({ email: body.email, password: body.password, confirmed: false });
    issueLink(body.email, 'email');
    return json(200, publicUser(users.get(id)));
  }

  function token({ url, body }) {
    const grant = url.searchParams.get('grant_type');
    if (grant === 'password') {
      const user = findUser(body?.email);
      if (!user || user.password !== body?.password) return authError(400, 'invalid_credentials', 'Invalid login credentials');
      if (!user.confirmedAt) return authError(400, 'email_not_confirmed', 'Email not confirmed');
      return json(200, newSession(user, 'aal1', ['password']));
    }
    if (grant === 'pkce') {
      const entry = codes.get(body?.auth_code);
      if (!entry || entry.used) return authError(404, 'flow_state_not_found', 'invalid flow state, no valid flow state found');
      entry.used = true;
      const challenge = createHash('sha256').update(body.code_verifier ?? '').digest('base64url');
      if (entry.method !== 's256' || challenge !== entry.challenge) return authError(400, 'bad_code_verifier', 'code challenge does not match previously saved code verifier');
      return json(200, newSession(users.get(entry.userId), 'aal1', ['oauth']));
    }
    if (grant === 'refresh_token') {
      const sessionId = refreshTokens.get(body?.refresh_token);
      const session = sessionId ? sessions.get(sessionId) : null;
      if (!session || session.revoked) return authError(400, 'refresh_token_not_found', 'Invalid Refresh Token');
      refreshTokens.delete(body.refresh_token);
      return json(200, sessionResponse(users.get(session.userId), session));
    }
    return authError(400, 'validation_failed', 'unsupported grant');
  }

  function verify({ body }) {
    const link = links.get(body?.token_hash);
    if (!link || link.used || link.type !== body?.type) return authError(403, 'otp_expired', 'Email link is invalid or has expired');
    link.used = true;
    const user = users.get(link.userId);
    if (!user.confirmedAt) user.confirmedAt = new Date().toISOString();
    return json(200, newSession(user, 'aal1', [link.type === 'recovery' ? 'recovery' : 'otp']));
  }

  function recover({ body }) {
    if (findUser(body?.email)) issueLink(body.email, 'recovery');
    return json(200, {});
  }

  function resend({ body }) {
    const user = findUser(body?.email);
    if (user && !user.confirmedAt) issueLink(body.email, 'email');
    return json(200, {});
  }

  function getUser({ headers }) {
    const found = liveSession(headers);
    if (found.error) return found.error;
    return json(200, publicUser(found.user));
  }

  function updateUser({ headers, body }) {
    const found = liveSession(headers);
    if (found.error) return found.error;
    if (found.user.factors.some((f) => f.status === 'verified') && found.claims.aal !== 'aal2') {
      return authError(403, 'insufficient_aal', 'AAL2 required to update password');
    }
    if (typeof body?.password !== 'string' || body.password.length < 6) {
      return authError(422, 'weak_password', 'Password should be at least 6 characters.', { weak_password: { reasons: ['length'] } });
    }
    if (body.password === found.user.password) return authError(422, 'same_password', 'New password should be different from the old password.');
    found.user.password = body.password;
    return json(200, publicUser(found.user));
  }

  function logout({ url, headers }) {
    const found = liveSession(headers);
    if (found.error) return found.error;
    const scope = url.searchParams.get('scope');
    for (const session of sessions.values()) {
      if (scope === 'global' ? session.userId === found.user.id : session.id === found.session.id) session.revoked = true;
    }
    return new Response(null, { status: 204 });
  }

  function enroll({ headers, body }) {
    const found = liveSession(headers);
    if (found.error) return found.error;
    if (body?.factor_type !== 'totp') return authError(422, 'validation_failed', 'unsupported factor');
    const factor = { id: randomUUID(), factor_type: 'totp', status: 'unverified' };
    found.user.factors.push(factor);
    return json(200, {
      id: factor.id,
      type: 'totp',
      totp: { qr_code: '<svg xmlns="http://www.w3.org/2000/svg"></svg>', secret: TOTP_SECRET, uri: `otpauth://totp/fixture:${found.user.email}?secret=${TOTP_SECRET}` },
    });
  }

  function challenge({ headers }, factorId) {
    const found = liveSession(headers);
    if (found.error) return found.error;
    if (!found.user.factors.some((f) => f.id === factorId)) return authError(404, 'mfa_factor_not_found', 'factor not found');
    const id = randomUUID();
    challenges.set(id, { factorId, used: false });
    return json(200, { id, type: 'totp', expires_at: Math.floor(Date.now() / 1000) + 300 });
  }

  function verifyFactor({ headers, body }, factorId) {
    const found = liveSession(headers);
    if (found.error) return found.error;
    const entry = challenges.get(body?.challenge_id);
    if (!entry || entry.used || entry.factorId !== factorId) return authError(422, 'mfa_challenge_expired', 'challenge expired');
    entry.used = true;
    if (body?.code !== TOTP_CODE) return authError(422, 'mfa_verification_failed', 'Invalid TOTP code entered');
    const factor = found.user.factors.find((f) => f.id === factorId);
    factor.status = 'verified';
    found.session.aal = verifyTokenAal ?? 'aal2';
    const response = sessionResponse(found.user, found.session);
    // A later refresh reflects the real level even if this answer lagged.
    found.session.aal = 'aal2';
    return json(200, response);
  }

  // ---- RPC handlers (auth_kit wrappers, per the integrated migration) -------

  function rpcCaller(headers) {
    if (headers.get('content-profile') !== 'auth_kit') return { error: json(404, { code: 'PGRST106', message: 'schema not exposed' }) };
    const claims = readToken(bearer(headers));
    // PostgREST checks the signature and expiry only, never Auth sessions.
    if (!claims || claims.exp * 1000 <= Date.now()) return { error: json(401, { code: 'PGRST301', message: 'JWT expired' }) };
    return { claims };
  }

  function ensureProfile({ headers }) {
    const caller = rpcCaller(headers);
    if (caller.error) return caller.error;
    const userId = caller.claims.sub;
    if (!profiles.has(userId)) profiles.set(userId, { user_id: userId, display_name: null, contact_email: null, contact_phone: null, updated_at: new Date().toISOString() });
    return json(200, profiles.get(userId));
  }

  function effectiveAccess({ headers, body }) {
    const caller = rpcCaller(headers);
    if (caller.error) return caller.error;
    if (typeof body?.client_id !== 'string') return refusal('invalid_argument');
    return json(200, accessOf(caller.claims.sub, body.client_id, caller.claims.aal));
  }

  function joinClient({ headers, body }) {
    const caller = rpcCaller(headers);
    if (caller.error) return caller.error;
    const clientId = body?.client_id;
    if (typeof clientId !== 'string') return refusal('invalid_argument');
    const userId = caller.claims.sub;
    const user = users.get(userId);
    if (!user?.confirmedAt) return json(200, { result: 'email_unverified' });
    const client = clients.get(clientId);
    if (!client) return json(200, { result: 'unknown_client' });
    const enrollment = enrollments.get(`${userId}|${clientId}`);
    if (enrollment) return json(200, { result: 'already_enrolled', enrolled_at: enrollment.enrolledAt });
    if (client.signupPolicy === 'closed') return json(200, { result: 'closed' });
    const selfAssignable = Object.keys(client.roles).filter((key) => client.roles[key].selfAssignable).sort();
    if (selfAssignable.length === 0) return json(200, { result: 'no_default_role' });
    const granted = selfAssignable.filter((key) => !memberships.has(`${userId}|${clientId}|${key}`));
    const enrolledAt = new Date().toISOString();
    enrollments.set(`${userId}|${clientId}`, { enrolledAt, grantedRoles: granted });
    for (const key of granted) {
      memberships.set(`${userId}|${clientId}|${key}`, { userId, clientId, roleKey: key, grantedAt: enrolledAt, grantedVia: 'join' });
      events.push({ action: 'join', userId, clientId, roleKey: key });
    }
    return json(200, { result: 'enrolled', enrolled_at: enrolledAt, granted_roles: granted });
  }

  function accessOf(userId, clientId, aal) {
    const client = clients.get(clientId);
    const rows = [...memberships.values()]
      .filter((m) => m.userId === userId && m.clientId === clientId && client?.roles[m.roleKey])
      .sort((a, b) => (a.roleKey < b.roleKey ? -1 : a.roleKey > b.roleKey ? 1 : 0))
      .map((m) => {
        const role = client.roles[m.roleKey];
        return {
          row: {
            role_key: m.roleKey,
            flags: { self_assignable: !!role.selfAssignable, manages_members: !!role.managesMembers, mfa_required: !!role.mfaRequired },
            granted_at: m.grantedAt,
            granted_via: m.grantedVia,
            permissions: [...(role.permissions ?? [])].sort(),
          },
          active: !role.mfaRequired || aal === 'aal2',
        };
      });
    const enrollment = enrollments.get(`${userId}|${clientId}`);
    return {
      client_id: clientId,
      enrolled_at: enrollment ? enrollment.enrolledAt : null,
      memberships: rows.map((r) => r.row),
      active_roles: rows.filter((r) => r.active).map((r) => r.row.role_key),
      permissions: [...new Set(rows.filter((r) => r.active).flatMap((r) => r.row.permissions))].sort(),
      mfa_pending: rows.some((r) => !r.active),
    };
  }

  // ---- helpers --------------------------------------------------------------

  function newSession(user, aal, amr) {
    const session = { id: randomUUID(), userId: user.id, aal, amr, revoked: false };
    sessions.set(session.id, session);
    return sessionResponse(user, session);
  }

  function sessionResponse(user, session) {
    const now = Math.floor(Date.now() / 1000);
    const refresh = randomUUID();
    refreshTokens.set(refresh, session.id);
    const claims = { sub: user.id, session_id: session.id, aal: session.aal, iat: now, exp: now + accessTtlSeconds, role: 'authenticated', aud: 'authenticated', amr: session.amr.map((method) => ({ method, timestamp: now })) };
    return {
      access_token: makeToken(claims),
      token_type: 'bearer',
      expires_in: accessTtlSeconds,
      expires_at: now + accessTtlSeconds,
      refresh_token: refresh,
      user: publicUser(user),
    };
  }

  function liveSession(headers) {
    const claims = readToken(bearer(headers));
    if (!claims) return { error: authError(401, 'bad_jwt', 'invalid JWT') };
    const session = sessions.get(claims.session_id);
    if (!session || session.revoked) return { error: authError(403, 'session_not_found', 'Session from session_id claim in JWT does not exist') };
    return { claims, session, user: users.get(session.userId) };
  }

  function findUser(email) {
    for (const user of users.values()) if (user.email === email) return user;
    return null;
  }

  function publicUser(user) {
    return {
      id: user.id,
      aud: 'authenticated',
      role: 'authenticated',
      email: user.email,
      email_confirmed_at: user.confirmedAt,
      identities: user.identities.map((identity) => ({ id: identity.id, provider: identity.provider })),
      factors: user.factors.map((f) => ({ id: f.id, factor_type: f.factor_type, status: f.status })),
      app_metadata: {},
      user_metadata: {},
    };
  }

  function snapshot() {
    return {
      users: users.size,
      profiles: profiles.size,
      enrollments: enrollments.size,
      memberships: [...memberships.values()].map((m) => `${m.clientId}:${m.roleKey}:${m.grantedVia}`).sort(),
      joinEvents: events.filter((e) => e.action === 'join').length,
      liveSessions: [...sessions.values()].filter((s) => !s.revoked).length,
    };
  }

  function count(operation) {
    return requests.filter((r) => r.operation === operation).length;
  }

  return {
    fetch: fetchImpl,
    requests,
    seedUser,
    seedFactor,
    seedClient,
    grant,
    revoke,
    issueLink,
    latestLink,
    fault,
    completeGoogle,
    snapshot,
    count,
    userIdOf: (email) => findUser(email)?.id ?? null,
    setVerifyTokenAal: (aal) => { verifyTokenAal = aal; },
    setAccessTtl: (seconds) => { accessTtlSeconds = seconds; },
    operations: () => requests.map((r) => r.operation),
  };
}

export function makeToken(claims) {
  const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'ES256', typ: 'JWT', kid: 'fixture' })}.${encode(claims)}.c3ludGhldGlj`;
}

function readToken(token) {
  if (typeof token !== 'string') return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  try {
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

function bearer(headers) {
  const value = headers.get('authorization') ?? '';
  return value.startsWith('Bearer ') ? value.slice(7) : null;
}

function bearerKind(headers) {
  const token = bearer(headers);
  if (token === null) return 'none';
  return token === PUBLISHABLE_KEY ? 'apikey' : 'user';
}

function json(status, body) {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

function authError(status, code, message, extra = {}) {
  return json(status, { code, error_code: code, msg: message, ...extra });
}

function refusal(code) {
  return json(400, { code: 'DW001', message: code, details: null, hint: null });
}
