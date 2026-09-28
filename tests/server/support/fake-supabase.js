// Synthetic stand-in for the Supabase endpoints the server library and the
// operator CLI call: Auth (JWKS, /user, token grant, logout, admin users,
// invite, factors), PostgREST RPC into `auth_kit`, and the Management API.
// It is a test fixture, not an emulator and not hosted proof: it answers the
// way the kit expects Supabase to answer, and every request is logged so
// tests can assert which calls were (and were not) made.
//
// It serves through an injected `fetch` (in-process) or over loopback HTTP
// (`listen()`, for the CLI child process). RPC and Management API answers
// come from pluggable handlers: scripted in unit tests, or the real
// migration on PostgreSQL (pg-bridge.js). `hooks` replace any route's answer
// for fault injection.

import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { generateKeyPair, exportJWK, SignJWT, jwtVerify, createLocalJWKSet } from 'jose';

export const PUBLISHABLE_KEY = 'sb_publishable_fixture_PUBLISHABLEMARKER';
export const SECRET_KEY = 'sb_secret_fixture_SECRETMARKER_5f2c9d';
export const MANAGEMENT_TOKEN = 'sbp_fixture_MANAGEMENTMARKER_91ab77';
export const PROJECT_REF = 'fixtureref';

function json(status, body, headers = {}) {
  return new Response(body === undefined ? null : JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
}

export async function newSigningKey(alg = 'ES256') {
  const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true });
  const kid = randomUUID();
  const jwk = { ...(await exportJWK(publicKey)), kid, alg, use: 'sig' };
  return { kid, alg, privateKey, jwk };
}

export async function createFakeSupabase({ origin = 'http://127.0.0.1:54321', alg = 'ES256' } = {}) {
  const fake = {
    origin,
    keys: [await newSigningKey(alg)],
    users: new Map(),
    sessions: new Map(),
    calls: [],
    hooks: new Map(),
    rpc: async () => json(404, { code: 'PGRST202', message: 'no rpc handler' }),
    management: async () => json(404, { message: 'no management handler' }),
    postgrestSchemas: 'public, graphql_public, auth_kit',
    authConfig: { site_url: 'https://www.example.test', uri_allow_list: '', smtp_pass: 'SMTPSECRETMARKER', external_google_secret: 'GOOGLESECRETMARKER' },
    server: null,
    // Auth's own clock and leeway when it checks a token (GET /user, PostgREST).
    now: () => Date.now(),
    authLeewaySeconds: 0,
  };

  fake.addUser = ({ id = randomUUID(), email = `user-${id.slice(0, 8)}@example.test`, confirmed = true, anonymous = false, providers = ['email'], bannedUntil = null } = {}) => {
    fake.users.set(id, {
      id, email, confirmed, anonymous, bannedUntil, deleted: false,
      identities: providers.map((provider) => ({ provider, id: randomUUID() })),
      factors: new Map(),
    });
    return id;
  };

  fake.addFactor = (userId, { id = randomUUID(), type = 'totp', status = 'verified' } = {}) => {
    fake.users.get(userId).factors.set(id, { id, factor_type: type, status });
    return id;
  };

  /** Signs an access token; `claims` override or delete (undefined) any default claim. */
  fake.token = async ({ userId, sessionId = randomUUID(), aal = 'aal1', iat, exp, claims = {}, key = fake.keys[0], header = {} } = {}) => {
    const now = Math.floor(Date.now() / 1000);
    const base = {
      iss: `${fake.origin}/auth/v1`, aud: 'authenticated', sub: userId, role: 'authenticated', aal,
      session_id: sessionId, is_anonymous: false, iat: iat ?? now, exp: exp ?? now + 1800, email: fake.users.get(userId)?.email,
    };
    const payload = { ...base, ...claims };
    for (const [name, value] of Object.entries(claims)) if (value === undefined) delete payload[name];
    return new SignJWT(payload).setProtectedHeader({ alg: key.alg, kid: key.kid, typ: 'JWT', ...header }).sign(key.privateKey);
  };

  fake.signIn = async (userId, { aal = 'aal1', ...rest } = {}) => {
    const sessionId = randomUUID();
    fake.sessions.set(sessionId, { userId, revoked: false });
    return { sessionId, token: await fake.token({ userId, sessionId, aal, ...rest }) };
  };

  fake.jwks = () => ({ keys: fake.keys.map((k) => k.jwk) });

  async function verifyUserToken(token) {
    try {
      const { payload } = await jwtVerify(token, createLocalJWKSet(fake.jwks()), {
        issuer: `${fake.origin}/auth/v1`, audience: 'authenticated', currentDate: new Date(fake.now()), clockTolerance: fake.authLeewaySeconds,
      });
      return payload;
    } catch {
      return null;
    }
  }

  function credential(request) {
    const apikey = request.headers.get('apikey');
    const auth = request.headers.get('authorization');
    const bearer = auth?.startsWith('Bearer ') ? auth.slice(7) : null;
    if (apikey === SECRET_KEY && (bearer === null || bearer === SECRET_KEY)) return { kind: 'secret' };
    if (bearer === MANAGEMENT_TOKEN) return { kind: 'management' };
    if (apikey === PUBLISHABLE_KEY && (bearer === null || bearer === PUBLISHABLE_KEY)) return { kind: 'anon' };
    if (apikey === PUBLISHABLE_KEY && bearer !== null) return { kind: 'user', token: bearer };
    return { kind: 'none' };
  }

  function userJson(user) {
    return {
      id: user.id, aud: 'authenticated', role: 'authenticated', email: user.email,
      email_confirmed_at: user.confirmed ? '2026-01-01T00:00:00Z' : null, is_anonymous: user.anonymous,
      banned_until: user.bannedUntil, identities: user.identities,
      app_metadata: { providers: ['google'], roles: ['owner'] }, user_metadata: { role: 'owner' },
    };
  }

  const routes = [
    ['jwks', 'GET', /^\/auth\/v1\/\.well-known\/jwks\.json$/, async () => json(200, fake.jwks())],
    ['user', 'GET', /^\/auth\/v1\/user$/, async ({ cred }) => {
      if (cred.kind !== 'user') return json(401, { code: 401, error_code: 'no_authorization', msg: 'no token' });
      const claims = await verifyUserToken(cred.token);
      if (!claims) return json(403, { code: 403, error_code: 'bad_jwt', msg: 'invalid JWT' });
      const session = fake.sessions.get(claims.session_id);
      if (!session || session.revoked) return json(403, { code: 403, error_code: 'session_not_found', msg: 'Session from session_id claim in JWT does not exist' });
      const user = fake.users.get(claims.sub);
      if (!user || user.deleted) return json(404, { code: 404, error_code: 'user_not_found', msg: 'User not found' });
      if (user.bannedUntil && Date.parse(user.bannedUntil) > Date.now()) return json(403, { code: 403, error_code: 'user_banned', msg: 'User is banned' });
      return json(200, userJson(user));
    }],
    ['token', 'POST', /^\/auth\/v1\/token$/, async ({ body, cred }) => {
      if (cred.kind !== 'anon') return json(401, { error_code: 'no_authorization' });
      const user = [...fake.users.values()].find((u) => u.email === body?.email && u.password === body?.password);
      if (!user) return json(400, { code: 400, error_code: 'invalid_credentials', msg: 'Invalid login credentials' });
      const { token } = await fake.signIn(user.id);
      return json(200, { access_token: token, token_type: 'bearer', expires_in: 1800, refresh_token: 'fixture-refresh' });
    }],
    ['logout', 'POST', /^\/auth\/v1\/logout$/, async ({ cred }) => {
      const claims = cred.kind === 'user' ? await verifyUserToken(cred.token) : null;
      if (!claims) return json(401, { error_code: 'bad_jwt' });
      const session = fake.sessions.get(claims.session_id);
      if (session) session.revoked = true;
      return new Response(null, { status: 204 });
    }],
    ['admin_get_user', 'GET', /^\/auth\/v1\/admin\/users\/([0-9a-f-]{36})$/, async ({ match }) => {
      const user = fake.users.get(match[1]);
      if (!user || user.deleted) return json(404, { code: 404, error_code: 'user_not_found', msg: 'User not found' });
      return json(200, userJson(user));
    }],
    ['admin_list_users', 'GET', /^\/auth\/v1\/admin\/users$/, async ({ url }) => {
      const page = Number(url.searchParams.get('page'));
      const perPage = Number(url.searchParams.get('per_page'));
      const all = [...fake.users.values()].filter((u) => !u.deleted);
      const slice = all.slice((page - 1) * perPage, page * perPage);
      const last = Math.max(1, Math.ceil(all.length / perPage));
      const links = [];
      if (page < last) links.push(`</admin/users?page=${page + 1}&per_page=${perPage}>; rel="next"`);
      links.push(`</admin/users?page=${last}&per_page=${perPage}>; rel="last"`);
      return json(200, { users: slice.map(userJson), aud: 'authenticated' }, { 'x-total-count': String(all.length), link: links.join(', ') });
    }],
    ['invite', 'POST', /^\/auth\/v1\/invite$/, async ({ body }) => {
      const id = fake.addUser({ email: body.email, confirmed: false });
      return json(200, userJson(fake.users.get(id)));
    }],
    ['list_factors', 'GET', /^\/auth\/v1\/admin\/users\/([0-9a-f-]{36})\/factors$/, async ({ match }) => {
      const user = fake.users.get(match[1]);
      if (!user || user.deleted) return json(404, { code: 404, error_code: 'user_not_found', msg: 'User not found' });
      return json(200, [...user.factors.values()]);
    }],
    ['delete_factor', 'DELETE', /^\/auth\/v1\/admin\/users\/([0-9a-f-]{36})\/factors\/([0-9a-f-]{36})$/, async ({ match }) => {
      const user = fake.users.get(match[1]);
      if (!user || user.deleted) return json(404, { code: 404, error_code: 'user_not_found', msg: 'User not found' });
      const factor = user.factors.get(match[2]);
      if (!factor) return json(404, { code: 404, error_code: 'mfa_factor_not_found', msg: 'Factor not found' });
      user.factors.delete(match[2]);
      return json(200, factor);
    }],
    ['rpc', 'POST', /^\/rest\/v1\/rpc\/([a-z_]+)$/, async ({ request, match, body, cred }) => {
      const profile = request.headers.get('content-profile') ?? 'public';
      if (profile !== 'auth_kit') return json(406, { code: 'PGRST106', message: 'Invalid schema', details: null, hint: 'Only the following schemas are exposed: public, graphql_public, auth_kit' });
      let actor;
      if (cred.kind === 'secret') actor = { role: 'service_role', claims: { role: 'service_role', iss: 'supabase' } };
      else if (cred.kind === 'anon') actor = { role: 'anon', claims: { role: 'anon', iss: 'supabase' } };
      else if (cred.kind === 'user') {
        const claims = await verifyUserToken(cred.token);
        if (!claims) return json(401, { code: 'PGRST301', message: 'JWT invalid' });
        actor = { role: claims.role, claims };
      } else return json(401, { code: 'PGRST301', message: 'No API key' });
      return fake.rpc({ fn: match[1], args: body ?? {}, actor });
    }],
    ['mgmt_query', 'POST', /^\/v1\/projects\/([a-z0-9]+)\/database\/query$/, async ({ body, cred, match }) => {
      if (cred.kind !== 'management' || match[1] !== PROJECT_REF) return json(401, { message: 'Unauthorized' });
      return fake.management(body?.query);
    }],
    ['mgmt_postgrest', 'GET', /^\/v1\/projects\/([a-z0-9]+)\/postgrest$/, async ({ cred }) => {
      if (cred.kind !== 'management') return json(401, { message: 'Unauthorized' });
      return json(200, { db_schema: fake.postgrestSchemas, max_rows: 1000, db_extra_search_path: 'public' });
    }],
    ['mgmt_auth_config', 'GET', /^\/v1\/projects\/([a-z0-9]+)\/config\/auth$/, async ({ cred }) => {
      if (cred.kind !== 'management') return json(401, { message: 'Unauthorized' });
      return json(200, fake.authConfig);
    }],
  ];

  fake.handle = async (request) => {
    const url = new URL(request.url);
    const text = request.method === 'GET' || request.method === 'DELETE' ? '' : await request.text();
    let body;
    try {
      body = text === '' ? undefined : JSON.parse(text);
    } catch {
      body = undefined;
    }
    const cred = credential(request);
    for (const [name, method, pattern, handler] of routes) {
      const match = pattern.exec(url.pathname);
      if (!match || method !== request.method) continue;
      const call = { route: name, method, path: url.pathname, search: url.search, credential: cred.kind, body, signal: request.signal };
      fake.calls.push(call);
      const context = { request, url, match, body, cred, call };
      const hook = fake.hooks.get(name);
      if (hook) {
        const hooked = await hook(context);
        if (hooked !== undefined) return hooked;
      }
      return handler(context);
    }
    fake.calls.push({ route: 'unknown', method: request.method, path: url.pathname });
    return json(404, { message: 'not found' });
  };

  /** In-process fetch; the caller's AbortSignal reaches hooks through call.signal. */
  fake.fetch = async (input, init = {}) => {
    const { signal, ...rest } = init;
    const request = new Request(input, rest);
    Object.defineProperty(request, 'signal', { value: signal ?? new AbortController().signal });
    return fake.handle(request);
  };

  fake.callsTo = (route) => fake.calls.filter((c) => c.route === route);
  fake.adminCalls = () => fake.calls.filter((c) => ['admin_get_user', 'admin_list_users', 'invite', 'list_factors', 'delete_factor'].includes(c.route));

  fake.listen = () => new Promise((resolve) => {
    fake.server = http.createServer(async (req, res) => {
      const chunks = [];
      for await (const chunk of req) chunks.push(chunk);
      const body = Buffer.concat(chunks);
      const request = new Request(`${fake.origin}${req.url}`, {
        method: req.method,
        headers: Object.entries(req.headers).flatMap(([k, v]) => (Array.isArray(v) ? v.map((x) => [k, x]) : [[k, v]])),
        body: body.length > 0 ? body : undefined,
      });
      let response;
      try {
        response = await fake.handle(request);
      } catch {
        // A hook that throws models a dropped connection.
        req.socket.destroy();
        return;
      }
      res.writeHead(response.status, Object.fromEntries(response.headers));
      res.end(Buffer.from(await response.arrayBuffer()));
    });
    fake.server.listen(0, '127.0.0.1', () => {
      fake.origin = `http://127.0.0.1:${fake.server.address().port}`;
      resolve(fake.origin);
    });
  });

  fake.close = () => new Promise((resolve) => (fake.server ? fake.server.close(() => resolve()) : resolve()));

  return fake;
}

export { json as jsonResponse };
