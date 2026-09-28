// Development-only, loopback-only fixture of the Supabase Auth subset and the
// `auth_kit` PostgREST RPCs that the dwarpal browser kit calls through
// @supabase/supabase-js 2.117.2. Synthetic: its answers are fixture evidence,
// never proof of hosted Supabase behaviour. It never makes an outbound request,
// sends mail or calls a real identity or TOTP provider, and it exposes no
// control endpoint over HTTP: tests drive it through `controls` in process.

import http from 'node:http';
import { createSigner, randomToken } from './lib/crypto.js';
import { BodyError, MAX_URL_CHARS, hostAllowed, isLoopbackOrigin, isLoopbackUrl, preflight, readBody, send } from './lib/http.js';
import { countRequest, createControls, createState, takeFault } from './lib/store.js';
import * as auth from './lib/auth.js';
import { EXPOSED_SCHEMAS, OPERATOR_FUNCTIONS, USER_FUNCTIONS, callFunction, notFound, readArgs, resolveRole } from './lib/rpc.js';

const OPTION_NAMES = ['host', 'port', 'now', 'accessTokenTtlSeconds', 'linkTtlSeconds', 'siteUrl', 'log'];
const HOSTS = new Set(['127.0.0.1', '::1']);
const API_VERSION = { 'x-supabase-api-version': '2024-01-01' };

// Auth routes: [method, path, name, handler, fault operation or null, needs apikey].
const AUTH_ROUTES = [
  ['GET', '/.well-known/jwks.json', 'jwks', auth.jwks, null, false],
  ['GET', '/settings', 'settings', auth.settings, null, true],
  ['POST', '/signup', 'signup', auth.signup, 'signup', true],
  ['POST', '/resend', 'resend', auth.resend, null, true],
  ['POST', '/recover', 'recovery_request', auth.recover, 'recovery_request', true],
  ['POST', '/verify', 'verify', auth.verify, auth.verifyOperation, true],
  ['GET', '/authorize', 'authorize', auth.authorize, null, false],
  ['GET', '/user', 'get_user', auth.getUser, null, true],
  ['PUT', '/user', 'update_password', auth.updateUser, 'update_password', true],
  ['POST', '/logout', 'global_sign_out', auth.logout, 'global_sign_out', true],
  ['POST', '/factors', 'mfa_enroll', auth.enroll, 'mfa_enroll', true],
];
const TOKEN_GRANTS = {
  password: ['password_sign_in', auth.passwordSignIn, 'password_sign_in'],
  pkce: ['oauth_exchange', auth.exchangeCode, 'oauth_exchange'],
  refresh_token: ['refresh', auth.refresh, null],
};
const FACTOR_ROUTE = /^\/factors\/([0-9a-f-]{36})\/(challenge|verify)$/;

function fail(message) {
  throw new TypeError(`startAuthEmulator: ${message}`);
}

function readOptions(options) {
  if (options === null || typeof options !== 'object' || Array.isArray(options)) fail('options must be an object.');
  for (const key of Object.keys(options)) if (!OPTION_NAMES.includes(key)) fail('unknown option.');
  const host = options.host ?? '127.0.0.1';
  if (!HOSTS.has(host)) fail("host must be the loopback address '127.0.0.1' or '::1'.");
  const port = options.port ?? 0;
  if (!Number.isInteger(port) || port < 0 || port > 65535) fail('port must be an integer from 0 to 65535.');
  const now = options.now ?? Date.now();
  if (typeof now !== 'number' || !Number.isFinite(now) || now < 0) fail('now must be a finite nonnegative epoch time in milliseconds.');
  const accessTokenTtlSeconds = options.accessTokenTtlSeconds ?? 3600;
  if (!Number.isInteger(accessTokenTtlSeconds) || accessTokenTtlSeconds < 60 || accessTokenTtlSeconds > 86_400) {
    fail('accessTokenTtlSeconds must be an integer from 60 to 86400.');
  }
  const linkTtlSeconds = options.linkTtlSeconds ?? 3600;
  if (!Number.isInteger(linkTtlSeconds) || linkTtlSeconds < 1 || linkTtlSeconds > 86_400) fail('linkTtlSeconds must be an integer from 1 to 86400.');
  if (options.siteUrl !== undefined && !isLoopbackUrl(options.siteUrl)) fail('siteUrl must be a loopback http(s) URL.');
  if (options.log !== undefined && typeof options.log !== 'function') fail('log must be a function.');
  return { host, port, now, accessTokenTtlSeconds, linkTtlSeconds, siteUrl: options.siteUrl, log: options.log };
}

/**
 * Starts one fixture instance on an ephemeral loopback port.
 * @param {import('./index.js').AuthEmulatorOptions} [options]
 */
export async function startAuthEmulator(options = {}) {
  const config = readOptions(options);
  const state = createState(config);
  const signer = createSigner();
  const publishableKey = `sb_publishable_fixture_${randomToken(18)}`;
  const sockets = new Set();
  const server = http.createServer({ maxHeaderSize: 16 * 1024, requestTimeout: 15_000, headersTimeout: 10_000, keepAliveTimeout: 2_000 });
  server.maxConnections = 256;
  server.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });

  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen({ host: config.host, port: config.port, exclusive: true }, () => {
      server.off('error', reject);
      resolve();
    });
  });
  const { port } = server.address();
  const origin = config.host === '::1' ? `http://[::1]:${port}` : `http://127.0.0.1:${port}`;
  const siteUrl = config.siteUrl ?? `${origin}/`;
  const log = (entry) => {
    if (!config.log) return;
    try {
      config.log(Object.freeze(entry));
    } catch {
      // A failing logger never changes an answer.
    }
  };

  server.on('request', (request, response) => {
    handle({ request, response, state, signer, publishableKey, origin, siteUrl, port, log }).catch(() => {
      if (!response.headersSent && !response.destroyed) send(request, response, 500, { message: 'fixture internal error' });
    });
  });

  let closing = null;
  const close = () => {
    closing ??= new Promise((resolve) => {
      server.close(() => resolve());
      server.closeAllConnections();
      for (const socket of sockets) socket.destroy();
    });
    return closing;
  };

  return Object.freeze({ origin, publishableKey, controls: createControls(state), close });
}

async function handle(ctx) {
  const { request, response } = ctx;
  const method = request.method;
  let routeName = 'unrouted';
  const finish = (status, body, headers) => {
    send(request, response, status, body, headers);
    ctx.log({ method, route: routeName, status });
  };
  if (!hostAllowed(request.headers.host, ctx.port)) return finish(421, { message: 'fixture: a loopback Host header is required' });
  if (request.url.length > MAX_URL_CHARS) return finish(414, { message: 'fixture: the request URL is too long' });
  if (request.headers.origin !== undefined && !isLoopbackOrigin(request.headers.origin)) {
    return finish(403, { message: 'fixture: only loopback pages may call the development fixture' });
  }
  if (method === 'OPTIONS') {
    preflight(request, response);
    ctx.log({ method, route: 'preflight', status: response.statusCode });
    return undefined;
  }
  const url = new URL(request.url, ctx.origin);
  const route = matchRoute(method, url);
  if (!route) return finish(404, { message: 'fixture: route not emulated' });
  routeName = route.name;

  const gate = gateway(ctx, route);
  if (gate) return finish(gate.status, gate.body, route.kind === 'auth' ? API_VERSION : {});

  let body = null;
  if (method !== 'GET') {
    try {
      body = await readBody(request);
    } catch (error) {
      if (!(error instanceof BodyError)) throw error;
      return finish(error.status, { message: `fixture: ${error.code.replaceAll('_', ' ')}` }, { connection: 'close' });
    }
  }
  if (route.kind === 'auth') {
    if (body === null) body = {};
    if (typeof body !== 'object' || Array.isArray(body)) return finish(400, { code: 'validation_failed', message: 'The request body must be a JSON object' }, API_VERSION);
  }

  const operation = typeof route.operation === 'function' ? route.operation(body) : route.operation;
  countRequest(ctx.state, operation ?? route.name);
  const fault = operation ? takeFault(ctx.state, operation) : null;
  const logFault = (status) => ctx.log({ method, route: routeName, operation, status, fault });
  if (fault === 'http_503') {
    send(request, response, 503, { message: 'fixture: service unavailable (injected)' }, route.kind === 'auth' ? API_VERSION : {});
    return logFault(503);
  }
  if (fault === 'transport_loss') {
    request.socket.destroy();
    return logFault(0);
  }
  if (fault === 'failed_before_commit') {
    const failure = route.kind === 'auth'
      ? { code: 'unexpected_failure', message: 'fixture: injected failure before commit' }
      : { code: 'XX000', details: null, hint: null, message: 'fixture: injected failure before commit' };
    send(request, response, 500, failure, route.kind === 'auth' ? API_VERSION : {});
    return logFault(500);
  }

  const handlerCtx = { ...ctx, url, body: body ?? {}, params: route.params ?? {} };
  const result = route.kind === 'auth' ? route.handler(handlerCtx) : await rpc(handlerCtx, route.fn, method, url, body);
  if (fault === 'lost_after_commit') {
    // The work above is kept; only the answer is lost.
    request.socket.destroy();
    return logFault(0);
  }
  if (result.location) {
    response.writeHead(result.status, { location: result.location, 'cache-control': 'no-store', 'content-length': '0' });
    response.end();
  } else {
    send(request, response, result.status, result.body, route.kind === 'auth' ? API_VERSION : {});
  }
  ctx.log({ method, route: routeName, operation: operation ?? undefined, status: result.status });
  return undefined;
}

function matchRoute(method, url) {
  const path = url.pathname;
  if (path.startsWith('/auth/v1/')) {
    const rest = path.slice('/auth/v1'.length);
    if (rest === '/token' && method === 'POST') {
      const grant = TOKEN_GRANTS[url.searchParams.get('grant_type')];
      if (!grant) return null;
      const [name, handler, operation] = grant;
      return { kind: 'auth', name, handler, operation, apikey: true };
    }
    const factor = FACTOR_ROUTE.exec(rest);
    if (factor && method === 'POST') {
      const verify = factor[2] === 'verify';
      return {
        kind: 'auth', name: verify ? 'mfa_verify' : 'mfa_challenge', handler: verify ? auth.verifyFactor : auth.challenge,
        operation: verify ? 'mfa_verify' : null, apikey: true, params: { factorId: factor[1] },
      };
    }
    const found = AUTH_ROUTES.find(([m, p]) => m === method && p === rest);
    if (!found) return null;
    const [, , name, handler, operation, apikey] = found;
    return { kind: 'auth', name, handler, operation, apikey };
  }
  const rpcMatch = /^\/rest\/v1\/rpc\/([a-z_]{1,64})$/.exec(path);
  if (rpcMatch && (method === 'POST' || method === 'GET')) {
    const fn = rpcMatch[1];
    const known = Object.hasOwn(USER_FUNCTIONS, fn);
    return { kind: 'rpc', fn, name: known ? `rpc_${fn}` : 'rpc_other', operation: known ? fn : null, apikey: true };
  }
  return null;
}

/** The API gateway: an apikey that is this fixture's publishable key, and never an operator credential. */
function gateway(ctx, route) {
  const { headers } = ctx.request;
  const apikey = headers.apikey;
  const bearer = typeof headers.authorization === 'string' ? headers.authorization.replace(/^Bearer\s+/i, '') : '';
  if (isOperatorCredential(apikey) || isOperatorCredential(bearer)) {
    return { status: 401, body: { message: 'fixture: operator credentials are refused by the development fixture' } };
  }
  if (!route.apikey) return null;
  if (apikey === undefined) return { status: 401, body: { message: 'No API key found in request' } };
  if (apikey !== ctx.publishableKey) return { status: 401, body: { message: 'Invalid API key' } };
  return null;
}

function isOperatorCredential(value) {
  if (typeof value !== 'string') return false;
  if (value.startsWith('sb_secret_') || value.startsWith('sbp_')) return true;
  const parts = value.split('.');
  if (parts.length !== 3) return false;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    return payload !== null && typeof payload === 'object' && payload.role !== undefined
      && payload.role !== 'authenticated' && payload.role !== 'anon';
  } catch {
    return false;
  }
}

async function rpc(ctx, fn, method, url, body) {
  const profileHeader = method === 'GET' ? ctx.request.headers['accept-profile'] : ctx.request.headers['content-profile'];
  const profile = profileHeader ?? 'public';
  if (!EXPOSED_SCHEMAS.includes(profile)) {
    return { status: 406, body: { code: 'PGRST106', details: null, hint: `Only the following schemas are exposed: ${EXPOSED_SCHEMAS.join(', ')}`, message: 'Invalid schema' } };
  }
  const role = resolveRole(ctx);
  if (role.error) return role.error;
  if (profile !== 'auth_kit') return notFound(fn);
  if (OPERATOR_FUNCTIONS.has(fn)) {
    return { status: role.role === 'anon' ? 401 : 403, body: { code: '42501', details: null, hint: null, message: `permission denied for function ${fn}` } };
  }
  if (!Object.hasOwn(USER_FUNCTIONS, fn)) return notFound(fn);
  if (method === 'GET' && !USER_FUNCTIONS[fn].stable) {
    return { status: 405, body: { code: 'PGRST101', details: null, hint: null, message: 'Cannot use the GET method on RPC for a volatile function' } };
  }
  const input = method === 'GET' ? Object.fromEntries(url.searchParams) : body ?? {};
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    return { status: 400, body: { code: 'PGRST102', details: null, hint: null, message: 'The request body must be a JSON object' } };
  }
  const parsed = readArgs(fn, input);
  if (parsed.error) return parsed.error;
  if (role.role === 'anon') {
    return { status: 401, body: { code: '42501', details: null, hint: null, message: `permission denied for function ${fn}` } };
  }
  return callFunction(ctx, fn, role, parsed.args);
}
