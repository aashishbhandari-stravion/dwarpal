// Clients for the hosted target, every one built on the gated fetch. Answers
// are reduced to the fields a case asserts on before they leave this module;
// a raw response body never reaches evidence. Credentials and every token a
// response carries are registered with the redactor the moment they appear.

import http from 'node:http';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { request, tryParseJson, TransportError } from '../../../packages/server/lib/http.js';
import { createAuthServer, isAuthError } from '../../../packages/server/index.js';
import { createOperatorClient } from '../../../packages/server/operator.js';
import { PUBLIC_ROOT } from './paths.js';
import { Blocked } from './status.js';
import { MANAGEMENT_ORIGIN } from './target.js';
import { parseProbe, probeStatement } from './sqlprobe.js';

const MAX_BYTES = 8 * 1024 * 1024;
// The admin users collection; single users and their factors are paths below it.
const ADMIN_USERS = '/auth/v1/admin/users';
const TIMEOUT_MS = 20_000;
export const CLI = path.join(PUBLIC_ROOT, 'packages', 'server', 'cli', 'auth-kit.js');

/** JWT claims without verification (the harness reads its own tokens' exp and aal). */
export function claimsOf(token) {
  try {
    return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

export class HostedError extends Error {
  constructor(stage, status, code = null) {
    super(`${stage}: unexpected answer ${status}${code ? ` ${code}` : ''}`);
    this.name = 'HostedError';
    this.stage = stage;
    this.status = status;
    this.code = code;
  }
}

/**
 * @param {{ gate: ReturnType<import('./net.js').createGate>, target: { url: string, ref: string },
 *           creds: Record<string, string>, redactor: import('./redact.js').Redactor,
 *           limits?: { signInsPerFiveMinutes?: number }, sleep?: (ms: number) => Promise<void>, clockNow?: () => number,
 *           managementOrigin?: string, cliEnv?: Record<string, string> }} deps (the last two exist for the local rehearsal)
 */
export function createHosted({ gate, target, creds, redactor, limits = {}, sleep = (ms) => new Promise((r) => setTimeout(r, ms)), clockNow = Date.now,
  managementOrigin = MANAGEMENT_ORIGIN, cliEnv = {} }) {
  const origin = target.url;
  const pub = creds.SUPABASE_PUBLISHABLE_KEY;
  const sec = creds.SUPABASE_SECRET_KEY;
  const pat = creds.SUPABASE_ACCESS_TOKEN ?? null;
  redactor.secret(sec, 'secret_key');
  redactor.secret(pub, 'publishable_key');
  if (pat) redactor.secret(pat, 'management_token');
  const fetch = gate.fetch;
  const signInBudget = limits.signInsPerFiveMinutes ?? 25;
  const signIns = [];

  async function call(url, { method = 'GET', headers = {}, body, timeoutMs = TIMEOUT_MS } = {}) {
    let response;
    try {
      response = await request(fetch, url, {
        method,
        headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers },
        body: body === undefined ? undefined : JSON.stringify(body),
        timeoutMs,
        maxBytes: MAX_BYTES,
      });
    } catch (error) {
      if (error instanceof TransportError) return { status: 0, reason: error.reason, json: undefined, headers: new Headers() };
      throw error;
    }
    return { status: response.status, json: tryParseJson(response.text), headers: response.headers, text: response.text };
  }

  function registerSession(json) {
    if (json && typeof json === 'object') {
      redactor.secret(json.access_token, 'access_token');
      if (typeof json.refresh_token === 'string' && json.refresh_token.length >= 6) redactor.secret(json.refresh_token, 'refresh_token');
    }
  }

  // Sign-ins are throttled to the configured budget; a 429 waits (bounded)
  // and is blocked, never failed, when the budget is exhausted.
  async function throttle() {
    const windowMs = 5 * 60_000;
    for (;;) {
      const now = Date.now();
      while (signIns.length > 0 && now - signIns[0] > windowMs) signIns.shift();
      if (signIns.length < signInBudget) break;
      await sleep(windowMs - (now - signIns[0]) + 1_000);
    }
    signIns.push(Date.now());
  }

  async function withRateLimit(stage, fn) {
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const res = await fn();
      if (res.status !== 429) return res;
      const retry = Number(res.headers.get('retry-after'));
      await sleep(Number.isFinite(retry) && retry > 0 && retry <= 600 ? retry * 1000 : 60_000);
    }
    throw new Blocked('rate_limited', { stage });
  }

  const userHeaders = (token) => ({ apikey: pub, ...(token ? { Authorization: `Bearer ${token}` } : {}) });
  const adminHeaders = { apikey: sec, Authorization: `Bearer ${sec}` };

  const auth = {
    /** Takes one sign-in from the shared budget for a sign-in the harness's browser makes. */
    reserveSignIn: throttle,
    async jwks() {
      return call(`${origin}/auth/v1/.well-known/jwks.json`);
    },
    async signIn(email, password) {
      await throttle();
      const res = await withRateLimit('sign_in', () => call(`${origin}/auth/v1/token?grant_type=password`, { method: 'POST', headers: userHeaders(null), body: { email, password } }));
      if (res.status !== 200 || typeof res.json?.access_token !== 'string') throw new HostedError('sign_in', res.status, res.json?.error_code ?? null);
      registerSession(res.json);
      return session(res.json);
    },
    async logout(token, scope = 'global') {
      return (await call(`${origin}/auth/v1/logout?scope=${scope}`, { method: 'POST', headers: userHeaders(token) })).status;
    },
    async user(token) {
      const res = await call(`${origin}/auth/v1/user`, { headers: userHeaders(token) });
      return { status: res.status, errorCode: res.json?.error_code ?? null, user: res.status === 200 ? res.json : null };
    },
    async updateUserMetadata(token, data) {
      return (await call(`${origin}/auth/v1/user`, { method: 'PUT', headers: userHeaders(token), body: { data } })).status;
    },
    async signUp(email, password, redirectTo) {
      const url = `${origin}/auth/v1/signup${redirectTo ? `?redirect_to=${encodeURIComponent(redirectTo)}` : ''}`;
      const res = await withRateLimit('sign_up', () => call(url, { method: 'POST', headers: userHeaders(null), body: { email, password } }));
      return { status: res.status, userId: res.json?.id ?? res.json?.user?.id ?? null, session: typeof res.json?.access_token === 'string' };
    },
    async verifyTokenHash(type, tokenHash) {
      redactor.secret(tokenHash, 'token_hash');
      const res = await call(`${origin}/auth/v1/verify`, { method: 'POST', headers: userHeaders(null), body: { type, token_hash: tokenHash } });
      if (res.status === 200) registerSession(res.json);
      return { status: res.status, errorCode: res.json?.error_code ?? null, session: res.status === 200 && typeof res.json?.access_token === 'string' ? session(res.json) : null };
    },
    async exchangePkce(authCode, verifier) {
      redactor.secret(authCode, 'auth_code');
      const res = await call(`${origin}/auth/v1/token?grant_type=pkce`, { method: 'POST', headers: userHeaders(null), body: { auth_code: authCode, code_verifier: verifier } });
      if (res.status === 200) registerSession(res.json);
      return { status: res.status, session: res.status === 200 ? session(res.json) : null };
    },
    authorizeUrl(provider, redirectTo, challenge) {
      return `${origin}/auth/v1/authorize?provider=${provider}&redirect_to=${encodeURIComponent(redirectTo)}&code_challenge=${challenge}&code_challenge_method=s256`;
    },
    async enrollTotp(token, friendlyName) {
      const res = await call(`${origin}/auth/v1/factors`, { method: 'POST', headers: userHeaders(token), body: { factor_type: 'totp', friendly_name: friendlyName } });
      if (res.status !== 200 || typeof res.json?.totp?.secret !== 'string') throw new HostedError('factor_enroll', res.status, res.json?.error_code ?? null);
      redactor.secret(res.json.totp.secret, 'totp_secret');
      if (typeof res.json.totp.uri === 'string') redactor.secret(res.json.totp.uri, 'totp_uri');
      if (typeof res.json.totp.qr_code === 'string') redactor.secret(res.json.totp.qr_code, 'totp_qr');
      return { id: res.json.id, secret: res.json.totp.secret };
    },
    async challengeAndVerify(token, factorId, code) {
      const ch = await call(`${origin}/auth/v1/factors/${factorId}/challenge`, { method: 'POST', headers: userHeaders(token), body: {} });
      if (ch.status !== 200 || typeof ch.json?.id !== 'string') throw new HostedError('factor_challenge', ch.status, ch.json?.error_code ?? null);
      const res = await call(`${origin}/auth/v1/factors/${factorId}/verify`, { method: 'POST', headers: userHeaders(token), body: { challenge_id: ch.json.id, code } });
      if (res.status !== 200 || typeof res.json?.access_token !== 'string') throw new HostedError('factor_verify', res.status, res.json?.error_code ?? null);
      registerSession(res.json);
      return session(res.json);
    },
    async unenroll(token, factorId) {
      return (await call(`${origin}/auth/v1/factors/${factorId}`, { method: 'DELETE', headers: userHeaders(token) })).status;
    },
  };

  const admin = {
    async createUser(email, password, { confirm = true } = {}) {
      const res = await call(`${origin}${ADMIN_USERS}`, { method: 'POST', headers: adminHeaders, body: { email, password, email_confirm: confirm } });
      if (res.status !== 200 && res.status !== 201) throw new HostedError('create_user', res.status, res.json?.error_code ?? null);
      return { id: String(res.json.id).toLowerCase() };
    },
    /**
     * A verification link's token hash, generated for the harness itself:
     * Auth sends no mail for it. `signup` creates an unconfirmed user.
     */
    async generateLink(type, email, password) {
      const res = await call(`${origin}/auth/v1/admin/generate_link`, { method: 'POST', headers: adminHeaders, body: { type, email, ...(password ? { password } : {}) } });
      const body = res.json ?? {};
      const tokenHash = body.hashed_token ?? body.properties?.hashed_token;
      for (const secret of [tokenHash, body.email_otp ?? body.properties?.email_otp, body.action_link ?? body.properties?.action_link]) {
        if (typeof secret === 'string' && secret.length >= 6) redactor.secret(secret, 'link');
      }
      const id = body.id ?? body.user?.id;
      if (res.status !== 200 || typeof tokenHash !== 'string' || typeof id !== 'string') throw new HostedError('generate_link', res.status, body.error_code ?? null);
      return { tokenHash, userId: id.toLowerCase() };
    },
    async deleteUser(id) {
      const res = await call(`${origin}${ADMIN_USERS}/${id}`, { method: 'DELETE', headers: adminHeaders });
      return { status: res.status, errorCode: res.json?.error_code ?? null };
    },
    async update(id, body) {
      return (await call(`${origin}${ADMIN_USERS}/${id}`, { method: 'PUT', headers: adminHeaders, body })).status;
    },
    async getUser(id) {
      const res = await call(`${origin}${ADMIN_USERS}/${id}`, { headers: adminHeaders });
      return { status: res.status, user: res.status === 200 ? res.json : null };
    },
    async listPage(page, perPage) {
      const res = await call(`${origin}${ADMIN_USERS}?page=${page}&per_page=${perPage}`, { headers: adminHeaders });
      if (res.status !== 200 || !Array.isArray(res.json?.users)) throw new HostedError('list_users', res.status);
      return res.json.users.map((u) => ({ id: String(u.id).toLowerCase(), email: typeof u.email === 'string' ? u.email : null }));
    },
    async factors(id) {
      const res = await call(`${origin}${ADMIN_USERS}/${id}/factors`, { headers: adminHeaders });
      if (res.status !== 200 || !Array.isArray(res.json)) throw new HostedError('list_factors', res.status);
      return res.json.map((f) => ({ id: String(f.id).toLowerCase(), type: f.factor_type, status: f.status }));
    },
  };

  const rest = {
    async rpc(token, fn, args, { profile = 'auth_kit', apikey = pub } = {}) {
      const res = await call(`${origin}/rest/v1/rpc/${fn}`, {
        method: 'POST',
        headers: { apikey, ...(token ? { Authorization: `Bearer ${token}` } : {}), 'Content-Profile': profile, 'Accept-Profile': profile },
        body: args,
      });
      return restOutcome(res);
    },
    async select(token, schema, table, query = 'select=*', { apikey = pub } = {}) {
      const res = await call(`${origin}/rest/v1/${table}?${query}`, {
        headers: { apikey, ...(token ? { Authorization: `Bearer ${token}` } : {}), 'Accept-Profile': schema },
      });
      return restOutcome(res);
    },
    async insert(token, schema, table, row) {
      const res = await call(`${origin}/rest/v1/${table}`, {
        method: 'POST',
        headers: { apikey: pub, Authorization: `Bearer ${token}`, 'Content-Profile': schema, 'Accept-Profile': schema, Prefer: 'return=representation' },
        body: row,
      });
      return restOutcome(res);
    },
  };

  const management = {
    available: pat !== null,
    base: `${managementOrigin}/v1/projects/${target.ref}`,
    async raw(sql) {
      if (!pat) throw new Blocked('management_token_missing');
      return call(`${this.base}/database/query`, { method: 'POST', headers: { Authorization: `Bearer ${pat}` }, body: { query: sql }, timeoutMs: 60_000 });
    },
    /** One statement whose single row has a `result` column of JSON text. */
    async read(sql) {
      const res = await this.raw(sql);
      if ((res.status !== 200 && res.status !== 201) || !Array.isArray(res.json) || res.json.length !== 1 || typeof res.json[0]?.result !== 'string') {
        throw new HostedError('management_read', res.status);
      }
      return JSON.parse(res.json[0].result);
    },
    /** A statement run for its effect; the answer status only. */
    async exec(sql) {
      const res = await this.raw(sql);
      if (res.status !== 200 && res.status !== 201) throw new HostedError('management_exec', res.status);
    },
    async probe(calls) {
      const res = await this.raw(probeStatement(calls));
      const message = typeof res.json?.message === 'string' ? res.json.message : typeof res.text === 'string' ? res.text : '';
      const outcomes = res.status >= 400 ? parseProbe(message) : null;
      if (outcomes === null || outcomes.length !== calls.length) throw new HostedError('management_probe', res.status, 'no_probe_marker');
      return outcomes;
    },
    async postgrestConfig() {
      const res = await call(`${this.base}/postgrest`, { headers: { Authorization: `Bearer ${pat}` } });
      if (res.status !== 200 || typeof res.json?.db_schema !== 'string') throw new HostedError('postgrest_config', res.status);
      return { schemas: res.json.db_schema.split(',').map((s) => s.trim()).filter(Boolean) };
    },
    /** Selected, non-secret Auth settings; the rest of the answer is dropped here. */
    async authSettings() {
      const res = await call(`${this.base}/config/auth`, { headers: { Authorization: `Bearer ${pat}` } });
      if (res.status !== 200 || res.json === null || typeof res.json !== 'object') throw new HostedError('auth_config', res.status);
      const c = res.json;
      const sender = typeof c.smtp_admin_email === 'string' ? c.smtp_admin_email.split('@')[1] ?? null : null;
      return {
        totpEnroll: c.mfa_totp_enroll_enabled === true,
        totpVerify: c.mfa_totp_verify_enabled === true,
        emailConfirmationRequired: c.mailer_autoconfirm === false,
        jwtExpSeconds: Number.isInteger(c.jwt_exp) ? c.jwt_exp : null,
        googleEnabled: c.external_google_enabled === true,
        customSmtp: typeof c.smtp_host === 'string' && c.smtp_host !== '',
        senderDomain: sender,
        allowList: typeof c.uri_allow_list === 'string' ? c.uri_allow_list.split(',').map((e) => e.trim()).filter(Boolean) : [],
      };
    },
  };

  function operator(fetchImpl = fetch, { management: withManagement = true } = {}) {
    return createOperatorClient({
      supabaseUrl: origin,
      secretKey: sec,
      publishableKey: pub,
      management: withManagement && pat ? { token: pat, projectRef: target.ref, url: managementOrigin } : null,
      fetch: fetchImpl,
    });
  }

  /**
   * The Node path: createAuthServer behind a loopback HTTP endpoint that maps
   * errors like the example consumer. Without `handle` it answers with the
   * resolved principal; with it, `handle(principal, url)` is the consumer's
   * own route (for example the L26 order guard) and returns { status, body }.
   */
  async function nodeEndpoint(clientId, { fetch: fetchImpl = fetch, now = clockNow, handle = null } = {}) {
    const server = createAuthServer({ supabaseUrl: origin, publishableKey: pub, clientId, fetch: fetchImpl, now });
    const STATUS = { no_token: 401, invalid_token: 401, expired: 401, email_unverified: 403, mfa_required: 403, forbidden: 403, request_conflict: 409, unavailable: 503 };
    const httpServer = http.createServer(async (req, res) => {
      let status = 200;
      let body;
      try {
        const principal = await server.resolveSession(req);
        if (handle) ({ status, body } = await handle(principal, new URL(req.url ?? '/', 'http://localhost')));
        else body = principal === null ? { principal: null } : { principal };
      } catch (error) {
        status = isAuthError(error) && Object.hasOwn(STATUS, error.code) ? STATUS[error.code] : 500;
        body = { error: isAuthError(error) ? error.code : 'internal' };
      }
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    });
    await new Promise((resolve) => httpServer.listen(0, '127.0.0.1', resolve));
    // An endpoint a failed procedure never closed must not keep the run alive.
    httpServer.unref();
    const url = `http://127.0.0.1:${httpServer.address().port}/`;
    return {
      server,
      // The harness's own loopback endpoint, not target traffic: reached directly, not through the gate.
      async get(token, pathname = '/') {
        const res = await request(globalThis.fetch, new URL(pathname, url).href, { headers: token ? { Authorization: `Bearer ${token}` } : {}, timeoutMs: TIMEOUT_MS, maxBytes: MAX_BYTES });
        return { status: res.status, body: tryParseJson(res.text) };
      },
      close: () => new Promise((resolve) => httpServer.close(resolve)),
    };
  }

  /** Runs the real auth-kit CLI with credentials in its environment only. */
  function cli(args, { management: withManagement = true, extraEnv = {}, cwd = PUBLIC_ROOT } = {}) {
    const env = { PATH: process.env.PATH, HOME: process.env.HOME, SUPABASE_URL: origin, SUPABASE_SECRET_KEY: sec, SUPABASE_PUBLISHABLE_KEY: pub, ...cliEnv, ...extraEnv };
    if (withManagement && pat) env.SUPABASE_ACCESS_TOKEN = pat;
    return new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [CLI, ...args], { env, cwd, stdio: ['ignore', 'pipe', 'pipe'] });
      let stdout = '';
      let stderr = '';
      child.stdout.on('data', (c) => { stdout += c; });
      child.stderr.on('data', (c) => { stderr += c; });
      const timer = setTimeout(() => child.kill('SIGKILL'), 300_000);
      child.on('error', reject);
      child.on('close', (code) => {
        clearTimeout(timer);
        resolve({ code, json: tryParseJson(stdout.trim()), stdout, stderr });
      });
    });
  }

  return { origin, auth, admin, rest, management, operator, nodeEndpoint, cli };
}

function session(json) {
  const claims = claimsOf(json.access_token);
  return { accessToken: json.access_token, claims, userId: typeof claims?.sub === 'string' ? claims.sub.toLowerCase() : null };
}

/** PostgREST answer: value, kit refusal (DW001) or failure with a fixed tag. */
export function restOutcome(res) {
  if (res.status >= 200 && res.status < 300) return { kind: 'value', status: res.status, value: res.json };
  const body = res.json;
  if (body && typeof body === 'object' && body.code === 'DW001' && typeof body.message === 'string') {
    return { kind: 'refusal', status: res.status, code: body.message };
  }
  const code = body && typeof body === 'object' && typeof body.code === 'string' ? body.code : null;
  return { kind: 'failure', status: res.status, code, reason: res.reason ?? null };
}

/** PKCE verifier and S256 challenge. */
export function pkcePair() {
  const verifier = randomBytes(48).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}
