// Local rehearsal target for the hosted procedures: the server lane's
// synthetic Supabase stand-in (tests/server/support/fake-supabase.js) with
// its PostgREST RPC and Management API answers bridged into the real
// migration on the SQL harness's throwaway PostgreSQL, plus the few Auth and
// PostgREST routes the hosted procedures use that the stand-in lacks (admin
// user creation and deletion, bans, user TOTP factors, table reads and
// inserts under RLS). It is a harness self-test fixture: it exercises the
// procedures' plumbing, requests and assertions end to end. It is not an
// emulator of Supabase and nothing it answers is hosted evidence; the
// rehearsal runs with hosted provenance off, so no case can pass.

import { randomBytes, randomUUID } from 'node:crypto';
import { jwtVerify, createLocalJWKSet } from 'jose';
import { createFakeSupabase, jsonResponse, PUBLISHABLE_KEY, SECRET_KEY, MANAGEMENT_TOKEN, PROJECT_REF } from '../../../server/support/fake-supabase.js';
import { pgRpc, pgManagement } from '../../../server/support/pg-bridge.js';
import { lit, PgError } from '../../../sql/harness/db.js';
import { totp } from '../../lib/totp.js';

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const COLUMN = /^[a-z_]{1,40}$/;
const TABLES = { auth_kit: new Set(['profiles', 'public_clients']), app: new Set(['notes']) };

function base32(bytes) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return bits > 0 ? out + BASE32[(value << (5 - bits)) & 31] : out;
}

export async function createRehearsal(db, { policiesSql }) {
  const fake = await createFakeSupabase();
  await fake.listen();
  fake.rpc = pgRpc(db);
  fake.management = pgManagement(db);
  fake.postgrestSchemas = 'public, graphql_public, auth_kit, app';
  fake.authConfig = {
    ...fake.authConfig, mfa_totp_enroll_enabled: true, mfa_totp_verify_enabled: true, mailer_autoconfirm: false, jwt_exp: 1800,
    external_google_enabled: false, smtp_host: '', smtp_admin_email: '',
  };
  let offset = 0;
  fake.now = () => Date.now() + offset;
  const clock = { now: () => Date.now() + offset, sleep: async (ms) => { offset += Math.max(0, ms); } };
  const postgres = await db.connection('postgres');
  await postgres.query(policiesSql);

  async function actorFor(request) {
    const apikey = request.headers.get('apikey');
    const auth = request.headers.get('authorization');
    const bearer = auth?.startsWith('Bearer ') ? auth.slice(7) : null;
    if (apikey === SECRET_KEY && (bearer === null || bearer === SECRET_KEY)) return { role: 'service_role', claims: { role: 'service_role' } };
    if (apikey === PUBLISHABLE_KEY && bearer === null) return { role: 'anon', claims: { role: 'anon' } };
    if (apikey === PUBLISHABLE_KEY && bearer !== null) {
      try {
        const { payload } = await jwtVerify(bearer, createLocalJWKSet(fake.jwks()), { issuer: `${fake.origin}/auth/v1`, audience: 'authenticated', currentDate: new Date(fake.now()) });
        return { role: payload.role, claims: payload, userId: payload.sub };
      } catch {
        return null;
      }
    }
    return undefined;
  }

  function pgFailure(error, actor) {
    if (!(error instanceof PgError)) throw error;
    const body = { code: error.code, message: error.message, details: null, hint: null };
    if (error.code === '42501') return jsonResponse(actor.role === 'anon' ? 401 : 403, body);
    return jsonResponse(error.code === 'DW001' || /^(22|23|P0)/.test(error.code) ? 400 : 500, body);
  }

  function where(params) {
    const parts = [];
    for (const [key, value] of params) {
      if (['select', 'limit', 'order'].includes(key)) continue;
      if (!COLUMN.test(key)) throw new Error('bad column');
      const eq = /^eq\.(.*)$/.exec(value);
      const inList = /^in\.\((.*)\)$/.exec(value);
      if (eq) parts.push(`${key} = ${lit(eq[1])}`);
      else if (inList) parts.push(`${key}::text in (${inList[1].split(',').map((v) => lit(v)).join(', ')})`);
      else throw new Error('unsupported filter');
    }
    return parts.length === 0 ? 'true' : parts.join(' and ');
  }

  async function table(request, url, match, body) {
    const profile = request.method === 'GET' ? request.headers.get('accept-profile') : request.headers.get('content-profile');
    if (!Object.hasOwn(TABLES, profile ?? '')) return jsonResponse(406, { code: 'PGRST106', message: 'Invalid schema', details: null, hint: null });
    if (!TABLES[profile].has(match[1])) return jsonResponse(404, { code: 'PGRST205', message: 'not found', details: null, hint: null });
    const actor = await actorFor(request);
    if (actor === null) return jsonResponse(401, { code: 'PGRST301', message: 'JWT expired or invalid', details: null, hint: null });
    if (actor === undefined) return jsonResponse(401, { message: 'No API key found in request' });
    const relation = `${profile}.${match[1]}`;
    let sql;
    if (request.method === 'GET') {
      const columns = (url.searchParams.get('select') ?? '*').split(',').map((c) => c.trim());
      if (!columns.every((c) => c === '*' || COLUMN.test(c))) return jsonResponse(400, { code: 'PGRST100' });
      const limit = url.searchParams.get('limit');
      const order = url.searchParams.get('order');
      sql = `select coalesce(jsonb_agg(to_jsonb(t)), '[]'::jsonb) from (select ${columns.join(', ')} from ${relation} where ${where(url.searchParams)}
        ${order && COLUMN.test(order) ? `order by ${order}` : ''} ${limit && /^\d+$/.test(limit) ? `limit ${limit}` : ''}) t`;
    } else {
      if (relation !== 'app.notes') return jsonResponse(405, { code: 'PGRST105' });
      sql = `with ins as (insert into app.notes (title, body) values (${lit(String(body?.title ?? ''))}, ${lit(String(body?.body ?? ''))}) returning id, owner_id, title)
        select coalesce(jsonb_agg(to_jsonb(ins)), '[]'::jsonb) from ins`;
    }
    try {
      return jsonResponse(request.method === 'GET' ? 200 : 201, await db.as(actor, sql));
    } catch (error) {
      return pgFailure(error, actor);
    }
  }

  async function userOf(request) {
    const actor = await actorFor(request);
    return actor && actor.userId ? { actor, user: fake.users.get(actor.userId) } : null;
  }

  const routes = [
    ['POST', /^\/auth\/v1\/admin\/users$/, async ({ body }) => {
      const email = String(body?.email ?? '').toLowerCase();
      if ([...fake.users.values()].some((u) => !u.deleted && u.email === email)) return jsonResponse(422, { code: 422, error_code: 'email_exists', msg: 'exists' });
      const confirmed = body?.email_confirm === true;
      const id = fake.addUser({ email, confirmed });
      fake.users.get(id).password = body?.password;
      await db.createUser({ id, email, confirmed });
      return jsonResponse(200, { id, email });
    }],
    ['DELETE', /^\/auth\/v1\/admin\/users\/([0-9a-f-]{36})$/, async ({ match }) => {
      const user = fake.users.get(match[1]);
      if (!user || user.deleted) return jsonResponse(404, { code: 404, error_code: 'user_not_found' });
      user.deleted = true;
      return jsonResponse(200, {});
    }],
    ['PUT', /^\/auth\/v1\/admin\/users\/([0-9a-f-]{36})$/, async ({ match, body }) => {
      const user = fake.users.get(match[1]);
      if (!user || user.deleted) return jsonResponse(404, { code: 404, error_code: 'user_not_found' });
      if (body?.ban_duration) user.bannedUntil = new Date(Date.now() + 24 * 3600_000).toISOString();
      return jsonResponse(200, { id: user.id });
    }],
    ['PUT', /^\/auth\/v1\/user$/, async ({ request }) => ((await userOf(request)) ? jsonResponse(200, {}) : jsonResponse(401, { error_code: 'bad_jwt' }))],
    ['POST', /^\/auth\/v1\/factors$/, async ({ request }) => {
      const who = await userOf(request);
      if (!who) return jsonResponse(401, { error_code: 'bad_jwt' });
      const id = randomUUID();
      const secret = base32(randomBytes(20));
      who.user.factors.set(id, { id, factor_type: 'totp', status: 'unverified', secret });
      return jsonResponse(200, { id, type: 'totp', totp: { secret, uri: `otpauth://totp/rehearsal?secret=${secret}`, qr_code: `data:image/svg+xml;${secret}` } });
    }],
    ['POST', /^\/auth\/v1\/factors\/([0-9a-f-]{36})\/challenge$/, async ({ request }) => ((await userOf(request)) ? jsonResponse(200, { id: randomUUID(), expires_at: 0 }) : jsonResponse(401, {}))],
    ['POST', /^\/auth\/v1\/factors\/([0-9a-f-]{36})\/verify$/, async ({ request, match, body }) => {
      const who = await userOf(request);
      const factor = who?.user.factors.get(match[1]);
      if (!factor) return jsonResponse(404, { error_code: 'mfa_factor_not_found' });
      const now = Date.now() / 1000;
      if (![now - 30, now, now + 30].some((t) => totp(factor.secret, t) === body?.code)) return jsonResponse(422, { error_code: 'mfa_verification_failed' });
      factor.status = 'verified';
      const { token } = await fake.signIn(who.user.id, { aal: 'aal2' });
      return jsonResponse(200, { access_token: token, token_type: 'bearer', refresh_token: 'fixture-refresh-aal2' });
    }],
    ['DELETE', /^\/auth\/v1\/factors\/([0-9a-f-]{36})$/, async ({ request, match }) => {
      const who = await userOf(request);
      if (!who || who.actor.claims.aal !== 'aal2') return jsonResponse(403, { error_code: 'insufficient_aal' });
      who.user.factors.delete(match[1]);
      return jsonResponse(200, { id: match[1] });
    }],
    // The stand-in's RPC route admits [a-z_] names only; has_aal2 is routed here the same way.
    ['POST', /^\/rest\/v1\/rpc\/(has_aal2)$/, async ({ request, match, body }) => {
      if ((request.headers.get('content-profile') ?? 'public') !== 'auth_kit') return jsonResponse(406, { code: 'PGRST106', message: 'Invalid schema' });
      const actor = await actorFor(request);
      if (actor === null) return jsonResponse(401, { code: 'PGRST301', message: 'JWT invalid' });
      if (actor === undefined) return jsonResponse(401, { code: 'PGRST301', message: 'No API key' });
      return fake.rpc({ fn: match[1], args: body ?? {}, actor });
    }],
    ['GET', /^\/rest\/v1\/([a-z_]+)$/, (c) => table(c.request, c.url, c.match)],
    ['POST', /^\/rest\/v1\/(?!rpc\/)([a-z_]+)$/, (c) => table(c.request, c.url, c.match, c.body)],
  ];

  /** In-process fetch: the extra routes first, then the stand-in. */
  async function fetch(input, init = {}) {
    const { signal, ...rest } = init;
    const request = new Request(input, rest);
    const url = new URL(request.url);
    for (const [method, pattern, handler] of routes) {
      const match = pattern.exec(url.pathname);
      if (!match || method !== request.method) continue;
      const text = request.method === 'GET' || request.method === 'DELETE' ? '' : await request.clone().text();
      let body;
      try {
        body = text === '' ? undefined : JSON.parse(text);
      } catch {
        body = undefined;
      }
      return handler({ request, url, match, body });
    }
    return fake.fetch(input, init);
  }

  return {
    fake, fetch, clock,
    creds: { SUPABASE_URL: fake.origin, SUPABASE_PUBLISHABLE_KEY: PUBLISHABLE_KEY, SUPABASE_SECRET_KEY: SECRET_KEY, SUPABASE_ACCESS_TOKEN: MANAGEMENT_TOKEN },
    target: { url: fake.origin, ref: PROJECT_REF },
    cliEnv: { SUPABASE_MANAGEMENT_API_URL: fake.origin, SUPABASE_PROJECT_REF: PROJECT_REF },
    close: () => fake.close(),
  };
}
