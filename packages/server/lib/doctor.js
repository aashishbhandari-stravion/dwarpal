// `doctor` (design 4.1, 9; L33). Each check reports `ok`, `fail` or
// `not_run` with a fixed reason; a check whose prerequisite is missing is
// `not_run`, never `ok`. Modes stay distinct in the report:
//
//   catalog  Management API SQL and project settings (schema version, grant
//            table, memberships without events, exposed schemas, redirects,
//            client registration) plus the secret-key model export
//   public   the project's published signing keys
//   probe    real anon and authenticated calls with a disposable user
//   host     the consumer's pages at --origin
//
// Output fields are check ids, statuses, counts, route names, catalog
// object names and UUID-free tags; never keys, tokens, e-mails or model
// values.

import { modelHash } from '../../core/index.js';
import { request, parseJson, TransportError } from './http.js';
import { callRpc } from './postgrest.js';
import { OperatorError, isOperatorError } from './operator-error.js';
import { jsonResult, textLiteral } from './management.js';
import { installedVersions } from './migrate.js';

const MAX_VIOLATIONS = 200;
const REDIRECT_ROUTES = ['callback', 'verify', 'reset'];
const PROBE_CLIENT = 'auth-kit-doctor-probe';

const CATALOG_SQL = `select jsonb_build_object(
  'violations', coalesce((select jsonb_agg(jsonb_build_object('object', v.object, 'grantee', v.grantee,
      'privilege', v.privilege, 'expected', v.expected, 'actual', v.actual) order by v.object, v.grantee, v.privilege)
    from auth_kit_private.grant_violations() v), '[]'::jsonb),
  'memberships_without_events', (select pg_catalog.count(*) from auth_kit_private.memberships m
    where not exists (select 1 from auth_kit_private.membership_events e
                       where e.user_id = m.user_id and e.client_id = m.client_id and e.role_key = m.role_key
                         and e.action in ('join', 'grant', 'bootstrap'))))::text as result`;

function clientSql(clientId) {
  return `select coalesce((select jsonb_build_object('state', c.state, 'signup_policy', c.signup_policy)
    from auth_kit_private.clients c where c.client_id = ${textLiteral(clientId)}), 'null'::jsonb)::text as result`;
}

function check(id, mode, status, details = {}) {
  return { id, mode, status, ...details };
}

function failureOf(error) {
  if (isOperatorError(error)) return { reason: error.code, ...(typeof error.details.reason === 'string' ? { cause: error.details.reason } : {}) };
  throw error;
}

/**
 * @param {{ management: object | null, exportModel: (clientId: string) => Promise<{ modelHash: string | null, lastAppliedHash: string | null }>, fetch: typeof fetch, timers: object,
 *           origin: string, timeoutMs: number, migrations: { version: string }[] | null, publishableKey?: string | null }} ctx
 * @param {{ clientId?: string | null, config?: object | null, model?: unknown, probe?: { email: string, password: string } | null, hostOrigin?: string | null }} options
 */
export async function runDoctor(ctx, options = {}) {
  const checks = [];
  await catalogChecks(ctx, options, checks);
  checks.push(await signingKeys(ctx));
  if (options.clientId !== undefined && options.clientId !== null) checks.push(await modelDrift(ctx, options));
  if (options.probe) checks.push(...await probeChecks(ctx, options));
  if (options.hostOrigin) checks.push(...await hostChecks(ctx, options));
  const counts = { ok: 0, fail: 0, not_run: 0 };
  for (const c of checks) counts[c.status] += 1;
  return {
    status: counts.fail > 0 ? 'fail' : counts.not_run > 0 ? 'incomplete' : 'ok',
    probeRan: Boolean(options.probe),
    counts,
    checks,
  };
}

async function catalogChecks(ctx, options, checks) {
  const ids = ['schema_version', 'grants', 'memberships_without_events', 'exposed_schemas'];
  if (options.config) ids.push('redirect_allow_list', 'client_registration');
  if (ctx.management === null) {
    for (const id of ids) checks.push(check(id, 'catalog', 'not_run', { reason: 'management_token_missing' }));
    return;
  }
  let installed;
  try {
    installed = await installedVersions(ctx.management);
  } catch (error) {
    for (const id of ids) checks.push(check(id, 'catalog', 'not_run', failureOf(error)));
    return;
  }
  if (installed === null) {
    checks.push(check('schema_version', 'catalog', 'fail', { reason: 'not_installed' }));
    for (const id of ids.slice(1)) {
      if (id === 'exposed_schemas' || id === 'redirect_allow_list') continue;
      checks.push(check(id, 'catalog', 'not_run', { reason: 'not_installed' }));
    }
  } else {
    checks.push(schemaVersion(installed, ctx.migrations));
    try {
      const catalog = jsonResult('catalog', await ctx.management.query(CATALOG_SQL, { stage: 'catalog' }));
      const violations = Array.isArray(catalog.violations) ? catalog.violations : null;
      if (violations === null) throw new OperatorError('unavailable', { stage: 'catalog', reason: 'malformed' });
      checks.push(check('grants', 'catalog', violations.length === 0 ? 'ok' : 'fail', {
        violationCount: violations.length,
        violations: violations.slice(0, MAX_VIOLATIONS).map((v) => ({
          object: String(v.object), grantee: String(v.grantee), privilege: String(v.privilege), expected: v.expected === true, actual: v.actual === true,
        })),
      }));
      const orphans = Number(catalog.memberships_without_events);
      checks.push(check('memberships_without_events', 'catalog', orphans === 0 ? 'ok' : 'fail', { count: orphans }));
    } catch (error) {
      checks.push(check('grants', 'catalog', 'not_run', failureOf(error)));
      checks.push(check('memberships_without_events', 'catalog', 'not_run', failureOf(error)));
    }
    if (options.config) checks.push(await clientRegistration(ctx, options.config));
  }
  checks.push(await exposedSchemas(ctx));
  if (options.config) checks.push(await redirectAllowList(ctx, options.config));
}

function schemaVersion(installed, migrations) {
  if (migrations === null) return check('schema_version', 'catalog', 'not_run', { reason: 'migration_files_missing', installed });
  const expected = migrations.map((m) => m.version);
  const missing = expected.filter((v) => !installed.includes(v));
  const unknown = installed.filter((v) => !expected.includes(v));
  return check('schema_version', 'catalog', missing.length === 0 && unknown.length === 0 ? 'ok' : 'fail', { installed, expected, missing, unknown });
}

async function exposedSchemas(ctx) {
  try {
    const schemas = await ctx.management.exposedSchemas();
    const kit = schemas.includes('auth_kit');
    const privateExposed = schemas.includes('auth_kit_private');
    return check('exposed_schemas', 'catalog', kit && !privateExposed ? 'ok' : 'fail', { authKitExposed: kit, privateSchemaExposed: privateExposed });
  } catch (error) {
    return check('exposed_schemas', 'catalog', 'not_run', failureOf(error));
  }
}

async function redirectAllowList(ctx, config) {
  try {
    const { allowList } = await ctx.management.redirectSettings();
    const missing = REDIRECT_ROUTES.filter((route) => !allowList.includes(`${config.origin}${config.routes[route]}`));
    const wildcards = allowList.filter((entry) => entry.includes('*')).length;
    return check('redirect_allow_list', 'catalog', missing.length === 0 ? 'ok' : 'fail', { missingRoutes: missing, wildcardEntries: wildcards });
  } catch (error) {
    return check('redirect_allow_list', 'catalog', 'not_run', failureOf(error));
  }
}

async function clientRegistration(ctx, config) {
  try {
    const row = jsonResult('client_registration', await ctx.management.query(clientSql(config.clientId), { stage: 'client_registration' }));
    if (row === null) return check('client_registration', 'catalog', 'fail', { reason: 'not_registered' });
    const policyMatches = (row.signup_policy === 'open') === config.selfSignup;
    const urlMatches = config.supabaseUrl === ctx.origin;
    return check('client_registration', 'catalog', policyMatches && urlMatches ? 'ok' : 'fail', {
      state: row.state === 'live' ? 'live' : 'registered', signupPolicyMatches: policyMatches, supabaseUrlMatches: urlMatches,
    });
  } catch (error) {
    return check('client_registration', 'catalog', 'not_run', failureOf(error));
  }
}

async function signingKeys(ctx) {
  let response;
  try {
    response = await request(ctx.fetch, `${ctx.origin}/auth/v1/.well-known/jwks.json`, { timeoutMs: ctx.timeoutMs, maxBytes: 64 * 1024, timers: ctx.timers });
  } catch (error) {
    if (!(error instanceof TransportError)) throw error;
    return check('signing_keys', 'public', 'not_run', { reason: 'unavailable', cause: error.reason });
  }
  if (response.status !== 200) return check('signing_keys', 'public', 'not_run', { reason: 'unavailable', cause: `http_${response.status}` });
  let keys;
  try {
    keys = parseJson(response.text).keys;
  } catch {
    return check('signing_keys', 'public', 'not_run', { reason: 'unavailable', cause: 'malformed' });
  }
  if (!Array.isArray(keys)) return check('signing_keys', 'public', 'not_run', { reason: 'unavailable', cause: 'malformed' });
  const asymmetric = keys.filter((k) => k && (k.kty === 'EC' || k.kty === 'RSA') && (k.alg === undefined || k.alg === 'ES256' || k.alg === 'RS256')).length;
  const symmetric = keys.filter((k) => k && k.kty === 'oct').length;
  return check('signing_keys', 'public', asymmetric > 0 && symmetric === 0 ? 'ok' : 'fail', { asymmetricKeys: asymmetric, symmetricKeys: symmetric });
}

async function modelDrift(ctx, options) {
  let exported;
  try {
    exported = await ctx.exportModel(options.clientId);
  } catch (error) {
    return check('model_drift', 'catalog', 'not_run', failureOf(error));
  }
  if (exported.modelHash === null) return check('model_drift', 'catalog', 'fail', { reason: 'no_model' });
  const appliedMatches = exported.modelHash === exported.lastAppliedHash;
  const details = { appliedMatchesDatabase: appliedMatches };
  let fileMatches = null;
  if (options.model !== undefined && options.model !== null) {
    try {
      fileMatches = (await modelHash(options.model)) === exported.modelHash;
    } catch {
      return check('model_drift', 'catalog', 'fail', { reason: 'model_invalid' });
    }
    details.fileMatchesDatabase = fileMatches;
  } else {
    details.fileCompared = false;
  }
  return check('model_drift', 'catalog', appliedMatches && fileMatches !== false ? 'ok' : 'fail', details);
}

// Disposable-user probe: every call is shaped so that it cannot write even if
// a grant were widened (operator wrappers get null arguments and would refuse
// with invalid_argument), and a refusal from an executed function is itself
// the evidence of the widening.
async function probeChecks(ctx, { probe, clientId }) {
  if (!ctx.publishableKey) return [check('probe', 'probe', 'not_run', { reason: 'publishable_key_missing' })];
  const signIn = await tokenGrant(ctx, probe);
  if (signIn.error) return [check('probe_sign_in', 'probe', signIn.error === 'refused' ? 'fail' : 'not_run', { reason: signIn.error })];
  const out = [check('probe_sign_in', 'probe', 'ok')];
  const user = signIn.token;
  const legacyAnon = ctx.publishableKey.split('.').length === 3;
  const rpc = (bearer, fn, args, profile = 'auth_kit') => callRpcWithProfile(ctx, bearer, fn, args, profile);
  const expectDenied = (outcome) => outcome.kind === 'failure' && outcome.reason === 'sqlstate_42501';
  const expectUnexposed = (outcome) => outcome.kind === 'failure' && outcome.reason === 'postgrest_106';

  const access = await rpc(user, 'effective_access', { client_id: clientId ?? PROBE_CLIENT });
  out.push(check('probe_authenticated_effective_access', 'probe', access.kind === 'value' ? 'ok' : 'fail', { observed: observed(access) }));
  const operatorCall = await rpc(user, 'register_client', { client_id: null, display_name: null, signup_policy: null });
  out.push(check('probe_authenticated_operator_wrapper', 'probe', expectDenied(operatorCall) ? 'ok' : 'fail', { observed: observed(operatorCall) }));
  const privateUser = await rpc(user, 'effective_access_impl', { p_client_id: PROBE_CLIENT }, 'auth_kit_private');
  out.push(check('probe_authenticated_private_schema', 'probe', expectUnexposed(privateUser) ? 'ok' : 'fail', { observed: observed(privateUser) }));

  const anonBearer = legacyAnon ? ctx.publishableKey : null;
  const anonAccess = await rpc(anonBearer, 'effective_access', { client_id: null });
  out.push(check('probe_anon_user_wrapper', 'probe', expectDenied(anonAccess) ? 'ok' : 'fail', { observed: observed(anonAccess) }));
  const anonHelper = await rpc(anonBearer, 'has_permission', { client_id: PROBE_CLIENT, permission_key: PROBE_CLIENT });
  out.push(check('probe_anon_helper', 'probe', anonHelper.kind === 'value' && anonHelper.value === false ? 'ok' : 'fail', { observed: observed(anonHelper) }));
  const privateAnon = await rpc(anonBearer, 'effective_access_impl', { p_client_id: PROBE_CLIENT }, 'auth_kit_private');
  out.push(check('probe_anon_private_schema', 'probe', expectUnexposed(privateAnon) ? 'ok' : 'fail', { observed: observed(privateAnon) }));

  out.push(await signOut(ctx, user));
  return out;
}

function observed(outcome) {
  if (outcome.kind === 'value') return 'value';
  if (outcome.kind === 'refusal') return `refusal_${outcome.code}`;
  return outcome.reason;
}

// The private schema is addressed only to prove it is unreachable.
function callRpcWithProfile(ctx, bearer, fn, args, profile) {
  return callRpc({ fetch: ctx.fetch, timers: ctx.timers, origin: ctx.origin, apikey: ctx.publishableKey, bearer, fn, args, timeoutMs: ctx.timeoutMs, profile });
}

async function tokenGrant(ctx, probe) {
  let response;
  try {
    response = await request(ctx.fetch, `${ctx.origin}/auth/v1/token?grant_type=password`, {
      method: 'POST',
      headers: { apikey: ctx.publishableKey, 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ email: probe.email, password: probe.password }),
      timeoutMs: ctx.timeoutMs,
      maxBytes: 256 * 1024,
      timers: ctx.timers,
    });
  } catch (error) {
    if (!(error instanceof TransportError)) throw error;
    return { error: 'unavailable' };
  }
  if (response.status === 400 || response.status === 401 || response.status === 403) return { error: 'refused' };
  if (response.status !== 200) return { error: 'unavailable' };
  try {
    const token = parseJson(response.text).access_token;
    return typeof token === 'string' && token !== '' ? { token } : { error: 'unavailable' };
  } catch {
    return { error: 'unavailable' };
  }
}

async function signOut(ctx, token) {
  try {
    const response = await request(ctx.fetch, `${ctx.origin}/auth/v1/logout`, {
      method: 'POST',
      headers: { apikey: ctx.publishableKey, Authorization: `Bearer ${token}` },
      timeoutMs: ctx.timeoutMs,
      maxBytes: 64 * 1024,
      timers: ctx.timers,
    });
    return check('probe_sign_out', 'probe', response.status === 204 || response.status === 200 ? 'ok' : 'fail', { observed: `http_${response.status}` });
  } catch (error) {
    if (!(error instanceof TransportError)) throw error;
    return check('probe_sign_out', 'probe', 'fail', { observed: error.reason });
  }
}

const NOINDEX_META = /<meta\s+[^>]*name\s*=\s*["']?robots["']?[^>]*content\s*=\s*["'][^"']*noindex/i;

// The consumer's auth pages: reachable, not indexed, and (when a CSP is sent)
// allowed to connect to the project.
async function hostChecks(ctx, { config, hostOrigin }) {
  if (!config) return [check('host', 'host', 'not_run', { reason: 'config_missing' })];
  const out = [];
  for (const route of Object.keys(config.routes).filter((name) => name !== 'prefix')) {
    let response;
    try {
      response = await request(ctx.fetch, `${hostOrigin}${config.routes[route]}`, { timeoutMs: ctx.timeoutMs, maxBytes: 1024 * 1024, timers: ctx.timers });
    } catch (error) {
      if (!(error instanceof TransportError)) throw error;
      out.push(check(`host_${route}`, 'host', 'not_run', { reason: 'unavailable', cause: error.reason }));
      continue;
    }
    const noindex = /noindex/i.test(response.headers.get('x-robots-tag') ?? '') || NOINDEX_META.test(response.text);
    const csp = response.headers.get('content-security-policy');
    const connect = csp === null ? null : (/(?:^|;)\s*connect-src([^;]*)/i.exec(csp)?.[1] ?? '').split(/\s+/);
    const cspOk = connect === null ? null : connect.includes(ctx.origin);
    const ok = response.status === 200 && noindex && cspOk !== false;
    out.push(check(`host_${route}`, 'host', ok ? 'ok' : 'fail', { httpStatus: response.status, noindex, cspConnectsToProject: cspOk }));
  }
  return out;
}
