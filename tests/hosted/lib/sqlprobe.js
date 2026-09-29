// SQL through the Management API: read queries and role impersonation.
//
// Reads are single statements returning one `result` column of JSON text.
//
// Impersonation runs a list of calls inside one DO block. Each call sets
// `request.jwt.claims` and the role with set_config(..., true), exactly as
// PostgREST does per request, executes one statement in its own
// subtransaction and records either its value or its SQLSTATE (and, for a kit
// refusal DW001, its code). The block then raises an exception carrying the
// hex-encoded outcomes. Raising is deliberate: it aborts the transaction, so
// nothing an impersonated call did (including a call that a widened grant
// let through) survives, and no role or claim setting leaks into a pooled
// connection. The harness reads the outcomes from the error message.

import { textLiteral } from '../../../packages/server/lib/management.js';

const MARK = /DWPROBE\[([0-9a-f]*)\]/;
const IDENT = /^[a-z_][a-z0-9_]{0,62}$/;
const ROLES = new Set(['anon', 'authenticated', 'service_role']);

/** A SQL literal for a JSON value, independent of quoting settings. */
export function jsonLiteral(value) {
  return `(${textLiteral(JSON.stringify(value))})::jsonb`;
}

export { textLiteral };

/**
 * @param {{ role: 'anon' | 'authenticated' | 'service_role', claims: object | null, sql: string }[]} calls
 * @returns {string} one DO statement
 */
export function probeStatement(calls) {
  for (const call of calls) {
    if (!ROLES.has(call.role)) throw new TypeError('probe: unknown role');
    if (typeof call.sql !== 'string' || call.sql === '') throw new TypeError('probe: empty statement');
  }
  const payload = calls.map((c) => ({ role: c.role, claims: c.claims === null ? '' : JSON.stringify(c.claims), sql: c.sql }));
  return `do $dwprobe$
declare
  v_calls jsonb := ${jsonLiteral(payload)};
  v_call jsonb;
  v_out jsonb := '[]'::jsonb;
  v_val text;
  v_state text;
  v_msg text;
begin
  for v_call in select value from pg_catalog.jsonb_array_elements(v_calls) loop
    begin
      perform pg_catalog.set_config('request.jwt.claims', v_call ->> 'claims', true);
      perform pg_catalog.set_config('role', v_call ->> 'role', true);
      execute v_call ->> 'sql' into v_val;
      v_out := v_out || pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object('outcome', 'value', 'value', v_val));
    exception when others then
      get stacked diagnostics v_state = returned_sqlstate, v_msg = message_text;
      v_out := v_out || pg_catalog.jsonb_build_array(pg_catalog.jsonb_build_object('outcome', 'error', 'sqlstate', v_state,
        'code', case when v_state = 'DW001' then v_msg end,
        'denied', case when v_state = '42501' then pg_catalog.split_part(v_msg, ' ', 4) end));
    end;
  end loop;
  raise exception 'DWPROBE[%]', pg_catalog.encode(pg_catalog.convert_to(v_out::text, 'UTF8'), 'hex');
end
$dwprobe$`;
}

/**
 * Outcomes from the text of the error the probe raised; null when the text
 * carries no probe marker (the channel did not work as expected).
 * @returns {({ outcome: 'value', value: string | null } | { outcome: 'error', sqlstate: string, code: string | null })[] | null}
 */
export function parseProbe(text) {
  if (typeof text !== 'string') return null;
  const match = MARK.exec(text);
  if (!match) return null;
  try {
    const outcomes = JSON.parse(Buffer.from(match[1], 'hex').toString('utf8'));
    return Array.isArray(outcomes) ? outcomes : null;
  } catch {
    return null;
  }
}

/**
 * A call's statement: the function's result as text, with NULL arguments of
 * its identity types. Each argument is a sub-select, not a constant: the
 * planner folds a strict function applied to a constant NULL into NULL
 * without ever checking EXECUTE, which would read as "executed". With
 * sub-selects the privilege check runs when the executor initialises the
 * call, and a strict function still returns NULL without running its body.
 */
export function nullCall(schema, name, argTypes, { set = false } = {}) {
  if (!IDENT.test(schema) || !IDENT.test(name)) throw new TypeError('probe: bad identifier');
  for (const t of argTypes) if (!/^[a-z_][a-z0-9_ ]*(\[\])?$/.test(t)) throw new TypeError('probe: bad type');
  const args = argTypes.map((t) => `(select null::${t})`).join(', ');
  if (set) return `select pg_catalog.count(*)::text from ${schema}.${name}(${args})`;
  return `select coalesce((${schema}.${name}(${args}))::text, 'null')`;
}

/**
 * Trigger functions cannot be called directly at all, so impersonation
 * cannot show their EXECUTE; the catalog check alone covers them.
 */
export function executionProbeable(fn) {
  return fn.returns !== 'trigger';
}

/**
 * Classifies one outcome: `denied` (42501 on the function itself), `executed` (a value, a kit
 * refusal or any runtime error after the privilege check) or `invalid`
 * (a statement the harness got wrong: any other class-42 error). An invalid
 * probe proves nothing and fails its case.
 */
export function classify(outcome) {
  if (outcome?.outcome === 'value') return 'executed';
  if (outcome?.outcome !== 'error' || typeof outcome.sqlstate !== 'string') return 'invalid';
  // 42501 from the privilege check names the object kind: "permission denied
  // for function f", or "... for schema s" when the caller lacks USAGE on the
  // function's schema. One raised inside a body that did run names what the
  // body touched ("... for table users"). A body that itself hits a schema
  // it cannot use would also read as denied; the catalog check
  // (has_function_privilege) runs beside every probe, so the two together
  // cannot turn an executable function into a pass.
  if (outcome.sqlstate === '42501') return outcome.denied === 'function' || outcome.denied === 'schema' ? 'denied' : 'executed';
  // Class 42 (other than 42501) and 0A000 ("not supported", for example a set
  // or trigger function called in the wrong context) mean the statement
  // itself was wrong for the probe, not that the privilege check passed.
  if (outcome.sqlstate.startsWith('42') || outcome.sqlstate === '0A000') return 'invalid';
  return 'executed';
}

/** A table probe is denied by the table's own privilege check or by the missing schema USAGE. */
export function tableDenied(outcome) {
  return outcome?.outcome === 'error' && outcome.sqlstate === '42501' && ['table', 'view', 'schema'].includes(outcome.denied);
}

/** Claims as PostgREST would set them for a user session. */
export function userClaims(sub, aal = 'aal1') {
  return { sub, role: 'authenticated', aud: 'authenticated', aal, session_id: '00000000-0000-4000-8000-000000000000', is_anonymous: false };
}

export const ANON_CLAIMS = Object.freeze({ role: 'anon' });
export const SERVICE_CLAIMS = Object.freeze({ role: 'service_role' });

// Catalog reads -----------------------------------------------------------------

/** Every function in both kit schemas with per-role EXECUTE and PUBLIC EXECUTE. */
export const FUNCTIONS_SQL = `select coalesce(jsonb_agg(jsonb_build_object(
    'schema', n.nspname, 'name', p.proname,
    'args', coalesce((select jsonb_agg(pg_catalog.format_type(t, null) order by i)
                        from unnest(p.proargtypes::oid[]) with ordinality as a(t, i)), '[]'::jsonb),
    'returns', pg_catalog.format_type(p.prorettype, null), 'set', p.proretset,
    'anon', pg_catalog.has_function_privilege('anon', p.oid, 'EXECUTE'),
    'authenticated', pg_catalog.has_function_privilege('authenticated', p.oid, 'EXECUTE'),
    'service_role', pg_catalog.has_function_privilege('service_role', p.oid, 'EXECUTE'),
    'public', exists (select 1 from pg_catalog.aclexplode(coalesce(p.proacl, pg_catalog.acldefault('f', p.proowner))) x
                       where x.grantee = 0 and x.privilege_type = 'EXECUTE'))
    order by n.nspname, p.proname), '[]'::jsonb)::text as result
  from pg_catalog.pg_proc p join pg_catalog.pg_namespace n on n.oid = p.pronamespace
 where n.nspname in ('auth_kit', 'auth_kit_private')`;

/** Tables and views of the private schema. */
export const PRIVATE_TABLES_SQL = `select coalesce(jsonb_agg(c.relname order by c.relname), '[]'::jsonb)::text as result
  from pg_catalog.pg_class c join pg_catalog.pg_namespace n on n.oid = c.relnamespace
 where n.nspname = 'auth_kit_private' and c.relkind in ('r', 'p', 'v')`;

export const MEMBERSHIP_SQL = `select jsonb_build_object(
    'user', current_user,
    'anon', pg_catalog.pg_has_role(current_user, 'anon', 'MEMBER'),
    'authenticated', pg_catalog.pg_has_role(current_user, 'authenticated', 'MEMBER'),
    'service_role', pg_catalog.pg_has_role(current_user, 'service_role', 'MEMBER'),
    'server_version', pg_catalog.current_setting('server_version_num'))::text as result`;

export const RLS_CONSUMER_SQL = `select jsonb_build_object(
    'table', pg_catalog.to_regclass('app.notes') is not null,
    'rls', coalesce((select c.relrowsecurity and c.relforcerowsecurity from pg_catalog.pg_class c where c.oid = pg_catalog.to_regclass('app.notes')), false),
    'policies', coalesce((select jsonb_agg(p.policyname order by p.policyname) from pg_catalog.pg_policies p
                           where p.schemaname = 'app' and p.tablename = 'notes'), '[]'::jsonb))::text as result`;

export const GRANT_VIOLATIONS_SQL = `select pg_catalog.count(*)::text as result from auth_kit_private.grant_violations()`;
