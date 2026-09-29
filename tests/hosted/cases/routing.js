// HTTP routing versus SQL EXECUTE (design 4.2 R4, L28, 5.1).
//
// Over HTTP, auth_kit_private is not an exposed schema, so PostgREST refuses
// every request that selects it (PGRST106) whatever the caller's role, and
// an implementation name under the exposed profile does not exist there.
// Through SQL, the same functions are guarded by EXECUTE grants: the
// Management API runs each call as anon, authenticated and service_role with
// PostgREST-style claims (lib/sqlprobe.js), and the catalog's own answer
// (has_function_privilege, PUBLIC in the ACL) is compared beside it. Both
// are compared with the design grant table (lib/expected.js).

import { attempt } from '../lib/world.js';
import {
  FUNCTIONS_SQL, PRIVATE_TABLES_SQL, nullCall, classify, tableDenied, executionProbeable, userClaims, ANON_CLAIMS, SERVICE_CLAIMS,
} from '../lib/sqlprobe.js';
import { expectedExecute, EXPOSED_FUNCTIONS, USER_IMPLS, HELPER_IMPLS, OPERATOR_WRAPPERS, ROLES } from '../lib/expected.js';

export const PRIVATE_FUNCTIONS = Object.freeze([...USER_IMPLS, ...HELPER_IMPLS, ...OPERATOR_WRAPPERS.map((n) => `${n}_impl`), 'grant_violations']);
export const PRIVATE_TABLES = Object.freeze(['clients', 'roles', 'permissions', 'role_permissions', 'memberships', 'enrollments',
  'membership_events', 'model_events', 'request_log', 'migrations']);

const CLAIM_FOR = (sub) => ({ anon: ANON_CLAIMS, authenticated: userClaims(sub), service_role: SERVICE_CLAIMS });

/**
 * Compares catalog and impersonation outcomes with the design table.
 * @returns {{ object: string, role: string, expected: boolean, catalog: boolean, probe: string }[]} mismatches
 */
export function executionFindings(functions, probes) {
  const findings = [];
  for (const { f, role, outcome } of probes) {
    const expected = expectedExecute(f.schema, f.name, role);
    const kind = outcome === null ? 'catalog_only' : classify(outcome);
    const catalog = f[role] === true;
    const probeAgrees = kind === 'catalog_only' || (kind !== 'invalid' && (kind === 'executed') === expected);
    if (catalog !== expected || !probeAgrees) findings.push({ object: `${f.schema}.${f.name}`, role, expected, catalog, probe: kind });
  }
  return findings;
}

async function probeFunctions(ctx, functions, sub) {
  const claims = CLAIM_FOR(sub);
  const rows = [];
  const calls = [];
  for (const f of functions) {
    for (const role of ROLES) {
      if (executionProbeable(f)) {
        rows.push({ f, role, index: calls.length });
        calls.push({ role, claims: claims[role], sql: nullCall(f.schema, f.name, f.args, { set: f.set }) });
      } else {
        rows.push({ f, role, index: null });
      }
    }
  }
  const outcomes = calls.length > 0 ? await ctx.hosted.management.probe(calls) : [];
  return rows.map((r) => ({ f: r.f, role: r.role, outcome: r.index === null ? null : outcomes[r.index] }));
}

export const procedures = [{
  id: 'routing',
  group: 'routing',
  requiresTargets: ['T.identity', 'T.signing_keys'],
  async run(ctx) {
    const { rest } = ctx.hosted;
    const needsUser = ['L28.http.private_rpc.authenticated', 'L28.http.private_table.authenticated', 'L28.http.impl_in_exposed_profile'].some((id) => ctx.wants(id));
    const user = needsUser ? await ctx.actors.signIn('routing_user') : null;
    const secret = ctx.creds.SUPABASE_SECRET_KEY;
    const bearers = { anon: { token: null }, authenticated: { token: user?.accessToken }, service: { token: secret, apikey: secret } };

    for (const [who, b] of Object.entries(bearers)) {
      await attempt(ctx, `L28.http.private_rpc.${who}`, async (check) => {
        const seen = {};
        for (const fn of PRIVATE_FUNCTIONS) {
          const o = await rest.rpc(b.token, fn, {}, { profile: 'auth_kit_private', ...(b.apikey ? { apikey: b.apikey } : {}) });
          seen[fn] = `${o.status}:${o.code ?? o.kind}`;
        }
        check.assert(`every private function refused as an unexposed schema (${who})`, Object.fromEntries(PRIVATE_FUNCTIONS.map((f) => [f, '406:PGRST106'])), seen);
      });
    }
    for (const who of ['anon', 'authenticated']) {
      await attempt(ctx, `L28.http.private_table.${who}`, async (check) => {
        const seen = {};
        for (const table of PRIVATE_TABLES) {
          const o = await rest.select(bearers[who].token, 'auth_kit_private', table, 'select=*&limit=1');
          seen[table] = `${o.status}:${o.code ?? o.kind}`;
        }
        check.assert(`every private table refused as an unexposed schema (${who})`, Object.fromEntries(PRIVATE_TABLES.map((t) => [t, '406:PGRST106'])), seen);
      });
    }
    await attempt(ctx, 'L28.http.impl_in_exposed_profile', async (check) => {
      for (const [who, token] of [['anon', null], ['authenticated', user?.accessToken]]) {
        const o = await rest.rpc(token, 'has_permission_impl', { p_client_id: 'x', p_permission_key: 'y' });
        check.assert(`has_permission_impl not found under auth_kit (${who})`, '404:PGRST202', `${o.status}:${o.code ?? o.kind}`);
      }
    });

    // SQL EXECUTE by impersonation, with the catalog beside it.
    const sqlCases = ['L28.sql.execute.anon', 'L28.sql.execute.authenticated', 'L28.sql.execute.service_role', 'L28.sql.wrappers', 'L28.sql.private_tables', 'L28.sql.public_execute'];
    if (!sqlCases.some((id) => ctx.wants(id))) return;
    const functions = await ctx.hosted.management.read(FUNCTIONS_SQL);
    ctx.observe('kit functions (catalog)', functions.map((f) => ({ fn: `${f.schema}.${f.name}(${f.args.join(',')})`, anon: f.anon, authenticated: f.authenticated, service_role: f.service_role, public: f.public })));
    const probes = await probeFunctions(ctx, functions, '00000000-0000-4000-8000-00000000a11d');
    ctx.observe('impersonation outcomes', probes.map((p) => ({ fn: `${p.f.schema}.${p.f.name}`, role: p.role, outcome: p.outcome })));

    for (const role of ROLES) {
      await attempt(ctx, `L28.sql.execute.${role}`, async (check) => {
        const mine = probes.filter((p) => p.role === role && p.f.schema === 'auth_kit_private');
        check.assert('every expected implementation exists', [], [...USER_IMPLS, ...HELPER_IMPLS].filter((n) => !functions.some((f) => f.schema === 'auth_kit_private' && f.name === n)));
        check.assert(`catalog and impersonation agree with the grant table (${role})`, [], executionFindings(functions, mine));
        const allowed = mine.filter((p) => p.outcome !== null && classify(p.outcome) === 'executed').map((p) => p.f.name).sort();
        if (role === 'authenticated') check.assert('authenticated executes exactly the five user and two helper implementations', [...USER_IMPLS, ...HELPER_IMPLS].sort(), allowed);
        if (role === 'anon') check.assert('anon executes no private function', [], allowed);
      });
    }
    await attempt(ctx, 'L28.sql.wrappers', async (check) => {
      check.assert('every exposed wrapper exists', [], EXPOSED_FUNCTIONS.filter((n) => !functions.some((f) => f.schema === 'auth_kit' && f.name === n)));
      check.assert('no unexpected function in auth_kit', [], functions.filter((f) => f.schema === 'auth_kit' && !EXPOSED_FUNCTIONS.includes(f.name)).map((f) => f.name));
      check.assert('catalog and impersonation agree with the grant table (wrappers)', [], executionFindings(functions, probes.filter((p) => p.f.schema === 'auth_kit')));
    });
    await attempt(ctx, 'L28.sql.private_tables', async (check) => {
      const tables = await ctx.hosted.management.read(PRIVATE_TABLES_SQL);
      check.assert('private tables present', [], PRIVATE_TABLES.filter((t) => !tables.includes(t)));
      const claims = CLAIM_FOR('00000000-0000-4000-8000-00000000a11d');
      const calls = tables.flatMap((t) => ['anon', 'authenticated'].map((role) => ({ role, claims: claims[role], sql: `select pg_catalog.count(*)::text from auth_kit_private.${t}` })));
      const outcomes = await ctx.hosted.management.probe(calls);
      const readable = calls.map((c, i) => (tableDenied(outcomes[i]) ? null : `${c.role}:${c.sql.split('.').at(-1)}`)).filter(Boolean);
      check.assert('anon and authenticated cannot select any private table', [], readable);
    });
    await attempt(ctx, 'L28.sql.public_execute', async (check) => {
      check.assert('PUBLIC holds EXECUTE on no function in either schema', [], functions.filter((f) => f.public).map((f) => `${f.schema}.${f.name}`));
    });
  },
}];
