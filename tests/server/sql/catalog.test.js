// migrate and doctor over the Management API transport, with the fixture's
// Management endpoints executing on the real throwaway PostgreSQL (as the
// non-superuser migration role) and the real grant assertion. Also the
// disposable-user probe (L33 local part). PostgREST schema exposure and the
// Management API's HTTP behavior are the fixture's; hosted catalog state is
// Lane 06.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { withDatabase, TEMPLATE_BASE } from '../../sql/harness/db.js';
import { exampleModel, register, applyModel, bootstrap } from '../../sql/harness/kit.js';
import { createOperatorClient, OperatorError } from '../../../packages/server/operator.js';
import { createFakeSupabase, SECRET_KEY, PUBLISHABLE_KEY, MANAGEMENT_TOKEN, PROJECT_REF } from '../support/fake-supabase.js';
import { pgRpc, pgManagement, addUser } from '../support/pg-bridge.js';

async function stack(db, { management = true } = {}) {
  const fake = await createFakeSupabase();
  fake.rpc = pgRpc(db);
  fake.management = pgManagement(db);
  const client = createOperatorClient({
    supabaseUrl: fake.origin, secretKey: SECRET_KEY, publishableKey: PUBLISHABLE_KEY, fetch: fake.fetch,
    management: management ? { token: MANAGEMENT_TOKEN, projectRef: PROJECT_REF, url: fake.origin } : null,
  });
  return { fake, client };
}

async function rejectsWith(promise, code, check) {
  await assert.rejects(promise, (error) => {
    assert.ok(error instanceof OperatorError, `expected ${code}, got ${error?.name} ${error?.code ?? error?.message}`);
    assert.equal(error.code, code);
    check?.(error);
    return true;
  });
}

function byId(report) {
  return Object.fromEntries(report.checks.map((c) => [c.id, c]));
}

const MARKERS = ['SECRETMARKER', 'MANAGEMENTMARKER', 'SMTPSECRETMARKER', 'GOOGLESECRETMARKER', 'PUBLISHABLEMARKER', 'probe-password-marker'];

function assertNoMarkers(value) {
  const text = JSON.stringify(value);
  for (const marker of MARKERS) assert.ok(!text.includes(marker), `${marker} leaked`);
}

test('migrate applies the migration once through the Management API and is idempotent on rerun', async () => {
  await withDatabase(async (db) => {
    const { fake, client } = await stack(db);
    const first = await client.migrate();
    assert.equal(first.applied.length, 1);
    assert.equal(first.applied[0].version, '20260927000000');
    assert.equal(first.applied[0].sha256, '3d2afcf0ae7bca9b3996c9013d2f19f3757d2408621378c837fb4875a5aee041');
    const [{ n }] = await db.rows("select count(*) as n from auth_kit_private.migrations where version = '20260927000000'");
    assert.equal(n, '1');
    const again = await client.migrate();
    assert.deepEqual(again.applied, []);
    assert.deepEqual(again.alreadyInstalled, ['20260927000000']);
    assert.equal(fake.management.queries.filter((q) => q.startsWith('begin;')).length, 1, 'never re-sent');
  }, { template: TEMPLATE_BASE });
});

test('a lost answer after the migration committed is outcome_unknown; the rerun finds it installed', async () => {
  await withDatabase(async (db) => {
    const { fake, client } = await stack(db);
    const real = fake.management;
    fake.management = async (sql) => {
      const response = await real(sql);
      if (sql.startsWith('begin;')) throw new TypeError('connection reset after commit');
      return response;
    };
    fake.management.queries = real.queries;
    await rejectsWith(client.migrate(), 'outcome_unknown', (e) => assert.equal(e.details.stage, 'migration_20260927000000'));
    fake.management = real;
    const rerun = await client.migrate();
    assert.deepEqual(rerun.applied, []);
    assert.deepEqual(rerun.alreadyInstalled, ['20260927000000']);
  }, { template: TEMPLATE_BASE });
});

test('a refused migration rolls back completely and reports only a tag', async () => {
  await withDatabase(async (db) => {
    const { client } = await stack(db);
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dwl3-mig-'));
    try {
      fs.writeFileSync(path.join(dir, '20990101000000_broken.sql'), "create schema auth_kit; create table auth_kit.t (x int); select 'SQLTEXTMARKER'::int;");
      await rejectsWith(client.migrate({ migrationsDir: dir }), 'migration_failed', (e) => {
        assert.equal(e.details.reason, 'sql_error');
        assert.ok(!JSON.stringify(e).includes('SQLTEXTMARKER'));
      });
      const [{ ns }] = await db.rows("select to_regnamespace('auth_kit')::text as ns");
      assert.equal(ns, null, 'nothing left behind');
      // The real migration's own precondition message maps to a named tag.
      await db.admin.query('create schema auth_kit');
      await rejectsWith(client.migrate(), 'migration_failed', (e) => assert.equal(e.details.reason, 'partial_install'));
      fs.rmSync(path.join(dir, '20990101000000_broken.sql'));
      await rejectsWith(client.migrate({ migrationsDir: dir }), 'prerequisite_missing', (e) => assert.equal(e.details.reason, 'no_migration_files'));
      await rejectsWith(client.migrate({ migrationsDir: path.join(dir, 'absent') }), 'prerequisite_missing');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }, { template: TEMPLATE_BASE });
});

test('migrate without a Management API token reports the prerequisite; it never tries PostgREST', async () => {
  await withDatabase(async (db) => {
    const { fake, client } = await stack(db, { management: false });
    await rejectsWith(client.migrate(), 'prerequisite_missing', (e) => assert.equal(e.details.reason, 'management_token_missing'));
    assert.equal(fake.calls.length, 0);
  }, { template: TEMPLATE_BASE });
});

function studioConfig(fake) {
  return {
    clientId: 'studio', supabaseUrl: fake.origin, publishableKey: PUBLISHABLE_KEY, origin: 'https://www.example.test',
    allowedReturnPaths: ['/'], defaultReturnPath: '/', providers: { email: true, google: false }, selfSignup: true,
  };
}

async function liveStudio(db, fake) {
  await register(db, 'studio');
  await applyModel(db, 'studio', exampleModel('studio'));
  await bootstrap(db, await addUser(fake, db), 'studio', 'steward');
  fake.authConfig.uri_allow_list = ['callback', 'verify', 'reset'].map((r) => `https://www.example.test/account/${r}`).join(',');
}

test('doctor catalog mode: every check performed and healthy on a clean installation; no probe claimed', async () => {
  await withDatabase(async (db) => {
    const { fake, client } = await stack(db);
    await liveStudio(db, fake);
    const report = await client.doctor({ config: studioConfig(fake), model: exampleModel('studio') });
    const checks = byId(report);
    assert.deepEqual(Object.keys(checks).sort(), ['client_registration', 'exposed_schemas', 'grants', 'memberships_without_events',
      'model_drift', 'redirect_allow_list', 'schema_version', 'signing_keys'].sort());
    for (const c of report.checks) assert.equal(c.status, 'ok', `${c.id}: ${JSON.stringify(c)}`);
    assert.equal(report.status, 'ok');
    assert.equal(report.probeRan, false);
    assert.equal(checks.model_drift.fileMatchesDatabase, true);
    assertNoMarkers(report);
  });
});

test('doctor catches drift: widened column grant, extra policy, orphan membership, SQL-editor model change, redirects, exposure', async () => {
  await withDatabase(async (db) => {
    const { fake, client } = await stack(db);
    await liveStudio(db, fake);
    const member = await addUser(fake, db);
    await db.admin.query('grant select (user_id) on auth_kit_private.memberships to authenticated');
    await db.admin.query('create policy widened on auth_kit.profiles for select to authenticated using (true)');
    await db.admin.query(`insert into auth_kit_private.memberships (user_id, client_id, role_key, granted_at, granted_via) values ('${member}', 'studio', 'editor', now(), 'operator')`);
    await db.admin.query("update auth_kit_private.roles set description = 'edited in the SQL editor' where client_id = 'studio' and role_key = 'editor'");
    fake.authConfig.uri_allow_list = 'https://www.example.test/account/callback,https://*.example.test/**';
    fake.postgrestSchemas = 'public, auth_kit, auth_kit_private';
    const report = await client.doctor({ config: studioConfig(fake), model: exampleModel('studio') });
    const checks = byId(report);
    assert.equal(report.status, 'fail');
    assert.equal(checks.grants.status, 'fail');
    assert.ok(checks.grants.violations.some((v) => v.object.includes('memberships') && v.grantee === 'authenticated'), JSON.stringify(checks.grants.violations));
    assert.ok(checks.grants.violations.some((v) => v.object.includes('profiles')), 'the extra policy is reported');
    assert.deepEqual([checks.memberships_without_events.status, checks.memberships_without_events.count], ['fail', 1]);
    assert.equal(checks.model_drift.status, 'fail');
    assert.equal(checks.model_drift.appliedMatchesDatabase, false);
    assert.equal(checks.model_drift.fileMatchesDatabase, false);
    assert.deepEqual(checks.redirect_allow_list.missingRoutes, ['verify', 'reset']);
    assert.equal(checks.redirect_allow_list.wildcardEntries, 1);
    assert.equal(checks.exposed_schemas.privateSchemaExposed, true);
    assertNoMarkers(report);
  });
});

test('doctor without Management API access reports catalog checks as not run, never healthy', async () => {
  await withDatabase(async (db) => {
    const { fake, client } = await stack(db, { management: false });
    await liveStudio(db, fake);
    const report = await client.doctor({ config: studioConfig(fake) });
    const checks = byId(report);
    for (const id of ['schema_version', 'grants', 'memberships_without_events', 'exposed_schemas', 'redirect_allow_list', 'client_registration']) {
      assert.deepEqual([checks[id].status, checks[id].reason], ['not_run', 'management_token_missing'], id);
    }
    assert.equal(checks.model_drift.status, 'ok', 'the secret-key export still works');
    assert.equal(checks.model_drift.fileCompared, false);
    assert.equal(report.status, 'incomplete');
    // A refused token is a missing prerequisite too.
    const refused = createOperatorClient({ supabaseUrl: fake.origin, secretKey: SECRET_KEY, fetch: fake.fetch, management: { token: 'sbp_wrong', projectRef: PROJECT_REF, url: fake.origin } });
    const r2 = byId(await refused.doctor({}));
    assert.equal(r2.grants.status, 'not_run');
    assert.equal(r2.grants.reason, 'prerequisite_missing');
  });
});

test('L33 local: the disposable-user probe reports real anon and authenticated outcomes; a widened grant is caught by both modes', async () => {
  await withDatabase(async (db) => {
    const { fake, client } = await stack(db);
    await liveStudio(db, fake);
    const password = 'probe-password-marker';
    const probeUser = await addUser(fake, db, { email: 'probe@example.test', password });
    assert.ok(probeUser);
    const probe = { email: 'probe@example.test', password };
    const clean = await client.doctor({ clientId: 'studio', probe });
    const checks = byId(clean);
    for (const id of ['probe_sign_in', 'probe_authenticated_effective_access', 'probe_authenticated_operator_wrapper', 'probe_authenticated_private_schema',
      'probe_anon_user_wrapper', 'probe_anon_helper', 'probe_anon_private_schema', 'probe_sign_out']) {
      assert.equal(checks[id]?.status, 'ok', `${id}: ${JSON.stringify(checks[id])}`);
      assert.equal(checks[id].mode, 'probe');
    }
    assert.equal(clean.probeRan, true);
    assert.equal(checks.grants.mode, 'catalog');
    const clientsBefore = await db.count('auth_kit_private.clients');
    // Widening only the invoker wrapper is not observable over HTTP: the call
    // still reaches the private implementation's grant, the second fence.
    // Catalog mode reports it; the probe truthfully sees the call denied.
    await db.admin.query('grant execute on function auth_kit.register_client(text, text, text) to authenticated');
    const wrapperOnly = byId(await client.doctor({ clientId: 'studio', probe }));
    assert.equal(wrapperOnly.grants.status, 'fail');
    assert.equal(wrapperOnly.probe_authenticated_operator_wrapper.status, 'ok');
    // An effective widening (wrapper and implementation) is caught by both modes.
    await db.admin.query('grant execute on function auth_kit_private.register_client_impl(text, text, text) to authenticated');
    const widened = byId(await client.doctor({ clientId: 'studio', probe }));
    assert.equal(widened.probe_authenticated_operator_wrapper.status, 'fail');
    assert.equal(widened.probe_authenticated_operator_wrapper.observed, 'refusal_invalid_argument');
    assert.equal(widened.grants.status, 'fail');
    assert.ok(widened.grants.violations.some((v) => v.object.includes('register_client') && v.grantee === 'authenticated'));
    assert.equal(await db.count('auth_kit_private.clients'), clientsBefore, 'the probe wrote nothing');
    assertNoMarkers(widened);
    assert.ok(!JSON.stringify(widened).includes('probe@example.test'));
    // Wrong password: the probe fails visibly instead of being skipped.
    const wrong = byId(await client.doctor({ clientId: 'studio', probe: { ...probe, password: 'nope' } }));
    assert.equal(wrong.probe_sign_in.status, 'fail');
  });
});

test('host check: auth pages must answer 200, be noindex, and allow connecting to the project when a CSP is sent', async () => {
  await withDatabase(async (db) => {
    const { fake } = await stack(db);
    const pages = new Map();
    const hostFetch = async (input, init) => {
      const url = new URL(typeof input === 'string' ? input : input.url);
      if (url.origin !== 'https://www.example.test') return fake.fetch(input, init);
      const page = pages.get(url.pathname) ?? { status: 404, headers: {}, body: '' };
      return new Response(page.body, { status: page.status, headers: page.headers });
    };
    const client = createOperatorClient({ supabaseUrl: fake.origin, secretKey: SECRET_KEY, fetch: hostFetch });
    const csp = `default-src 'self'; connect-src 'self' ${fake.origin}`;
    for (const route of ['sign-in', 'sign-up', 'verify', 'callback', 'forgot', 'reset', 'mfa', 'sign-out']) {
      pages.set(`/account/${route}`, { status: 200, headers: { 'content-security-policy': csp }, body: '<head><meta name="robots" content="noindex, nofollow"></head>' });
    }
    pages.set('/account/mfa', { status: 200, headers: { 'x-robots-tag': 'noindex' }, body: '' });
    pages.set('/account/reset', { status: 200, headers: { 'content-security-policy': "connect-src 'self'" }, body: '<meta name="robots" content="noindex">' });
    pages.set('/account/forgot', { status: 200, headers: {}, body: '<title>indexable</title>' });
    pages.delete('/account/sign-out');
    const report = await client.doctor({ config: studioConfig(fake), hostOrigin: 'https://www.example.test' });
    const checks = byId(report);
    assert.equal(checks.host_signIn.status, 'ok');
    assert.equal(checks.host_mfa.status, 'ok');
    assert.equal(checks.host_mfa.cspConnectsToProject, null);
    assert.deepEqual([checks.host_reset.status, checks.host_reset.cspConnectsToProject], ['fail', false]);
    assert.deepEqual([checks.host_forgot.status, checks.host_forgot.noindex], ['fail', false]);
    assert.deepEqual([checks.host_signOut.status, checks.host_signOut.httpStatus], ['fail', 404]);
    await rejectsWith(client.doctor({ config: studioConfig(fake), hostOrigin: 'http://www.example.test' }), 'invalid_argument');
  });
});

test('the catalog query quotes a client id with quotes, backslashes and dollar signs exactly', async () => {
  await withDatabase(async (db) => {
    const { fake, client } = await stack(db);
    const odd = "it's \\ \"odd\" $$ ; --";
    await register(db, odd);
    await applyModel(db, odd, exampleModel(odd));
    await bootstrap(db, await addUser(fake, db), odd, 'steward');
    const config = { ...studioConfig(fake), clientId: odd };
    const checks = byId(await client.doctor({ config }));
    assert.equal(checks.client_registration.status, 'ok', JSON.stringify(checks.client_registration));
    assert.equal(checks.client_registration.state, 'live');
  });
});
