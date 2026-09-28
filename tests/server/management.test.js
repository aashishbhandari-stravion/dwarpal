// doctor's redirect check and migrate's write outcomes over the Management
// API, with scripted catalog answers (no database). The same paths run
// against the real migration in sql/catalog.test.js. Nothing here is hosted
// evidence.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createOperatorClient, OperatorError } from '../../packages/server/operator.js';
import { readMigrations, DEFAULT_MIGRATIONS_DIR } from '../../packages/server/lib/migrate.js';
import { canonicalModelJson, sha256Hex } from '../../packages/core/index.js';
import { createFakeSupabase, SECRET_KEY, PUBLISHABLE_KEY, MANAGEMENT_TOKEN, PROJECT_REF, jsonResponse } from './support/fake-supabase.js';

const ORIGIN = 'https://www.example.test';
const EXACT = ['callback', 'verify', 'reset'].map((route) => `${ORIGIN}/account/${route}`);
const MODEL = { client: 'studio', roles: { owner: { manages_members: true, permissions: [] } }, permissions: {} };

function rows(value) {
  return jsonResponse(200, [{ result: JSON.stringify(value) }]);
}

// A healthy installed catalog; `installed: false` answers as an empty project.
function catalog({ installed = true } = {}) {
  const versions = readMigrations(DEFAULT_MIGRATIONS_DIR).map((m) => m.version);
  const queries = [];
  const handler = async (sql) => {
    queries.push(sql);
    if (sql.includes('to_regnamespace')) return rows({ kit: installed, private: installed, ledger: installed });
    if (sql.includes('from auth_kit_private.migrations')) return rows(versions);
    if (sql.includes('grant_violations() v')) return rows({ violations: [], memberships_without_events: 0 });
    if (sql.includes('from auth_kit_private.clients c')) return rows({ state: 'live', signup_policy: 'open' });
    return jsonResponse(400, { message: 'unexpected query' });
  };
  handler.queries = queries;
  return handler;
}

async function setup(options = {}) {
  const fake = await createFakeSupabase();
  fake.management = catalog(options);
  const text = canonicalModelJson(MODEL);
  const hash = await sha256Hex(text);
  fake.rpc = async () => jsonResponse(200, { client_id: 'studio', model_json: text, model_hash: hash, last_applied_hash: hash });
  const client = createOperatorClient({
    supabaseUrl: fake.origin, secretKey: SECRET_KEY, publishableKey: PUBLISHABLE_KEY, fetch: fake.fetch, rpcTimeoutMs: 300,
    management: { token: MANAGEMENT_TOKEN, projectRef: PROJECT_REF, url: fake.origin },
  });
  const config = {
    clientId: 'studio', supabaseUrl: fake.origin, publishableKey: PUBLISHABLE_KEY, origin: ORIGIN,
    allowedReturnPaths: ['/'], defaultReturnPath: '/', providers: { email: true, google: false }, selfSignup: true,
  };
  return { fake, client, config };
}

async function redirectCheck(allowList) {
  const { fake, client, config } = await setup();
  fake.authConfig.uri_allow_list = allowList.join(',');
  const report = await client.doctor({ config });
  const redirect = report.checks.find((c) => c.id === 'redirect_allow_list');
  // Diagnostics name routes and counts only, never a configured URL.
  assert.ok(!JSON.stringify(report).includes('example.test'), JSON.stringify(redirect));
  return { report, redirect };
}

test('doctor redirect check: exactly the three account routes is healthy', async () => {
  const { report, redirect } = await redirectCheck(EXACT);
  assert.deepEqual(redirect, { id: 'redirect_allow_list', mode: 'catalog', status: 'ok', missingRoutes: [], wildcardEntries: 0 });
  assert.equal(report.status, 'ok', JSON.stringify(report.checks));
});

test('doctor redirect check: a missing exact route fails and is named', async () => {
  const { report, redirect } = await redirectCheck([EXACT[0], EXACT[2], `${ORIGIN}/account/other`]);
  assert.deepEqual(redirect, { id: 'redirect_allow_list', mode: 'catalog', status: 'fail', missingRoutes: ['verify'], wildcardEntries: 0 });
  assert.equal(report.status, 'fail');
});

test('doctor redirect check: any pattern entry fails even when every exact route is present', async () => {
  for (const pattern of ['https://*.example.test/**', `${ORIGIN}/account/*`, `${ORIGIN}/accoun?/callback`, `${ORIGIN}/[a-z]*`, `${ORIGIN}/{account}/callback`]) {
    const { report, redirect } = await redirectCheck([...EXACT, pattern]);
    assert.deepEqual(redirect, { id: 'redirect_allow_list', mode: 'catalog', status: 'fail', missingRoutes: [], wildcardEntries: 1 }, pattern);
    assert.equal(report.status, 'fail');
  }
  const { redirect } = await redirectCheck(['https://*.example.test/**']);
  assert.deepEqual([redirect.status, redirect.missingRoutes, redirect.wildcardEntries], ['fail', ['callback', 'verify', 'reset'], 1]);
});

test('migrate: an accepted migration whose answer is lost, unreadable or a 5xx is outcome_unknown with the rerun-migrate recovery', async () => {
  for (const answer of [
    async () => { throw new TypeError('connection reset after commit'); },
    async () => jsonResponse(200, { not: 'rows' }),
    async () => new Response('<html>', { status: 200 }),
    async () => jsonResponse(502, { message: 'bad gateway' }),
  ]) {
    const { fake, client } = await setup({ installed: false });
    const state = fake.management;
    let writes = 0;
    fake.management = async (sql) => {
      if (!sql.startsWith('begin;')) return state(sql);
      writes += 1;
      return answer();
    };
    await assert.rejects(client.migrate(), (error) => {
      assert.ok(error instanceof OperatorError);
      assert.equal(error.code, 'outcome_unknown');
      assert.equal(error.details.recovery, 'rerun_migrate');
      assert.match(error.details.stage, /^migration_\d{14}$/);
      assert.doesNotMatch(error.message, /nothing|unchanged/i);
      return true;
    });
    assert.equal(writes, 1, 'the write was sent once');
  }
});

test('migrate: a failed grant assertion after committed files is migration_failed without claiming a rollback', async () => {
  const { fake, client } = await setup();
  const all = readMigrations(DEFAULT_MIGRATIONS_DIR).map((m) => m.version);
  const installed = [];
  fake.management = async (sql) => {
    if (sql.startsWith('begin;')) {
      installed.push(all[installed.length]);
      return jsonResponse(201, []);
    }
    if (sql.includes('to_regnamespace')) return rows({ kit: installed.length > 0, private: installed.length > 0, ledger: installed.length > 0 });
    if (sql.includes('from auth_kit_private.migrations')) return rows(installed);
    if (sql.includes('count(*)::text as result from auth_kit_private.grant_violations()')) return jsonResponse(200, [{ result: '2' }]);
    return jsonResponse(400, { message: 'unexpected query' });
  };
  await assert.rejects(client.migrate(), (error) => {
    assert.equal(error.code, 'migration_failed');
    assert.deepEqual({ ...error.details }, { stage: 'grant_assertion', reason: 'grant_violations', count: 2 });
    assert.doesNotMatch(error.message, /rolled back|nothing|unchanged/i);
    return true;
  });
  assert.deepEqual(installed, all, 'the files were committed before the check failed');
});
