// The operator flow of design 7 / LLD S1 through the real auth-kit executable,
// against the real migration on the SQL harness cluster (run through
// tests/sql/run.js): migrate, doctor, register-client, apply-model (dry run,
// apply, replay), export-model, bootstrap-manager, doctor again, mfa-reset
// and revoke-manager. Auth, PostgREST routing and the Management API's HTTP
// layer are the loopback fixture. Local evidence only; not hosted proof.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { withDatabase, TEMPLATE_BASE } from '../sql/harness/db.js';
import { exampleModel, requestRow } from '../sql/harness/kit.js';
import { canonicalModelJson } from '../../packages/core/index.js';
import { createFakeSupabase, PUBLISHABLE_KEY } from '../server/support/fake-supabase.js';
import { pgRpc, pgManagement, addUser } from '../server/support/pg-bridge.js';
import { runCli, baseEnv, PROBE_PASSWORD } from './support.js';

test('operator flow end to end through the CLI', async () => {
  await withDatabase(async (db) => {
    const fake = await createFakeSupabase();
    fake.rpc = pgRpc(db);
    fake.management = pgManagement(db);
    await fake.listen();
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dwl3-flow-'));
    try {
      const env = baseEnv(fake);
      const model = exampleModel('studio');
      fs.writeFileSync(path.join(dir, 'auth-model.json'), JSON.stringify(model, null, 2));
      fs.writeFileSync(path.join(dir, 'auth-kit.config.json'), JSON.stringify({
        clientId: 'studio', supabaseUrl: fake.origin, publishableKey: PUBLISHABLE_KEY, origin: 'https://www.example.test',
        allowedReturnPaths: ['/'], defaultReturnPath: '/', providers: { email: true, google: false }, selfSignup: true,
      }));
      fake.authConfig.uri_allow_list = ['callback', 'verify', 'reset'].map((r) => `https://www.example.test/account/${r}`).join(',');
      const cli = (args, extra = {}) => runCli(args, { env, cwd: dir, ...extra });

      const migrated = await cli(['migrate']);
      assert.equal(migrated.code, 0, migrated.stderr);
      assert.equal(migrated.json.result, 'migrated');
      assert.equal((await cli(['migrate'])).json.result, 'up_to_date');

      const early = await cli(['doctor', '--config', 'auth-kit.config.json']);
      assert.equal(early.code, 1, 'client not registered yet');
      assert.equal(early.json.checks.find((c) => c.id === 'grants').status, 'ok');
      assert.equal(early.json.checks.find((c) => c.id === 'client_registration').reason, 'not_registered');

      assert.equal((await cli(['register-client', '--client', 'studio', '--name', 'Studio', '--signup', 'open'])).json.result, 'registered');
      const dry = await cli(['apply-model', '--dry-run']);
      assert.equal(dry.json.changed, true);
      assert.equal(dry.json.hashMatchesFile, true);
      const requestId = '00000000-0000-4000-8000-00000000c0de';
      assert.equal((await cli(['apply-model', '--request-id', requestId])).json.result, 'applied');
      assert.equal((await cli(['apply-model', '--request-id', requestId])).json.result, 'applied', 'replay');
      assert.equal((await cli(['apply-model'])).json.result, 'unchanged');
      const exported = await cli(['export-model', '--client', 'studio']);
      assert.equal(exported.stdout, `${canonicalModelJson(model)}\n`);

      const manager = await addUser(fake, db);
      const unconfirmed = await addUser(fake, db, { confirmed: false });
      const refusedBoot = await cli(['bootstrap-manager', '--client', 'studio', '--role', 'steward', '--user-id', unconfirmed]);
      assert.equal(refusedBoot.json.error, 'email_unverified');
      const boot = await cli(['bootstrap-manager', '--client', 'studio', '--role', 'steward', '--user-id', manager]);
      assert.equal(boot.code, 0, boot.stderr);
      assert.equal(boot.json.result, 'granted');

      await addUser(fake, db, { email: 'probe-user@example.test', password: PROBE_PASSWORD });
      const healthy = await cli(['doctor', '--config', 'auth-kit.config.json', '--model', 'auth-model.json', '--probe', '--probe-email', 'probe-user@example.test'],
        { forbidden: ['probe-user@'] });
      assert.equal(healthy.code, 0, JSON.stringify(healthy.json?.checks?.filter((c) => c.status !== 'ok')));
      assert.equal(healthy.json.probeRan, true);
      assert.ok(!/no actor probe ran/.test(healthy.stderr));

      const factor = fake.addFactor(manager);
      const resetId = '00000000-0000-4000-8000-00000000fade';
      const reset = await cli(['mfa-reset', '--user-id', manager, '--request-id', resetId]);
      assert.equal(reset.code, 0, reset.stderr);
      assert.deepEqual(reset.json.factorsDeleted, [factor]);
      assert.equal((await requestRow(db, resetId)).state, 'completed');
      const replay = await cli(['mfa-reset', '--user-id', manager, '--request-id', resetId]);
      assert.equal(replay.json.outcome, 'completed');

      const last = await cli(['revoke-manager', '--client', 'studio', '--role', 'steward', '--user-id', manager]);
      assert.equal(last.code, 1);
      assert.equal(last.json.error, 'last_manager');
    } finally {
      await fake.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }, { template: TEMPLATE_BASE });
});
