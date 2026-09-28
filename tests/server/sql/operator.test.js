// Operator commands against the real migration: register, apply (dry run,
// applied, unchanged, refused), export parity with core, bootstrap and
// revoke-manager with the L30 retry rules. Auth is the fixture; SQL is
// PostgreSQL's. Not hosted evidence.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { withDatabase, uuid } from '../../sql/harness/db.js';
import { exampleModel, snapshot } from '../../sql/harness/kit.js';
import { createOperatorClient, OperatorError } from '../../../packages/server/operator.js';
import { canonicalModelJson, modelHash } from '../../../packages/core/index.js';
import { createFakeSupabase, SECRET_KEY } from '../support/fake-supabase.js';
import { pgRpc, addUser } from '../support/pg-bridge.js';

async function stack(db) {
  const fake = await createFakeSupabase();
  fake.rpc = pgRpc(db);
  return { fake, client: createOperatorClient({ supabaseUrl: fake.origin, secretKey: SECRET_KEY, fetch: fake.fetch }) };
}

async function rejectsWith(promise, code, check) {
  await assert.rejects(promise, (error) => {
    assert.ok(error instanceof OperatorError, `expected ${code}, got ${error?.name} ${error?.code ?? error?.message}`);
    assert.equal(error.code, code);
    check?.(error);
    return true;
  });
}

test('register, apply and export: lifecycle, hash parity and byte-exact canonical export', async () => {
  await withDatabase(async (db) => {
    const { client } = await stack(db);
    await rejectsWith(client.exportModel('studio'), 'unknown_client');
    assert.equal((await client.registerClient({ clientId: 'studio', displayName: 'Studio', signupPolicy: 'open' })).result, 'registered');
    assert.equal((await client.registerClient({ clientId: 'studio', displayName: 'Studio', signupPolicy: 'open' })).result, 'unchanged');
    assert.equal((await client.registerClient({ clientId: 'studio', displayName: 'Studio 2', signupPolicy: 'closed' })).result, 'updated');
    assert.equal((await client.exportModel('studio')).modelJson, null);
    const model = exampleModel('studio');
    const dry = await client.applyModel(model, { dryRun: true });
    assert.equal(dry.result, 'dry_run');
    assert.equal(dry.changed, true);
    assert.equal(dry.hashMatchesFile, true);
    assert.equal(await db.count('auth_kit_private.request_log'), 0, 'a dry run writes nothing');
    const r = uuid();
    const applied = await client.applyModel(model, { requestId: r });
    assert.equal(applied.result, 'applied');
    assert.equal(applied.hashMatchesFile, true);
    assert.equal((await client.applyModel(model, { requestId: r })).result, 'applied', 'replay returns the stored result');
    await rejectsWith(client.applyModel({ ...model, permissions: { ...model.permissions, extra: '' } }, { requestId: r }), 'request_conflict');
    assert.equal((await client.applyModel(model, { requestId: uuid() })).result, 'unchanged');
    const exported = await client.exportModel('studio');
    assert.equal(exported.modelJson, canonicalModelJson(model));
    assert.equal(exported.modelHash, await modelHash(model));
    assert.equal(exported.lastAppliedHash, exported.modelHash);
  });
});

test('bootstrap makes the client live; revoke-manager refuses the last manager; retries follow L30', async () => {
  await withDatabase(async (db) => {
    const { fake, client } = await stack(db);
    await client.registerClient({ clientId: 'studio', displayName: 'Studio', signupPolicy: 'open' });
    const model = exampleModel('studio');
    await client.applyModel(model, { requestId: uuid() });
    const u = await addUser(fake, db);
    const args = { clientId: 'studio', roleKey: 'steward', userId: u };
    await rejectsWith(client.bootstrapManager({ ...args, roleKey: 'member', requestId: uuid() }), 'not_manager_role');
    await rejectsWith(client.bootstrapManager({ ...args, roleKey: 'nope', requestId: uuid() }), 'unknown_role');
    await rejectsWith(client.bootstrapManager({ ...args, clientId: 'nobody', requestId: uuid() }), 'unknown_client');
    const r = uuid();
    assert.equal((await client.bootstrapManager({ ...args, requestId: r })).result, 'granted');
    const [{ state }] = await db.rows("select state from auth_kit_private.clients where client_id = 'studio'");
    assert.equal(state, 'live');
    const before = await snapshot(db);
    assert.equal((await client.bootstrapManager({ ...args, requestId: r })).result, 'granted');
    await rejectsWith(client.bootstrapManager({ ...args, roleKey: 'owner', requestId: r }), 'request_conflict');
    assert.deepEqual(await snapshot(db), before);
    const noop = uuid();
    assert.equal((await client.bootstrapManager({ ...args, requestId: noop })).result, 'already_member');
    await rejectsWith(client.revokeManager({ ...args, requestId: uuid() }), 'last_manager');
    // Demoting the only held manager role on a live client is refused, with the holders.
    const demote = structuredClone(model);
    demote.roles.steward.manages_members = false;
    demote.roles.owner.manages_members = true;
    await rejectsWith(client.applyModel(demote, { requestId: uuid() }), 'model_refused', (error) => {
      assert.deepEqual(error.details.refusals.map((x) => x.rule), ['no_manager_would_remain']);
      assert.ok(!JSON.stringify(error).includes('steward'));
    });
    // Promoting a held role is refused with its holder list (by position, never by key).
    const member = await addUser(fake, db);
    await db.as({ role: 'authenticated', claims: { sub: member, role: 'authenticated', aal: 'aal1' } }, "select auth_kit.join_client('studio')");
    const promote = structuredClone(model);
    promote.roles.reader.self_assignable = false;
    promote.roles.reader.manages_members = true;
    await rejectsWith(client.applyModel(promote, { requestId: uuid() }), 'model_refused', (error) => {
      const refusal = error.details.refusals.find((x) => x.rule === 'promotes_holders');
      assert.equal(refusal.role, `roles.#${Object.keys(promote.roles).sort().indexOf('reader')}`);
      assert.deepEqual(refusal.holders, [member]);
    });
    const second = await addUser(fake, db);
    await client.bootstrapManager({ ...args, userId: second, requestId: uuid() });
    const rr = uuid();
    assert.equal((await client.revokeManager({ ...args, requestId: rr })).result, 'revoked');
    assert.equal((await client.revokeManager({ ...args, requestId: rr })).result, 'revoked');
    assert.equal((await client.revokeManager({ ...args, requestId: uuid() })).result, 'not_member');
  });
});
