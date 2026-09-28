// Session resolution and manager writes against the real migration (L30
// manager part, L31, L34, exact opaque keys). Auth and PostgREST routing are
// the synthetic fixture; the SQL answers are PostgreSQL's. Run through
// tests/sql/run.js. Not hosted evidence.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { withDatabase, actors, uuid } from '../../sql/harness/db.js';
import { exampleModel, register, applyModel, bootstrap, grant } from '../../sql/harness/kit.js';
import { createAuthServer, AuthError, can, explain } from '../../../packages/server/index.js';
import { createFakeSupabase, PUBLISHABLE_KEY } from '../support/fake-supabase.js';
import { pgRpc, addUser } from '../support/pg-bridge.js';

async function stack(db, clientId = 'studio') {
  const fake = await createFakeSupabase();
  fake.rpc = pgRpc(db);
  const server = createAuthServer({ supabaseUrl: fake.origin, publishableKey: PUBLISHABLE_KEY, clientId, fetch: fake.fetch });
  return { fake, server };
}

function req(token) {
  return new Request('https://app.example.test/', { headers: { authorization: `Bearer ${token}` } });
}

async function rejects(promise, code) {
  await assert.rejects(promise, (error) => {
    assert.ok(error instanceof AuthError, `expected AuthError ${code}, got ${error?.name} ${error?.code ?? error?.message}`);
    assert.equal(error.code, code);
    return true;
  });
}

async function counts(db) {
  return {
    requests: await db.count('auth_kit_private.request_log'),
    events: await db.count('auth_kit_private.membership_events'),
    memberships: await db.count('auth_kit_private.memberships'),
  };
}

async function liveStudio(db, fake) {
  await register(db, 'studio');
  await applyModel(db, 'studio', exampleModel('studio'));
  const steward = await addUser(fake, db);
  await bootstrap(db, steward, 'studio', 'steward');
  return steward;
}

test('the real effective_access answer converts into a principal that matches it exactly', async () => {
  await withDatabase(async (db) => {
    const { fake, server } = await stack(db);
    const steward = await liveStudio(db, fake);
    const member = await addUser(fake, db);
    await grant(db, actors.user(steward), member, 'studio', 'editor');
    await db.as(actors.user(member), "select auth_kit.join_client('studio')");
    const low = await server.resolveSession(req((await fake.signIn(member)).token));
    assert.deepEqual(low.access.roles, ['editor', 'member', 'reader']);
    assert.deepEqual(low.access.activeRoles, ['member', 'reader']);
    assert.equal(low.access.mfaPending, true);
    assert.match(low.access.enrolledAt, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/);
    assert.deepEqual(explain(low, 'posts:publish').withheld, [{ role: 'editor', reason: 'mfa_required' }]);
    const high = await server.resolveSession(req((await fake.signIn(member, { aal: 'aal2' })).token));
    assert.equal(can(high, 'posts:publish'), true);
    assert.equal(high.access.mfaPending, false);
  });
});

test('L30 manager commands: stored result on replay, conflict on a changed payload or another actor, no-op rows too', async () => {
  await withDatabase(async (db) => {
    const { fake, server } = await stack(db);
    const steward = await liveStudio(db, fake);
    const steward2 = await addUser(fake, db);
    await bootstrap(db, steward2, 'studio', 'steward');
    const target = await addUser(fake, db);
    const other = await addUser(fake, db);
    const t1 = req((await fake.signIn(steward)).token);
    const t2 = req((await fake.signIn(steward2)).token);

    // (i) mutating first call: one event, one request row.
    const r1 = uuid();
    let before = await counts(db);
    assert.equal((await server.grantMembership(target, 'editor', r1, t1)).result, 'granted');
    let after = await counts(db);
    assert.deepEqual([after.requests - before.requests, after.events - before.events], [1, 1]);
    // (a) same id, same payload: the stored result, nothing new.
    before = after;
    assert.equal((await server.grantMembership(target, 'editor', r1, t1)).result, 'granted');
    assert.deepEqual(await counts(db), before);
    // (b) same id, another payload, or the same id from another manager: conflict, nothing new.
    await rejects(server.grantMembership(other, 'editor', r1, t1), 'request_conflict');
    await rejects(server.revokeMembership(target, 'editor', r1, t1), 'request_conflict');
    await rejects(server.grantMembership(target, 'editor', r1, t2), 'request_conflict');
    assert.deepEqual(await counts(db), before);

    // (ii) no-op first call (already_member): a request row, no event; then the same checks.
    const r2 = uuid();
    assert.equal((await server.grantMembership(target, 'editor', r2, t1)).result, 'already_member');
    after = await counts(db);
    assert.deepEqual([after.requests - before.requests, after.events - before.events], [1, 0]);
    assert.equal((await server.grantMembership(target, 'editor', r2, t1)).result, 'already_member');
    await rejects(server.grantMembership(target, 'reader', r2, t1), 'request_conflict');
    const r3 = uuid();
    assert.equal((await server.revokeMembership(other, 'editor', r3, t1)).result, 'not_member');
    await rejects(server.revokeMembership(target, 'editor', r3, t1), 'request_conflict');
    assert.equal((await server.revokeMembership(other, 'editor', r3, t1)).result, 'not_member');
  });
});

test('manager refusals from the real SQL map to the closed consumer set and write nothing', async () => {
  await withDatabase(async (db) => {
    const { fake, server } = await stack(db);
    const steward = await liveStudio(db, fake);
    const plain = await addUser(fake, db);
    const unconfirmed = await addUser(fake, db, { confirmed: false });
    const target = await addUser(fake, db);
    const managerReq = req((await fake.signIn(steward)).token);
    const before = await counts(db);
    await rejects(server.grantMembership(target, 'owner', uuid(), managerReq), 'forbidden'); // manager role
    await rejects(server.grantMembership(target, 'no-such-role', uuid(), managerReq), 'forbidden'); // unknown_role
    await rejects(server.grantMembership('00000000-0000-4000-8000-00000000dead', 'editor', uuid(), managerReq), 'forbidden'); // unknown_user
    await rejects(server.grantMembership(unconfirmed, 'editor', uuid(), managerReq), 'email_unverified');
    await rejects(server.grantMembership(steward, 'editor', uuid(), managerReq), 'forbidden'); // self
    await rejects(server.grantMembership(target, 'editor', uuid(), req((await fake.signIn(plain)).token)), 'forbidden');
    assert.deepEqual(await counts(db), before);
  });
});

test('L34 manager authority with an MFA-free and an MFA-required manager role', async () => {
  await withDatabase(async (db) => {
    const { fake, server } = await stack(db);
    await liveStudio(db, fake);
    const [u1, u2, u3] = [await addUser(fake, db), await addUser(fake, db), await addUser(fake, db)];
    await bootstrap(db, u1, 'studio', 'owner');
    await bootstrap(db, u1, 'studio', 'steward');
    await bootstrap(db, u2, 'studio', 'owner');
    await bootstrap(db, u3, 'studio', 'steward');
    const target = await addUser(fake, db);
    const p1 = await server.resolveSession(req((await fake.signIn(u1)).token));
    assert.deepEqual(explain(p1, 'reports:read').withheld, [{ role: 'owner', reason: 'mfa_required' }]);
    assert.equal((await server.grantMembership(target, 'editor', uuid(), req((await fake.signIn(u1)).token))).result, 'granted');
    const before = await counts(db);
    await rejects(server.grantMembership(target, 'reader', uuid(), req((await fake.signIn(u2)).token)), 'mfa_required');
    assert.deepEqual(await counts(db), before);
    assert.equal((await server.grantMembership(target, 'reader', uuid(), req((await fake.signIn(u3)).token))).result, 'granted');
    assert.equal((await server.grantMembership(target, 'member', uuid(), req((await fake.signIn(u2, { aal: 'aal2' })).token))).result, 'granted');
  });
});

test('L31 a manager of client A who is a member of client B resolves, on B, to B only', async () => {
  await withDatabase(async (db) => {
    const { fake } = await stack(db);
    await liveStudio(db, fake);
    await register(db, 'bakery');
    await applyModel(db, 'bakery', exampleModel('bakery'));
    const user = await addUser(fake, db);
    await bootstrap(db, user, 'studio', 'steward');
    await db.as(actors.user(user), "select auth_kit.join_client('bakery')");
    const onB = createAuthServer({ supabaseUrl: fake.origin, publishableKey: PUBLISHABLE_KEY, clientId: 'bakery', fetch: fake.fetch });
    const principal = await onB.resolveSession(req((await fake.signIn(user)).token));
    assert.deepEqual(principal.memberships.map((m) => [m.clientId, m.roleKey]), [['bakery', 'member'], ['bakery', 'reader']]);
    assert.equal(can(principal, 'members:manage'), false);
    assert.ok(!JSON.stringify(principal).includes('studio'));
    assert.ok(fake.callsTo('rpc').every((c) => c.body.client_id === 'bakery'));
    // A manager token for A cannot act on B through B's server.
    await rejects(onB.grantMembership(await addUser(fake, db), 'editor', uuid(), req((await fake.signIn(user)).token)), 'forbidden');
  });
});

test('exact opaque keys survive the round trip, including the empty client, role and permission key', async () => {
  await withDatabase(async (db) => {
    const { fake, server } = await stack(db, '');
    const model = {
      client: '',
      roles: { '': { manages_members: true, permissions: ['', 'members:manage'] }, ' ': { permissions: [''] } },
      permissions: { '': 'the empty key', 'members:manage': 'manage' },
    };
    await register(db, '');
    await applyModel(db, '', model);
    const manager = await addUser(fake, db);
    await bootstrap(db, manager, '', '');
    const target = await addUser(fake, db);
    const managerReq = req((await fake.signIn(manager)).token);
    const principal = await server.resolveSession(managerReq);
    assert.equal(principal.access.clientId, '');
    assert.deepEqual(principal.access.roles, ['']);
    assert.equal(can(principal, ''), true);
    const granted = await server.grantMembership(target, ' ', uuid(), managerReq);
    assert.equal(granted.roleKey, ' ');
    assert.equal(granted.clientId, '');
    const targetPrincipal = await server.resolveSession(req((await fake.signIn(target)).token));
    assert.deepEqual(targetPrincipal.access.activeRoles, [' ']);
    assert.deepEqual(targetPrincipal.access.permissions, ['']);
  });
});
