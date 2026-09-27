// Membership commands: manager authority (I15, active roles only), target
// rules, operator bootstrap and revoke_manager, cross-client isolation, and
// the two-manager-role case L34 checked against core's shared fixture.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { explain, requireRole, isAuthError } from '@briqvent/dwarpal';
import { FIXTURE_MODEL, FIXTURE_CLIENT_ID, fixturePrincipals } from '@briqvent/dwarpal/testing';
import { withDatabase, actors, refusal, dbError, lit, uuid } from '../harness/db.js';
import {
  exampleModel, register, applyModel, bootstrap, revokeManager, grant, revoke, join, snapshot, events, requestRow,
} from '../harness/kit.js';

async function studio(db) {
  await register(db, 'studio');
  await applyModel(db, 'studio', exampleModel('studio'));
  const steward = await db.createUser();
  await bootstrap(db, steward, 'studio', 'steward');
  return steward;
}

test('grant and revoke by an active manager: rows, events with the actor, and no-op outcomes', () => withDatabase(async (db) => {
  const steward = await studio(db);
  const manager = actors.user(steward);
  const target = await db.createUser();
  const id = uuid();
  assert.deepEqual(await grant(db, manager, target, 'studio', 'editor', id),
    { result: 'granted', user_id: target, client_id: 'studio', role_key: 'editor' });
  const [event] = await events(db, `request_id = ${lit(id)}`);
  assert.equal(event.action, 'grant');
  assert.equal(event.actor_user_id, steward);
  assert.equal(event.actor_kind, 'user');
  assert.equal(event.payload_hash, (await requestRow(db, id)).payload_hash);
  const row = await db.rows(`select granted_via, granted_by from auth_kit_private.memberships where user_id = ${lit(target)} and role_key = 'editor'`);
  assert.deepEqual(row, [{ granted_via: 'manager', granted_by: steward }]);
  assert.equal((await grant(db, manager, target, 'studio', 'editor')).result, 'already_member');
  assert.equal((await revoke(db, manager, target, 'studio', 'editor')).result, 'revoked');
  assert.equal((await revoke(db, manager, target, 'studio', 'editor')).result, 'not_member');
  assert.deepEqual((await events(db, `user_id = ${lit(target)}`)).map((e) => e.action), ['grant', 'revoke']);
}));

test('manager authority: none -> forbidden, only MFA-withheld -> mfa_required, aal2 -> allowed; nothing written on refusal', () => withDatabase(async (db) => {
  await studio(db);
  const owner = await db.createUser();
  await bootstrap(db, owner, 'studio', 'owner');
  const plain = await db.createUser();
  await join(db, plain, 'studio');
  const target = await db.createUser();
  const before = await snapshot(db);
  await refusal(grant(db, actors.user(plain), target, 'studio', 'editor'), 'forbidden');
  await refusal(grant(db, actors.user(owner, 'aal1'), target, 'studio', 'editor'), 'mfa_required');
  await refusal(revoke(db, actors.user(owner, 'aal1'), plain, 'studio', 'member'), 'mfa_required');
  // An aal claim other than exactly aal2 never activates an MFA role.
  for (const aal of ['AAL2', 'aal3', '', 'aal2 ']) await refusal(grant(db, actors.user(owner, aal), target, 'studio', 'editor'), 'mfa_required');
  assert.deepEqual(await snapshot(db), before);
  assert.equal((await grant(db, actors.user(owner, 'aal2'), target, 'studio', 'editor')).result, 'granted');
}));

test('target rules: manager roles, unknown role, unknown or unconfirmed user and self are refused', () => withDatabase(async (db) => {
  const steward = await studio(db);
  const manager = actors.user(steward);
  const target = await db.createUser();
  const unconfirmed = await db.createUser({ confirmed: false });
  const before = await snapshot(db);
  await refusal(grant(db, manager, target, 'studio', 'owner'), 'forbidden');
  await refusal(grant(db, manager, target, 'studio', 'steward'), 'forbidden');
  await refusal(revoke(db, manager, steward, 'studio', 'steward'), 'forbidden');
  await refusal(grant(db, manager, target, 'studio', 'nope'), 'unknown_role');
  await refusal(revoke(db, manager, target, 'studio', 'nope'), 'unknown_role');
  await refusal(grant(db, manager, uuid(), 'studio', 'editor'), 'unknown_user');
  await refusal(grant(db, manager, unconfirmed, 'studio', 'editor'), 'email_unverified');
  await refusal(grant(db, manager, steward, 'studio', 'editor'), 'forbidden');
  for (const args of [{ user_id: null }, { client_id: null }, { role_key: null }, { request_id: null }]) {
    await refusal(db.call(manager, 'auth_kit.grant_membership', { user_id: target, client_id: 'studio', role_key: 'editor', request_id: uuid(), ...args }), 'invalid_argument');
  }
  assert.deepEqual(await snapshot(db), before);
}));

test('authority is per client: a manager of one client is nobody in another; the actor is never an argument', () => withDatabase(async (db) => {
  const steward = await studio(db);
  await register(db, 'other');
  await applyModel(db, 'other', exampleModel('other'));
  const target = await db.createUser();
  await refusal(grant(db, actors.user(steward), target, 'other', 'editor'), 'forbidden');
  await refusal(grant(db, actors.user(steward), target, 'nowhere', 'editor'), 'forbidden');
  // service_role has no user id: it cannot act as a manager.
  await refusal(grant(db, actors.service(), target, 'studio', 'editor'), 'forbidden');
  // The only way to name an actor is the verified claims.
  const signature = await db.admin.value(`select pg_get_function_arguments('auth_kit.grant_membership(uuid, text, text, uuid)'::regprocedure)`);
  assert.equal(signature, 'user_id uuid, client_id text, role_key text, request_id uuid');
}));

test('bootstrap_manager: operator only, sets live on first success, refuses unknown and non-manager targets', () => withDatabase(async (db) => {
  await register(db, 'studio');
  const user = await db.createUser();
  const before = await snapshot(db);
  await refusal(bootstrap(db, user, 'studio', 'steward'), 'unknown_role');
  await refusal(bootstrap(db, user, 'nowhere', 'steward'), 'unknown_client');
  assert.deepEqual(await snapshot(db), before);
  await applyModel(db, 'studio', exampleModel('studio'));
  const unconfirmed = await db.createUser({ confirmed: false });
  const afterModel = await snapshot(db);
  await refusal(bootstrap(db, user, 'studio', 'editor'), 'not_manager_role');
  await refusal(bootstrap(db, uuid(), 'studio', 'steward'), 'unknown_user');
  await refusal(bootstrap(db, unconfirmed, 'studio', 'steward'), 'email_unverified');
  assert.deepEqual(await snapshot(db), afterModel);
  const clientState = () => db.admin.value("select state from auth_kit_private.clients where client_id = 'studio'");
  assert.equal(await clientState(), 'registered');
  assert.equal((await bootstrap(db, user, 'studio', 'steward')).result, 'granted');
  assert.equal(await clientState(), 'live');
  assert.equal((await bootstrap(db, user, 'studio', 'steward')).result, 'already_member');
  assert.equal(await clientState(), 'live');
  const [event] = await events(db, "action = 'bootstrap'");
  assert.equal(event.actor_kind, 'operator');
  assert.equal(event.actor_user_id, null);
  for (const actor of [actors.user(user, 'aal2'), actors.anon()]) {
    await dbError(db.call(actor, 'auth_kit.bootstrap_manager', { user_id: user, client_id: 'studio', role_key: 'steward', request_id: uuid() }), '42501');
    await dbError(db.call(actor, 'auth_kit.revoke_manager', { user_id: user, client_id: 'studio', role_key: 'steward', request_id: uuid() }), '42501');
  }
}));

test('revoke_manager: never the last manager membership; not_member when absent; one event when revoked', () => withDatabase(async (db) => {
  const steward = await studio(db);
  const before = await snapshot(db);
  await refusal(revokeManager(db, steward, 'studio', 'steward'), 'last_manager');
  await refusal(revokeManager(db, steward, 'studio', 'editor'), 'not_manager_role');
  await refusal(revokeManager(db, steward, 'studio', 'nope'), 'unknown_role');
  assert.deepEqual(await snapshot(db), before);
  assert.equal((await revokeManager(db, uuid(), 'studio', 'steward')).result, 'not_member');
  const second = await db.createUser();
  await bootstrap(db, second, 'studio', 'owner');
  assert.equal((await revokeManager(db, steward, 'studio', 'steward')).result, 'revoked');
  await refusal(revokeManager(db, second, 'studio', 'owner'), 'last_manager');
  // The same user holding two manager roles may lose one of them.
  await bootstrap(db, second, 'studio', 'steward');
  assert.equal((await revokeManager(db, second, 'studio', 'owner')).result, 'revoked');
  assert.deepEqual((await events(db, "action = 'revoke_manager'")).length, 2);
}));

// L34 against the shared evaluation fixture: `coordinator` manages members
// without MFA (role A), `lead` manages members with MFA (role B).
test('L34: two manager roles at aal1 and aal2 match core evaluation of the shared fixture', () => withDatabase(async (db) => {
  const client = FIXTURE_CLIENT_ID;
  await register(db, client);
  await applyModel(db, client, JSON.parse(JSON.stringify(FIXTURE_MODEL)));
  const u1 = await db.createUser();
  const u2 = await db.createUser();
  const u3 = await db.createUser();
  const nobody = await db.createUser();
  await bootstrap(db, u1, client, 'lead');
  await bootstrap(db, u1, client, 'coordinator');
  await bootstrap(db, u2, client, 'lead');
  await bootstrap(db, u3, client, 'coordinator');
  await join(db, nobody, client);
  const targets = [await db.createUser(), await db.createUser(), await db.createUser(), await db.createUser()];
  const has = (user, aal, role) => db.call(actors.user(user, aal), 'auth_kit.has_role', { client_id: client, role_key: role });

  // U1: granted through the MFA-free role; lead is withheld at aal1.
  assert.equal((await grant(db, actors.user(u1, 'aal1'), targets[0], client, 'clerk')).result, 'granted');
  assert.equal(await has(u1, 'aal1', 'coordinator'), true);
  assert.equal(await has(u1, 'aal1', 'lead'), false);
  const p1 = fixturePrincipals.leadCoordinatorAal1;
  assert.deepEqual(explain(p1, 'tasks:assign:any').withheld, [{ role: 'lead', reason: 'mfa_required' }]);
  assert.deepEqual(p1.access.activeRoles, ['coordinator']);

  // U2 at aal1: mfa_required, nothing written; at aal2 granted.
  const before = await snapshot(db);
  await refusal(grant(db, actors.user(u2, 'aal1'), targets[1], client, 'clerk'), 'mfa_required');
  assert.deepEqual(await snapshot(db), before);
  assert.throws(() => requireRole(fixturePrincipals.leadAal1, ['lead', 'coordinator']), (e) => isAuthError(e) && e.code === 'mfa_required');
  assert.equal((await grant(db, actors.user(u2, 'aal2'), targets[1], client, 'clerk')).result, 'granted');
  assert.equal(requireRole(fixturePrincipals.leadAal2, ['lead', 'coordinator']), fixturePrincipals.leadAal2);

  // U3: granted.
  assert.equal((await grant(db, actors.user(u3, 'aal1'), targets[2], client, 'clerk')).result, 'granted');
  assert.equal(requireRole(fixturePrincipals.coordinator, ['lead', 'coordinator']), fixturePrincipals.coordinator);

  // No manager role: forbidden, as core says for the same principal.
  await refusal(grant(db, actors.user(nobody, 'aal2'), targets[3], client, 'clerk'), 'forbidden');
  assert.throws(() => requireRole(fixturePrincipals.patron, ['lead', 'coordinator']), (e) => isAuthError(e) && e.code === 'forbidden');
}));
