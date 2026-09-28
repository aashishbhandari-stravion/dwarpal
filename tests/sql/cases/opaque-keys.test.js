// Opaque keys of any length. Core accepts client ids, role keys and
// permission keys without a length bound, so the SQL authority must store,
// reference, export and authorize them exactly, however long. B-tree entries
// are limited to about 2.7 kB, so the tables key on digests of the text; these
// gates prove the logical contract is unchanged: exact key equality, parity
// with core, request-id retries, references, uniqueness and concurrency, with
// keys that are individually over the limit and with composite tuples that
// only exceed it together. A last gate installs a copy whose digest collides
// on purpose and shows that every lookup still compares the text and that a
// collision can only make a write fail.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { validateModel, canonicalModelJson, modelHash, requestFingerprint } from '@briqvent/dwarpal';
import { withDatabase, open, actors, uuid, lit, refusal, dbError, migrationFiles, TEMPLATE_BASE } from '../harness/db.js';
import {
  register, applyModel, exportModel, bootstrap, revokeManager, grant, revoke, join, access, exampleModel, snapshot, events, requestRow,
} from '../harness/kit.js';

// Hex text of chained SHA-256 digests: deterministic and incompressible, so
// PostgreSQL cannot shrink it below the index limit.
function opaqueKey(label, length) {
  let out = '';
  for (let i = 0; out.length < length; i += 1) out += createHash('sha256').update(`${label}-${i}`).digest('hex');
  return out.slice(0, length);
}

/** The same key with its last character changed. */
function twin(key) {
  return key.slice(0, -1) + (key.endsWith('0') ? '1' : '0');
}

const LONG = 7680;
const PART = 1500; // under the limit alone, over it in any pair

/** exampleModel plus one self-assignable role holding one extra permission. */
function modelWith({ client, role, permission }) {
  const model = exampleModel(client);
  model.permissions[permission] = 'an opaque permission';
  model.roles[role] = { self_assignable: true, description: 'an opaque role', permissions: [permission, 'posts:read'] };
  return model;
}

async function stored(db, table, column, where) {
  return db.admin.value(`select string_agg(${column}, ',') from ${table} where ${where}`);
}

/**
 * The whole lifecycle for one key set: registration, apply/export parity with
 * core, bootstrap, enrollment, helpers, effective_access, manager grant and
 * revoke with request-id replay and conflict, and the held-role refusal.
 */
async function exerciseKeys(db, keys) {
  const { client, role, permission } = keys;
  const model = modelWith(keys);
  validateModel(model);
  assert.equal((await register(db, client)).result, 'registered');
  assert.equal((await register(db, client)).result, 'unchanged');
  const applyId = uuid();
  const applied = await applyModel(db, client, model, { requestId: applyId });
  assert.equal(applied.result, 'applied');
  assert.equal(applied.model_hash, await modelHash(model));
  assert.deepEqual(await applyModel(db, client, model, { requestId: applyId }), applied, 'replay returns the stored result');
  assert.equal((await applyModel(db, client, model)).result, 'unchanged');
  const exported = await exportModel(db, client);
  assert.equal(exported.client_id, client);
  assert.equal(exported.model_json, canonicalModelJson(model), 'export bytes equal core canonical bytes');
  assert.equal(exported.model_hash, await modelHash(model));
  assert.equal(exported.last_applied_hash, applied.model_hash);

  // Stored exactly, full length.
  const clientSql = lit(client);
  assert.equal(await stored(db, 'auth_kit_private.clients', 'client_id', `client_id = ${clientSql}`), client);
  assert.equal(await stored(db, 'auth_kit_private.roles', 'role_key', `client_id = ${clientSql} and role_key = ${lit(role)}`), role);
  assert.equal(await stored(db, 'auth_kit_private.role_permissions', 'permission_key',
    `client_id = ${clientSql} and role_key = ${lit(role)} and permission_key = ${lit(permission)}`), permission);

  const manager = await db.createUser();
  assert.equal((await bootstrap(db, manager, client, 'steward')).result, 'granted');
  assert.equal(await db.admin.value(`select state from auth_kit_private.clients where client_id = ${clientSql}`), 'live');

  const joiner = await db.createUser();
  const joined = await join(db, joiner, client);
  assert.equal(joined.result, 'enrolled');
  assert.deepEqual(joined.granted_roles, [role, 'member', 'reader'].sort());
  assert.equal((await join(db, joiner, client)).result, 'already_enrolled');
  const asJoiner = actors.user(joiner);
  assert.equal(await db.call(asJoiner, 'auth_kit.has_role', { client_id: client, role_key: role }), true);
  assert.equal(await db.call(asJoiner, 'auth_kit.has_permission', { client_id: client, permission_key: permission }), true);
  assert.equal(await db.call(asJoiner, 'auth_kit.has_role', { client_id: client, role_key: twin(role) }), false);
  assert.equal(await db.call(asJoiner, 'auth_kit.has_permission', { client_id: client, permission_key: twin(permission) }), false);
  assert.equal(await db.call(asJoiner, 'auth_kit.has_permission', { client_id: twin(client), permission_key: permission }), false);
  const view = await access(db, joiner, client);
  assert.equal(view.client_id, client);
  assert.deepEqual(view.active_roles, [role, 'member', 'reader'].sort());
  assert.ok(view.permissions.includes(permission));
  assert.deepEqual(view.memberships.find((m) => m.role_key === role).permissions, [permission, 'posts:read'].sort());

  // A manager grant and revoke of the long role to a second user, with replay and conflict.
  const target = await db.createUser();
  const asManager = actors.user(manager);
  const grantId = uuid();
  const granted = await grant(db, asManager, target, client, role, grantId);
  assert.deepEqual(granted, { result: 'granted', user_id: target, client_id: client, role_key: role });
  const before = await snapshot(db);
  assert.deepEqual(await grant(db, asManager, target, client, role, grantId), granted);
  await refusal(grant(db, asManager, joiner, client, role, grantId), 'request_conflict');
  assert.deepEqual(await snapshot(db), before, 'replay and conflict write nothing');
  assert.equal((await grant(db, asManager, target, client, role)).result, 'already_member');
  const row = await requestRow(db, grantId);
  assert.equal(row.client_id, client);
  assert.equal(row.payload_hash, await requestFingerprint({
    operation: 'grant_membership', clientId: client, actorId: manager, payload: { user_id: target, role_key: role } }));
  const [event] = await events(db, `request_id = '${grantId}'`);
  assert.equal(event.client_id, client);
  assert.equal(event.role_key, role);
  await refusal(grant(db, asManager, target, client, twin(role)), 'unknown_role');
  await refusal(grant(db, asManager, target, twin(client), role), 'forbidden');
  const revokeId = uuid();
  assert.equal((await revoke(db, asManager, target, client, role, revokeId)).result, 'revoked');
  assert.equal((await revoke(db, asManager, target, client, role, revokeId)).result, 'revoked');
  assert.equal((await revoke(db, asManager, target, client, role)).result, 'not_member');

  // The role is still held by the joiner: removing it from the model is refused with its holder.
  const without = modelWith(keys);
  delete without.roles[role];
  const error = await refusal(applyModel(db, client, without), 'model_refused');
  assert.deepEqual(JSON.parse(error.detail).refusals, [{ rule: 'role_held', role, holders: [joiner] }]);
  assert.equal((await exportModel(db, client)).model_json, canonicalModelJson(model));
}

test('a client id over the index limit persists and authorizes exactly', () => withDatabase(async (db) => {
  await exerciseKeys(db, { client: opaqueKey('client', LONG), role: 'guest', permission: 'guest:enter' });
}));

test('a role key over the index limit persists and authorizes exactly', () => withDatabase(async (db) => {
  await exerciseKeys(db, { client: 'studio', role: opaqueKey('role', LONG), permission: 'guest:enter' });
}));

test('a permission key over the index limit persists and authorizes exactly', () => withDatabase(async (db) => {
  await exerciseKeys(db, { client: 'studio', role: 'guest', permission: opaqueKey('permission', LONG) });
}));

test('composite keys over the index limit only in combination persist and authorize exactly', () => withDatabase(async (db) => {
  await exerciseKeys(db, { client: opaqueKey('c', PART), role: opaqueKey('r', PART), permission: opaqueKey('p', PART) });
}));

test('long keys that differ only in their last character stay distinct everywhere', () => withDatabase(async (db) => {
  const clientA = opaqueKey('client', LONG);
  const clientB = twin(clientA);
  const roleA = opaqueKey('role', LONG);
  const roleB = twin(roleA);
  const permA = opaqueKey('permission', LONG);
  const permB = twin(permA);
  const model = (client) => {
    const m = exampleModel(client);
    m.permissions[permA] = 'a';
    m.permissions[permB] = 'b';
    m.roles[roleA] = { self_assignable: true, permissions: [permA] };
    m.roles[roleB] = { permissions: [permB] };
    return m;
  };
  for (const client of [clientA, clientB]) {
    assert.equal((await register(db, client)).result, 'registered');
    assert.equal((await applyModel(db, client, model(client))).result, 'applied');
  }
  assert.equal(await db.count('auth_kit_private.clients'), 2);
  assert.equal(await db.count('auth_kit_private.roles', `role_key in (${lit(roleA)}, ${lit(roleB)})`), 4);
  const user = await db.createUser();
  assert.deepEqual((await join(db, user, clientA)).granted_roles, [roleA, 'member', 'reader'].sort());
  const asUser = actors.user(user);
  const has = (client, fn, key) => db.call(asUser, `auth_kit.${fn}`, fn === 'has_role' ? { client_id: client, role_key: key } : { client_id: client, permission_key: key });
  assert.equal(await has(clientA, 'has_role', roleA), true);
  assert.equal(await has(clientA, 'has_role', roleB), false);
  assert.equal(await has(clientB, 'has_role', roleA), false);
  assert.equal(await has(clientA, 'has_permission', permA), true);
  assert.equal(await has(clientA, 'has_permission', permB), false);
  assert.equal(await has(clientB, 'has_permission', permA), false);
  assert.deepEqual((await access(db, user, clientB)).memberships, []);
  for (const client of [clientA, clientB]) {
    assert.equal((await exportModel(db, client)).model_json, canonicalModelJson(model(client)));
  }
  // Removing one twin from one client leaves every other row alone.
  const smaller = model(clientB);
  delete smaller.roles[roleB];
  delete smaller.permissions[permB];
  const applied = await applyModel(db, clientB, smaller);
  assert.deepEqual(applied.diff.map((d) => d.kind), ['permission_removed', 'role_removed']);
  assert.equal((await exportModel(db, clientA)).model_json, canonicalModelJson(model(clientA)));
  assert.equal((await exportModel(db, clientB)).model_json, canonicalModelJson(smaller));
}));

test('direct SQL-editor writes with long keys keep uniqueness, exact references and restrict', () => withDatabase(async (db) => {
  const client = opaqueKey('client', LONG);
  const role = opaqueKey('role', LONG);
  await register(db, client);
  await applyModel(db, client, modelWith({ client, role, permission: 'guest:enter' }));
  const user = await db.createUser();
  const editor = { role: 'postgres' };
  const insertMembership = (r) => db.as(editor,
    `insert into auth_kit_private.memberships (user_id, client_id, role_key, granted_via) values (${lit(user)}, ${lit(client)}, ${lit(r)}, 'operator')`);
  await insertMembership(role);
  await dbError(insertMembership(role), '23505');
  await dbError(insertMembership(twin(role)), '23503');
  await dbError(db.as(editor, `insert into auth_kit_private.roles (client_id, role_key) values (${lit(twin(client))}, 'x')`), '23503');
  await dbError(db.as(editor, `delete from auth_kit_private.roles where client_id = ${lit(client)} and role_key = ${lit(role)}`), '23503');
  await dbError(db.as(editor, `update auth_kit_private.roles set role_key = ${lit(twin(role))} where client_id = ${lit(client)} and role_key = ${lit(role)}`), '23503');
  await dbError(db.as(editor, `update auth_kit_private.clients set client_id = ${lit(twin(client))} where client_id = ${lit(client)}`), '23503');
  // Digests are derived from the text, never written.
  await dbError(db.as(editor, `insert into auth_kit_private.clients (client_id, display_name, signup_policy, client_digest) values ('x', 'x', 'open', '\\x00')`), '428C9');
  // Positional inserts of the logical columns still work.
  await db.as(editor, `insert into auth_kit_private.clients values (${lit(twin(client))}, 'Twin', 'closed')`);
  assert.equal((await db.as(actors.user(user), 'select json_agg(c.client_id order by c.client_id) from auth_kit.public_clients c')).length, 2);
  // The operator path sees the SQL-editor membership exactly.
  assert.equal((await bootstrap(db, user, client, 'steward')).result, 'granted');
  assert.equal(await db.call(actors.user(user), 'auth_kit.has_role', { client_id: client, role_key: role }), true);
  await dbError(db.as(editor, `delete from auth_kit_private.roles where client_id = ${lit(client)} and role_key = 'steward'`), '23503');
}));

test('concurrent writes of one long-key membership: one row, one event, and a racing SQL-editor insert fails loudly', () => withDatabase(async (db) => {
  const client = opaqueKey('client', LONG);
  const role = opaqueKey('role', LONG);
  await register(db, client);
  await applyModel(db, client, modelWith({ client, role, permission: 'guest:enter' }));
  const manager = await db.createUser();
  await bootstrap(db, manager, client, 'steward');
  const target = await db.createUser();
  const first = await db.session(actors.user(manager));
  const second = await db.session(actors.user(manager));
  await first.begin();
  const a = await first.call('auth_kit.grant_membership', { user_id: target, client_id: client, role_key: role, request_id: uuid() });
  await second.begin();
  const pending = second.call('auth_kit.grant_membership', { user_id: target, client_id: client, role_key: role, request_id: uuid() });
  await db.waitForAdvisoryWait(second.pid);
  await first.commit();
  const b = await pending;
  await second.commit();
  assert.deepEqual([a.result, b.result], ['granted', 'already_member']);
  assert.equal(await db.count('auth_kit_private.memberships', `user_id = '${target}'`), 1);
  assert.equal((await events(db, `user_id = '${target}'`)).length, 1);

  // Two SQL-editor sessions insert the same long-key membership: the second
  // waits on the digest key and then fails, it never duplicates.
  const other = await db.createUser();
  const insert = `insert into auth_kit_private.memberships (user_id, client_id, role_key, granted_via) values (${lit(other)}, ${lit(client)}, ${lit(role)}, 'operator')`;
  const e1 = await db.session({ role: 'postgres' });
  const e2 = await db.session({ role: 'postgres' });
  await e1.begin();
  await e1.query(insert);
  await e2.begin();
  const racing = e2.query(insert).then(() => 'inserted', (error) => error.code);
  const deadline = Date.now() + 10_000;
  while (Number(await db.admin.value(`select count(*) from pg_locks where pid = ${e2.pid} and not granted`)) === 0) {
    assert.ok(Date.now() < deadline, 'second insert did not wait');
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  await e1.commit();
  assert.equal(await racing, '23505');
  await e2.rollback();
  assert.equal(await db.count('auth_kit_private.memberships', `user_id = '${other}'`), 1);
}));

// A copy of the migration whose digest ignores letter case, so that keys such
// as 'studio' and 'STUDIO' collide. Nothing may treat them as the same key.
const COLLIDING = "  select sha256(convert_to(lower(p_key), 'UTF8'))";

async function installColliding(db) {
  const text = fs.readFileSync(migrationFiles()[0], 'utf8');
  const anchor = "  select sha256(convert_to(p_key, 'UTF8'))";
  assert.equal(text.split(anchor).length, 2, 'digest body anchor occurs once');
  const c = await open('postgres', db.name);
  try {
    await c.query(text.replace(anchor, () => COLLIDING), { timeoutMs: 120_000 });
  } finally {
    await c.close();
  }
  assert.equal(await db.admin.value("select auth_kit_private.key_digest('studio') = auth_kit_private.key_digest('STUDIO')"), 't');
}

test('with a deliberately colliding digest, lookups stay exact and a collision only makes writes fail', () => withDatabase(async (db) => {
  await installColliding(db);
  assert.deepEqual(await db.rows('select * from auth_kit_private.grant_violations()'), []);
  await register(db, 'studio');
  const registered = await snapshot(db);
  await dbError(register(db, 'STUDIO'), '23505');
  assert.deepEqual(await snapshot(db), registered, 'a colliding client is refused, never merged or reported registered');
  await refusal(exportModel(db, 'STUDIO'), 'unknown_client');
  await refusal(applyModel(db, 'STUDIO', exampleModel('STUDIO')), 'unknown_client');

  // A model whose own keys collide cannot be applied; nothing of it remains.
  const twins = exampleModel('studio');
  twins.roles.READER = { self_assignable: true, permissions: ['posts:read'] };
  await dbError(applyModel(db, 'studio', twins), '23505');
  const twinPermissions = exampleModel('studio');
  twinPermissions.permissions['POSTS:READ'] = '';
  await dbError(applyModel(db, 'studio', twinPermissions), '23505');
  assert.deepEqual(await snapshot(db), registered);

  await applyModel(db, 'studio', exampleModel('studio'));
  const manager = await db.createUser();
  await bootstrap(db, manager, 'studio', 'steward');
  const user = await db.createUser();
  assert.equal((await join(db, user, 'studio')).result, 'enrolled');
  const state = await snapshot(db);
  // Renaming a mapped permission to its colliding twin: the insert fails, the model stays.
  const renamed = exampleModel('studio');
  delete renamed.permissions['posts:read'];
  renamed.permissions['POSTS:READ'] = '';
  for (const r of Object.values(renamed.roles)) r.permissions = (r.permissions ?? []).map((p) => (p === 'posts:read' ? 'POSTS:READ' : p));
  await dbError(applyModel(db, 'studio', renamed), '23505');
  assert.deepEqual(await snapshot(db), state);

  // Every read compares the text.
  const asUser = actors.user(user);
  assert.equal(await db.call(asUser, 'auth_kit.has_role', { client_id: 'studio', role_key: 'reader' }), true);
  assert.equal(await db.call(asUser, 'auth_kit.has_role', { client_id: 'studio', role_key: 'READER' }), false);
  assert.equal(await db.call(asUser, 'auth_kit.has_role', { client_id: 'STUDIO', role_key: 'reader' }), false);
  assert.equal(await db.call(asUser, 'auth_kit.has_permission', { client_id: 'studio', permission_key: 'posts:read' }), true);
  assert.equal(await db.call(asUser, 'auth_kit.has_permission', { client_id: 'studio', permission_key: 'POSTS:READ' }), false);
  assert.equal(await db.call(asUser, 'auth_kit.has_permission', { client_id: 'STUDIO', permission_key: 'posts:read' }), false);
  assert.deepEqual((await access(db, user, 'STUDIO')).memberships, []);
  assert.equal((await access(db, user, 'studio')).enrolled_at !== null, true);
  assert.equal((await join(db, user, 'STUDIO')).result, 'unknown_client');
  const asManager = actors.user(manager);
  const target = await db.createUser();
  await refusal(grant(db, asManager, target, 'studio', 'READER'), 'unknown_role');
  await refusal(revoke(db, asManager, user, 'studio', 'READER'), 'unknown_role');
  await refusal(grant(db, asManager, target, 'STUDIO', 'reader'), 'forbidden');
  await refusal(bootstrap(db, target, 'studio', 'STEWARD'), 'unknown_role');
  await refusal(revokeManager(db, manager, 'STUDIO', 'steward'), 'unknown_client');
  assert.deepEqual(await snapshot(db), state);

  // Direct writes: a reference to the colliding twin, or a key renamed to it, fails.
  const editor = { role: 'postgres' };
  await dbError(db.as(editor, `insert into auth_kit_private.memberships (user_id, client_id, role_key, granted_via) values (${lit(target)}, 'studio', 'READER', 'operator')`), '23503');
  await dbError(db.as(editor, "insert into auth_kit_private.permissions (client_id, permission_key) values ('STUDIO', 'x')"), '23503');
  await dbError(db.as(editor, "insert into auth_kit_private.role_permissions (client_id, role_key, permission_key) values ('studio', 'reader', 'REPORTS:READ')"), '23503');
  await dbError(db.as(editor, "update auth_kit_private.clients set client_id = 'STUDIO' where client_id = 'studio'"), '23503');
  await dbError(db.as(editor, "update auth_kit_private.roles set role_key = 'READER' where client_id = 'studio' and role_key = 'reader'"), '23503');
  await dbError(db.as(editor, "update auth_kit_private.permissions set permission_key = 'REPORTS:READ' where client_id = 'studio' and permission_key = 'reports:read'"), '23503');
  assert.deepEqual(await snapshot(db), state);
}, { template: TEMPLATE_BASE }));
