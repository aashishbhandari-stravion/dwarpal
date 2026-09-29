// Model lifecycle: registration, whole-model apply, dry-run, annotated diff
// and reach (compared with core planModelChange), export, no-op logging,
// held-role / mapped-permission / promotion / last-manager guards and
// atomicity under injected failures.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { planModelChange } from '@briqvent/dwarpal';
import { withDatabase, actors, uuid, refusal, dbError, jsonLit, sqlArg } from '../harness/db.js';
import {
  service, exampleModel, register, applyModel, exportModel, bootstrap, grant, join, snapshot, requestRow,
} from '../harness/kit.js';

async function holders(db, client) {
  const rows = await db.rows(`select role_key, array_to_json(array_agg(user_id::text order by user_id::text)) as ids
                                from auth_kit_private.memberships where client_id = '${client}' group by role_key`);
  return Object.fromEntries(rows.map((r) => [r.role_key, JSON.parse(r.ids)]));
}

async function state(db, client) {
  return db.admin.value(`select state from auth_kit_private.clients where client_id = '${client}'`);
}

async function currentModel(db, client) {
  const exported = await exportModel(db, client);
  return exported.model_json === null ? null : JSON.parse(exported.model_json);
}

/** Current holders of the client's manager roles, deduplicated and sorted (the L29 affected holders). */
function managerHolders(current, held) {
  const ids = Object.keys(current?.roles ?? {}).filter((role) => current.roles[role].manages_members === true).flatMap((role) => held[role] ?? []);
  return [...new Set(ids)].sort();
}

/**
 * Dry-run in SQL and planModelChange in core must agree exactly, except that
 * SQL's no_manager_would_remain refusal also names the affected holders
 * (L29), which core's plan does not carry.
 */
async function assertPlanParity(db, client, next, label) {
  const current = await currentModel(db, client);
  const held = await holders(db, client);
  const plan = planModelChange(current, next, { state: await state(db, client), holders: held });
  const dry = await applyModel(db, client, next, { dryRun: true });
  assert.equal(dry.result, 'dry_run', label);
  assert.equal(dry.changed, plan.changed, `${label}: changed`);
  assert.deepEqual(dry.diff, JSON.parse(JSON.stringify(plan.diff)), `${label}: diff`);
  const expected = JSON.parse(JSON.stringify(plan.refusals)).map((r) => (r.rule === 'no_manager_would_remain' ? { ...r, holders: managerHolders(current, held) } : r));
  assert.deepEqual(dry.refusals, expected, `${label}: refusals`);
  return dry;
}

test('registration: idempotent on client_id, updates name/policy, never resets a live client', () => withDatabase(async (db) => {
  assert.deepEqual(await register(db, 'studio', { name: 'Studio', policy: 'open' }), { result: 'registered', client_id: 'studio', state: 'registered' });
  assert.deepEqual(await register(db, 'studio', { name: 'Studio', policy: 'open' }), { result: 'unchanged', client_id: 'studio', state: 'registered' });
  assert.deepEqual(await register(db, 'studio', { name: 'Studio Two', policy: 'closed' }), { result: 'updated', client_id: 'studio', state: 'registered' });
  await applyModel(db, 'studio', exampleModel('studio'));
  const manager = await db.createUser();
  await bootstrap(db, manager, 'studio', 'steward');
  assert.equal(await state(db, 'studio'), 'live');
  assert.deepEqual(await register(db, 'studio', { name: 'Renamed', policy: 'open' }), { result: 'updated', client_id: 'studio', state: 'live' });
  assert.equal(await state(db, 'studio'), 'live');
  // The empty string is a literal client id, distinct from every other.
  assert.equal((await register(db, '', { name: 'Empty' })).result, 'registered');
  assert.equal(await db.count('auth_kit_private.clients'), 2);
  // No request_log row for registration (not request-bearing).
  assert.equal(await db.count('auth_kit_private.request_log', "operation not in ('apply_model', 'bootstrap_manager')"), 0);
  await refusal(db.call(service, 'auth_kit.register_client', { client_id: 'x', display_name: 'X', signup_policy: 'invite' }), 'invalid_argument');
  await refusal(db.call(service, 'auth_kit.register_client', { client_id: null, display_name: 'X', signup_policy: 'open' }), 'invalid_argument');
}));

test('dry-run validates, annotates and writes nothing; its request id stays unbound', () => withDatabase(async (db) => {
  await register(db, 'studio');
  const before = await snapshot(db);
  const id = uuid();
  const dry = await applyModel(db, 'studio', exampleModel('studio'), { dryRun: true, requestId: id });
  assert.equal(dry.result, 'dry_run');
  assert.equal(dry.changed, true);
  assert.deepEqual(await snapshot(db), before);
  // The same id is still free for a real apply of a different model.
  const other = exampleModel('studio');
  delete other.roles.reader;
  assert.equal((await applyModel(db, 'studio', other, { requestId: id })).result, 'applied');
}));

test('annotated diff and reach agree with core planModelChange through a scripted model history', () => withDatabase(async (db) => {
  const client = 'studio';
  await register(db, client);
  const m1 = exampleModel(client);
  await assertPlanParity(db, client, m1, 'first model');
  await applyModel(db, client, m1);
  const [ownerId] = [await db.createUser()];
  await bootstrap(db, ownerId, client, 'owner');
  const stewardId = await db.createUser();
  await bootstrap(db, stewardId, client, 'steward');
  const users = [];
  for (let i = 0; i < 3; i += 1) {
    const id = await db.createUser();
    users.push(id);
    await join(db, id, client);
  }
  await grant(db, actors.user(stewardId), users[0], client, 'editor');

  // Every kind of change, with holder counts, integer-like and Unicode keys.
  const m2 = structuredClone(m1);
  m2.permissions['posts:publish'] = 'publish a post';
  delete m2.permissions['reports:read'];
  m2.roles.owner.permissions = m2.roles.owner.permissions.filter((p) => p !== 'reports:read');
  m2.permissions['10'] = 'ten';
  m2.permissions['2'] = 'two';
  m2.permissions['\u{1f600}'] = 'smile';
  m2.permissions['￿'] = '';
  m2.roles.member.permissions.push('10', '\u{1f600}', '￿');
  m2.roles.editor.mfa_required = false;
  m2.roles.editor.description = 'edits';
  m2.roles.reader.self_assignable = false;
  m2.roles['7'] = { self_assignable: true, permissions: ['2'] };
  m2.roles['\u{1f600}'] = { permissions: ['￿'] };
  delete m2.roles.steward.permissions;
  await assertPlanParity(db, client, m2, 'broad change');
  assert.equal((await applyModel(db, client, m2)).result, 'applied');

  // Refusals: removing held roles, promoting holders, no manager remaining.
  const m3 = structuredClone(m2);
  delete m3.roles.member;
  m3.roles.editor.manages_members = true;
  m3.roles.owner.manages_members = false;
  m3.roles.steward.manages_members = false;
  m3.roles.fresh = { manages_members: true };
  const dry = await assertPlanParity(db, client, m3, 'refusals');
  assert.deepEqual(dry.refusals.map((r) => r.rule).sort(), ['no_manager_would_remain', 'promotes_holders', 'role_held']);

  // Unchanged model: no diff.
  const same = await assertPlanParity(db, client, m2, 'unchanged');
  assert.equal(same.changed, false);
  assert.deepEqual(same.diff, []);
}));

test('apply is atomic: an injected failure at the event or request row leaves the model untouched; the same id then applies', () => withDatabase(async (db) => {
  await db.installFaults();
  await register(db, 'studio');
  for (const table of ['model_events', 'request_log', 'role_permissions']) {
    const before = await snapshot(db);
    const id = uuid();
    const error = await dbError(db.call(service, 'auth_kit.apply_model', {
      client_id: 'studio', model: sqlArg(jsonLit(JSON.stringify(exampleModel('studio')))), request_id: id,
    }, { settings: [['dwarpal_test.fail_on', table]] }), 'DT001');
    assert.match(error.message, new RegExp(table));
    assert.deepEqual(await snapshot(db), before, table);
  }
  const id = uuid();
  const applied = await applyModel(db, 'studio', exampleModel('studio'), { requestId: id });
  assert.equal(applied.result, 'applied');
  assert.equal(await db.count('auth_kit_private.model_events'), 1);
}));

test('unchanged model: empty diff, no model event, but a request_log row whose id then conflicts', () => withDatabase(async (db) => {
  await register(db, 'studio');
  await applyModel(db, 'studio', exampleModel('studio'));
  const id = uuid();
  const first = await applyModel(db, 'studio', exampleModel('studio'), { requestId: id });
  assert.equal(first.result, 'unchanged');
  assert.deepEqual(first.diff, []);
  assert.equal(await db.count('auth_kit_private.model_events'), 1);
  const row = await requestRow(db, id);
  assert.equal(row.operation, 'apply_model');
  assert.equal(row.actor_id, 'operator');
  assert.deepEqual(row.result, first);
  const before = await snapshot(db);
  assert.deepEqual(await applyModel(db, 'studio', exampleModel('studio'), { requestId: id }), first);
  const changed = exampleModel('studio');
  changed.permissions['posts:read'] = 'changed';
  await refusal(applyModel(db, 'studio', changed, { requestId: id }), 'request_conflict');
  assert.deepEqual(await snapshot(db), before);
}));

test('held role deletion is refused with its holders; a mapped permission cannot vanish unless unmapped in the same model', () => withDatabase(async (db) => {
  await register(db, 'studio');
  await applyModel(db, 'studio', exampleModel('studio'));
  const user = await db.createUser();
  await join(db, user, 'studio');
  const withoutMember = exampleModel('studio');
  delete withoutMember.roles.member;
  const before = await snapshot(db);
  const error = await refusal(applyModel(db, 'studio', withoutMember), 'model_refused');
  assert.deepEqual(JSON.parse(error.detail), { refusals: [{ rule: 'role_held', role: 'member', holders: [user] }] });
  assert.deepEqual(await snapshot(db), before);

  const stillMapped = exampleModel('studio');
  delete stillMapped.permissions['posts:read'];
  const invalid = await refusal(applyModel(db, 'studio', stillMapped), 'model_invalid');
  assert.ok(JSON.parse(invalid.detail).issues.every((i) => i.rule === 'undeclared_permission'));
  assert.deepEqual(await snapshot(db), before);

  const unmapped = structuredClone(stillMapped);
  for (const role of Object.values(unmapped.roles)) role.permissions = (role.permissions ?? []).filter((p) => p !== 'posts:read');
  assert.equal((await applyModel(db, 'studio', unmapped)).result, 'applied');
  assert.equal(await db.count('auth_kit_private.permissions', "permission_key = 'posts:read'"), 0);
  assert.equal(await db.count('auth_kit_private.role_permissions', "permission_key = 'posts:read'"), 0);
}));

test('strict promotion: manages_members on a held role is refused with the holders; allowed while nobody holds it (L29)', () => withDatabase(async (db) => {
  await register(db, 'studio');
  await applyModel(db, 'studio', exampleModel('studio'));
  const promote = exampleModel('studio');
  promote.roles.editor.manages_members = true;
  // Registered client with no holders: accepted.
  assert.equal((await applyModel(db, 'studio', promote)).result, 'applied');
  await applyModel(db, 'studio', exampleModel('studio'));
  const steward = await db.createUser();
  await bootstrap(db, steward, 'studio', 'steward');
  const holder = await db.createUser();
  await grant(db, actors.user(steward), holder, 'studio', 'editor');
  const before = await snapshot(db);
  const error = await refusal(applyModel(db, 'studio', promote), 'model_refused');
  assert.deepEqual(JSON.parse(error.detail), { refusals: [{ rule: 'promotes_holders', role: 'editor', holders: [holder] }] });
  assert.deepEqual(await snapshot(db), before);
}));

test('a live client keeps an assigned manager; the same models apply on a registered client with no holders (L29)', () => withDatabase(async (db) => {
  const strip = exampleModel('studio');
  strip.roles.steward.manages_members = false;
  strip.roles.owner.manages_members = false;
  strip.roles.newboss = { manages_members: true };
  const drop = exampleModel('studio');
  delete drop.roles.steward;
  delete drop.roles.owner;
  drop.roles.newboss = { manages_members: true, permissions: ['members:manage'] };

  await register(db, 'fresh');
  for (const model of [strip, drop]) {
    const m = { ...structuredClone(model), client: 'fresh' };
    await applyModel(db, 'fresh', exampleModel('fresh'));
    assert.equal((await applyModel(db, 'fresh', m)).result, 'applied');
  }

  await register(db, 'studio');
  await applyModel(db, 'studio', exampleModel('studio'));
  const steward = await db.createUser();
  await bootstrap(db, steward, 'studio', 'steward');
  const before = await snapshot(db);
  const stripped = await refusal(applyModel(db, 'studio', strip), 'model_refused');
  assert.deepEqual(JSON.parse(stripped.detail), { refusals: [{ rule: 'no_manager_would_remain', holders: [steward] }] });
  const dropped = await refusal(applyModel(db, 'studio', drop), 'model_refused');
  assert.deepEqual(JSON.parse(dropped.detail), { refusals: [
    { rule: 'role_held', role: 'steward', holders: [steward] }, { rule: 'no_manager_would_remain', holders: [steward] },
  ] });
  assert.deepEqual(await snapshot(db), before);
  // Dropping the unheld manager role keeps the held one: allowed.
  const keep = exampleModel('studio');
  delete keep.roles.owner;
  keep.permissions = { ...keep.permissions };
  delete keep.permissions['reports:read'];
  assert.equal((await applyModel(db, 'studio', keep)).result, 'applied');

  // Two holders across two manager roles (one holds both): each named once,
  // in order; holders of other roles are not named; still nothing written.
  await register(db, 'duo');
  await applyModel(db, 'duo', exampleModel('duo'));
  const first = await db.createUser();
  const second = await db.createUser();
  const reader = await db.createUser();
  await bootstrap(db, first, 'duo', 'steward');
  await bootstrap(db, first, 'duo', 'owner');
  await bootstrap(db, second, 'duo', 'owner');
  assert.equal((await join(db, reader, 'duo')).result, 'enrolled');
  const wider = await snapshot(db);
  const both = await refusal(applyModel(db, 'duo', { ...structuredClone(strip), client: 'duo' }), 'model_refused');
  assert.deepEqual(JSON.parse(both.detail), { refusals: [{ rule: 'no_manager_would_remain', holders: [first, second].sort() }] });
  assert.deepEqual(await snapshot(db), wider);
}));

test('export: canonical file text for the applied model, null before any model, unknown client refused', () => withDatabase(async (db) => {
  await register(db, 'studio');
  assert.deepEqual(await exportModel(db, 'studio'), { client_id: 'studio', model_json: null, model_hash: null, last_applied_hash: null });
  await refusal(exportModel(db, 'nope'), 'unknown_client');
  await refusal(applyModel(db, 'nope', exampleModel('nope')), 'unknown_client');
  assert.equal(await db.count('auth_kit_private.request_log'), 0);
  // SQL editor drift is visible: the exported hash differs from the last applied one.
  const applied = await applyModel(db, 'studio', exampleModel('studio'));
  await db.admin.query("update auth_kit_private.permissions set description = 'edited in SQL' where permission_key = 'posts:read'");
  const exported = await exportModel(db, 'studio');
  assert.equal(exported.last_applied_hash, applied.model_hash);
  assert.notEqual(exported.model_hash, applied.model_hash);
  assert.equal(JSON.parse(exported.model_json).permissions['posts:read'], 'edited in SQL');
}));

test('operator-only: the SQL editor role and service_role may apply; authenticated and anon may not', () => withDatabase(async (db) => {
  await register(db, 'studio');
  const editor = { role: 'postgres' };
  assert.equal((await applyModel(db, 'studio', exampleModel('studio'), { actor: editor })).result, 'applied');
  const user = await db.createUser();
  for (const actor of [actors.user(user, 'aal2'), actors.anon()]) {
    const error = await dbError(applyModel(db, 'studio', exampleModel('studio'), { actor }), '42501');
    assert.match(error.message, /permission denied/);
    await dbError(db.call(actor, 'auth_kit.export_model', { client_id: 'studio' }), '42501');
    await dbError(db.call(actor, 'auth_kit.register_client', { client_id: 'x', display_name: 'x', signup_policy: 'open' }), '42501');
  }
}));
