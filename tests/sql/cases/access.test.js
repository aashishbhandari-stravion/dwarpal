// Actor matrix by real role switching plus request.jwt.claims (the way
// PostgREST calls the database): executed privileges on every function,
// direct table access, profiles own-row RLS, public_clients, the RLS helpers
// inside a real consumer policy, effective_access parity with core's shared
// evaluation fixture, cross-client isolation and malformed claims. This proves
// SQL privileges only; HTTP routing of the private schema is a hosted gate.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { can, createPrincipal } from '@briqvent/dwarpal';
import { FIXTURE_MODEL, FIXTURE_CLIENT_ID, FIXTURE_OTHER_CLIENT_ID, FIXTURE_USER_IDS, fixturePrincipals } from '@briqvent/dwarpal/testing';
import { withDatabase, actors, uuid, dbError, lit, refusal } from '../harness/db.js';
import { register, applyModel, bootstrap, grant, revoke, join, access } from '../harness/kit.js';

const USER_WRAPPERS = ['ensure_profile', 'join_client', 'effective_access', 'grant_membership', 'revoke_membership'];
const HELPERS = ['has_permission', 'has_role', 'has_aal2'];
const USER_IMPLS = [...USER_WRAPPERS.map((n) => `${n}_impl`), 'has_permission_impl', 'has_role_impl'];

/** Executes fn with NULL arguments as `actor` inside a rolled-back transaction; 'denied' or 'allowed'. */
async function probe(db, actor, signature) {
  const session = await db.session(actor);
  const [schema, rest] = signature.split('.');
  const name = rest.slice(0, rest.indexOf('('));
  const types = rest.slice(rest.indexOf('(') + 1, -1).split(',').map((t) => t.trim()).filter(Boolean);
  // Scalar subqueries, not NULL literals: the planner folds a strict function
  // called with a NULL constant to NULL without ever checking EXECUTE.
  const args = types.map((t) => `(select null::${t})`).join(', ');
  await session.begin();
  try {
    await session.query(`select ${schema}.${name}(${args})`);
    return 'allowed';
  } catch (error) {
    // Only a refusal to execute the function (or to resolve its schema) is a
    // denial; an allowed function may still fail inside on missing privileges.
    if (error.code === '42501' && /permission denied for (function|schema) /.test(error.message)) return 'denied';
    return 'allowed';
  } finally {
    await session.rollback().catch(() => {});
    await session.connection.close();
  }
}

test('executed privileges on every function for anon, authenticated and service_role match the grant table', () => withDatabase(async (db) => {
  const user = await db.createUser();
  const rows = await db.rows(`select p.oid::regprocedure::text as sig,
                                     n.nspname as schema, p.proname as name, p.prorettype = 'trigger'::regtype as is_trigger
                                from pg_proc p join pg_namespace n on n.oid = p.pronamespace
                               where n.nspname in ('auth_kit', 'auth_kit_private') order by 1`);
  let checked = 0;
  for (const row of rows) {
    if (row.is_trigger === 't') continue; // a trigger function cannot be called directly by anyone
    const sig = row.sig;
    const expected = {
      anon: row.schema === 'auth_kit' && HELPERS.includes(row.name),
      authenticated: row.schema === 'auth_kit' ? USER_WRAPPERS.includes(row.name) || HELPERS.includes(row.name) : USER_IMPLS.includes(row.name),
      service_role: true,
    };
    for (const [role, actor] of [['anon', actors.anon()], ['authenticated', actors.user(user, 'aal2')], ['service_role', actors.service()]]) {
      assert.equal(await probe(db, actor, sig), expected[role] ? 'allowed' : 'denied', `${role} ${sig}`);
      checked += 1;
    }
  }
  assert.ok(checked > 100, `probed ${checked} role/function pairs`);
  // PUBLIC holds EXECUTE nowhere in either schema.
  const publicExec = await db.rows(`select p.oid::regprocedure::text as f from pg_proc p join pg_namespace n on n.oid = p.pronamespace
                                     where n.nspname in ('auth_kit', 'auth_kit_private') and has_function_privilege('public', p.oid, 'EXECUTE')`);
  assert.deepEqual(publicExec, []);
}));

test('no direct table access for anon or authenticated; service_role has it', () => withDatabase(async (db) => {
  const user = await db.createUser();
  const tables = (await db.rows(`select 'auth_kit_private.' || relname as t from pg_class c join pg_namespace n on n.oid = c.relnamespace
                                  where n.nspname = 'auth_kit_private' and relkind = 'r' order by 1`)).map((r) => r.t);
  assert.equal(tables.length, 10);
  for (const table of tables) {
    for (const actor of [actors.anon(), actors.user(user, 'aal2')]) {
      for (const sql of [`select * from ${table} limit 1`, `delete from ${table}`, `insert into ${table} default values`, `truncate ${table}`]) {
        await dbError(db.as(actor, sql), '42501');
      }
    }
    await db.as(actors.service(), `select * from ${table} limit 1`);
  }
}));

test('profiles: own row only for authenticated, through RLS and column grants; anon has nothing', () => withDatabase(async (db) => {
  const a = await db.createUser();
  const b = await db.createUser();
  const asA = actors.user(a);
  const created = await db.call(asA, 'auth_kit.ensure_profile');
  assert.equal(created.user_id, a);
  assert.deepEqual(await db.call(asA, 'auth_kit.ensure_profile'), created);
  await db.call(actors.user(b), 'auth_kit.ensure_profile');
  await db.as(asA, `update auth_kit.profiles set display_name = 'Ada', contact_phone = '+1 555' where user_id = ${lit(a)}`);
  const visible = await db.as(asA, 'select json_agg(p) from auth_kit.profiles p');
  assert.deepEqual(visible.map((p) => [p.user_id, p.display_name]), [[a, 'Ada']]);
  assert.ok(Date.parse(visible[0].updated_at) >= Date.parse(created.updated_at));
  assert.equal(await db.as(asA, `with u as (update auth_kit.profiles set display_name = 'Mallory' where user_id = ${lit(b)} returning 1) select count(*) from u`), 0);
  const rls = await dbError(db.as(asA, `insert into auth_kit.profiles (user_id, display_name) values (${lit(uuid())}, 'x')`), '42501');
  assert.match(rls.message, /row-level security/);
  await dbError(db.as(asA, `update auth_kit.profiles set user_id = ${lit(b)} where user_id = ${lit(a)}`), '42501');
  await dbError(db.as(asA, `update auth_kit.profiles set updated_at = now() where user_id = ${lit(a)}`), '42501');
  await dbError(db.as(asA, `delete from auth_kit.profiles where user_id = ${lit(a)}`), '42501');
  await dbError(db.as(actors.anon(), 'select * from auth_kit.profiles'), '42501');
  await dbError(db.call(actors.anon(), 'auth_kit.ensure_profile'), '42501');
  assert.equal(Number(await db.as(actors.service(), 'select count(*) from auth_kit.profiles')), 2);
  await refusal(db.call(actors.service(), 'auth_kit.ensure_profile'), 'forbidden');
}));

test('public_clients: authenticated reads id and display name only; anon cannot; nobody writes through it but the operator', () => withDatabase(async (db) => {
  await register(db, 'studio', { name: 'Studio', policy: 'closed' });
  const user = await db.createUser();
  const rows = await db.as(actors.user(user), 'select json_agg(c) from auth_kit.public_clients c');
  assert.deepEqual(rows, [{ client_id: 'studio', display_name: 'Studio' }]);
  await dbError(db.as(actors.anon(), 'select * from auth_kit.public_clients'), '42501');
  await dbError(db.as(actors.user(user), "insert into auth_kit.public_clients values ('x', 'y')"), '42501');
  await dbError(db.as(actors.user(user), "update auth_kit.public_clients set display_name = 'z'"), '42501');
}));

/** Fixture memberships mirroring @briqvent/dwarpal/testing. */
async function fixtureWorld(db) {
  await register(db, FIXTURE_CLIENT_ID);
  await applyModel(db, FIXTURE_CLIENT_ID, JSON.parse(JSON.stringify(FIXTURE_MODEL)));
  await register(db, FIXTURE_OTHER_CLIENT_ID);
  await applyModel(db, FIXTURE_OTHER_CLIENT_ID, { ...JSON.parse(JSON.stringify(FIXTURE_MODEL)), client: FIXTURE_OTHER_CLIENT_ID });
  const ids = FIXTURE_USER_IDS;
  for (const id of Object.values(ids)) await db.createUser({ id });
  const coordinator = actors.user(ids.coordinator);
  await bootstrap(db, ids.coordinator, FIXTURE_CLIENT_ID, 'coordinator');
  await bootstrap(db, ids.lead, FIXTURE_CLIENT_ID, 'lead');
  await bootstrap(db, ids.leadCoordinator, FIXTURE_CLIENT_ID, 'lead');
  await bootstrap(db, ids.leadCoordinator, FIXTURE_CLIENT_ID, 'coordinator');
  for (const id of [ids.patron, ids.otherPatron, ids.patronClerk, ids.enrolledNoRoles]) await join(db, id, FIXTURE_CLIENT_ID);
  await grant(db, coordinator, ids.clerk, FIXTURE_CLIENT_ID, 'clerk');
  await grant(db, coordinator, ids.patronClerk, FIXTURE_CLIENT_ID, 'clerk');
  await revoke(db, coordinator, ids.enrolledNoRoles, FIXTURE_CLIENT_ID, 'patron');
  // The other client: the patron manages it, so nothing of it may leak into the fixture client.
  const otherBoss = await db.createUser();
  await bootstrap(db, otherBoss, FIXTURE_OTHER_CLIENT_ID, 'coordinator');
  await bootstrap(db, ids.patron, FIXTURE_OTHER_CLIENT_ID, 'lead');
  await grant(db, actors.user(otherBoss), ids.notEnrolled, FIXTURE_OTHER_CLIENT_ID, 'clerk');
}

test('effective_access and the helpers agree with core for every principal of the shared evaluation fixture', () => withDatabase(async (db) => {
  await fixtureWorld(db);
  const keys = [...Object.keys(FIXTURE_MODEL.permissions), 'unknown:key', ''];
  const roles = [...Object.keys(FIXTURE_MODEL.roles), 'unknown-role', ''];
  for (const [name, principal] of Object.entries(fixturePrincipals)) {
    const user = principal.identity.userId;
    const aal = principal.session.aal;
    const sql = await access(db, user, FIXTURE_CLIENT_ID, aal);
    assert.equal(sql.client_id, FIXTURE_CLIENT_ID, name);
    assert.deepEqual(sql.active_roles, [...principal.access.activeRoles], `${name}: active roles`);
    assert.deepEqual(sql.permissions, [...principal.access.permissions], `${name}: permissions`);
    assert.equal(sql.mfa_pending, principal.access.mfaPending, `${name}: mfaPending`);
    // The SQL snapshot builds the same principal through core.
    const rebuilt = createPrincipal({
      clientId: sql.client_id,
      identity: principal.identity,
      session: principal.session,
      enrolledAt: sql.enrolled_at,
      memberships: sql.memberships.map((m) => ({
        clientId: sql.client_id, roleKey: m.role_key,
        flags: { selfAssignable: m.flags.self_assignable, managesMembers: m.flags.manages_members, mfaRequired: m.flags.mfa_required },
        grantedAt: m.granted_at, grantedVia: m.granted_via, permissions: m.permissions,
      })),
    });
    assert.deepEqual({ ...rebuilt.access, enrolledAt: null }, { ...principal.access, enrolledAt: null }, `${name}: access`);
    assert.deepEqual(rebuilt.memberships.map((m) => [m.roleKey, m.flags, m.permissions]),
      principal.memberships.map((m) => [m.roleKey, m.flags, m.permissions]), `${name}: memberships`);
    const actor = actors.user(user, aal);
    for (const key of keys) {
      assert.equal(await db.call(actor, 'auth_kit.has_permission', { client_id: FIXTURE_CLIENT_ID, permission_key: key }), can(principal, key), `${name}: has_permission ${key}`);
    }
    for (const role of roles) {
      assert.equal(await db.call(actor, 'auth_kit.has_role', { client_id: FIXTURE_CLIENT_ID, role_key: role }), principal.access.activeRoles.includes(role), `${name}: has_role ${role}`);
    }
    assert.equal(await db.call(actor, 'auth_kit.has_aal2'), aal === 'aal2');
  }
  // The fixture's enrolledAt is a synthetic default; enrollment is asserted where this world defines it.
  const ids = FIXTURE_USER_IDS;
  assert.equal((await access(db, ids.notEnrolled, FIXTURE_CLIENT_ID)).enrolled_at, null);
  const revoked = await access(db, ids.enrolledNoRoles, FIXTURE_CLIENT_ID);
  assert.ok(revoked.enrolled_at !== null && revoked.memberships.length === 0);
}));

test('a consumer RLS policy over the helpers: anon, other client, MFA-withheld and own/any outcomes (L26, L28 SQL part)', () => withDatabase(async (db) => {
  await fixtureWorld(db);
  const ids = FIXTURE_USER_IDS;
  await db.admin.query(`
    create table public.records (id int primary key, owner_id uuid not null, body text not null);
    alter table public.records enable row level security;
    create policy records_read on public.records for select to anon, authenticated using (
      auth_kit.has_permission('${FIXTURE_CLIENT_ID}', 'records:read:any')
      or (auth_kit.has_permission('${FIXTURE_CLIENT_ID}', 'records:read:own') and owner_id = auth.uid()));
    grant usage on schema public to anon, authenticated;
    grant select on public.records to anon, authenticated;
    insert into public.records values (1, '${ids.patron}', 'p'), (2, '${ids.otherPatron}', 'o'), (3, '${ids.patronClerk}', 'pc');`);
  const visible = async (actor) => (await db.as(actor, 'select coalesce(json_agg(id order by id), \'[]\') from public.records')) ?? [];
  // Core's own/any guard (design 4.3) decides the same rows.
  const coreRows = (principal) => [1, 2, 3].filter((id) => {
    const owner = { 1: ids.patron, 2: ids.otherPatron, 3: ids.patronClerk }[id];
    return can(principal, 'records:read:any') || (can(principal, 'records:read:own') && owner === principal.identity.userId);
  });
  assert.deepEqual(await visible(actors.anon()), []);
  for (const [name, principal] of Object.entries(fixturePrincipals)) {
    assert.deepEqual(await visible(actors.user(principal.identity.userId, principal.session.aal)), coreRows(principal), name);
  }
  // L26: customer plus MFA-required staff at aal1 sees only the own row; at aal2 everything.
  assert.deepEqual(await visible(actors.user(ids.patronClerk, 'aal1')), [3]);
  assert.deepEqual(await visible(actors.user(ids.patronClerk, 'aal2')), [1, 2, 3]);
  // A member of another client only: nothing here, though it holds keys there.
  assert.deepEqual(await visible(actors.user(ids.notEnrolled, 'aal2')), []);
  // Anonymous helpers answer false without touching the private schema.
  for (const [fn, args] of [['auth_kit.has_permission', { client_id: FIXTURE_CLIENT_ID, permission_key: 'records:read:any' }],
    ['auth_kit.has_role', { client_id: FIXTURE_CLIENT_ID, role_key: 'patron' }], ['auth_kit.has_aal2', {}]]) {
    assert.equal(await db.call(actors.anon(), fn, args), false, fn);
  }
}));

test('no cross-client leakage: effective_access names the requested client only', () => withDatabase(async (db) => {
  await fixtureWorld(db);
  const ids = FIXTURE_USER_IDS;
  const here = await access(db, ids.patron, FIXTURE_CLIENT_ID, 'aal2');
  assert.deepEqual(here.memberships.map((m) => m.role_key), ['patron']);
  const there = await access(db, ids.patron, FIXTURE_OTHER_CLIENT_ID, 'aal2');
  assert.deepEqual(there.memberships.map((m) => m.role_key), ['lead']);
  assert.equal(there.enrolled_at, null);
  const nowhere = await access(db, ids.patron, 'no-such-client', 'aal2');
  assert.deepEqual(nowhere, { client_id: 'no-such-client', enrolled_at: null, memberships: [], active_roles: [], permissions: [], mfa_pending: false });
  assert.equal(await db.call(actors.user(ids.patron, 'aal2'), 'auth_kit.has_permission', { client_id: FIXTURE_CLIENT_ID, permission_key: 'people:manage' }), false);
  // effective_access requires a user; anon cannot call it at all.
  await dbError(db.call(actors.anon(), 'auth_kit.effective_access', { client_id: FIXTURE_CLIENT_ID }), '42501');
  await refusal(db.call(actors.service(), 'auth_kit.effective_access', { client_id: FIXTURE_CLIENT_ID }), 'forbidden');
}));

test('malformed or forged claims never grant: bad JSON and non-uuid subjects fail, odd aal values stay aal1', () => withDatabase(async (db) => {
  await fixtureWorld(db);
  const ids = FIXTURE_USER_IDS;
  const args = { client_id: FIXTURE_CLIENT_ID, permission_key: 'records:read:any' };
  await dbError(db.call(actors.raw('authenticated', '{not json'), 'auth_kit.has_permission', args), '22P02');
  await dbError(db.call(actors.raw('authenticated', '{"sub":"not-a-uuid","role":"authenticated"}'), 'auth_kit.has_permission', args), '22P02');
  assert.equal(await db.call(actors.raw('authenticated', '{"role":"authenticated"}'), 'auth_kit.has_permission', args), false);
  for (const aal of [null, 2, 'AAL2', ['aal2']]) {
    const claims = JSON.stringify({ sub: ids.lead, role: 'authenticated', aal });
    assert.equal(await db.call(actors.raw('authenticated', claims), 'auth_kit.has_permission', args), false, `aal ${JSON.stringify(aal)}`);
  }
  // Metadata claims are never read for authorization.
  const forged = actors.user(ids.otherPatron, 'aal2', { app_metadata: { roles: ['lead'] }, user_metadata: { role: 'coordinator' } });
  assert.equal(await db.call(forged, 'auth_kit.has_role', { client_id: FIXTURE_CLIENT_ID, role_key: 'lead' }), false);
  assert.equal(await db.call(forged, 'auth_kit.has_permission', args), false);
}));
