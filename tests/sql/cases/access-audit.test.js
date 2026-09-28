// The access audit (grant_violations, re-run by doctor and run at the end of
// the migration) must report configuration drift that widens access even when
// table privileges and the RLS flag look right: column-only grants on any kit
// relation, and profile policies that are missing, changed or added. Each
// drift is first shown to open real access under impersonation, then shown to
// be reported; removing it returns the audit to empty. A widened installation
// fails its own final assertion.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { withDatabase, open, actors, lit, dbError, migrationFiles, TEMPLATE_BASE } from '../harness/db.js';
import { register, applyModel, exampleModel, join } from '../harness/kit.js';

const violations = (db) => db.rows('select * from auth_kit_private.grant_violations()');

async function assertReported(db, predicate, label) {
  const rows = await violations(db);
  assert.ok(rows.some(predicate), `${label}: ${JSON.stringify(rows)}`);
  return rows;
}

test('a fresh installation reports nothing; service_role and the profile allowlist keep their access', () => withDatabase(async (db) => {
  assert.deepEqual(await violations(db), []);
  const columns = await db.rows(`select c.relname || '.' || a.attname as col,
         has_column_privilege('service_role', c.oid, a.attnum, 'SELECT') as service_select,
         has_column_privilege('service_role', c.oid, a.attnum, 'UPDATE') as service_update,
         has_column_privilege('authenticated', c.oid, a.attnum, 'SELECT') as user_select,
         has_column_privilege('authenticated', c.oid, a.attnum, 'UPDATE') as user_update
    from pg_class c join pg_namespace n on n.oid = c.relnamespace join pg_attribute a on a.attrelid = c.oid
   where n.nspname in ('auth_kit', 'auth_kit_private') and c.relkind in ('r', 'v') and a.attnum > 0 and not a.attisdropped`);
  assert.ok(columns.length > 60, `${columns.length} columns checked`);
  assert.ok(columns.every((c) => c.service_select === 't' && c.service_update === 't'));
  const userSelect = columns.filter((c) => c.user_select === 't').map((c) => c.col).sort();
  assert.deepEqual(userSelect, ['profiles.contact_email', 'profiles.contact_phone', 'profiles.display_name', 'profiles.updated_at',
    'profiles.user_id', 'public_clients.client_id', 'public_clients.display_name']);
  const userUpdate = columns.filter((c) => c.user_update === 't').map((c) => c.col).sort();
  assert.deepEqual(userUpdate, ['profiles.contact_email', 'profiles.contact_phone', 'profiles.display_name']);
}));

test('column-only grants on kit relations open real access and are reported until revoked', () => withDatabase(async (db) => {
  await register(db, 'studio');
  await applyModel(db, 'studio', exampleModel());
  const member = await db.createUser();
  const outsider = await db.createUser();
  await join(db, member, 'studio');
  const asOutsider = actors.user(outsider);

  // A private membership column readable by any signed-in user.
  await dbError(db.as(asOutsider, 'select user_id from auth_kit_private.memberships limit 1'), '42501');
  await db.admin.query('grant select (user_id) on auth_kit_private.memberships to authenticated');
  assert.equal(await db.as(asOutsider, 'select user_id from auth_kit_private.memberships limit 1'), member);
  await assertReported(db, (r) => r.object === 'auth_kit_private.memberships.user_id' && r.grantee === 'authenticated'
    && r.privilege === 'SELECT' && r.expected === 'f' && r.actual === 't', 'private column grant');
  await db.admin.query('revoke select (user_id) on auth_kit_private.memberships from authenticated');
  assert.deepEqual(await violations(db), []);

  // A writable column of public_clients: any user renames a client.
  await db.admin.query('grant update (display_name) on auth_kit.public_clients to authenticated');
  await db.as(asOutsider, "update auth_kit.public_clients set display_name = 'Hijacked' where client_id = 'studio'");
  assert.equal(await db.admin.value("select display_name from auth_kit_private.clients where client_id = 'studio'"), 'Hijacked');
  await assertReported(db, (r) => r.object === 'auth_kit.public_clients.display_name' && r.grantee === 'authenticated'
    && r.privilege === 'UPDATE', 'view column grant');
  await db.admin.query('revoke update (display_name) on auth_kit.public_clients from authenticated');

  // A private column granted through PUBLIC reaches every role that holds schema usage.
  await db.admin.query('grant select (state) on auth_kit_private.clients to public');
  assert.equal(await db.as(asOutsider, 'select state from auth_kit_private.clients'), 'registered');
  const rows = await assertReported(db, (r) => r.object === 'auth_kit_private.clients.state' && r.grantee === 'public', 'public column grant');
  assert.ok(rows.some((r) => r.object === 'auth_kit_private.clients.state' && r.grantee === 'authenticated'), 'inherited by authenticated');
  await db.admin.query('revoke select (state) on auth_kit_private.clients from public');

  // A profile column outside the allowlist.
  await db.admin.query('grant update (user_id) on auth_kit.profiles to authenticated');
  await assertReported(db, (r) => r.object === 'auth_kit.profiles.user_id' && r.grantee === 'authenticated' && r.privilege === 'UPDATE', 'profile column');
  await db.admin.query('revoke update (user_id) on auth_kit.profiles from authenticated');
  assert.deepEqual(await violations(db), []);
}));

test('profile policy drift is reported: added, widened, retargeted, weakened or missing', () => withDatabase(async (db) => {
  const a = await db.createUser();
  const b = await db.createUser();
  await db.call(actors.user(a), 'auth_kit.ensure_profile');
  await db.call(actors.user(b), 'auth_kit.ensure_profile');
  const asB = actors.user(b);
  const visibleToB = async () => db.as(asB, 'select coalesce(json_agg(user_id order by user_id), \'[]\') from auth_kit.profiles');
  assert.deepEqual(await visibleToB(), [b]);

  // An additional permissive policy.
  await db.admin.query('create policy widened on auth_kit.profiles for select to authenticated using (true)');
  assert.deepEqual(await visibleToB(), [a, b].sort());
  await assertReported(db, (r) => r.object === 'auth_kit.profiles policy widened' && r.privilege === 'POLICY' && r.actual === 't', 'added');
  await db.admin.query('drop policy widened on auth_kit.profiles');
  assert.deepEqual(await violations(db), []);

  // The installed select policy changed to allow every row.
  await db.admin.query('alter policy profiles_select_own on auth_kit.profiles using (true)');
  assert.deepEqual(await visibleToB(), [a, b].sort());
  await assertReported(db, (r) => r.object === 'auth_kit.profiles policy profiles_select_own' && r.expected === 't' && r.actual === 'f', 'changed');
  await db.admin.query('alter policy profiles_select_own on auth_kit.profiles using (user_id = (select auth.uid()))');
  assert.deepEqual(await violations(db), []);

  // The insert policy's WITH CHECK weakened: B creates the profile of another user.
  const victim = await db.createUser();
  const plant = `insert into auth_kit.profiles (user_id, display_name) values (${lit(victim)}, 'planted')`;
  await dbError(db.as(asB, plant), '42501');
  await db.admin.query('alter policy profiles_insert_own on auth_kit.profiles with check (true)');
  await db.as(asB, plant);
  assert.equal(await db.admin.value(`select display_name from auth_kit.profiles where user_id = ${lit(victim)}`), 'planted');
  await assertReported(db, (r) => r.object === 'auth_kit.profiles policy profiles_insert_own' && r.actual === 'f', 'weakened check');
  await db.admin.query('alter policy profiles_insert_own on auth_kit.profiles with check (user_id = (select auth.uid()))');
  assert.deepEqual(await violations(db), []);

  // Retargeted to PUBLIC.
  await db.admin.query('alter policy profiles_select_own on auth_kit.profiles to public');
  await assertReported(db, (r) => r.object === 'auth_kit.profiles policy profiles_select_own' && r.actual === 'f', 'retargeted');
  await db.admin.query('alter policy profiles_select_own on auth_kit.profiles to authenticated');

  // Missing: the own-row insert policy dropped (A can no longer create its row).
  await db.admin.query('drop policy profiles_insert_own on auth_kit.profiles');
  await assertReported(db, (r) => r.object === 'auth_kit.profiles policy profiles_insert_own' && r.expected === 't' && r.actual === 'f', 'missing');
  const c = await db.createUser();
  await dbError(db.as(actors.user(c), `insert into auth_kit.profiles (user_id) values (${lit(c)})`), '42501');
  await db.admin.query('create policy profiles_insert_own on auth_kit.profiles for insert to authenticated with check (user_id = (select auth.uid()))');

  // A policy on a private table is not part of the installation either.
  await db.admin.query('alter table auth_kit_private.clients enable row level security');
  await db.admin.query('create policy stray on auth_kit_private.clients for select to authenticated using (true)');
  await assertReported(db, (r) => r.object === 'auth_kit_private.clients policy stray', 'stray');
  await db.admin.query('drop policy stray on auth_kit_private.clients');
  await db.admin.query('alter table auth_kit_private.clients disable row level security');
  assert.deepEqual(await violations(db), []);
}));

test('BYPASSRLS on anon or authenticated is reported', () => withDatabase(async (db) => {
  // Role attributes are cluster-wide, so the change never commits.
  await db.admin.query('begin');
  try {
    await db.admin.query('alter role authenticated bypassrls');
    const rows = await db.rows('select * from auth_kit_private.grant_violations()');
    assert.ok(rows.some((r) => r.object === 'role authenticated' && r.privilege === 'BYPASSRLS'), JSON.stringify(rows));
  } finally {
    await db.admin.query('rollback');
  }
  assert.deepEqual(await violations(db), []);
}));

async function migrateWith(db, extra) {
  const text = fs.readFileSync(migrationFiles()[0], 'utf8');
  const marker = '-- 9. Identity and assertion';
  assert.equal(text.split(marker).length, 2);
  const c = await open('postgres', db.name);
  try {
    return await c.query(text.replace(marker, () => `${extra}\n${marker}`), { timeoutMs: 120_000 });
  } finally {
    await c.close();
  }
}

for (const [label, extra, pattern] of [
  ['a private column-only grant', 'grant select (user_id) on auth_kit_private.memberships to authenticated;',
    /auth_kit_private\.memberships\.user_id \[authenticated\] SELECT expected=f actual=t/],
  ['an added profile policy', 'create policy widened on auth_kit.profiles for select to authenticated using (true);',
    /auth_kit\.profiles policy widened \[authenticated\] POLICY expected=f actual=t/],
  ['a changed profile policy', 'alter policy profiles_select_own on auth_kit.profiles using (true);',
    /auth_kit\.profiles policy profiles_select_own \[authenticated\] POLICY expected=t actual=f/],
]) {
  test(`the migration's final assertion aborts the installation on ${label}`, () => withDatabase(async (db) => {
    const error = await dbError(migrateWith(db, extra), 'P0001');
    assert.match(error.message, pattern);
    assert.equal(await db.admin.value("select count(*) from pg_namespace where nspname in ('auth_kit', 'auth_kit_private')"), '0');
    await migrateWith(db, '');
    assert.deepEqual(await violations(db), []);
  }, { template: TEMPLATE_BASE }));
}
