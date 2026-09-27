// Migration lifecycle: identity, once-only application, all-or-nothing
// failure, preconditions, and the grant assertion's sensitivity.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { withDatabase, open, migrationFiles, dbError, TEMPLATE_BASE } from '../harness/db.js';

const migrationText = () => fs.readFileSync(migrationFiles()[0], 'utf8');

async function objectCounts(db) {
  const rows = await db.rows(`select
      (select count(*) from pg_namespace where nspname in ('auth_kit', 'auth_kit_private')) as schemas,
      (select count(*) from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname in ('auth_kit', 'auth_kit_private')) as functions,
      (select count(*) from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname in ('auth_kit', 'auth_kit_private')) as relations`);
  return rows[0];
}

async function asMigrator(db, sql) {
  const c = await open('postgres', db.name);
  try {
    return await c.query(sql, { timeoutMs: 120_000 });
  } finally {
    await c.close();
  }
}

test('one migration file, applied as the non-superuser migration role, records its identity', () => withDatabase(async (db) => {
  assert.equal(migrationFiles().length, 1);
  const rows = await db.rows('select version, name from auth_kit_private.migrations');
  assert.deepEqual(rows, [{ version: '20260927000000', name: 'dwarpal_auth_kit' }]);
  const owner = await db.rows(`select r.rolname, r.rolsuper, r.rolbypassrls from pg_namespace n join pg_roles r on r.oid = n.nspowner where n.nspname = 'auth_kit_private'`);
  assert.deepEqual(owner, [{ rolname: 'postgres', rolsuper: 'f', rolbypassrls: 't' }]);
  assert.deepEqual(await db.rows('select * from auth_kit_private.grant_violations()'), []);
}));

test('function inventory: 16 exposed invokers, 15 definer implementations, empty search_path everywhere', () => withDatabase(async (db) => {
  const rows = await db.rows(`select n.nspname as schema, p.proname as name, p.prosecdef as definer, p.proconfig::text as config
                                from pg_proc p join pg_namespace n on n.oid = p.pronamespace
                               where n.nspname in ('auth_kit', 'auth_kit_private') order by 1, 2`);
  const exposed = rows.filter((r) => r.schema === 'auth_kit');
  assert.deepEqual(exposed.map((r) => r.name), ['apply_model', 'bootstrap_manager', 'effective_access', 'ensure_profile', 'export_model',
    'grant_membership', 'has_aal2', 'has_permission', 'has_role', 'join_client', 'mfa_reset_begin', 'mfa_reset_finish', 'mfa_reset_note',
    'register_client', 'revoke_manager', 'revoke_membership']);
  assert.ok(exposed.every((r) => r.definer === 'f'));
  const impls = rows.filter((r) => r.name.endsWith('_impl'));
  assert.equal(impls.length, 15);
  assert.ok(impls.every((r) => r.definer === 't'));
  assert.ok(rows.filter((r) => r.schema === 'auth_kit_private' && !r.name.endsWith('_impl')).every((r) => r.definer === 'f'));
  assert.ok(rows.every((r) => r.config.startsWith('{"search_path=\\"\\""')), 'every function pins search_path to empty');
}));

test('a second application is refused and changes nothing', () => withDatabase(async (db) => {
  const before = await objectCounts(db);
  const error = await dbError(asMigrator(db, migrationText()));
  assert.match(error.message, /already installed/);
  assert.deepEqual(await objectCounts(db), before);
  assert.equal(await db.count('auth_kit_private.migrations'), 1);
}));

test('a failure anywhere in the file leaves nothing behind; the exact file then applies', () => withDatabase(async (db) => {
  const text = migrationText();
  const empty = { schemas: '0', functions: '0', relations: '0' };
  assert.deepEqual(await objectCounts(db), empty);
  // Failure at the very end, after the assertion.
  await dbError(asMigrator(db, `${text}\nselect 1 / 0;`), '22012');
  assert.deepEqual(await objectCounts(db), empty);
  // Failure in the middle: the identity insert is made to fail.
  const broken = text.replace("values ('20260927000000', 'dwarpal_auth_kit')", "values (null, 'dwarpal_auth_kit')");
  assert.notEqual(broken, text);
  await dbError(asMigrator(db, broken), '23502');
  assert.deepEqual(await objectCounts(db), empty);
  await asMigrator(db, text);
  assert.equal(await db.count('auth_kit_private.migrations'), 1);
  assert.deepEqual(await db.rows('select * from auth_kit_private.grant_violations()'), []);
}, { template: TEMPLATE_BASE }));

test('preconditions: no Supabase auth schema, or a non-UTF8 database, is refused before any object exists', async () => {
  await withDatabase(async (db) => {
    await db.admin.query('drop schema auth cascade');
    const error = await dbError(asMigrator(db, migrationText()));
    assert.match(error.message, /auth schema/);
    assert.deepEqual(await objectCounts(db), { schemas: '0', functions: '0', relations: '0' });
  }, { template: TEMPLATE_BASE });
  const root = await open('supabase_admin', 'postgres');
  const name = `t_ascii_${process.pid}`;
  try {
    await root.query(`create database ${name} template template0 encoding 'SQL_ASCII' locale 'C'`);
    await root.query(`grant create on database ${name} to postgres`);
    const c = await open('postgres', name);
    try {
      const error = await dbError(c.query(migrationText()));
      assert.match(error.message, /UTF8/);
    } finally {
      await c.close();
    }
  } finally {
    await root.query(`drop database if exists ${name} with (force)`);
    await root.close();
  }
});

test('grant assertion is sensitive: each widened or missing privilege is reported, and fails the migration', () => withDatabase(async (db) => {
  const widenings = [
    ['grant execute on function auth_kit_private.apply_model_impl(text, jsonb, uuid, boolean) to authenticated', 'auth_kit_private.apply_model_impl', 'authenticated'],
    ['grant execute on function auth_kit.grant_membership(uuid, text, text, uuid) to anon', 'auth_kit.grant_membership', 'anon'],
    ['grant execute on function auth_kit.has_aal2() to public', 'auth_kit.has_aal2', 'public'],
    ['grant select on auth_kit_private.memberships to authenticated', 'auth_kit_private.memberships', 'authenticated'],
    ['grant usage on schema auth_kit_private to anon', 'auth_kit_private', 'anon'],
    ['grant delete on auth_kit.profiles to authenticated', 'auth_kit.profiles', 'authenticated'],
    ['grant update (user_id) on auth_kit.profiles to authenticated', 'auth_kit.profiles.user_id', 'authenticated'],
    ['grant insert on auth_kit.public_clients to authenticated', 'auth_kit.public_clients', 'authenticated'],
    ['revoke execute on function auth_kit.join_client(text) from authenticated', 'auth_kit.join_client', 'authenticated'],
    ['alter table auth_kit.profiles disable row level security', 'auth_kit.profiles', '-'],
    ['alter function auth_kit_private.join_client_impl(text) security invoker', 'auth_kit_private.join_client_impl', '-'],
    ['alter function auth_kit_private.has_role_impl(text, text) reset search_path', 'auth_kit_private.has_role_impl', '-'],
  ];
  for (const [statement, object, grantee] of widenings) {
    await db.admin.query('begin');
    try {
      await db.admin.query(statement);
      const rows = await db.rows('select * from auth_kit_private.grant_violations()');
      assert.ok(rows.some((r) => r.object.startsWith(object) && r.grantee === grantee), `${statement} -> ${JSON.stringify(rows)}`);
    } finally {
      await db.admin.query('rollback');
    }
  }
  // Built-in default: a function created later in the private schema is
  // executable by PUBLIC despite the per-schema default revocation; the
  // assertion reports it (this is why the migration revokes explicitly).
  await db.admin.query('begin');
  try {
    await db.admin.query('set local role postgres');
    await db.admin.query('create function auth_kit_private.later() returns int language sql set search_path = \'\' as $$ select 1 $$');
    const rows = await db.rows('select * from auth_kit_private.grant_violations()');
    assert.ok(rows.some((r) => r.object === 'auth_kit_private.later()' && r.grantee === 'public' && r.privilege === 'EXECUTE'));
  } finally {
    await db.admin.query('rollback');
  }
  assert.deepEqual(await db.rows('select * from auth_kit_private.grant_violations()'), []);
}));

test('the migration\'s own final assertion aborts it when a grant is widened before it runs', () => withDatabase(async (db) => {
  const text = migrationText();
  const marker = '-- 9. Identity and assertion';
  assert.ok(text.includes(marker));
  const widened = text.replace(marker, `grant select on auth_kit_private.request_log to anon;\n${marker}`);
  const error = await dbError(asMigrator(db, widened), 'P0001');
  assert.match(error.message, /grant assertion failed: .*auth_kit_private\.request_log \[anon\] SELECT/);
  assert.deepEqual(await objectCounts(db), { schemas: '0', functions: '0', relations: '0' });
}, { template: TEMPLATE_BASE }));
