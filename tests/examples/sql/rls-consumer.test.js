// examples/rls-consumer/policies.sql — the file a consumer would apply — run
// against the real migration on a throwaway PostgreSQL through role and claim
// impersonation (the way PostgREST calls the database). Covers L26(b) and the
// consumer side of L28, plus membership revoke taking effect on the next query.
// Run through tests/sql/run.js (`npm run test:examples-sql`). SQL proof only:
// PostgREST routing, JWT verification and live Auth sessions are not present,
// so the JWT-expiry revocation bound (L25b) remains a hosted gate.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { withDatabase, actors, dbError, lit } from '../../sql/harness/db.js';
import { setupClient, join, grant, revoke } from '../../sql/harness/kit.js';

const model = JSON.parse(readFileSync(new URL('../../../examples/rls-consumer/auth-model.json', import.meta.url), 'utf8'));
const policies = readFileSync(new URL('../../../examples/rls-consumer/policies.sql', import.meta.url), 'utf8');
const CLIENT = model.client;

async function world(db) {
  const [managerId] = await setupClient(db, CLIENT, model, { managers: [{ role: 'manager' }] });
  await setupClient(db, 'other-client', { ...model, client: 'other-client' }, { managers: [{ role: 'manager' }] });
  await db.admin.query(policies);
  const ids = { manager: managerId };
  for (const name of ['alice', 'bob', 'staffer']) {
    ids[name] = await db.createUser();
    await join(db, ids[name], CLIENT);
  }
  ids.stranger = await db.createUser();
  await join(db, ids.stranger, 'other-client');
  await grant(db, actors.user(ids.manager, 'aal2'), ids.staffer, CLIENT, 'staff');
  await db.admin.query(`insert into app.notes (owner_id, title) values (${lit(ids.alice)}, 'alice'), (${lit(ids.bob)}, 'bob')`);
  return ids;
}

const titles = async (db, actor) => (await db.as(actor, `select coalesce(json_agg(title order by title), '[]') from app.notes`)) ?? [];

test('the example policies: own/any, MFA withholding, other clients and anon (L26 b, L28 consumer side)', () => withDatabase(async (db) => {
  const ids = await world(db);
  assert.deepEqual(await titles(db, actors.user(ids.alice, 'aal1')), ['alice']);
  assert.deepEqual(await titles(db, actors.user(ids.bob, 'aal2')), ['bob']);
  // Customer plus MFA-required staff: the own row at aal1, every row at aal2.
  assert.deepEqual(await titles(db, actors.user(ids.staffer, 'aal1')), []);
  assert.deepEqual(await titles(db, actors.user(ids.staffer, 'aal2')), ['alice', 'bob']);
  assert.deepEqual(await titles(db, actors.user(ids.manager, 'aal1')), []);
  assert.deepEqual(await titles(db, actors.user(ids.manager, 'aal2')), ['alice', 'bob']);
  // A user who belongs to another client only sees nothing here, whatever their aal.
  assert.deepEqual(await titles(db, actors.user(ids.stranger, 'aal2')), []);
  // anon has no grant at all.
  await dbError(db.as(actors.anon(), 'select count(*) from app.notes'), '42501');
  // Metadata claims are never read for authorization.
  const forged = actors.user(ids.bob, 'aal2', { app_metadata: { roles: ['staff'] }, user_metadata: { role: 'staff' } });
  assert.deepEqual(await titles(db, forged), ['bob']);
}));

test('writes follow the same keys: own rows only for a member, any row for active staff', () => withDatabase(async (db) => {
  const ids = await world(db);
  const alice = actors.user(ids.alice, 'aal1');
  await db.as(alice, `insert into app.notes (title) values ('alice two')`);
  await dbError(db.as(alice, `insert into app.notes (owner_id, title) values (${lit(ids.bob)}, 'forged owner')`), '42501');
  // Another member's row is invisible to update and delete: no error, no change.
  await db.as(alice, `update app.notes set body = 'changed' where title = 'bob'`);
  await db.as(alice, `delete from app.notes where title = 'bob'`);
  assert.equal(await db.count('app.notes', `title = 'bob' and body = ''`), 1);
  // A change may not move a row to someone else.
  await dbError(db.as(alice, `update app.notes set owner_id = ${lit(ids.bob)} where title = 'alice'`), '42501');
  // Staff at aal1 has no active broad key; at aal2 it may change any row.
  const staffAal1 = actors.user(ids.staffer, 'aal1');
  await db.as(staffAal1, `update app.notes set body = 'no' where title = 'bob'`);
  assert.equal(await db.count('app.notes', `body = 'no'`), 0);
  await db.as(actors.user(ids.staffer, 'aal2'), `update app.notes set body = 'yes' where title = 'bob'`);
  assert.equal(await db.count('app.notes', `title = 'bob' and body = 'yes'`), 1);
}));

test('a membership revoke or a role change takes effect on the next query, with the same token claims', () => withDatabase(async (db) => {
  const ids = await world(db);
  const staffer = actors.user(ids.staffer, 'aal2');
  assert.deepEqual(await titles(db, staffer), ['alice', 'bob']);
  await revoke(db, actors.user(ids.manager, 'aal2'), ids.staffer, CLIENT, 'staff');
  // The claims are unchanged (an unexpired token), the answer is not: membership is read live.
  assert.deepEqual(await titles(db, staffer), []);
  await revoke(db, actors.user(ids.manager, 'aal2'), ids.alice, CLIENT, 'member');
  assert.deepEqual(await titles(db, actors.user(ids.alice, 'aal1')), []);
  await grant(db, actors.user(ids.manager, 'aal2'), ids.alice, CLIENT, 'member');
  assert.deepEqual(await titles(db, actors.user(ids.alice, 'aal1')), ['alice']);
}));

test('the helpers answer false, without an error, for anon and unknown keys', () => withDatabase(async (db) => {
  const ids = await world(db);
  assert.equal(await db.call(actors.anon(), 'auth_kit.has_permission', { client_id: CLIENT, permission_key: 'notes:read:any' }), false);
  assert.equal(await db.call(actors.user(ids.alice, 'aal2'), 'auth_kit.has_permission', { client_id: CLIENT, permission_key: 'notes:read:everything' }), false);
  assert.equal(await db.call(actors.user(ids.alice, 'aal2'), 'auth_kit.has_permission', { client_id: 'no-such-client', permission_key: 'notes:read:own' }), false);
}));
