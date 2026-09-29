// Harness self-test, not hosted evidence: runs the hosted harness's own SQL
// (catalog reads and the impersonation probe) against the real migration on
// the throwaway PostgreSQL cluster of tests/sql. It proves the statements the
// harness will send through the Management API parse, return what the
// harness expects, roll back everything an impersonated call did, and leave
// no role or claim setting on the connection. PostgREST, the Management API
// envelope and hosted grants are not involved.
//
//   DWARPAL_PG_BIN=<bin> node tests/sql/run.js tests/hosted/selftest/sql/probes.test.js

import test from 'node:test';
import assert from 'node:assert/strict';
import { withDatabase, PgError } from '../../../sql/harness/db.js';
import {
  probeStatement, parseProbe, nullCall, classify, tableDenied, executionProbeable, userClaims, ANON_CLAIMS, SERVICE_CLAIMS,
  FUNCTIONS_SQL, PRIVATE_TABLES_SQL, MEMBERSHIP_SQL, GRANT_VIOLATIONS_SQL, textLiteral,
} from '../../lib/sqlprobe.js';
import { expectedExecute, EXPOSED_FUNCTIONS, ROLES } from '../../lib/expected.js';

const CLAIMS = { anon: ANON_CLAIMS, authenticated: userClaims('11111111-1111-4111-8111-111111111111'), service_role: SERVICE_CLAIMS };

async function one(conn, sql) {
  const results = await conn.query(sql);
  const last = results.filter((r) => r.rows).at(-1);
  return JSON.parse(last.rows[0].result);
}

async function probe(conn, calls) {
  try {
    await conn.query(probeStatement(calls));
  } catch (error) {
    assert.ok(error instanceof PgError, 'the probe raises a database error');
    const outcomes = parseProbe(error.message);
    assert.ok(outcomes, 'the error carries the probe marker');
    return outcomes;
  }
  throw new Error('the probe did not raise');
}

test('catalog reads return the shapes the harness parses', async () => {
  await withDatabase(async (db) => {
    const conn = await db.connection('postgres');
    const functions = await one(conn, FUNCTIONS_SQL);
    assert.ok(functions.length > 20);
    for (const name of EXPOSED_FUNCTIONS) assert.ok(functions.some((f) => f.schema === 'auth_kit' && f.name === name), name);
    for (const f of functions) {
      for (const role of ROLES) assert.equal(f[role], expectedExecute(f.schema, f.name, role), `${f.schema}.${f.name} ${role}`);
      assert.equal(f.public, false, `${f.schema}.${f.name} PUBLIC`);
    }
    const tables = await one(conn, PRIVATE_TABLES_SQL);
    assert.ok(tables.includes('request_log') && tables.includes('memberships'));
    const membership = await one(conn, MEMBERSHIP_SQL);
    assert.deepEqual([membership.anon, membership.authenticated, membership.service_role], [true, true, true]);
    assert.equal(await one(conn, GRANT_VIOLATIONS_SQL), 0);
  });
});

test('impersonated EXECUTE matches the design grant table for every function and role', async () => {
  await withDatabase(async (db) => {
    const conn = await db.connection('postgres');
    const functions = await one(conn, FUNCTIONS_SQL);
    const calls = [];
    for (const f of functions.filter(executionProbeable)) {
      for (const role of ROLES) calls.push({ f, role, call: { role, claims: CLAIMS[role], sql: nullCall(f.schema, f.name, f.args, { set: f.set }) } });
    }
    assert.ok(functions.filter((f) => !executionProbeable(f)).every((f) => f.schema === 'auth_kit_private'));
    const outcomes = await probe(conn, calls.map((c) => c.call));
    assert.equal(outcomes.length, calls.length);
    calls.forEach(({ f, role }, i) => {
      const kind = classify(outcomes[i]);
      assert.notEqual(kind, 'invalid', `${f.schema}.${f.name} as ${role}: ${JSON.stringify(outcomes[i])}`);
      assert.equal(kind === 'executed', expectedExecute(f.schema, f.name, role), `${f.schema}.${f.name} as ${role}: ${JSON.stringify(outcomes[i])}`);
    });
    const tables = await one(conn, PRIVATE_TABLES_SQL);
    const tableCalls = tables.flatMap((t) => ['anon', 'authenticated'].map((role) => ({
      role, claims: CLAIMS[role], sql: `select pg_catalog.count(*)::text from auth_kit_private.${t}`,
    })));
    for (const outcome of await probe(conn, tableCalls)) assert.ok(tableDenied(outcome), JSON.stringify(outcome));
  });
});

test('a probe rolls back what its calls wrote and leaves no role or claims behind', async () => {
  await withDatabase(async (db) => {
    const conn = await db.connection('postgres');
    const before = await one(conn, 'select pg_catalog.count(*)::text as result from auth_kit_private.clients');
    const outcomes = await probe(conn, [
      { role: 'service_role', claims: SERVICE_CLAIMS, sql: `select auth_kit.register_client(${textLiteral('probe-client')}, ${textLiteral('Probe')}, 'open')::text` },
      { role: 'authenticated', claims: CLAIMS.authenticated, sql: `select auth_kit.join_client(${textLiteral('probe-client')})::text` },
      { role: 'anon', claims: ANON_CLAIMS, sql: `select auth_kit.has_permission(${textLiteral('probe-client')}, 'x')::text` },
    ]);
    assert.equal(outcomes[0].outcome, 'value');
    assert.equal(JSON.parse(outcomes[0].value).result, 'registered');
    // The unconfirmed probe user cannot enroll; the call itself executed.
    assert.equal(outcomes[1].outcome, 'value');
    assert.deepEqual(outcomes[2], { outcome: 'value', value: 'false' });
    assert.equal(await one(conn, 'select pg_catalog.count(*)::text as result from auth_kit_private.clients'), before);
    const session = await one(conn, `select jsonb_build_object('user', current_user, 'claims', coalesce(current_setting('request.jwt.claims', true), ''))::text as result`);
    assert.deepEqual(session, { user: 'postgres', claims: '' });
  });
});

test('the classifier refuses statement errors as evidence', () => {
  assert.equal(classify({ outcome: 'error', sqlstate: '42883', code: null }), 'invalid');
  assert.equal(classify({ outcome: 'error', sqlstate: '42P01', code: null }), 'invalid');
  assert.equal(classify({ outcome: 'error', sqlstate: '42501', code: null, denied: 'function' }), 'denied');
  assert.equal(classify({ outcome: 'error', sqlstate: '42501', code: null, denied: 'schema' }), 'denied');
  assert.equal(classify({ outcome: 'error', sqlstate: '42501', code: null, denied: 'table' }), 'executed');
  assert.equal(classify({ outcome: 'error', sqlstate: 'DW001', code: 'forbidden' }), 'executed');
  assert.equal(classify({ outcome: 'error', sqlstate: '0A000', code: null }), 'invalid');
  assert.equal(classify({ outcome: 'error', sqlstate: 'P0001', code: null }), 'executed');
  assert.equal(classify({ outcome: 'value', value: null }), 'executed');
  assert.equal(classify(null), 'invalid');
});

test('a kit refusal inside a probe is reported with its code', async () => {
  await withDatabase(async (db) => {
    const conn = await db.connection('postgres');
    const [outcome] = await probe(conn, [{ role: 'service_role', claims: SERVICE_CLAIMS, sql: `select auth_kit.export_model(${textLiteral('no-such-client')})::text` }]);
    assert.deepEqual(outcome, { outcome: 'error', sqlstate: 'DW001', code: 'unknown_client', denied: null });
  });
});
