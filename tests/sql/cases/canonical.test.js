// Canonical JSON, SHA-256, request fingerprints, canonical model bytes and
// hashes, and model validation issues: the SQL implementation must produce the
// same bytes and verdicts as packages/core, which is the read-only oracle.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { canonicalJson, requestFingerprint, validateModel, canonicalModelJson, modelHash, isAuthError } from '@briqvent/dwarpal';
import { withDatabase, lit, jsonLit, dbError, uuid } from '../harness/db.js';
import { register, applyModel, exportModel, exampleModel } from '../harness/kit.js';

// Seeded generator so a failure is reproducible from the seed alone.
function prng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const CHAR_POOL = [
  'a', 'b', 'B', 'z', '_', '-', ':', ' ', '0', '1', '9', '"', '\\', '/', '\u0001', '\u0008', '\u000b', '\u001f', '\u007f',
  '\n', '\t', '\r', 'é', 'ÿ', 'Ā', ' ', ' ', '퟿', '', '', '﻿', '￿', '�',
  '\u{10000}', '\u{1f600}', '\u{1f47e}', '\u{10ffff}', '\u{20000}',
];

function randomString(next, max = 6) {
  const length = Math.floor(next() * (max + 1));
  let out = '';
  for (let i = 0; i < length; i += 1) out += CHAR_POOL[Math.floor(next() * CHAR_POOL.length)];
  return out;
}

const NUMBER_POOL = [0, -0, 1, -1, 7, 10, 100, 1e15, 1e16, 1e20, 1e21, 1e22, 0.1, 0.5, 1.5, -2.25, 1e-6, 1e-7, 1.5e-10,
  123456789012345680000, 2 ** 53, 2 ** 53 + 2, 5e-324, 1.7976931348623157e308, 3.141592653589793, 0.000001, 12345678.9];

function randomNumber(next) {
  if (next() < 0.5) return NUMBER_POOL[Math.floor(next() * NUMBER_POOL.length)];
  const mantissa = next() * 10;
  const exp = Math.floor(next() * 60) - 30;
  const value = Number((mantissa * 10 ** exp).toPrecision(1 + Math.floor(next() * 17)));
  return next() < 0.5 ? -value : value;
}

function randomValue(next, depth = 0) {
  const r = next();
  if (depth > 3 || r < 0.35) {
    const s = next();
    if (s < 0.15) return null;
    if (s < 0.3) return next() < 0.5;
    if (s < 0.6) return randomNumber(next);
    return randomString(next);
  }
  if (r < 0.65) {
    const out = [];
    const n = Math.floor(next() * 4);
    for (let i = 0; i < n; i += 1) out.push(randomValue(next, depth + 1));
    return out;
  }
  const out = {};
  const n = Math.floor(next() * 5);
  for (let i = 0; i < n; i += 1) out[randomString(next, 4)] = randomValue(next, depth + 1);
  return out;
}

/** SQL canonical_json of each JSON text, in order (one round trip). */
async function sqlCanonical(db, texts) {
  const rows = await db.rows(`select auth_kit_private.canonical_json(t.j::jsonb) as c
                                from unnest(array[${texts.map(lit).join(',')}]::text[]) with ordinality as t(j, i) order by t.i`);
  return rows.map((r) => r.c);
}

test('canonical JSON: fixed vectors match core byte for byte', () => withDatabase(async (db) => {
  const vectors = [
    '{"b":1,"a":[3,1,2],"c":{"z":null,"y":true}}',
    '{"b":0,"B":0,"_":0,"é":0,"a":0}',
    '{"😀":1,"￿":2,"":3,"퟿":4}',
    '"line\\n\\"quote\\"\\u0001\\u001f\\u007f  /\\\\"',
    '{"__proto__":{"x":1},"constructor":2,"toString":3,"hasOwnProperty":4}',
    '{"10":1,"2":2,"1":3,"0":4,"-1":5,"01":6,"4294967295":7,"4294967294":8,"":9}',
    '{"":{"":[""]}}',
    '[]', '{}', '""', 'null', 'true', 'false',
    '[-0, 0, 1, -1, 1.5, 0.1, 1e21, 1e-7, 1e-6, 123456789012345680000, 5e-324, 1.7976931348623157e308]',
    '[100, 1e15, 1e16, 12345678.9, -1.5e-10, 9007199254740993, 1.0000000000000000001, 2e-324, 1e-400, 0.000001]',
    '{"a":1,"a":2}',
  ];
  const sql = await sqlCanonical(db, vectors);
  vectors.forEach((text, i) => assert.equal(sql[i], canonicalJson(JSON.parse(text)), `vector ${i}: ${text}`));
  assert.equal(sql[1], '{"B":0,"_":0,"a":0,"b":0,"é":0}');
  // UTF-16 order puts the supplementary character (a surrogate pair) before U+E000..U+FFFF.
  assert.equal(sql[2], '{"퟿":4,"😀":1,"":3,"￿":2}');
}));

test('canonical JSON: 400 seeded random values match core', () => withDatabase(async (db) => {
  const next = prng(20260927);
  const values = Array.from({ length: 400 }, () => randomValue(next));
  const texts = values.map((v) => JSON.stringify(v));
  const sql = await sqlCanonical(db, texts);
  values.forEach((v, i) => assert.equal(sql[i], canonicalJson(v), `sample ${i}: ${texts[i]}`));
}));

test('canonical JSON numbers: 16000 seeded doubles (random bit patterns and short decimals) match JSON.stringify', () => withDatabase(async (db) => {
  const next = prng(1_000_003);
  const view = new DataView(new ArrayBuffer(8));
  const texts = [];
  // Random IEEE-754 bit patterns cover subnormals, extremes and full-precision values.
  while (texts.length < 8000) {
    view.setUint32(0, Math.floor(next() * 2 ** 32));
    view.setUint32(4, Math.floor(next() * 2 ** 32));
    const value = view.getFloat64(0);
    if (Number.isFinite(value)) texts.push(JSON.stringify(value));
  }
  // Short decimals land on exact ties between doubles far more often, where
  // the shortest-digit choice depends on ties-to-even.
  for (let i = 0; i < 8000; i += 1) {
    const digits = String(Math.floor(next() * 10 ** (1 + Math.floor(next() * 17)))).replace(/^0+(?=.)/, '');
    const exp = Math.floor(next() * 640) - 330;
    texts.push(`${next() < 0.5 ? '-' : ''}${digits}e${exp}`);
  }
  const finite = texts.filter((text) => Number.isFinite(JSON.parse(text)));
  for (let start = 0; start < finite.length; start += 2000) {
    const batch = finite.slice(start, start + 2000);
    const sql = await sqlCanonical(db, batch);
    batch.forEach((text, i) => assert.equal(sql[i], canonicalJson(JSON.parse(text)), `number ${text}`));
  }
  assert.ok(finite.length > 15000);
}));

test('canonical JSON: the nesting limit is the same on both sides', () => withDatabase(async (db) => {
  const nest = (n) => '['.repeat(n) + '1' + ']'.repeat(n);
  assert.equal((await sqlCanonical(db, [nest(64)]))[0], canonicalJson(JSON.parse(nest(64))));
  assert.throws(() => canonicalJson(JSON.parse(nest(65))), TypeError);
  await dbError(sqlCanonical(db, [nest(65)]), '22023');
}));

test('canonical JSON: a magnitude beyond double range is refused on both sides', () => withDatabase(async (db) => {
  assert.throws(() => canonicalJson(JSON.parse('1e400')), TypeError);
  await dbError(sqlCanonical(db, ['1e400']), '22003');
}));

test('SHA-256 and UTF-16 length helpers match node and JS', () => withDatabase(async (db) => {
  const texts = ['', 'abc', 'café \u{1f600}', 'x'.repeat(5000), '\u{10ffff}￿ '];
  for (const text of texts) {
    assert.equal(await db.admin.value(`select auth_kit_private.sha256_hex(${lit(text)})`), createHash('sha256').update(text, 'utf8').digest('hex'));
    assert.equal(Number(await db.admin.value(`select auth_kit_private.utf16_length(${lit(text)})`)), text.length);
  }
}));

test('request fingerprints match core for every client form, payload shape and operation', () => withDatabase(async (db) => {
  const clients = ['', null, 'shop', ' ', '__proto__', 'constructor', '0', '01', 'é', '\u{1f600}', '￿', 'a"b\\c'];
  const payloads = [
    { user_id: '10000000-0000-4000-8000-000000000002', role_key: 'helper' },
    { user_id: '10000000-0000-4000-8000-000000000002', role_key: '' },
    { user_id: '10000000-0000-4000-8000-000000000002', role_key: 'constructor' },
    { user_id: '10000000-0000-4000-8000-000000000002', role_key: '\u{1f600}￿' },
    { user_id: '10000000-0000-4000-8000-000000000002' },
    'a3f1c2d4e5b6a7980123456789abcdef0123456789abcdef0123456789abcdef',
    { x: 1 }, {}, [], null,
  ];
  const operations = ['grant_membership', 'revoke_membership', 'bootstrap_manager', 'revoke_manager', 'apply_model', 'mfa_reset'];
  const actorsList = ['operator', '10000000-0000-4000-8000-000000000001'];
  const cases = [];
  for (const operation of operations) for (const clientId of clients) for (const payload of payloads) for (const actorId of actorsList) {
    cases.push({ operation, clientId, actorId, payload });
  }
  const rows = await db.rows(`select auth_kit_private.request_fingerprint(c.op, c.client, c.actor, c.payload::jsonb) as h
    from unnest(array[${cases.map((c) => lit(c.operation)).join(',')}]::text[],
                array[${cases.map((c) => lit(c.clientId)).join(',')}]::text[],
                array[${cases.map((c) => lit(c.actorId)).join(',')}]::text[],
                array[${cases.map((c) => lit(JSON.stringify(c.payload))).join(',')}]::text[]) with ordinality as c(op, client, actor, payload, i)
    order by c.i`);
  assert.equal(rows.length, cases.length);
  for (let i = 0; i < cases.length; i += 1) assert.equal(rows[i].h, await requestFingerprint(cases[i]), JSON.stringify(cases[i]));
  // Core's published vectors, including the empty client distinct from null.
  const empty = await db.admin.value(`select auth_kit_private.request_fingerprint('role_grant', '', 'a', '{"x":1}')`);
  assert.equal(empty, createHash('sha256').update('{"actor_id":"a","client_id":"","operation":"role_grant","payload":{"x":1}}').digest('hex'));
  const nullScope = await db.admin.value(`select auth_kit_private.request_fingerprint('role_grant', null, 'a', '{"x":1}')`);
  assert.notEqual(empty, nullScope);
}));

// Models whose canonical bytes and hash must agree with core.
function parityModels() {
  const bigPermissions = {};
  for (let i = 0; i < 2048; i += 1) bigPermissions[`p${i}`] = i % 7 === 0 ? 'x'.repeat(1024) : '';
  const bigRoles = {};
  for (let i = 0; i < 256; i += 1) bigRoles[`r${i}`] = { permissions: [`p${i}`, `p${(i * 7 + 1) % 2048}`] };
  bigRoles.r0.manages_members = true;
  return [
    ['example', exampleModel('studio')],
    ['empty keys', { client: '', roles: { '': { manages_members: true, permissions: [''] } }, permissions: { '': '' } }],
    ['prototype-like names', JSON.parse('{"client":"__proto__","roles":{"__proto__":{"manages_members":true,"permissions":["constructor","__proto__"]},"constructor":{"self_assignable":true,"permissions":["toString"]}},"permissions":{"constructor":"c","__proto__":"p","toString":"t","hasOwnProperty":""}}')],
    ['integer-looking keys', { client: '0', roles: { 10: { manages_members: true, permissions: ['2', '10', '1'] }, 2: { permissions: ['01'] }, '01': { mfa_required: true } }, permissions: { 1: '', 2: '', 10: '', '01': '' } }],
    ['unicode ordering', { client: '\u{1f600}', roles: { '￿': { manages_members: true, permissions: ['\u{1f600}', '', 'z'] }, '\u{10000}': { description: '  "\\\u0001' } }, permissions: { '\u{1f600}': 'smile', '': '', z: 'last' } }],
    ['astral description at the bound', { client: 'c', roles: { m: { manages_members: true, description: '\u{1f600}'.repeat(512) } }, permissions: { k: '\u{10000}'.repeat(512) } }],
    ['duplicate-free unsorted lists and defaults', { client: 'c', roles: { m: { manages_members: true, permissions: ['c', 'a', 'b'] }, x: {} }, permissions: { a: '', b: '', c: '' } }],
    ['bounds: 256 roles, 2048 permissions', { client: 'big', roles: bigRoles, permissions: bigPermissions }],
  ];
}

test('canonical model bytes and hash: SQL apply/export agree with core for every model shape', () => withDatabase(async (db) => {
  for (const [label, model] of parityModels()) {
    const expectedText = canonicalModelJson(model);
    const expectedHash = await modelHash(model);
    await register(db, model.client);
    const dry = await applyModel(db, model.client, model, { dryRun: true });
    assert.equal(dry.model_hash, expectedHash, `${label}: dry-run hash`);
    const applied = await applyModel(db, model.client, model);
    assert.equal(applied.result, 'applied', label);
    assert.equal(applied.model_hash, expectedHash, `${label}: applied hash`);
    const exported = await exportModel(db, model.client);
    assert.equal(exported.model_json, expectedText, `${label}: exported bytes`);
    assert.equal(exported.model_hash, expectedHash, `${label}: export hash`);
    assert.equal(exported.last_applied_hash, expectedHash, `${label}: last applied hash`);
    // The exported text is itself a valid model file with the same canonical bytes.
    assert.equal(canonicalModelJson(JSON.parse(exported.model_json)), expectedText, `${label}: round trip`);
  }
}));

/** SQL issue list, truncated like core's AuthError (first 50). */
async function sqlIssues(db, jsonText) {
  const text = await db.admin.value(`select auth_kit_private.model_issues(${jsonLit(jsonText)})`);
  return JSON.parse(text).slice(0, 50);
}

function coreIssues(model) {
  try {
    validateModel(model);
    return [];
  } catch (error) {
    assert.ok(isAuthError(error) && error.code === 'model_invalid');
    return error.issues.map((i) => ({ path: i.path, rule: i.rule }));
  }
}

function invalidModels() {
  const ok = exampleModel('c');
  const many = (n, make) => Object.fromEntries(Array.from({ length: n }, (_, i) => make(i)));
  return [
    ['array', []], ['string', 'x'], ['null', null], ['number', 1],
    ['unknown top-level fields', { ...ok, extra: 1, aaa: 2 }],
    ['missing client', { roles: ok.roles, permissions: ok.permissions }],
    ['client number', { ...ok, client: 1 }],
    ['client null', { ...ok, client: null }],
    ['permissions missing', { client: 'c', roles: ok.roles }],
    ['permissions null', { ...ok, permissions: null }],
    ['permissions array', { ...ok, permissions: [] }],
    ['too many permissions', { ...ok, permissions: many(2049, (i) => [`p${i}`, '']) }],
    ['description types and lengths', { ...ok, permissions: { ...ok.permissions, a: 1, b: null, c: 'x'.repeat(1025), d: '\u{1f600}'.repeat(513), e: '\u{1f600}'.repeat(512) } }],
    ['roles missing', { client: 'c', permissions: ok.permissions }],
    ['roles array', { ...ok, roles: [] }],
    ['too many roles', { ...ok, roles: many(257, (i) => [`r${i}`, { manages_members: i === 0 }]) }],
    ['role not object', { ...ok, roles: { ...ok.roles, bad: 'x', worse: null, list: [] } }],
    ['role unknown fields', { ...ok, roles: { ...ok.roles, z: { zzz: 1, aaa: 2, permissions: [] } } }],
    ['flag types', { ...ok, roles: { ...ok.roles, f: { self_assignable: 'true', manages_members: 1, mfa_required: null } } }],
    ['self-assignable manager', { ...ok, roles: { ...ok.roles, both: { self_assignable: true, manages_members: true } } }],
    ['role description types', { ...ok, roles: { ...ok.roles, d1: { description: 5 }, d2: { description: 'y'.repeat(1025) } } }],
    ['role permissions not array', { ...ok, roles: { ...ok.roles, p1: { permissions: 'posts:read' }, p2: { permissions: null }, p3: { permissions: {} } } }],
    ['invalid, duplicate and undeclared keys', { ...ok, roles: { ...ok.roles, k: { permissions: [1, 'posts:read', 'posts:read', 'nope', null, 'nope', {}, 1] } } }],
    ['undeclared when a declaration is itself invalid', { ...ok, permissions: { ...ok.permissions, 'posts:read': 7 } }],
    ['no manager role', { client: 'c', roles: { a: { permissions: [] } }, permissions: {} }],
    ['empty roles', { client: 'c', roles: {}, permissions: {} }],
    ['invalid manager role is not also missing', { client: 'c', roles: { m: { manages_members: true, zz: 1 } }, permissions: {} }],
    ['permissions unusable, roles still checked', { client: 'c', roles: { m: { manages_members: true, permissions: ['anything'] } }, permissions: 'x' }],
    ['more than 50 issues', { ...ok, roles: many(80, (i) => [`r${String(i).padStart(2, '0')}`, { permissions: ['undeclared'] }]) }],
    ['prototype-like invalid', JSON.parse('{"client":"c","roles":{"__proto__":{"manages_members":"yes"},"constructor":{"permissions":["toString"]}},"permissions":{"hasOwnProperty":""}}')],
    ['integer-like keys with issues', { client: 'c', roles: { 10: { permissions: ['1'] }, 2: { x: 1 } }, permissions: { 1: 3 } }],
    ['valid example', ok],
  ];
}

test('model validation: SQL reports exactly core\'s issues, in order, for 32 shapes', () => withDatabase(async (db) => {
  for (const [label, model] of invalidModels()) {
    assert.deepEqual(await sqlIssues(db, JSON.stringify(model)), coreIssues(model), label);
  }
}));

test('model validation: apply_model refuses with core\'s issues and writes nothing', () => withDatabase(async (db) => {
  await register(db, 'c');
  for (const [label, model] of invalidModels()) {
    if (label === 'valid example') continue;
    const before = await db.count('auth_kit_private.request_log');
    let error;
    try {
      await applyModel(db, 'c', model);
    } catch (e) {
      error = e;
    }
    assert.ok(error, label);
    assert.equal(error.code, 'DW001', label);
    assert.equal(error.message, 'model_invalid', label);
    assert.deepEqual(JSON.parse(error.detail).issues, coreIssues(model), label);
    assert.equal(await db.count('auth_kit_private.request_log'), before, label);
  }
  // Core's clientId option and the SQL client argument agree.
  const other = exampleModel('other');
  const error = await applyModel(db, 'c', other).catch((e) => e);
  assert.equal(error.message, 'model_invalid');
  let coreError;
  try {
    validateModel(other, { clientId: 'c' });
  } catch (e) {
    coreError = e;
  }
  assert.deepEqual(JSON.parse(error.detail).issues, coreError.issues.map((i) => ({ path: i.path, rule: i.rule })));
}));

test('representability: keys PostgreSQL text/jsonb cannot hold are refused at the jsonb boundary', () => withDatabase(async (db) => {
  // Core refuses NUL and unpaired surrogates as invalid_key; such a model can
  // never reach SQL validation because jsonb input rejects it first.
  for (const key of ['a\u0000b', '\ud800', 'x\udc00']) {
    const model = { client: 'c', roles: { [key]: { manages_members: true } }, permissions: {} };
    assert.deepEqual(coreIssues(model).map((i) => i.rule), ['invalid_key']);
    const error = await dbError(db.admin.query(`select ${jsonLit(JSON.stringify(model))}`));
    assert.ok(['22P05', '22P02'].includes(error.code), `${JSON.stringify(key)}: ${error.code}`);
  }
  // A text argument cannot carry NUL either: the harness refuses to send it,
  // and a PostgreSQL text value can never contain one.
  assert.throws(() => lit('a\u0000b'), TypeError);
  const request = uuid();
  assert.equal(await db.count('auth_kit_private.request_log', `request_id = '${request}'`), 0);
}));
