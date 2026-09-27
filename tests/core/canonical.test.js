import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { canonicalJson, sha256Hex, requestFingerprint } from '@briqvent/dwarpal';

test('canonical JSON: sorted keys, no whitespace, arrays keep order', () => {
  assert.equal(canonicalJson({ b: 1, a: [3, 1, 2], c: { z: null, y: true } }), '{"a":[3,1,2],"b":1,"c":{"y":true,"z":null}}');
  assert.equal(canonicalJson({ a: 1, b: 2 }), canonicalJson({ b: 2, a: 1 }));
  assert.notEqual(canonicalJson([1, 2]), canonicalJson([2, 1]));
});

test('canonical JSON: keys sort by UTF-16 code unit and strings use JSON escaping', () => {
  assert.equal(canonicalJson({ b: 0, B: 0, _: 0, '\u00e9': 0, a: 0 }), '{"B":0,"_":0,"a":0,"b":0,"\u00e9":0}');
  assert.equal(canonicalJson({ '\ud83d\ude00': 1, '\uffff': 2 }), '{"\ud83d\ude00":1,"\uffff":2}');
  assert.equal(canonicalJson('line\n"quote"\u0001'), '"line\\n\\"quote\\"\\u0001"');
  assert.equal(canonicalJson(-0), '0');
  assert.equal(canonicalJson(1e21), '1e+21');
});

test('canonical JSON rejects values without a single JSON meaning', () => {
  const cyclic = {};
  cyclic.self = cyclic;
  let deep = [];
  for (let i = 0; i < 80; i += 1) deep = [deep];
  const bad = [undefined, Number.NaN, Infinity, () => 1, Symbol('s'), 10n, new Date(0), new Map(), /x/, cyclic, deep, { a: undefined }, [1, , 3], Object.create({ inherited: 1 })];
  for (const value of bad) assert.throws(() => canonicalJson(value), TypeError);
});

test('canonical JSON treats a JSON-parsed __proto__ key as data, not a prototype', () => {
  const parsed = JSON.parse('{"__proto__":{"x":1},"a":2}');
  assert.equal(canonicalJson(parsed), '{"__proto__":{"x":1},"a":2}');
});

test('sha256Hex matches node:crypto on UTF-8 bytes', async () => {
  for (const text of ['', 'abc', 'caf\u00e9 \ud83d\ude00', 'x'.repeat(10000)]) {
    assert.equal(await sha256Hex(text), createHash('sha256').update(text, 'utf8').digest('hex'));
  }
  assert.equal(await sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  await assert.rejects(sha256Hex(42), TypeError);
});

test('request fingerprint: vector, stable over key order, changes with every field (L30 unit part)', async () => {
  const base = { operation: 'grant_membership', clientId: 'shop', actorId: '10000000-0000-4000-8000-000000000001', payload: { user_id: '10000000-0000-4000-8000-000000000002', role_key: 'helper' } };
  const text = '{"actor_id":"10000000-0000-4000-8000-000000000001","client_id":"shop","operation":"grant_membership","payload":{"role_key":"helper","user_id":"10000000-0000-4000-8000-000000000002"}}';
  const fp = await requestFingerprint(base);
  assert.equal(fp, createHash('sha256').update(text).digest('hex'));
  assert.equal(await requestFingerprint({ ...base, payload: { role_key: 'helper', user_id: base.payload.user_id } }), fp);

  const variants = [
    { ...base, operation: 'revoke_membership' },
    { ...base, clientId: 'other' },
    { ...base, actorId: '10000000-0000-4000-8000-000000000003' },
    { ...base, payload: { ...base.payload, role_key: 'boss' } },
    { ...base, payload: { ...base.payload, extra: null } },
  ];
  const seen = new Set([fp]);
  for (const v of variants) seen.add(await requestFingerprint(v));
  assert.equal(seen.size, variants.length + 1);
});

test('project-wide fingerprint uses a null client and the operator actor', async () => {
  const fp = await requestFingerprint({ operation: 'mfa_reset', clientId: null, actorId: 'operator', payload: { user_id: '10000000-0000-4000-8000-000000000002' } });
  const text = '{"actor_id":"operator","client_id":null,"operation":"mfa_reset","payload":{"user_id":"10000000-0000-4000-8000-000000000002"}}';
  assert.equal(fp, createHash('sha256').update(text).digest('hex'));
});

test('request fingerprint rejects malformed input', async () => {
  const ok = { operation: 'x', clientId: 'c', actorId: 'a', payload: {} };
  const bad = [
    null,
    { ...ok, operation: '' },
    { ...ok, clientId: 1 },
    { ...ok, clientId: undefined },
    { ...ok, clientId: 'c\u0000' },
    { ...ok, clientId: '\ud800' },
    { ...ok, actorId: undefined },
    { ...ok, actorId: '' },
    { ...ok, payload: undefined },
    { ...ok, payload: { n: Number.NaN } },
  ];
  for (const input of bad) {
    await assert.rejects(requestFingerprint(input), TypeError);
  }
});

test('request fingerprint: an empty client id is a literal id, distinct from null and other ids', async () => {
  const input = (clientId) => ({ operation: 'role_grant', clientId, actorId: 'a', payload: { x: 1 } });
  const empty = await requestFingerprint(input(''));
  const text = '{"actor_id":"a","client_id":"","operation":"role_grant","payload":{"x":1}}';
  assert.equal(empty, createHash('sha256').update(text).digest('hex'));
  assert.notEqual(empty, await requestFingerprint(input(null)));
  assert.notEqual(empty, await requestFingerprint(input('shop')));
  assert.notEqual(empty, await requestFingerprint(input(' ')));
});
