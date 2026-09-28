// Unit checks for the browser kit's storage, address reading and answer
// classification, including hostile but valid stored and wire values.

import test from 'node:test';
import assert from 'node:assert/strict';
import { validateClientConfig } from '../../packages/core/config.js';
import { AuthError } from '../../packages/core/errors.js';
import { createKitStorage, storagePrefix } from '../../packages/browser/lib/storage.js';
import { readLocation, routeFor } from '../../packages/browser/lib/location.js';
import { authFailure, callKitRpc, readAccessClaims, verifiedTotpFactors } from '../../packages/browser/lib/answers.js';
import { authErrorCode, linkRejected, BROWSER_ERROR_CODES } from '../../packages/browser/lib/codes.js';
import { BROWSER_STATES, createAuthController } from '../../packages/browser/index.js';
import { FakeStorage, baseConfig, createTab, SITE } from './support/env.js';
import { makeToken } from './support/scripted-supabase.js';

test('states and error codes are closed, frozen sets', () => {
  assert.deepEqual([...BROWSER_STATES], ['idle', 'submitting', 'sent', 'error', 'expired_link', 'already_used', 'mfa_enrol', 'mfa_challenge', 'setup_pending', 'no_access', 'signed_in', 'offline']);
  assert.ok(Object.isFrozen(BROWSER_STATES) && Object.isFrozen(BROWSER_ERROR_CODES));
  for (const table of ['signIn', 'signUp', 'recovery', 'password', 'mfa']) {
    for (const code of ['', 'invalid_credentials', 'weak_password', 'user_already_exists', 'something_new', 'constructor', '__proto__']) {
      const mapped = authErrorCode(table, { kind: 'api', status: 400, code });
      assert.ok(mapped === 'sent' || BROWSER_ERROR_CODES.includes(mapped), `${table}/${code}`);
    }
  }
  assert.equal(authErrorCode('signIn', { kind: 'api', status: 422, code: 'constructor' }), 'unavailable');
  assert.equal(authErrorCode('signUp', { kind: 'api', status: 429, code: '' }), 'rate_limited');
  assert.equal(authErrorCode('mfa', { kind: 'unavailable' }), 'unavailable');
  assert.equal(linkRejected({ kind: 'api', status: 429, code: '' }), false);
  assert.equal(linkRejected({ kind: 'api', status: 403, code: 'otp_expired' }), true);
});

test('the controller validates its config through core and refuses secret keys', () => {
  const tab = createTab(`${SITE}/account/sign-in`);
  for (const publishableKey of ['sb_secret_abcdefghijklmnop', makeToken({ role: 'service_role' })]) {
    assert.throws(() => createAuthController({ config: baseConfig({ publishableKey }), env: tab.env, fetch: async () => {} }), (e) => e instanceof AuthError && e.code === 'config_invalid');
  }
  assert.throws(() => createAuthController({ config: baseConfig(), env: tab.env, requestTimeoutMs: 0 }), TypeError);
});

test('storage keys share one encoded per-client prefix that no other client id can extend', () => {
  assert.equal(storagePrefix('a'), 'dwarpal:a:');
  assert.equal(storagePrefix('a:b'), 'dwarpal:a%3Ab:');
  assert.ok(!storagePrefix('a:b').startsWith(storagePrefix('a')));
  const local = new FakeStorage();
  const tab = new FakeStorage();
  const one = createKitStorage({ clientId: 'a', localStorage: local, sessionStorage: tab });
  const two = createKitStorage({ clientId: 'a:b', localStorage: local, sessionStorage: tab });
  one.authAdapter.setItem(one.authKey, 'x');
  two.authAdapter.setItem(two.authKey, 'y');
  two.authAdapter.setItem(`${two.authKey}-code-verifier`, 'v');
  assert.equal(one.wipe(), true);
  assert.deepEqual(local.keys(), ['dwarpal:a%3Ab:auth'], "one client's wipe leaves the other's keys");
  assert.deepEqual(tab.keys(), ['dwarpal:a%3Ab:auth-code-verifier']);
  assert.throws(() => one.authAdapter.setItem('other-key', 'x'), TypeError);
});

test('flow records outside their shape or lifetime read as absent', () => {
  const tab = new FakeStorage();
  const store = createKitStorage({ clientId: 'c', localStorage: new FakeStorage(), sessionStorage: tab });
  store.writeFlow({ kind: 'oauth', id: 'abcdefgh12345678', next: '/app', at: 1000 });
  assert.equal(store.readFlow(1000).id, 'abcdefgh12345678');
  assert.equal(store.readFlow(1000 + 10 * 60 * 1000 + 1), null, 'past the oauth lifetime');
  assert.equal(store.readFlow(999), null, 'clock moved back');
  for (const bad of ['{', '[]', 'null', '{"v":2}', JSON.stringify({ v: 1, kind: 'oauth', id: 'x', next: '/app', at: 1 }),
    JSON.stringify({ v: 1, kind: 'password', id: 'abcdefgh1', next: '/app', at: 1 }), JSON.stringify({ v: 1, kind: 'magic', id: null, next: '/app', at: 1 }),
    JSON.stringify({ v: 1, kind: 'password', id: null, next: 5, at: 1 }), JSON.stringify({ v: 1, kind: 'password', id: null, next: '/app', at: '1' })]) {
    tab.setItem('dwarpal:c:flow', bad);
    assert.equal(store.readFlow(1), null, bad);
  }
});

test('an unusable Web Storage falls back to a memory area instead of failing', () => {
  const broken = { getItem() { throw new Error('denied'); }, setItem() { throw new Error('denied'); }, removeItem() {}, key() { return null; }, length: 0 };
  const store = createKitStorage({ clientId: 'c', localStorage: broken, sessionStorage: null });
  assert.equal(store.persistent, false);
  store.writeRecovery('pending', null);
  assert.deepEqual(store.readRecovery(), { phase: 'pending', userId: null });
  assert.equal(store.wipe(), true);
  assert.equal(store.readRecovery(), null);
});

test('reading the address strips every secret parameter and fragment token, keeping other parameters', () => {
  const config = validateClientConfig(baseConfig());
  const tab = createTab(`${SITE}/account/callback?code=c0de&sb_flow_id=abcdefgh1&keep=1#access_token=t&refresh_token=r`);
  const place = readLocation(tab.env, config);
  assert.equal(place.route, 'callback');
  assert.deepEqual(place.callback, { code: 'c0de', providerError: true });
  assert.equal(tab.href, `${SITE}/account/callback?keep=1`);
  const verify = createTab(`${SITE}/account/verify?token_hash=th&type=email&next=%2Fapp%2Forders`);
  const read = readLocation(verify.env, config);
  assert.deepEqual(read.link, { tokenHash: 'th', type: 'email' });
  assert.equal(read.next, '/app/orders');
  assert.equal(verify.href, `${SITE}/account/verify?next=%2Fapp%2Forders`);
  const plain = createTab(`${SITE}/account/sign-in?next=%2Fapp`);
  readLocation(plain.env, config);
  assert.deepEqual(plain.replaced, [], 'nothing to strip, history untouched');
  assert.equal(routeFor('/account/sign-in/', config.routes), null, 'exact route paths only');
  assert.equal(routeFor('/account', config.routes), null);
});

test('answer classification: transport, service, session and API failures stay distinct', () => {
  assert.deepEqual(authFailure({ name: 'AuthRetryableFetchError', status: 0 }), { kind: 'offline' });
  assert.deepEqual(authFailure({ name: 'AuthRetryableFetchError', status: 503 }), { kind: 'unavailable' });
  assert.deepEqual(authFailure({ name: 'AuthSessionMissingError', status: 400 }), { kind: 'session_missing' });
  assert.deepEqual(authFailure({ name: 'AuthApiError', status: 400, code: 'invalid_credentials' }), { kind: 'api', status: 400, code: 'invalid_credentials' });
  assert.deepEqual(authFailure({ name: 'AuthApiError', status: 400, code: 'Bad Code!' }), { kind: 'api', status: 400, code: '' });
  assert.deepEqual(authFailure({ name: 'AuthApiError', status: 505, code: 'x' }), { kind: 'unavailable' });
  assert.deepEqual(authFailure(new Error('storage')), { kind: 'unavailable' });
  assert.deepEqual(authFailure(undefined), { kind: 'unavailable' });
});

test('RPC classification: only DW001 with a safe code is a refusal; empty or non-object bodies fail', async () => {
  const cases = [
    [{ data: { a: 1 }, error: null, status: 200 }, { kind: 'value', value: { a: 1 } }],
    [{ data: null, error: { code: 'DW001', message: 'forbidden' }, status: 400 }, { kind: 'refusal', code: 'forbidden' }],
    [{ data: null, error: { code: 'DW001', message: 'Not Safe' }, status: 400 }, { kind: 'failure', transport: false }],
    [{ data: null, error: { code: '42501', message: 'forbidden' }, status: 403 }, { kind: 'failure', transport: false }],
    [{ data: null, error: { message: 'fetch failed', code: '' }, status: 0 }, { kind: 'failure', transport: true }],
    [{ data: null, error: null, status: 204 }, { kind: 'failure', transport: false }],
    [{ data: [], error: null, status: 200 }, { kind: 'failure', transport: false }],
    [{ data: 'text', error: null, status: 200 }, { kind: 'failure', transport: false }],
  ];
  for (const [response, expected] of cases) {
    const seen = {};
    const builder = {
      setHeader(name, value) { seen[name] = value; return builder; },
      retry(enabled) { seen.retry = enabled; return Promise.resolve(response); },
    };
    const client = { schema: (name) => ({ rpc: (fn, args) => { seen.schema = name; seen.fn = fn; seen.args = args; return builder; } }) };
    assert.deepEqual(await callKitRpc(client, 'effective_access', { client_id: 'c' }, 'tok'), expected);
    assert.deepEqual(seen, { schema: 'auth_kit', fn: 'effective_access', args: { client_id: 'c' }, Authorization: 'Bearer tok', retry: false });
  }
  const throwing = { schema: () => ({ rpc: () => { throw new Error('boom'); } }) };
  assert.deepEqual(await callKitRpc(throwing, 'ensure_profile', {}, 't'), { kind: 'failure', transport: true });
});

test('access-token claims: malformed, foreign-shaped or unknown-assurance tokens fail closed', () => {
  const good = { sub: '11111111-1111-4111-8111-111111111111', session_id: 's1', aal: 'aal1', iat: 10, exp: 20 };
  assert.deepEqual(readAccessClaims(makeToken(good)), { sub: good.sub, sessionId: 's1', aal: 'aal1', iat: 10, exp: 20 });
  const bad = [
    'a.b', 'x.%%%.y', makeToken({ ...good, sub: 'not-a-uuid' }), makeToken({ ...good, session_id: '' }), makeToken({ ...good, aal: 'aal3' }),
    makeToken({ ...good, exp: 5 }), makeToken({ ...good, iat: 1.5 }), makeToken([]), null,
  ];
  for (const token of bad) assert.throws(() => readAccessClaims(token), (e) => e instanceof AuthError && e.code === 'unavailable');
  assert.deepEqual(verifiedTotpFactors({ factors: [{ id: good.sub, factor_type: 'totp', status: 'verified' }, { id: 'x', factor_type: 'totp', status: 'unverified' }, { id: 'y', factor_type: 'phone', status: 'verified' }] }), [good.sub]);
  assert.deepEqual(verifiedTotpFactors({}), []);
  assert.throws(() => verifiedTotpFactors({ factors: 'x' }), AuthError);
  assert.throws(() => verifiedTotpFactors({ factors: [{ id: 'nope', factor_type: 'totp', status: 'verified' }] }), AuthError);
});
