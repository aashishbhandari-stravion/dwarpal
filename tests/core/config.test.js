import { test } from 'node:test';
import assert from 'node:assert/strict';
import { AuthError, validateClientConfig } from '@briqvent/dwarpal';

function validConfig(overrides = {}) {
  return {
    clientId: 'shop',
    supabaseUrl: 'https://project-ref.supabase.co',
    publishableKey: 'sb_publishable_abc123',
    origin: 'https://shop.example',
    allowedReturnPaths: ['/', '/orders', '/account/profile'],
    defaultReturnPath: '/',
    providers: { email: true, google: false },
    selfSignup: true,
    ...overrides,
  };
}

function issuesOf(input) {
  try {
    validateClientConfig(input);
  } catch (err) {
    assert.ok(err instanceof AuthError);
    assert.equal(err.code, 'config_invalid');
    return err.issues.map((i) => `${i.path}:${i.rule}`);
  }
  assert.fail('expected config_invalid');
}

// A syntactically valid legacy JWT with the given role claim (unsigned; only the payload is read).
function legacyJwt(role) {
  const enc = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');
  return `${enc({ alg: 'HS256', typ: 'JWT' })}.${enc({ iss: 'supabase', role })}.c2lnbmF0dXJl`;
}

test('valid config is normalized with default routes and session and frozen', () => {
  const c = validateClientConfig(validConfig({ supabaseUrl: 'https://project-ref.supabase.co/' }));
  assert.equal(c.supabaseUrl, 'https://project-ref.supabase.co');
  assert.equal(c.routes.prefix, '/account');
  assert.equal(c.routes.signIn, '/account/sign-in');
  assert.equal(c.routes.signOut, '/account/sign-out');
  assert.deepEqual(c.session, { accessTokenMinutes: 30 });
  assert.equal(c.brand, null);
  assert.ok(Object.isFrozen(c.routes) && Object.isFrozen(c.allowedReturnPaths));
});

test('route overrides stay under the prefix and must be distinct segments', () => {
  const c = validateClientConfig(validConfig({ routes: { prefix: '/auth', signIn: 'login' } }));
  assert.equal(c.routes.signIn, '/auth/login');
  assert.equal(c.routes.callback, '/auth/callback');
  assert.deepEqual(issuesOf(validConfig({ routes: { signIn: 'verify' } })), ['routes.verify:duplicate']);
  assert.deepEqual(issuesOf(validConfig({ routes: { signIn: '../admin' } })), ['routes.signIn:segment_syntax']);
  assert.deepEqual(issuesOf(validConfig({ routes: { prefix: '/' } })), ['routes.prefix:unsafe_path']);
  assert.deepEqual(issuesOf(validConfig({ routes: { admin: 'x' } })), ['routes.admin:unknown_field']);
});

test('booleans must be real booleans', () => {
  assert.deepEqual(issuesOf(validConfig({ selfSignup: 'true' })), ['selfSignup:type']);
  assert.deepEqual(issuesOf(validConfig({ providers: { email: 1, google: false } })), ['providers.email:type']);
  assert.deepEqual(issuesOf(validConfig({ providers: { email: true } })), ['providers.google:required']);
  assert.deepEqual(issuesOf(validConfig({ providers: { email: false, google: false } })), ['providers:no_provider']);
});

test('undeclared keys and missing fields are refused', () => {
  assert.deepEqual(issuesOf(validConfig({ secretKey: 'x' })), ['secretKey:unknown_field']);
  const missing = validConfig();
  delete missing.origin;
  assert.deepEqual(issuesOf(missing), ['origin:required']);
  assert.deepEqual(issuesOf(null), ['$:not_object']);
});

test('origins: https only, loopback http allowed, no path or credentials', () => {
  assert.equal(validateClientConfig(validConfig({ origin: 'http://localhost:5173' })).origin, 'http://localhost:5173');
  for (const bad of ['http://shop.example', 'https://shop.example/path', 'https://u:p@shop.example', 'javascript:alert(1)', 'https://shop.example?x=1', 'https://SHOP.example', 'not a url']) {
    const issues = issuesOf(validConfig({ origin: bad }));
    assert.equal(issues.length, 1, bad);
    assert.match(issues[0], /^origin:(not_origin|not_url)$/, bad);
  }
});

test('return paths: unsafe entries are refused', () => {
  for (const bad of ['orders', '//evil.example', '/a/../b', '/a?b', '/a#b', '/a%2fb', '/a\\b', '/a b', '/caf\u00e9']) {
    assert.deepEqual(issuesOf(validConfig({ allowedReturnPaths: ['/', bad] })), ['allowedReturnPaths[1]:unsafe_path'], bad);
  }
  assert.deepEqual(issuesOf(validConfig({ allowedReturnPaths: ['/', '/'] })), ['allowedReturnPaths[1]:duplicate']);
  assert.deepEqual(issuesOf(validConfig({ allowedReturnPaths: [] })), ['allowedReturnPaths:type']);
  assert.deepEqual(issuesOf(validConfig({ defaultReturnPath: 'https://evil.example/' })), ['defaultReturnPath:unsafe_path']);
});

test('publishable key: secret keys and service_role JWTs are refused', () => {
  assert.equal(validateClientConfig(validConfig({ publishableKey: legacyJwt('anon') })).publishableKey.split('.').length, 3);
  const fakeSecretKey = ['sb', 'secret', 'abc123'].join('_');
  for (const bad of [fakeSecretKey, legacyJwt('service_role'), legacyJwt('authenticated'), 'random-string', 'a.b.c', 'sb_publishable_']) {
    assert.deepEqual(issuesOf(validConfig({ publishableKey: bad })), ['publishableKey:not_publishable_key'], bad);
  }
  assert.deepEqual(issuesOf(validConfig({ publishableKey: 'has space' })), ['publishableKey:type']);
});

test('brand, copy and session are bounded', () => {
  const ok = validateClientConfig(validConfig({
    brand: { name: 'Shop', logoUrl: '/logo.svg', colors: { primary: '#123abc' }, fontStack: "Inter, 'Segoe UI', sans-serif" },
    copy: { 'signIn.title': 'Welcome' },
    session: { accessTokenMinutes: 15 },
  }));
  assert.equal(ok.brand.colors.primary, '#123abc');
  assert.deepEqual(issuesOf(validConfig({ brand: { name: 'S', colors: { primary: 'red;background:url(x)' } } })), ['brand.colors.primary:not_hex_color']);
  assert.deepEqual(issuesOf(validConfig({ brand: { name: 'S', logoUrl: 'javascript:alert(1)' } })), ['brand.logoUrl:unsafe_url']);
  assert.deepEqual(issuesOf(validConfig({ brand: { name: 'S', fontStack: 'x;}body{display:none' } })), ['brand.fontStack:type']);
  assert.deepEqual(issuesOf(validConfig({ copy: { 'a b': 'x' } })), ['copy.<invalid-key>:key_syntax']);
  for (const minutes of [0, 1.5, '30', 1441, Number.NaN]) {
    assert.deepEqual(issuesOf(validConfig({ session: { accessTokenMinutes: minutes } })), ['session.accessTokenMinutes:out_of_range']);
  }
});
