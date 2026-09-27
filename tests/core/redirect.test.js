import { test } from 'node:test';
import assert from 'node:assert/strict';
import { resolveReturnPath, validateClientConfig } from '@briqvent/dwarpal';

const config = validateClientConfig({
  clientId: 'shop',
  supabaseUrl: 'https://project-ref.supabase.co',
  publishableKey: 'sb_publishable_abc123',
  origin: 'https://shop.example',
  allowedReturnPaths: ['/orders', '/account/profile', '/admin'],
  defaultReturnPath: '/home',
  providers: { email: true, google: true },
  selfSignup: true,
});
const DEFAULT = '/home';

test('allowed paths pass exactly (L11)', () => {
  assert.equal(resolveReturnPath('/orders', config), '/orders');
  assert.equal(resolveReturnPath('/account/profile', config), '/account/profile');
  assert.equal(resolveReturnPath('https://shop.example/orders', config), '/orders');
  // Only the pathname is carried over.
  assert.equal(resolveReturnPath('/orders?tab=open', config), '/orders');
});

test('traversal is normalized first and then must match exactly', () => {
  assert.equal(resolveReturnPath('/orders/../admin', config), '/admin');
  assert.equal(resolveReturnPath('/orders/%2e%2e/admin', config), '/admin');
  assert.equal(resolveReturnPath('/orders/../../etc/passwd', config), DEFAULT);
  assert.equal(resolveReturnPath('/orders/.', config), DEFAULT);
  assert.equal(resolveReturnPath('/orders/', config), DEFAULT);
  assert.equal(resolveReturnPath('/ORDERS', config), DEFAULT);
});

test('open-redirect and injection attempts fall back to the default (L11)', () => {
  const cases = {
    schemeRelative: '//evil.example/orders',
    crossOrigin: 'https://evil.example/orders',
    otherPort: 'https://shop.example:8443/orders',
    otherScheme: 'http://shop.example/orders',
    javascript: 'javascript:alert(1)',
    data: 'data:text/html,<script>alert(1)</script>',
    backslash: '/\\evil.example',
    backslashOnly: '\\\\evil.example',
    rawBackslashInside: '/orders\\..\\admin',
    encodedSlash: '/%2fevil.example',
    encodedSlashUpper: '/%2Fevil.example',
    encodedBackslash: '/%5cevil.example',
    encodedBackslashUpper: '/orders%5C..%5Cadmin',
    nul: '/orders\u0000',
    tab: '/or\tders',
    newline: '/orders\n',
    cr: '\r/orders',
    del: '/orders\u007f',
    c1: '/orders\u0085',
    space: '/orders ',
    leadingSpace: ' /orders',
    nbsp: '/orders\u00a0',
    ideographicSpace: '/orders\u3000',
    lineSeparator: '/orders\u2028',
    zeroWidth: '/orders\u200b',
    fragment: '/orders#x',
    emptyFragment: '/orders#',
    userinfo: 'https://user@shop.example/orders',
    userinfoPassword: 'https://user:pass@shop.example/orders',
    unlisted: '/secret',
    empty: '',
    overlong: `/orders?${'a'.repeat(3000)}`,
  };
  for (const [name, next] of Object.entries(cases)) {
    assert.equal(resolveReturnPath(next, config), DEFAULT, name);
  }
});

test('non-string input falls back to the default', () => {
  for (const next of [undefined, null, 0, ['/orders'], { toString: () => '/orders' }, true]) {
    assert.equal(resolveReturnPath(next, config), DEFAULT);
  }
});
