// Listener lifecycle, loopback-only transport, gateway credential rules,
// input bounds and the absence of any HTTP control surface. Synthetic fixture
// evidence only.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validateClientConfig } from '@briqvent/dwarpal';
import { startAuthEmulator } from '../../packages/emulator/index.js';
import { raw, start } from './support.js';

const EMULATOR_DIR = fileURLToPath(new URL('../../packages/emulator/', import.meta.url));

function rawHttp(emulator, { method = 'GET', path = '/auth/v1/settings', headers = {} } = {}) {
  const { hostname, port } = new URL(emulator.origin);
  return new Promise((resolve, reject) => {
    const request = http.request({ host: hostname.replace(/^\[|\]$/g, ''), port, method, path, headers: { apikey: emulator.publishableKey, ...headers } }, (response) => {
      response.resume();
      response.on('end', () => resolve(response));
    });
    request.on('error', reject);
    request.end();
  });
}

test('defaults: loopback origin on an ephemeral port and a publishable key that core accepts for a browser config', async (t) => {
  const emulator = await start(t);
  assert.match(emulator.origin, /^http:\/\/127\.0\.0\.1:\d+$/);
  assert.notEqual(new URL(emulator.origin).port, '0');
  assert.match(emulator.publishableKey, /^sb_publishable_fixture_[A-Za-z0-9_-]+$/);
  assert.ok(Object.isFrozen(emulator) && Object.isFrozen(emulator.controls));
  const config = validateClientConfig({
    clientId: 'studio', supabaseUrl: emulator.origin, publishableKey: emulator.publishableKey, origin: 'http://127.0.0.1:5173',
    allowedReturnPaths: ['/'], defaultReturnPath: '/', providers: { email: true, google: true }, selfSignup: true,
  });
  assert.equal(config.supabaseUrl, emulator.origin);
  const settings = await raw(emulator, '/auth/v1/settings');
  assert.equal(settings.status, 200);
  assert.equal(settings.headers.get('x-supabase-api-version'), '2024-01-01');
});

test('options are validated: only loopback hosts, bounded values, no unknown options', async () => {
  const bad = [
    { host: '0.0.0.0' }, { host: 'localhost' }, { host: '192.168.1.10' }, { port: -1 }, { port: 1.5 }, { now: -1 },
    { now: Number.NaN }, { accessTokenTtlSeconds: 10 }, { linkTtlSeconds: 0 }, { siteUrl: 'https://example.com/' },
    { log: 'console' }, { publicControls: true }, null, [],
  ];
  for (const options of bad) await assert.rejects(startAuthEmulator(options), TypeError, JSON.stringify(options));
});

test('close() is awaitable and idempotent, drops open connections and leaves other instances running', async () => {
  const first = await startAuthEmulator();
  const second = await startAuthEmulator();
  assert.notEqual(first.origin, second.origin);
  assert.notEqual(first.publishableKey, second.publishableKey);
  const agent = new http.Agent({ keepAlive: true });
  await new Promise((resolve) => http.get(`${first.origin}/auth/v1/settings`, { agent, headers: { apikey: first.publishableKey } }, (r) => { r.resume(); r.on('end', resolve); }));
  const closing = first.close();
  assert.equal(first.close(), closing, 'the same promise for every call');
  await closing;
  await first.close();
  await assert.rejects(fetch(`${first.origin}/auth/v1/settings`), /fetch failed/);
  assert.equal((await raw(second, '/auth/v1/settings')).status, 200, 'closing one instance leaves the other listening');
  await second.close();
  agent.destroy();
});

test('an IPv6 loopback listener works when the host has ::1', async (t) => {
  let emulator;
  try {
    emulator = await startAuthEmulator({ host: '::1' });
  } catch (error) {
    t.skip(`::1 unavailable here (${error.code})`);
    return;
  }
  t.after(() => emulator.close());
  assert.match(emulator.origin, /^http:\/\/\[::1\]:\d+$/);
  assert.equal((await raw(emulator, '/auth/v1/settings')).status, 200);
});

test('a Host header naming another site is refused (DNS rebinding guard)', async (t) => {
  const emulator = await start(t);
  const port = new URL(emulator.origin).port;
  assert.equal((await rawHttp(emulator, { headers: { host: `evil.example:${port}` } })).statusCode, 421);
  assert.equal((await rawHttp(emulator, { headers: { host: `localhost:${port}` } })).statusCode, 200);
});

test('CORS: loopback pages are allowed with the headers supabase-js sends; other origins are refused', async (t) => {
  const emulator = await start(t);
  const preflight = (origin, requested) => fetch(`${emulator.origin}/rest/v1/rpc/join_client`, {
    method: 'OPTIONS', headers: { origin, 'access-control-request-method': 'POST', 'access-control-request-headers': requested },
  });
  const allowed = await preflight('http://127.0.0.1:5173', 'apikey, authorization, content-type, content-profile, x-client-info, x-supabase-api-version');
  assert.equal(allowed.status, 204);
  assert.equal(allowed.headers.get('access-control-allow-origin'), 'http://127.0.0.1:5173');
  assert.equal((await preflight('https://evil.example', 'apikey')).status, 403);
  assert.equal((await preflight('http://127.0.0.1:5173', 'x-operator-token')).status, 403);
  const foreign = await raw(emulator, '/auth/v1/settings', { headers: { origin: 'https://evil.example' } });
  assert.equal(foreign.status, 403);
  assert.equal(foreign.headers.get('access-control-allow-origin'), null);
  const local = await raw(emulator, '/auth/v1/settings', { headers: { origin: 'http://localhost:3000' } });
  assert.equal(local.headers.get('access-control-allow-origin'), 'http://localhost:3000');
});

test('gateway: the publishable key is required; secret keys, management tokens and service-role tokens are refused', async (t) => {
  const emulator = await start(t);
  const serviceRoleShaped = `x.${Buffer.from(JSON.stringify({ role: 'service_role' })).toString('base64url')}.y`;
  const cases = [
    [{ apikey: undefined }, 'No API key found in request'],
    [{ apikey: 'sb_publishable_someone_else' }, 'Invalid API key'],
    [{ apikey: 'sb_secret_fixture_value' }, 'fixture: operator credentials are refused by the development fixture'],
    [{ authorization: 'Bearer sb_secret_fixture_value' }, 'fixture: operator credentials are refused by the development fixture'],
    [{ authorization: 'Bearer sbp_management_token' }, 'fixture: operator credentials are refused by the development fixture'],
    [{ authorization: `Bearer ${serviceRoleShaped}` }, 'fixture: operator credentials are refused by the development fixture'],
  ];
  for (const [headers, message] of cases) {
    for (const path of ['/auth/v1/settings', '/rest/v1/rpc/effective_access?client_id=x']) {
      const response = await raw(emulator, path, { headers: { 'accept-profile': 'auth_kit', ...headers } });
      assert.equal(response.status, 401, `${path} ${JSON.stringify(headers)}`);
      assert.equal((await response.json()).message, message);
    }
  }
});

test('no control or admin surface is reachable over HTTP', async (t) => {
  const emulator = await start(t);
  const paths = [
    '/', '/controls', '/__fixture/seed', '/snapshot', '/auth/v1/admin/users', '/auth/v1/admin/generate_link',
    '/auth/v1/fixture', '/rest/v1/', '/rest/v1/profiles', '/rest/v1/rpc/', '/auth/v1/token?grant_type=id_token',
    '/auth/v1/otp', '/auth/v1/factors/00000000-0000-4000-8000-000000000000',
  ];
  for (const path of paths) {
    for (const method of ['GET', 'POST', 'PUT', 'DELETE']) {
      const response = await raw(emulator, path, { method, body: method === 'GET' ? undefined : {} });
      assert.equal(response.status, 404, `${method} ${path}`);
    }
  }
});

test('input bounds: body size, URL length, content type and JSON shape', async (t) => {
  const emulator = await start(t);
  const big = await raw(emulator, '/auth/v1/signup', { method: 'POST', body: { email: 'a@example.test', password: 'x'.repeat(70 * 1024) } });
  assert.equal(big.status, 413);
  const longUrl = await raw(emulator, `/auth/v1/settings?pad=${'a'.repeat(9000)}`);
  assert.equal(longUrl.status, 414);
  const malformed = await raw(emulator, '/auth/v1/signup', { method: 'POST', body: '{"email":' });
  assert.equal(malformed.status, 400);
  const form = await raw(emulator, '/auth/v1/signup', { method: 'POST', body: 'email=a', headers: { 'content-type': 'application/x-www-form-urlencoded' } });
  assert.equal(form.status, 415);
  const array = await raw(emulator, '/auth/v1/signup', { method: 'POST', body: [] });
  assert.equal(array.status, 400);
  const rpcArray = await raw(emulator, '/rest/v1/rpc/join_client', { method: 'POST', body: [{ client_id: 'x' }], headers: { 'content-profile': 'auth_kit' } });
  assert.equal(rpcArray.status, 400);
  assert.equal((await rpcArray.json()).code, 'PGRST102');
  const longEmail = await raw(emulator, '/auth/v1/signup', { method: 'POST', body: { email: `${'a'.repeat(250)}@example.test`, password: 'fixture-password' } });
  assert.equal(longEmail.status, 400);
  assert.equal(emulator.controls.snapshot().counts.users, 0);
});

test('source: no outbound network calls, no non-loopback bind and no consumer-specific names in the emulator', async () => {
  const files = [];
  const walk = async (dir) => {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) await walk(path);
      else if (/\.(js|d\.ts)$/.test(entry.name)) files.push(path);
    }
  };
  await walk(EMULATOR_DIR);
  assert.ok(files.length >= 7);
  for (const file of files) {
    const source = await readFile(file, 'utf8');
    for (const pattern of [/\bfetch\(/, /http\.request|https\.|http\.get\(/, /node:(net|tls|dns|dgram|child_process)/, /\bcreditone\b/i, /0\.0\.0\.0/]) {
      assert.doesNotMatch(source, pattern, `${file} ${pattern}`);
    }
  }
});
