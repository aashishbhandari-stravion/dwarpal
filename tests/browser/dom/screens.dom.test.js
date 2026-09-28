// Real-browser check of the built bundle, the default screens and the
// stylesheet: headless Chromium (playwright-core) loads a static page under a
// strict CSP from a loopback site server and talks over real HTTP to the
// scripted fixture from support/ on a second loopback port. Real localStorage,
// sessionStorage, history and CORS are in play.
//
// SYNTHETIC: this is the scripted fixture, not the development emulator and
// not Supabase. The shared browser suite against the emulator is a later
// integration gate.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { chromium } from 'playwright-core';
import { buildBrowser } from '../../../scripts/build-browser.mjs';
import { createScriptedSupabase, PUBLISHABLE_KEY, TOTP_CODE } from '../support/scripted-supabase.js';

const CLIENT_ID = 'studio';
const ROLES = {
  member: { selfAssignable: true, permissions: ['orders:read:own'] },
  staff: { mfaRequired: true, permissions: ['orders:read:any'] },
};

let assets;
let browser;

test.before(async () => {
  assets = await mkdtemp(join(tmpdir(), 'dwarpal-dom-'));
  await buildBrowser({ outdir: assets });
  browser = await chromium.launch();
});

test.after(async () => {
  await browser?.close();
  if (assets) await rm(assets, { recursive: true, force: true });
});

async function world({ brand } = {}) {
  const fixture = createScriptedSupabase();
  fixture.seedClient({ clientId: CLIENT_ID, roles: ROLES });
  const auth = await listen((req, res) => serveFixture(fixture, req, res));
  const site = await listen((req, res) => serveSite(req, res, { auth, brand }));
  const context = await browser.newContext();
  const consoleLines = [];
  context.on('console', (message) => consoleLines.push(message.text()));
  return {
    fixture,
    site,
    auth,
    context,
    consoleLines,
    async open(path) {
      const page = await context.newPage();
      page.on('pageerror', (error) => consoleLines.push(`pageerror ${error.message}`));
      await page.goto(`${site.origin}${path}`);
      await page.waitForSelector('.ak-card');
      return page;
    },
    async close() {
      await context.close();
      await site.close();
      await auth.close();
    },
  };
}

function config(auth, site, brand) {
  return {
    clientId: CLIENT_ID,
    supabaseUrl: auth.origin,
    publishableKey: PUBLISHABLE_KEY,
    origin: site.origin,
    allowedReturnPaths: ['/app', '/app/orders'],
    defaultReturnPath: '/app',
    providers: { email: true, google: true },
    selfSignup: true,
    brand: brand ?? { name: 'Studio', colors: { primary: '#0a7d3b' } },
  };
}

async function serveSite(req, res, { auth, brand }) {
  const url = new URL(req.url, 'http://x');
  const csp = `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src ${auth.origin}; form-action 'none'; base-uri 'none'`;
  const send = (type, body) => {
    res.writeHead(200, { 'content-type': type, 'content-security-policy': csp, 'cache-control': 'no-store' });
    res.end(body);
  };
  if (url.pathname === '/assets/dwarpal-browser.js') return send('text/javascript', await readFile(join(assets, 'dwarpal-browser.js')));
  if (url.pathname === '/assets/dwarpal-browser.css') return send('text/css', await readFile(join(assets, 'dwarpal-browser.css')));
  if (url.pathname === '/config.js') {
    const origin = `http://${req.headers.host}`;
    return send('text/javascript', `export default ${JSON.stringify(config(auth, { origin }, brand))};`);
  }
  if (url.pathname === '/boot.js') {
    return send('text/javascript', [
      "import { createAuthController, mountAuthScreens } from '/assets/dwarpal-browser.js';",
      "import config from '/config.js';",
      'const controller = createAuthController({ config, requestTimeoutMs: 3000 });',
      "mountAuthScreens(document.getElementById('auth'), controller);",
      'window.__view = () => controller.getView();',
      'controller.start();',
    ].join('\n'));
  }
  if (url.pathname.startsWith('/app')) return send('text/html', '<!doctype html><title>App</title><p id="app">app page</p>');
  return send('text/html', '<!doctype html><html><head><title>Account</title><link rel="stylesheet" href="/assets/dwarpal-browser.css"><script type="module" src="/boot.js"></script></head><body><main id="auth"></main></body></html>');
}

// The fixture over real HTTP, with the CORS answers a browser needs. The
// authorize endpoint plays Google: it redirects straight to the callback.
async function serveFixture(fixture, req, res) {
  const origin = req.headers.origin ?? '*';
  const cors = {
    'access-control-allow-origin': origin,
    'access-control-allow-headers': 'apikey, authorization, content-type, x-client-info, x-supabase-api-version, content-profile, accept-profile, prefer, x-retry-count',
    'access-control-allow-methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'access-control-expose-headers': 'x-supabase-api-version',
  };
  if (req.method === 'OPTIONS') {
    res.writeHead(204, cors);
    return res.end();
  }
  const url = new URL(req.url, `http://${req.headers.host}`);
  if (url.pathname === '/auth/v1/authorize') {
    res.writeHead(302, { location: fixture.completeGoogle(url.toString().replace(url.origin, 'http://127.0.0.1:54321')) });
    return res.end();
  }
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const body = Buffer.concat(chunks).toString('utf8');
  let response;
  try {
    response = await fixture.fetch(`http://127.0.0.1:54321${url.pathname}${url.search}`, {
      method: req.method,
      headers: Object.fromEntries(Object.entries(req.headers).filter(([, v]) => typeof v === 'string')),
      body: body === '' ? undefined : body,
    });
  } catch {
    req.socket.destroy();
    return undefined;
  }
  res.writeHead(response.status, { ...cors, ...Object.fromEntries(response.headers) });
  res.end(Buffer.from(await response.arrayBuffer()));
  return undefined;
}

function listen(handler) {
  return new Promise((resolve) => {
    const server = createServer((req, res) => {
      Promise.resolve(handler(req, res)).catch(() => {
        res.writeHead(500);
        res.end();
      });
    });
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      let closing = null;
      const close = () => {
        closing ??= new Promise((r) => {
          server.closeAllConnections();
          server.close(() => r());
        });
        return closing;
      };
      resolve({ origin: `http://127.0.0.1:${port}`, close });
    });
  });
}

async function kitKeys(page) {
  return page.evaluate(() => [...Object.keys(localStorage), ...Object.keys(sessionStorage)].filter((key) => key.startsWith('dwarpal:')));
}

test('sign-up, click-only verification with a stripped address, then onboarding under a strict CSP', async () => {
  const w = await world();
  try {
    const signUp = await w.open('/account/sign-up?next=%2Fapp%2Forders');
    await signUp.fill('#ak-email', 'dom@example.test');
    await signUp.fill('#ak-password', 'long enough');
    await signUp.click('button[type=submit]');
    await signUp.waitForSelector('[data-ak-state=sent]');
    assert.equal(await signUp.isDisabled('.ak-button--secondary'), true, 'resend waits for its countdown');

    const tokenHash = w.fixture.latestLink('dom@example.test', 'email');
    await signUp.goto(`${w.site.origin}/account/verify?token_hash=${tokenHash}&type=email`);
    await signUp.waitForSelector('[data-ak-screen=verify]');
    assert.equal(new URL(signUp.url()).search, '', 'token_hash and type are gone from the address bar');
    assert.equal(w.fixture.count('verify_email'), 0, 'loading the page verified nothing');
    await signUp.click('text=Confirm my e-mail address');
    await signUp.waitForURL(`${w.site.origin}/app/orders`);
    assert.equal(w.fixture.count('verify_email'), 1);
    assert.deepEqual(w.fixture.snapshot().memberships, ['studio:member:join']);
    assert.deepEqual(w.consoleLines.filter((line) => /Content Security Policy|pageerror/i.test(line)), []);
  } finally {
    await w.close();
  }
});

test('password sign-in, then sign-out with Auth unreachable clears browser storage and says so', async () => {
  const w = await world();
  try {
    w.fixture.seedUser({ email: 'out@example.test' });
    const page = await w.open('/account/sign-in');
    await page.fill('#ak-email', 'out@example.test');
    await page.fill('#ak-password', 'correct horse battery');
    await page.click('button[type=submit]');
    await page.waitForURL(`${w.site.origin}/app`);
    await page.goto(`${w.site.origin}/account/sign-out`);
    await page.waitForSelector('[data-ak-screen=signOut] .ak-button');
    assert.ok((await kitKeys(page)).length > 0);
    // Auth goes away entirely. (A one-shot reset socket is not enough here:
    // Chromium silently retries a request whose reused connection was reset.)
    await w.auth.close();
    await page.click('text=Sign out everywhere');
    await page.waitForSelector('[role=alert]');
    assert.match(await page.textContent('.ak-card'), /could not confirm that your other sessions were signed out/);
    assert.deepEqual(await kitKeys(page), []);
    await page.goto(`${w.site.origin}/account/sign-in`);
    await page.waitForSelector('[data-ak-state=idle]');
    assert.equal(await page.evaluate(() => window.__view().principal), null);
  } finally {
    await w.close();
  }
});

test('two tabs start Google at once; each callback completes with its own verifier', async () => {
  const w = await world();
  try {
    const one = await w.open('/account/sign-in');
    const two = await w.open('/account/sign-in');
    await Promise.all([one.click('text=Continue with Google'), two.click('text=Continue with Google')]);
    await Promise.all([one.waitForURL(`${w.site.origin}/app`), two.waitForURL(`${w.site.origin}/app`)]);
    assert.equal(w.fixture.count('oauth_exchange'), 2);
    assert.equal(w.fixture.snapshot().liveSessions, 2, 'both flows completed with their own verifier');
  } finally {
    await w.close();
  }
});

test('a failed recovery update keeps the reset screen, and other kit pages return to it', async () => {
  const w = await world();
  try {
    w.fixture.seedUser({ email: 'rec@example.test' });
    const tokenHash = w.fixture.issueLink('rec@example.test', 'recovery');
    const page = await w.open(`/account/reset?token_hash=${tokenHash}&type=recovery`);
    await page.click('text=Continue to set a new password');
    await page.waitForSelector('#ak-password');
    w.fixture.fault('update_password', 'http_503');
    await page.fill('#ak-password', 'a brand new secret');
    await page.click('button[type=submit]');
    await page.waitForSelector('[data-ak-state=error]');
    await page.goto(`${w.site.origin}/account/sign-in`);
    await page.waitForSelector('[data-ak-screen=reset] #ak-password');
    await page.fill('#ak-password', 'a brand new secret');
    await page.click('button[type=submit]');
    await page.waitForURL(`${w.site.origin}/app`);
  } finally {
    await w.close();
  }
});

test('MFA enrolment shows the QR image and key, and the verified session activates the withheld role', async () => {
  const w = await world();
  try {
    const userId = w.fixture.seedUser({ email: 'mfa@example.test' });
    const page = await w.open('/account/sign-in');
    await page.fill('#ak-email', 'mfa@example.test');
    await page.fill('#ak-password', 'correct horse battery');
    await page.click('button[type=submit]');
    await page.waitForURL(`${w.site.origin}/app`);
    w.fixture.grant(userId, CLIENT_ID, 'staff');
    await page.goto(`${w.site.origin}/account/mfa`);
    await page.waitForSelector('[data-ak-state=mfa_enrol]');
    assert.match(await page.textContent('.ak-withheld'), /staff/);
    await page.click('text=Set up authenticator');
    await page.waitForSelector('img.ak-qr');
    assert.equal(await page.evaluate(() => document.querySelector('img.ak-qr').naturalWidth > 0), true, 'the data: QR image loads under the CSP');
    assert.match(await page.textContent('.ak-secret'), /^[A-Z2-7]+$/);
    await page.fill('#ak-code', TOTP_CODE);
    await page.click('button[type=submit]');
    await page.waitForURL(`${w.site.origin}/app`);
  } finally {
    await w.close();
  }
});

test('brand text is rendered as text, colors apply through ak- custom properties', async () => {
  const hostile = '<img src=x onerror="window.__owned=1">Studio';
  const w = await world({ brand: { name: hostile, colors: { primary: '#aa0000' } } });
  try {
    const page = await w.open('/account/sign-in');
    assert.equal(await page.evaluate(() => document.querySelectorAll('.ak-card img').length), 0);
    assert.match(await page.textContent('h1'), /<img src=x/);
    assert.equal(await page.evaluate(() => window.__owned), undefined);
    const background = await page.evaluate(() => getComputedStyle(document.querySelector('.ak-button--primary')).backgroundColor);
    assert.equal(background, 'rgb(170, 0, 0)');
    const outside = await page.evaluate(() => {
      const probe = document.createElement('button');
      document.body.append(probe);
      return getComputedStyle(probe).backgroundColor;
    });
    assert.notEqual(outside, 'rgb(170, 0, 0)', 'host elements are untouched');
  } finally {
    await w.close();
  }
});
