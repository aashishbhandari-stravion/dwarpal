// The two built examples in real Chromium against the synthetic loopback
// fixture: CREDITONE (esbuild, default prefix and roles) and the synthetic
// second brand Example Studio (Vite, another prefix, route names, roles and
// copy) run the same unchanged package. Fixture evidence: no real SMTP,
// Google, TOTP provider or hosted Supabase is involved.
//
// Not part of `npm test`: it needs the examples installed against the packed
// tarball. Run `npm run test:examples-built`, which stages them and sets
// DWARPAL_EXAMPLES_STAGE.

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { extname, join, normalize } from 'node:path';
import { chromium } from 'playwright-core';
import { startAuthEmulator } from '../../../packages/emulator/index.js';

const STAGE = process.env.DWARPAL_EXAMPLES_STAGE;
if (!STAGE) throw new Error('DWARPAL_EXAMPLES_STAGE is not set; run `npm run test:examples-built`.');
const PASSWORD = 'fixture-password-1';

const EXAMPLES = [
  {
    name: 'CREDITONE example (esbuild)', dir: 'creditone', build: ['build.mjs'], clientId: 'creditone', prefix: '/account',
    signIn: '/account/sign-in', signUp: '/account/sign-up', verify: '/account/verify', next: '/orders',
    title: 'Sign in to CREDITONE', roles: ['customer'],
  },
  {
    name: 'Example Studio (Vite)', dir: 'studio', build: ['node_modules/vite/bin/vite.js', 'build'], clientId: 'example-studio', prefix: '/studio/account',
    signIn: '/studio/account/log-in', signUp: '/studio/account/join', verify: '/studio/account/verify', next: '/studio/posts',
    title: 'Welcome back to Example Studio', roles: ['member'],
  },
];
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css' };
let browser;
test.before(async () => { browser = await chromium.launch(); });
test.after(async () => { await browser?.close(); });

function listen(handler) {
  return new Promise((resolve, reject) => {
    const server = createServer((req, res) => {
      Promise.resolve(handler(req, res)).catch(() => {
        if (!res.headersSent) res.writeHead(500);
        res.end();
      });
    });
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve({
      server,
      origin: `http://127.0.0.1:${server.address().port}`,
      close: () => new Promise((done) => { server.closeAllConnections(); server.close(done); }),
    }));
  });
}

for (const example of EXAMPLES) {
  test(`${example.name}: built pages sign a new user up, verify, enrol with the model's self-assignable role and land on the return path`, async (t) => {
    const emulator = await startAuthEmulator();
    t.after(() => emulator.close());
    const model = JSON.parse(await readFile(join(STAGE, example.dir, 'auth-model.json'), 'utf8'));
    emulator.controls.seedClient({ clientId: example.clientId, signupPolicy: 'open', model });

    let dist = null;
    const site = await listen(async (req, res) => {
      const url = new URL(req.url, 'http://x');
      const headers = {
        'cache-control': 'no-store',
        'content-security-policy': `default-src 'none'; script-src 'self'; style-src 'self'; connect-src ${emulator.origin}; img-src 'self' data:; base-uri 'none'; form-action 'self'`,
      };
      if (dist && url.pathname.startsWith(`${example.prefix}/`)) {
        let relative = normalize(url.pathname.slice(example.prefix.length + 1));
        if (relative.startsWith('..')) { res.writeHead(400); return res.end(); }
        // Like `try_files $uri $uri/index.html`: a route resolves to its directory's index page.
        let file = join(dist, relative);
        if ((await stat(file).catch(() => null))?.isDirectory()) file = join(file, 'index.html');
        if ((await stat(file).catch(() => null))?.isFile()) {
          res.writeHead(200, { ...headers, 'content-type': TYPES[extname(file)] ?? 'application/octet-stream' });
          return res.end(await readFile(file));
        }
        res.writeHead(404, headers);
        return res.end();
      }
      // The host site's own pages (return paths) are stubs here.
      res.writeHead(200, { ...headers, 'content-type': TYPES['.html'] });
      res.end('<!doctype html><title>host page</title><p>host page</p>');
    });
    t.after(() => site.close());

    dist = await mkdtemp(join(tmpdir(), 'dwarpal-example-dist-'));
    t.after(() => rm(dist, { recursive: true, force: true }));
    const built = spawnSync(process.execPath, example.build, {
      cwd: join(STAGE, example.dir), encoding: 'utf8',
      env: { PATH: process.env.PATH, HOME: process.env.HOME, SUPABASE_URL: emulator.origin, SUPABASE_PUBLISHABLE_KEY: emulator.publishableKey, SITE_ORIGIN: site.origin, OUT_DIR: dist },
    });
    assert.equal(built.status, 0, built.stderr || built.stdout);

    const context = await browser.newContext();
    t.after(() => context.close());
    const problems = [];
    const hosts = new Set();
    context.on('page', (page) => {
      page.on('pageerror', (error) => problems.push(`pageerror: ${error.message}`));
      page.on('console', (message) => { if (message.type() === 'error') problems.push(`console: ${message.text()}`); });
      page.on('request', (request) => hosts.add(new URL(request.url()).host));
    });
    const page = await context.newPage();

    await page.goto(`${site.origin}${example.signIn}`);
    await page.waitForSelector('.ak-title');
    assert.equal(await page.textContent('.ak-title'), example.title);
    assert.equal(await page.getAttribute('meta[name=robots]', 'content'), 'noindex, nofollow');
    assert.ok((await page.title()).length > 0);

    // The sign-in page links to the configured sign-up route. The return path is chosen where the flow starts.
    assert.ok(await page.locator(`a.ak-link[href="${example.signUp}"]`).count() === 1);
    await page.goto(`${site.origin}${example.signUp}?next=${encodeURIComponent(example.next)}`);
    await page.waitForSelector('form input[name=password]');
    await page.fill('input[name=email]', 'new@example.test');
    await page.fill('input[name=password]', PASSWORD);
    await page.click('form button[type=submit]');
    await page.waitForSelector('[data-ak-state="sent"]');
    assert.equal(emulator.controls.snapshot().counts.mailsSent, 1);

    // Following the mail link only asks for a click; the click confirms and signs in.
    const { tokenHash } = emulator.controls.issueLink({ type: 'email', email: 'new@example.test' });
    await page.goto(`${site.origin}${example.verify}?token_hash=${tokenHash}&type=email`);
    await page.waitForSelector('[data-ak-screen="verify"] button.ak-button--primary');
    assert.equal(emulator.controls.snapshot().counts.linksUsed, 0, 'loading the page did not consume the link');
    await page.click('[data-ak-screen="verify"] button.ak-button--primary');
    await page.waitForURL(`${site.origin}${example.next}`);

    const client = emulator.controls.snapshot().clients.find((c) => c.clientId === example.clientId);
    assert.equal(client.enrollments.length, 1);
    assert.deepEqual(client.memberships.map((m) => m.roleKey), example.roles);
    assert.deepEqual(client.events.map((e) => [e.action, e.roleKey]), example.roles.map((role) => ['join', role]));
    assert.deepEqual([...hosts].sort(), [new URL(emulator.origin).host, new URL(site.origin).host].sort(), 'no request left the loopback');
    assert.deepEqual(problems, []);
  });
}
