// The prebuilt browser assets exactly as installed from the packed tarball,
// served like a static host would serve them, in real Chromium against the
// synthetic loopback fixture. A consuming site imports one JS module and one
// stylesheet and needs no bundler. Fixture evidence, not hosted proof.
//
// Run by scripts/check-package.mjs, which sets DWARPAL_INSTALLED_PACKAGE to the
// installed package directory. Not part of `npm test`.

import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { chromium } from 'playwright-core';
import { startAuthEmulator } from '../../../packages/emulator/index.js';
import { studioModel } from '../../emulator/support.js';

const PACKAGE = process.env.DWARPAL_INSTALLED_PACKAGE;
if (!PACKAGE) throw new Error('DWARPAL_INSTALLED_PACKAGE is not set; run `npm run check:package`.');
const DIST = join(PACKAGE, 'packages/browser/dist');

test('the installed prebuilt module and stylesheet sign a seeded user in under a strict Content-Security-Policy', async (t) => {
  const emulator = await startAuthEmulator();
  t.after(() => emulator.close());
  emulator.controls.seedClient({ clientId: 'studio', signupPolicy: 'open', model: studioModel() });
  emulator.controls.seedUser({ email: 'static@example.test', password: 'fixture-password-1' });

  const seen = [];
  const server = createServer(async (req, res) => {
    const path = new URL(req.url, 'http://x').pathname;
    seen.push(path);
    const headers = {
      'cache-control': 'no-store',
      'content-security-policy': `default-src 'none'; script-src 'self'; style-src 'self'; connect-src ${emulator.origin}; img-src 'self' data:; base-uri 'none'`,
    };
    const send = (type, body) => { res.writeHead(200, { ...headers, 'content-type': type }); res.end(body); };
    if (path === '/dwarpal-browser.js') return send('text/javascript', await readFile(join(DIST, 'dwarpal-browser.js')));
    if (path === '/dwarpal-browser.css') return send('text/css', await readFile(join(DIST, 'dwarpal-browser.css')));
    const origin = `http://${req.headers.host}`;
    if (path === '/boot.js') {
      return send('text/javascript', [
        "import { createAuthController, mountAuthScreens } from '/dwarpal-browser.js';",
        `const controller = createAuthController({ autoNavigate: false, config: ${JSON.stringify({
          clientId: 'studio', supabaseUrl: emulator.origin, publishableKey: emulator.publishableKey, origin,
          allowedReturnPaths: ['/app'], defaultReturnPath: '/app', providers: { email: true, google: false }, selfSignup: true,
        })} });`,
        "mountAuthScreens(document.getElementById('auth'), controller);",
        'controller.start();',
      ].join('\n'));
    }
    return send('text/html', '<!doctype html><title>static host</title><link rel="stylesheet" href="/dwarpal-browser.css"><script type="module" src="/boot.js"></script><main id="auth"></main>');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((done) => { server.closeAllConnections(); server.close(done); }));
  const site = `http://127.0.0.1:${server.address().port}`;

  const browser = await chromium.launch();
  t.after(() => browser.close());
  const page = await browser.newPage();
  const problems = [];
  page.on('pageerror', (error) => problems.push(error.message));
  page.on('console', (message) => { if (message.type() === 'error') problems.push(message.text()); });
  await page.goto(`${site}/account/sign-in`);
  await page.waitForSelector('form input[name=password]');
  await page.fill('input[name=email]', 'static@example.test');
  await page.fill('input[name=password]', 'fixture-password-1');
  await page.click('form button[type=submit]');
  await page.waitForSelector('[data-ak-state="signed_in"]');
  const client = emulator.controls.snapshot().clients[0];
  assert.deepEqual(client.memberships.map((m) => m.roleKey), ['member', 'reader'], 'first sign-in enrolled the self-assignable roles');
  assert.ok(seen.includes('/dwarpal-browser.js') && seen.includes('/dwarpal-browser.css'));
  assert.deepEqual(problems, []);
});
