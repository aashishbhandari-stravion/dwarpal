// The two built examples in real Chromium against the synthetic loopback
// fixture: CREDITONE (esbuild, default prefix and roles) and the synthetic
// second brand Example Studio (Vite, another prefix, route names, roles and
// copy) run the same unchanged package. Both are also built with hostile and
// punctuated (valid) brand names, which must stay text in every page. Fixture
// evidence: no real SMTP, Google, TOTP provider or hosted Supabase is involved.
//
// Not part of `npm test`: it needs the examples installed against the packed
// tarball. Run `npm run test:examples-built`, which stages them and sets
// DWARPAL_EXAMPLES_STAGE.

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
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

const cspFor = (emulatorOrigin) => `default-src 'none'; script-src 'self'; style-src 'self'; connect-src ${emulatorOrigin}; img-src 'self' data:; base-uri 'none'; form-action 'self'`;

/** A static host for one built example: `setDist(dir)` chooses the build served under the prefix. */
async function serveExample(example, emulatorOrigin) {
  let dist = null;
  const site = await listen(async (req, res) => {
    const url = new URL(req.url, 'http://x');
    const headers = { 'cache-control': 'no-store', 'content-security-policy': cspFor(emulatorOrigin) };
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
  return { ...site, setDist: (dir) => { dist = dir; } };
}

/** Builds the staged example into a fresh directory against the fixture; returns the directory. */
async function buildExample(t, example, emulator, siteOrigin) {
  const dist = await mkdtemp(join(tmpdir(), 'dwarpal-example-dist-'));
  t.after(() => rm(dist, { recursive: true, force: true }));
  const built = spawnSync(process.execPath, example.build, {
    cwd: join(STAGE, example.dir), encoding: 'utf8',
    env: { PATH: process.env.PATH, HOME: process.env.HOME, SUPABASE_URL: emulator.origin, SUPABASE_PUBLISHABLE_KEY: emulator.publishableKey, SITE_ORIGIN: siteOrigin, OUT_DIR: dist },
  });
  assert.equal(built.status, 0, built.stderr || built.stdout);
  return dist;
}

for (const example of EXAMPLES) {
  test(`${example.name}: built pages sign a new user up, verify, enrol with the model's self-assignable role and land on the return path`, async (t) => {
    const emulator = await startAuthEmulator();
    t.after(() => emulator.close());
    const model = JSON.parse(await readFile(join(STAGE, example.dir, 'auth-model.json'), 'utf8'));
    emulator.controls.seedClient({ clientId: example.clientId, signupPolicy: 'open', model });

    const site = await serveExample(example, emulator.origin);
    t.after(() => site.close());
    site.setDist(await buildExample(t, example, emulator, site.origin));

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

// The public validator accepts any brand name of 1 to 128 characters, so the
// page generators must treat it as text. Each case is a valid configuration.
const BRANDS = [
  ['markup that closes the title and adds an external script', 'Valid brand</title><script src="https://example.org/extra.js"></script>'],
  ['an attribute break-out and an element with a handler', 'Brand" data-injected="1"><img src="https://example.org/x.png" onerror="alert(1)">'],
  ['ordinary punctuation', `O'Brien & Söhne "Café" – Nº 1 (Pty) Ltd. <Est. 1999>`],
];

/** Every route page as Chromium parses it. */
function readPage() {
  return {
    title: document.title,
    descriptions: [...document.querySelectorAll('meta[name=description]')].map((meta) => meta.content),
    scripts: [...document.scripts].map((script) => script.getAttribute('src')),
    head: [...document.head.children].map((element) => element.tagName.toLowerCase()),
    body: [...document.body.children].map((element) => element.tagName.toLowerCase()),
    injected: document.querySelectorAll('[data-injected], [onerror]').length,
  };
}

for (const example of EXAMPLES) {
  test(`${example.name}: hostile and punctuated brand names stay text in every built page`, async (t) => {
    const emulator = await startAuthEmulator();
    t.after(() => emulator.close());
    const model = JSON.parse(await readFile(join(STAGE, example.dir, 'auth-model.json'), 'utf8'));
    emulator.controls.seedClient({ clientId: example.clientId, signupPolicy: 'open', model });
    const site = await serveExample(example, emulator.origin);
    t.after(() => site.close());

    // The brand comes from the example's configuration file; the staged copy is restored afterwards.
    const configPath = join(STAGE, example.dir, 'auth-kit.config.json');
    const original = await readFile(configPath, 'utf8');
    t.after(() => writeFile(configPath, original));
    const defaultBrand = JSON.parse(original).brand.name;
    const buildWithBrand = async (name) => {
      const config = JSON.parse(original);
      config.brand.name = name;
      await writeFile(configPath, JSON.stringify(config, null, 2));
      return buildExample(t, example, emulator, site.origin);
    };

    const context = await browser.newContext();
    t.after(() => context.close());
    const problems = [];
    const leftLoopback = [];
    const loopback = new Set([new URL(emulator.origin).host, new URL(site.origin).host]);
    await context.route('**/*', (route) => {
      if (loopback.has(new URL(route.request().url()).host)) return route.continue();
      leftLoopback.push(route.request().url());
      return route.abort();
    });
    context.on('page', (page) => {
      page.on('pageerror', (error) => problems.push(`pageerror: ${error.message}`));
      page.on('console', (message) => { if (/Content Security Policy/i.test(message.text())) problems.push(`console: ${message.text()}`); });
    });
    const page = await context.newPage();

    const pagesOf = async (dist) => (await readdir(dist, { recursive: true })).filter((file) => file.endsWith('index.html')).sort();
    const reference = await buildWithBrand(defaultBrand);
    const routes = await pagesOf(reference);
    assert.equal(routes.length, 8);
    site.setDist(reference);
    const expected = {};
    for (const route of routes) {
      await page.goto(`${site.origin}${example.prefix}/${route.replace(/index\.html$/, '')}`);
      expected[route] = await page.evaluate(readPage);
      assert.equal(expected[route].scripts.length, 1);
      assert.equal(expected[route].descriptions.length, 1);
      assert.ok(expected[route].title.includes(defaultBrand) && expected[route].descriptions[0].includes(defaultBrand));
    }

    for (const [label, brand] of BRANDS) {
      assert.ok(brand.length <= 128, label);
      const dist = await buildWithBrand(brand);
      assert.deepEqual(await pagesOf(dist), routes, label);
      site.setDist(dist);
      const swap = (text) => text.split(defaultBrand).join(brand);
      for (const route of routes) {
        const html = await readFile(join(dist, route), 'utf8');
        assert.equal(html.match(/<script\b/gi).length, 1, `${label}: ${route} has one script tag`);
        assert.ok(!html.includes(brand), `${label}: ${route} carries the brand only escaped`);
        await page.goto(`${site.origin}${example.prefix}/${route.replace(/index\.html$/, '')}`);
        const { scripts, ...seen } = await page.evaluate(readPage);
        const { scripts: _, ...want } = expected[route];
        // Exactly one script, the example's own (Vite names it by content hash, and the brand is in the bundle).
        assert.equal(scripts.length, 1, `${label}: ${route} has one script`);
        assert.match(scripts[0], new RegExp(`^${example.prefix}/assets/[^/]+\\.js$`), `${label}: ${route}`);
        assert.deepEqual(seen, {
          ...want, title: swap(want.title), descriptions: want.descriptions.map(swap),
        }, `${label}: ${route} parses to the same page with the brand as text`);
      }
      // The default screens show the brand as text too.
      await page.goto(`${site.origin}${example.signIn}`);
      await page.waitForSelector('.ak-title');
      assert.equal(await page.textContent('.ak-title'), swap(example.title), label);
    }
    assert.deepEqual(leftLoopback, [], 'no request left the loopback');
    assert.deepEqual(problems, []);
  });
}
