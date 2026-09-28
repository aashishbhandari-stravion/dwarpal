// Cross-lane browser gate: the built 04A bundle runs in Chromium against the
// 04B HTTP emulator. All identities, mail, OAuth and TOTP are synthetic.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { chromium } from 'playwright-core';
import { buildBrowser } from '../../scripts/build-browser.mjs';
import { startAuthEmulator } from '../../packages/emulator/index.js';
import { studioModel } from '../emulator/support.js';

const CLIENT = 'studio';
const PASSWORD = 'fixture-password-1';
let assets;
let browser;

test.before(async () => {
  assets = await mkdtemp(join(tmpdir(), 'dwarpal-cross-browser-'));
  await buildBrowser({ outdir: assets });
  browser = await chromium.launch();
});

test.after(async () => {
  await browser?.close();
  if (assets) await rm(assets, { recursive: true, force: true });
});

function listen(handler) {
  return new Promise((resolve, reject) => {
    const server = createServer((req, res) => {
      Promise.resolve(handler(req, res)).catch(() => {
        if (!res.headersSent) res.writeHead(500);
        res.end();
      });
    });
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ origin: `http://127.0.0.1:${port}`, close: () => new Promise((done) => {
        server.closeAllConnections();
        server.close(done);
      }) });
    });
  });
}

async function world(t, { model = studioModel(), signupPolicy = 'open' } = {}) {
  const emulator = await startAuthEmulator();
  t.after(() => emulator.close());
  emulator.controls.seedClient({ clientId: CLIENT, signupPolicy, model });
  const site = await listen(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const send = (type, body) => {
      res.writeHead(200, {
        'content-type': type,
        'cache-control': 'no-store',
        'content-security-policy': `default-src 'none'; script-src 'self'; style-src 'self'; connect-src ${emulator.origin}; img-src 'self' data:; base-uri 'none'`,
      });
      res.end(body);
    };
    if (url.pathname === '/bundle.js') return send('text/javascript', await readFile(join(assets, 'dwarpal-browser.js')));
    if (url.pathname === '/bundle.css') return send('text/css', await readFile(join(assets, 'dwarpal-browser.css')));
    if (url.pathname === '/config.js') return send('text/javascript', `export default ${JSON.stringify({
      clientId: CLIENT,
      supabaseUrl: emulator.origin,
      publishableKey: emulator.publishableKey,
      origin: `http://${req.headers.host}`,
      allowedReturnPaths: ['/app', '/app/orders'],
      defaultReturnPath: '/app',
      providers: { email: true, google: true },
      selfSignup: true,
    })};`);
    if (url.pathname === '/boot.js') return send('text/javascript', [
      "import { createAuthController, mountAuthScreens } from '/bundle.js';",
      "import config from '/config.js';",
      'const controller = createAuthController({ config, autoNavigate: false, requestTimeoutMs: 1500 });',
      "mountAuthScreens(document.getElementById('auth'), controller);",
      'window.__controller = controller;',
      'window.__view = () => controller.getView();',
      'window.__ready = controller.start();',
    ].join('\n'));
    return send('text/html', '<!doctype html><title>Fixture account</title><link rel="stylesheet" href="/bundle.css"><script type="module" src="/boot.js"></script><main id="auth"></main>');
  });
  t.after(() => site.close());
  const context = await browser.newContext();
  t.after(() => context.close());
  const errors = [];
  context.on('page', (page) => page.on('pageerror', (error) => errors.push(error.message)));
  async function open(path) {
    const page = await context.newPage();
    await page.goto(`${site.origin}${path}`);
    await page.evaluate(() => window.__ready);
    return page;
  }
  return { emulator, site, context, errors, open };
}

const view = (page) => page.evaluate(() => window.__view());
const act = (page, method, input) => page.evaluate(({ method, input }) => window.__controller[method](input), { method, input });
const client = (emulator) => emulator.controls.snapshot().clients.find((item) => item.clientId === CLIENT);
const keys = (page) => page.evaluate(() => [...Object.keys(localStorage), ...Object.keys(sessionStorage)].filter((key) => key.startsWith('dwarpal:')));

test('L1/L2/L11: neutral existing signup, click-only verification and a safe return path', async (t) => {
  const w = await world(t);
  w.emulator.controls.seedUser({ email: 'existing@example.test', password: PASSWORD });
  const page = await w.open('/account/sign-up?next=https%3A%2F%2Fevil.example%2Fsteal');
  const before = w.emulator.controls.snapshot().counts;
  assert.equal((await act(page, 'signUp', { email: 'existing@example.test', password: PASSWORD })).state, 'sent');
  const after = w.emulator.controls.snapshot().counts;
  assert.equal(after.users, before.users);
  assert.equal(after.mailsSent, before.mailsSent);

  assert.equal((await act(page, 'signUp', { email: 'new@example.test', password: PASSWORD })).state, 'sent');
  const { tokenHash } = w.emulator.controls.issueLink({ type: 'email', email: 'new@example.test' });
  const link = await w.open(`/account/verify?token_hash=${tokenHash}&type=email&next=https%3A%2F%2Fevil.example`);
  assert.equal(new URL(link.url()).searchParams.has('token_hash'), false);
  assert.equal(w.emulator.controls.snapshot().counts.linksUsed, 0, 'page load did not consume the link');
  const confirmed = await act(link, 'confirmLink');
  assert.equal(confirmed.state, 'signed_in');
  assert.equal(confirmed.next, '/app');
  assert.equal(w.emulator.controls.snapshot().counts.linksUsed, 1);
  assert.equal(client(w.emulator).enrollments.length, 1);
  assert.deepEqual(w.errors, []);
});

test('L3/L8: two browser tabs bind their own Google PKCE flow; denied consent creates no session', async (t) => {
  const w = await world(t);
  w.emulator.controls.setOAuthAccount({ email: 'google@example.test' });
  const one = await w.open('/account/sign-in');
  const two = await w.open('/account/sign-in');
  await Promise.all([act(one, 'startGoogle'), act(two, 'startGoogle')]);
  await Promise.all([one.waitForURL(`${w.site.origin}/account/callback`), two.waitForURL(`${w.site.origin}/account/callback`)]);
  await Promise.all([one.evaluate(() => window.__ready), two.evaluate(() => window.__ready)]);
  assert.equal((await view(one)).state, 'signed_in');
  assert.equal((await view(two)).state, 'signed_in');
  assert.equal(w.emulator.controls.snapshot().httpRequests.oauth_exchange, 2);

  w.emulator.controls.setOAuthAccount(null);
  const denied = await w.open('/account/sign-in');
  await act(denied, 'startGoogle');
  await denied.waitForURL(`${w.site.origin}/account/callback`);
  await denied.evaluate(() => window.__ready);
  assert.notEqual((await view(denied)).state, 'signed_in');
  assert.equal(w.emulator.controls.snapshot().httpRequests.oauth_exchange, 2);
  assert.deepEqual(w.errors, []);
});

test('L4/L21/L27: lost join reply converges on retry; a revoked membership stays revoked', async (t) => {
  const w = await world(t);
  const { userId } = w.emulator.controls.seedUser({ email: 'join@example.test', password: PASSWORD });
  const page = await w.open('/account/sign-in');
  w.emulator.controls.setFault({ operation: 'join_client', mode: 'lost_after_commit' });
  const first = await act(page, 'signIn', { email: 'join@example.test', password: PASSWORD });
  assert.ok(['setup_pending', 'signed_in'].includes(first.state), 'Chromium may retry a reset HTTP connection');
  assert.equal(client(w.emulator).enrollments.length, 1);
  assert.equal(client(w.emulator).events.filter((event) => event.action === 'join').length, 2);
  const retried = first.state === 'signed_in' ? first : await act(page, 'retry');
  assert.equal(retried.state, 'signed_in');
  assert.equal(client(w.emulator).events.filter((event) => event.action === 'join').length, 2);

  w.emulator.controls.setMembership({ userId, clientId: CLIENT, roleKey: 'member', present: false });
  w.emulator.controls.setMembership({ userId, clientId: CLIENT, roleKey: 'reader', present: false });
  await act(page, 'signOut');
  const again = await act(page, 'signIn', { email: 'join@example.test', password: PASSWORD });
  assert.equal(again.state, 'no_access');
  assert.equal(client(w.emulator).enrollments.length, 1);
  assert.equal(client(w.emulator).memberships.filter((m) => m.userId === userId).length, 0);
  assert.deepEqual(w.errors, []);
});

test('L4/L21: an explicit retry follows a pre-commit fault; missing defaults and closed signup stay pending or denied', async (t) => {
  const w = await world(t);
  w.emulator.controls.seedUser({ email: 'retry@example.test', password: PASSWORD });
  const page = await w.open('/account/sign-in');
  w.emulator.controls.setFault({ operation: 'join_client', mode: 'http_503' });
  const failed = await act(page, 'signIn', { email: 'retry@example.test', password: PASSWORD });
  assert.deepEqual([failed.state, failed.setupReason], ['setup_pending', 'unavailable']);
  assert.equal(client(w.emulator).enrollments.length, 0);
  assert.equal((await act(page, 'retry')).state, 'signed_in');
  assert.equal(client(w.emulator).enrollments.length, 1);
  assert.equal(client(w.emulator).events.filter((event) => event.action === 'join').length, 2);

  const noModel = await world(t, { model: null });
  noModel.emulator.controls.seedUser({ email: 'pending@example.test', password: PASSWORD });
  const pending = await noModel.open('/account/sign-in');
  const pendingView = await act(pending, 'signIn', { email: 'pending@example.test', password: PASSWORD });
  assert.deepEqual([pendingView.state, pendingView.setupReason], ['setup_pending', 'no_default_role']);
  assert.equal(client(noModel.emulator).enrollments.length, 0);

  const closed = await world(t, { signupPolicy: 'closed' });
  closed.emulator.controls.seedUser({ email: 'closed@example.test', password: PASSWORD });
  const denied = await closed.open('/account/sign-in');
  assert.equal((await act(denied, 'signIn', { email: 'closed@example.test', password: PASSWORD })).state, 'no_access');
  assert.equal(client(closed.emulator).enrollments.length, 0);
  assert.deepEqual([...w.errors, ...noModel.errors, ...closed.errors], []);
});

test('L13/L14/L20: recovery remains pending after an error; MFA activates a withheld role', async (t) => {
  const w = await world(t);
  const { userId } = w.emulator.controls.seedUser({ email: 'factor@example.test', password: PASSWORD });
  const { tokenHash } = w.emulator.controls.issueLink({ type: 'recovery', email: 'factor@example.test' });
  const reset = await w.open(`/account/reset?token_hash=${tokenHash}&type=recovery`);
  assert.equal((await act(reset, 'confirmLink')).recoveryPending, true);
  w.emulator.controls.setFault({ operation: 'update_password', mode: 'http_503' });
  const failed = await act(reset, 'updatePassword', { password: 'new-secret-password' });
  assert.equal(failed.recoveryPending, true);
  assert.equal(failed.state, 'error');
  assert.equal((await act(reset, 'updatePassword', { password: 'new-secret-password' })).recoveryPending, false);

  w.emulator.controls.setMembership({ userId, clientId: CLIENT, roleKey: 'curator', present: true });
  await act(reset, 'signOut');
  const signedIn = await act(reset, 'signIn', { email: 'factor@example.test', password: 'new-secret-password' });
  assert.equal(signedIn.state, 'mfa_enrol');
  assert.ok(signedIn.withheldRoles.includes('curator'));
  const enrol = await act(reset, 'startMfaEnrol');
  assert.equal(enrol.state, 'mfa_enrol');
  const factorId = w.emulator.controls.snapshot().users.find((user) => user.userId === userId).factors[0].factorId;
  const code = w.emulator.controls.totpCode({ factorId });
  const verified = await act(reset, 'verifyMfa', { code });
  assert.equal(verified.state, 'signed_in');
  assert.ok(verified.principal.access.activeRoles.includes('curator'));
  assert.deepEqual(await keys(reset).then((all) => all.filter((key) => key.includes('recovery'))), []);
  assert.deepEqual(w.errors, []);
});
