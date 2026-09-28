// The shipped browser artifacts: source and bundle carry no secret or
// operator markers, the bundle builds reproducibly, the stylesheet is fully
// `ak-` scoped, and no flow writes tokens, passwords or links to the console.

import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildBrowser, scanForSecrets } from '../../scripts/build-browser.mjs';
import { signedIn, setup, CLIENT_ID, MODEL_ROLES } from './support/env.js';
import { createScriptedSupabase, makeToken, TOTP_CODE } from './support/scripted-supabase.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../..');

async function sourceFiles(dir) {
  const out = [];
  for (const entry of await readdir(join(ROOT, dir), { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...await sourceFiles(path));
    else out.push(path);
  }
  return out;
}

test('the scanner itself finds each marker class it guards against', () => {
  const samples = [
    'sb_secret_0123456789abcdef', 'sbp_0123456789abcdef0123', 'SUPABASE_SECRET_KEY', 'SUPABASE_ACCESS_TOKEN',
    'https://api.supabase.com/v1/projects', 'auth_kit_private.clients', 'rpc("bootstrap_manager")', 'grant_membership',
    makeToken({ role: 'service_role', iss: 'supabase' }),
  ];
  for (const sample of samples) assert.ok(scanForSecrets(`x ${sample} y`).length > 0, sample);
  assert.deepEqual(scanForSecrets(`${makeToken({ role: 'anon' })} sb_publishable_abc join_client effective_access`), []);
});

test('browser source files carry no secret or operator markers', async () => {
  const files = [...await sourceFiles('packages/browser'), 'scripts/build-browser.mjs'].filter((f) => !f.includes('/dist/'));
  assert.ok(files.length >= 10);
  for (const file of files) {
    const text = await readFile(join(ROOT, file), 'utf8');
    // The build script names the markers it forbids; only its values matter.
    const markers = scanForSecrets(file.endsWith('build-browser.mjs') ? text.replace(/FORBIDDEN_PATTERNS = Object\.freeze\(\[[\s\S]*?\]\);/, '') : text);
    assert.deepEqual(markers, [], file);
  }
});

test('the bundle builds reproducibly, is secret-free, and is self-contained', async () => {
  const one = await mkdtemp(join(tmpdir(), 'dwarpal-browser-'));
  const two = await mkdtemp(join(tmpdir(), 'dwarpal-browser-'));
  try {
    const a = await buildBrowser({ outdir: one });
    const b = await buildBrowser({ outdir: two });
    assert.deepEqual(a.manifest, b.manifest, 'same inputs, same bytes');
    assert.equal(a.manifest.supabaseJs, '2.117.2');
    const bundle = await readFile(join(one, 'dwarpal-browser.js'), 'utf8');
    assert.deepEqual(scanForSecrets(bundle), []);
    assert.deepEqual(a.manifest.externalImports, [], 'no unresolved imports');
    assert.ok(!bundle.includes(ROOT), 'no absolute build paths');
    const js = a.manifest.files.find((f) => f.name === 'dwarpal-browser.js');
    assert.ok(js.gzipBytes < 120 * 1024, `gzip size ${js.gzipBytes} stays under the review threshold`);
  } finally {
    await rm(one, { recursive: true, force: true });
    await rm(two, { recursive: true, force: true });
  }
});

test('the stylesheet is scoped: every selector and custom property is ak- prefixed, no imports or remote URLs', async () => {
  const css = (await readFile(join(ROOT, 'packages/browser/styles.css'), 'utf8')).replace(/\/\*[\s\S]*?\*\//g, '');
  assert.ok(!/@import|url\(/i.test(css));
  const selectors = [];
  for (const match of css.matchAll(/([^{}]+)\{/g)) {
    const head = match[1].trim();
    if (head.startsWith('@media')) continue;
    selectors.push(...head.split(',').map((s) => s.trim()));
  }
  assert.ok(selectors.length > 20);
  for (const selector of selectors) assert.match(selector, /^\.ak-[a-z-]+/, selector);
  for (const [, name] of css.matchAll(/(--[A-Za-z-]+)\s*:/g)) assert.match(name, /^--ak-/, name);
});

test('no flow writes tokens, passwords, token hashes or codes to the console', async () => {
  const captured = [];
  const originals = {};
  for (const level of ['log', 'info', 'warn', 'error', 'debug', 'trace']) {
    originals[level] = console[level];
    console[level] = (...args) => captured.push(args.map(String).join(' '));
  }
  try {
    const fixture = createScriptedSupabase();
    fixture.seedClient({ clientId: CLIENT_ID, roles: MODEL_ROLES });
    const password = 'correct horse battery';
    const { controller, userId } = await signedIn({ fixture });
    fixture.grant(userId, CLIENT_ID, 'staff');
    await controller.start();
    await controller.startMfaEnrol();
    await controller.verifyMfa({ code: TOTP_CODE });
    fixture.fault('global_sign_out', 'transport_loss');
    await controller.signOut();
    const recovery = fixture.issueLink('member@example.test', 'recovery');
    const reset = await setup(`/account/reset?token_hash=${recovery}&type=recovery`, { fixture });
    await reset.controller.confirmLink();
    await reset.controller.updatePassword({ password: 'a brand new secret' });
    const logs = captured.join('\n');
    for (const secret of [password, 'a brand new secret', recovery, TOTP_CODE, 'eyJ', 'sb_publishable_']) {
      assert.ok(!logs.includes(secret), `console output contains ${secret.slice(0, 6)}…`);
    }
  } finally {
    Object.assign(console, originals);
  }
});
