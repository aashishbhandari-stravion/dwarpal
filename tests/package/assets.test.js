// The prebuilt browser assets: deterministic, current, self-consistent and
// guarded against stale or tainted output.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { cp, mkdtemp, readFile, rm, unlink, writeFile } from 'node:fs/promises';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildBrowser, checkBrowser, scanForSecrets } from '../../scripts/build-browser.mjs';

const dist = fileURLToPath(new URL('../../packages/browser/dist/', import.meta.url));
const temp = async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'dwarpal-assets-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
};

test('the default build writes the assets a tarball would carry, and a rebuild matches them byte for byte', async () => {
  const { manifest } = await buildBrowser();
  assert.deepEqual(manifest.externalImports, []);
  assert.deepEqual((await checkBrowser({ outdir: dist })).stale, []);
});

test('two builds in different directories give identical bytes and the manifest matches the files', async (t) => {
  const one = await temp(t);
  const two = await temp(t);
  await buildBrowser({ outdir: one });
  await buildBrowser({ outdir: two });
  const manifest = JSON.parse(await readFile(join(one, 'build-manifest.json'), 'utf8'));
  for (const name of ['dwarpal-browser.js', 'dwarpal-browser.css', 'build-manifest.json']) {
    const [a, b] = await Promise.all([readFile(join(one, name)), readFile(join(two, name))]);
    assert.ok(a.equals(b), `${name} differs between builds`);
  }
  for (const file of manifest.files) {
    const bytes = await readFile(join(one, file.name));
    assert.equal(file.bytes, bytes.length);
    assert.equal(file.sha256, createHash('sha256').update(bytes).digest('hex'));
  }
  assert.equal(manifest.supabaseJs, '2.117.2');
  const text = await readFile(join(one, 'dwarpal-browser.js'), 'utf8');
  assert.ok(!text.includes(homedir()) && !text.includes(fileURLToPath(new URL('../..', import.meta.url))), 'no build or home path in the bundle');
});

test('a stale, missing or altered asset is reported, not accepted', async (t) => {
  const dir = await temp(t);
  await cp(dist, dir, { recursive: true });
  assert.deepEqual((await checkBrowser({ outdir: dir })).stale, []);
  await writeFile(join(dir, 'dwarpal-browser.css'), `${await readFile(join(dir, 'dwarpal-browser.css'), 'utf8')}/* edited */`);
  await unlink(join(dir, 'build-manifest.json'));
  assert.deepEqual((await checkBrowser({ outdir: dir })).stale.sort(), ['build-manifest.json', 'dwarpal-browser.css']);
});

test('the secret and operator scan flags what a browser must never hold', () => {
  const service = `eyJhbGciOiJIUzI1NiJ9.${Buffer.from(JSON.stringify({ role: 'service_role' })).toString('base64url')}.c2lnbmF0dXJl`;
  assert.deepEqual(scanForSecrets('const a = 1;'), []);
  for (const bad of ['sb_secret_abcdefghij1234', 'sbp_abcdefghijklmnop1234', 'process.env.SUPABASE_SECRET_KEY', 'https://api.supabase.com/v1', 'auth_kit_private.x', 'rpc("bootstrap_manager")', 'grant_membership', service]) {
    assert.ok(scanForSecrets(bad).length > 0, bad);
  }
  // The validators name the prefix without holding a key value.
  assert.deepEqual(scanForSecrets('value.startsWith("sb_secret_")'), []);
});
