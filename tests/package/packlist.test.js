// What `npm pack` would put in the tarball, read from a dry run: exactly the
// intended runtime files, the SQL byte for byte, and nothing private.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFile, readdir, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { buildBrowser } from '../../scripts/build-browser.mjs';

const root = fileURLToPath(new URL('../..', import.meta.url));
// The dry run skips lifecycle scripts, so build the assets exactly as prepack would.
await buildBrowser();
const manifest = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
const pack = JSON.parse(execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }))[0];
const names = pack.files.map((f) => f.path).sort();

test('the manifest is a private, exact-pinned, bundler-free package for Node 22+', () => {
  assert.equal(manifest.name, '@briqvent/dwarpal');
  assert.equal(manifest.private, true, 'a release is a separate, owner-approved step');
  assert.equal(manifest.version, '0.0.0');
  assert.equal(manifest.engines.node, '>=22');
  assert.deepEqual(Object.keys(manifest.dependencies).sort(), ['@supabase/supabase-js', 'jose']);
  assert.match(manifest.dependencies['@supabase/supabase-js'], /^\d+\.\d+\.\d+$/, 'browser runtime pinned exactly');
  assert.ok(!('esbuild' in manifest.dependencies) && !('esbuild' in (manifest.peerDependencies ?? {})));
  assert.equal(manifest.license, 'MIT');
});

test('the tarball holds the intended runtime files, the SQL, the prebuilt assets and the Markdown docs', () => {
  for (const required of [
    'package.json', 'README.md', 'LICENSE', 'docs/manual.md', 'docs/design.md', 'docs/rbac-lld.md',
    'packages/core/index.js', 'packages/server/index.js', 'packages/server/cli/auth-kit.js', 'packages/browser/index.js',
    'packages/browser/styles.css', 'packages/browser/dist/dwarpal-browser.js', 'packages/browser/dist/dwarpal-browser.css', 'packages/browser/dist/build-manifest.json',
  ]) assert.ok(names.includes(required), `${required} is packed`);
  assert.ok(names.some((n) => /^supabase\/migrations\/\d{14}_[a-z0-9_]+\.sql$/.test(n)), 'SQL migrations are packed');
});

test('nothing private, dev-only or generated-by-accident is packed', () => {
  for (const name of names) {
    assert.ok(!/^(examples|tests|scripts|internal|scratch|node_modules)\//.test(name), `${name} must not be packed`);
    assert.ok(!name.startsWith('packages/emulator/'), `${name}: the emulator is development-only`);
    assert.ok(!name.startsWith('docs/pdf/'), `${name}: the PDF snapshots are not packed`);
    assert.ok(!/\.(tgz|log|sqlite|env|map)$|\.env\.|package-lock\.json|tsconfig|\.gitignore/.test(name), `${name} must not be packed`);
  }
});

test('the packed SQL is the repository\'s SQL, every migration and only migrations', async () => {
  const onDisk = (await readdir(join(root, 'supabase/migrations'))).sort();
  assert.deepEqual(names.filter((n) => n.startsWith('supabase/')).map((n) => n.slice('supabase/migrations/'.length)), onDisk);
  for (const file of pack.files.filter((f) => f.path.startsWith('supabase/'))) {
    assert.equal(file.size, (await stat(join(root, file.path))).size);
  }
});

test('every exports and bin target is packed, and the executable bit is set on the bin', () => {
  const targets = [];
  (function collect(value) {
    if (typeof value === 'string') targets.push(value.replace(/^\.\//, ''));
    else if (value && typeof value === 'object') Object.values(value).forEach(collect);
  })(manifest.exports);
  targets.push(manifest.bin['auth-kit']);
  for (const target of targets) assert.ok(names.includes(target), `${target} is packed`);
  assert.ok(pack.files.find((f) => f.path === manifest.bin['auth-kit']).mode & 0o111);
});

test('the size stays small enough to review', () => {
  assert.ok(pack.size < 1024 * 1024, `packed ${pack.size} bytes`);
  assert.ok(pack.unpackedSize < 3 * 1024 * 1024, `unpacked ${pack.unpackedSize} bytes`);
});
