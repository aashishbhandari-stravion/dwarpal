// The example builds install their build tools from committed lockfiles, so a
// later run gets the same transitive tools and licences. `npm run
// test:examples-built` installs them with `npm ci` and checks every installed
// version against the lock; this checks the locks themselves.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../..', import.meta.url));
const LOCKED = ['examples/creditone', 'examples/example-studio'];

for (const dir of LOCKED) {
  test(`${dir}: package-lock.json pins exactly the manifest's build tools, from the npm registry`, async () => {
    const manifest = JSON.parse(await readFile(join(root, dir, 'package.json'), 'utf8'));
    const lock = JSON.parse(await readFile(join(root, dir, 'package-lock.json'), 'utf8'));
    assert.equal(lock.lockfileVersion, 3);
    assert.equal(lock.name, manifest.name);
    const { '': top, ...packages } = lock.packages;
    // Build tools only, pinned exactly; the kit itself is installed from the packed tarball, never locked here.
    assert.deepEqual(manifest.dependencies ?? {}, {});
    assert.deepEqual(top.devDependencies, manifest.devDependencies);
    for (const version of Object.values(manifest.devDependencies)) assert.match(version, /^\d+\.\d+\.\d+$/);
    assert.ok(Object.keys(packages).length > 0);
    for (const [path, entry] of Object.entries(packages)) {
      assert.ok(!path.includes('@briqvent/'), path);
      assert.equal(entry.dev, true, `${path} is a development dependency`);
      assert.ok(entry.resolved?.startsWith('https://registry.npmjs.org/'), `${path} resolves from the npm registry`);
      assert.match(entry.integrity ?? '', /^sha512-/, `${path} has an integrity hash`);
      assert.equal(typeof entry.license, 'string', `${path} declares a licence`);
    }
    for (const name of Object.keys(manifest.devDependencies)) {
      assert.equal(packages[`node_modules/${name}`]?.version, manifest.devDependencies[name]);
    }
  });
}
