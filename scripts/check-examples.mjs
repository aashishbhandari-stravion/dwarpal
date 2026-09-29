#!/usr/bin/env node
// Builds and exercises the reuse examples against the *packed* package, the way
// a consuming project would: pack, stage each example in a throwaway directory,
// install each example's build tool exactly as its committed package-lock.json
// pins it (`npm ci`), install the tarball next to it without touching that
// lock, check that every locked package is installed at its locked version,
// and then
//
//   1. build the client-specific example (esbuild) and the synthetic second
//      brand (Vite) with their shipped placeholder configuration and inspect
//      the output: one page per route under the configured prefix, `noindex`,
//      no inline script, no secret marker; a secret key in the configuration
//      stops the build before anything is written and leaves a previous build
//      untouched; for the esbuild example, a bundling failure after validation
//      does too, and leaves no staging directory behind;
//   2. run the generic protected consumer against the installed package;
//   3. drive both built sites in Chromium against the loopback fixture,
//      including builds with hostile and punctuated (valid) brand names.
//
// Usage: node scripts/check-examples.mjs [--tarball <file>] [--work-dir <empty dir>] [--keep] [--offline]
// Installing the locked example build tools (esbuild, Vite) and the tarball's
// own dependencies uses the npm registry unless --offline is given and they are
// already in the npm cache. Nothing here contacts Supabase or any provider.

import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cp, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const args = process.argv.slice(2);
const keep = args.includes('--keep');
const offline = args.includes('--offline');
const option = (name) => (args.includes(name) ? args[args.indexOf(name) + 1] : undefined);
const FORBIDDEN = [/sb_secret_[A-Za-z0-9_-]{8,}/, /sbp_[A-Za-z0-9]{16,}/, /SUPABASE_SECRET_KEY/, /SUPABASE_ACCESS_TOKEN/, /api\.supabase\.com/, /auth_kit_private/];
const ROUTES = ['callback', 'forgot', 'mfa', 'reset', 'signIn', 'signOut', 'signUp', 'verify'];

// A failed check throws, so the `finally` in main() still removes the throwaway
// directory; main's handler reports it and sets the exit status.
class CheckFailure extends Error {}

function fail(message) {
  throw new CheckFailure(message);
}

function run(command, commandArgs, cwd, env) {
  return execFileSync(command, commandArgs, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...(env ? { env } : {}) });
}

async function listFiles(dir) {
  const out = [];
  for (const entry of await readdir(dir, { recursive: true, withFileTypes: true })) {
    if (entry.isFile()) out.push(join(entry.parentPath, entry.name).slice(dir.length + 1));
  }
  return out.sort();
}

/** Inspects one default build: pages, robots meta, no inline script, no secrets. */
async function inspectBuild(label, dist, { prefix, routes }) {
  const files = await listFiles(dist);
  const pages = files.filter((f) => f.endsWith('/index.html'));
  const expected = ROUTES.map((name) => `${routes[name]}/index.html`).sort();
  if (JSON.stringify(pages) !== JSON.stringify(expected)) fail(`${label}: pages ${pages.join(', ')} differ from the configured routes ${expected.join(', ')}`);
  const assets = files.filter((f) => f.startsWith('assets/'));
  if (!assets.some((f) => f.endsWith('.js')) || !assets.some((f) => f.endsWith('.css'))) fail(`${label}: script or stylesheet missing`);
  for (const file of files) {
    const text = await readFile(join(dist, file), 'utf8');
    const hit = FORBIDDEN.find((pattern) => pattern.test(text));
    if (hit) fail(`${label}: ${hit} in ${file}`);
    if (file.endsWith('.html')) {
      if (!text.includes('<meta name="robots" content="noindex, nofollow">')) fail(`${label}: ${file} is not noindex`);
      if (!/<title>[^<]+<\/title>/.test(text)) fail(`${label}: ${file} has no title`);
      if (/<script(?![^>]*\bsrc=)/i.test(text) || /\sstyle=|\son[a-z]+=/i.test(text)) fail(`${label}: ${file} has inline script or style`);
      if (!text.includes(`src="${prefix}/assets/`)) fail(`${label}: ${file} does not load its script from ${prefix}/assets/`);
    }
  }
  return { files: files.length, pages: pages.length };
}

/** Fails unless every package in `dir`'s lockfile is installed at its locked version; returns the installed count. */
async function verifyLocked(label, dir) {
  const lock = JSON.parse(await readFile(join(dir, 'package-lock.json'), 'utf8'));
  let installed = 0;
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (path === '') continue;
    const manifest = await readFile(join(dir, path, 'package.json'), 'utf8').then(JSON.parse, () => null);
    // Optional platform packages (other operating systems, CPUs or libc) are locked but not installed here.
    if (manifest === null && entry.optional) continue;
    if (manifest === null) fail(`${label}: locked ${path} is not installed`);
    if (manifest.version !== entry.version) fail(`${label}: ${path} is ${manifest.version}, locked ${entry.version}`);
    installed += 1;
  }
  return installed;
}

/** A digest of every file's path and bytes under `dir`. */
async function snapshot(dir) {
  const hash = createHash('sha256');
  for (const file of await listFiles(dir)) hash.update(`${file}\0`).update(await readFile(join(dir, file))).update('\0');
  return hash.digest('hex');
}

async function main() {
  const workDir = option('--work-dir') ? resolve(option('--work-dir')) : await mkdtemp(join(tmpdir(), 'dwarpal-examples-'));
  await mkdir(workDir, { recursive: true });
  if ((await readdir(workDir)).length > 0) fail('work directory must be empty.');
  try {
    let tarball = option('--tarball') ? resolve(option('--tarball')) : null;
    if (!tarball) {
      const packed = JSON.parse(run('npm', ['pack', '--json', '--pack-destination', workDir], root));
      tarball = join(workDir, packed[0].filename);
    }
    const stage = join(workDir, 'stage');
    await mkdir(stage);
    const npmFlags = ['--no-audit', '--no-fund', '--ignore-scripts', ...(offline ? ['--offline'] : [])];
    const layout = { creditone: 'creditone', studio: 'example-studio', consumer: 'protected-consumer' };
    // The two build examples carry a lockfile for their build tool; the protected consumer needs none.
    const locked = ['creditone', 'studio'];
    for (const [dir, source] of Object.entries(layout)) {
      await cp(join(root, 'examples', source), join(stage, dir), { recursive: true, filter: (path) => !/\/(node_modules|dist)(\/|$)/.test(path) });
    }
    // The protected consumer is a copy-and-own sample without a manifest of its own.
    await writeFile(join(stage, 'consumer/package.json'), JSON.stringify({ name: 'protected-consumer-check', private: true, type: 'module' }));
    await cp(join(root, 'tests/examples/support/installed-consumer-smoke.mjs'), join(stage, 'consumer/smoke.mjs'));
    const npm = (dir, npmArgs) => {
      try {
        run('npm', [...npmArgs, ...npmFlags], join(stage, dir));
      } catch (error) {
        fail(`npm ${npmArgs[0]} in ${dir} failed (environment, not an example result): ${String(error.stderr ?? error.message).trim().split('\n').slice(-3).join(' | ')}`);
      }
    };
    for (const dir of Object.keys(layout)) {
      if (locked.includes(dir)) {
        const lock = await readFile(join(stage, dir, 'package-lock.json'));
        npm(dir, ['ci']);
        // The package goes next to the locked tools without being written into the example's manifest or lock.
        npm(dir, ['install', '--no-save', tarball]);
        if (!lock.equals(await readFile(join(stage, dir, 'package-lock.json')))) fail(`${dir}: installing the tarball changed package-lock.json`);
        const count = await verifyLocked(dir, join(stage, dir));
        console.log(`check-examples: ${dir} build tools installed from its lockfile (${count} locked packages at their locked versions)`);
      } else {
        npm(dir, ['install', tarball]);
      }
    }
    const installed = JSON.parse(await readFile(join(stage, 'creditone/node_modules/@briqvent/dwarpal/package.json'), 'utf8'));
    console.log(`check-examples: node ${process.version}; examples installed the packed ${installed.name} ${installed.version}`);

    // 1. Default builds with the shipped placeholder configuration.
    const builds = [
      ['CREDITONE (esbuild)', 'creditone', ['build.mjs'], { prefix: '/account' }],
      ['Example Studio (Vite)', 'studio', ['node_modules/vite/bin/vite.js', 'build'], { prefix: '/studio/account' }],
    ];
    for (const [label, dir, command, { prefix }] of builds) {
      const cwd = join(stage, dir);
      const config = JSON.parse(await readFile(join(cwd, 'auth-kit.config.json'), 'utf8'));
      const routes = { signIn: 'sign-in', signUp: 'sign-up', verify: 'verify', callback: 'callback', forgot: 'forgot', reset: 'reset', mfa: 'mfa', signOut: 'sign-out', ...config.routes };
      const absolute = Object.fromEntries(ROUTES.map((name) => [name, `${prefix}/${routes[name]}`]));
      // dist/ mirrors the prefix directory, so page paths are relative to it.
      const relative = Object.fromEntries(ROUTES.map((name) => [name, routes[name]]));
      run(process.execPath, command, cwd);
      const summary = await inspectBuild(label, join(cwd, 'dist'), { prefix, routes: relative });
      // The second build overwrites in place.
      run(process.execPath, command, cwd);
      // A secret key in the public configuration is refused, and the previous build survives.
      const before = await listFiles(join(cwd, 'dist'));
      const refused = spawnSync(process.execPath, command, { cwd, encoding: 'utf8', env: { PATH: process.env.PATH, HOME: process.env.HOME, SUPABASE_PUBLISHABLE_KEY: 'sb_secret_examplecheckmarker0000' } });
      if (refused.status === 0) fail(`${label}: a secret key in the configuration was accepted`);
      if (`${refused.stdout}${refused.stderr}`.includes('sb_secret_examplecheckmarker0000')) fail(`${label}: the refusal printed the key`);
      if (JSON.stringify(before) !== JSON.stringify(await listFiles(join(cwd, 'dist')))) fail(`${label}: a refused build changed dist/`);
      console.log(`check-examples: ${label} builds ${summary.pages} pages under ${absolute.signIn.replace(/\/[^/]+$/, '')}/ (${summary.files} files), noindex, no inline script, no secret marker; a secret key is refused and dist/ is untouched`);
      if (dir === 'creditone') {
        // A bundling failure after validation also leaves dist/ as it was, and no staging directory.
        const source = join(cwd, 'src/account.js');
        const original = await readFile(source);
        const distBytes = await snapshot(join(cwd, 'dist'));
        await writeFile(source, `${original}\nimport './does-not-exist.js';\n`);
        let broken;
        try {
          broken = spawnSync(process.execPath, command, { cwd, encoding: 'utf8', env: { PATH: process.env.PATH, HOME: process.env.HOME } });
        } finally {
          await writeFile(source, original);
        }
        if (broken.status === 0) fail(`${label}: a build with an unresolvable import succeeded`);
        if (distBytes !== await snapshot(join(cwd, 'dist'))) fail(`${label}: a failed bundling step changed dist/`);
        const leftovers = (await readdir(cwd)).filter((name) => name.startsWith('dist.'));
        if (leftovers.length > 0) fail(`${label}: a failed build left ${leftovers.join(', ')}`);
        console.log(`check-examples: ${label}: a bundling failure after validation leaves dist/ byte for byte and no staging directory`);
      }
    }

    // 2. The generic protected consumer against the installed package.
    const smoke = run(process.execPath, ['smoke.mjs'], join(stage, 'consumer'), { PATH: process.env.PATH, HOME: process.env.HOME, REPO_ROOT: root }).trim();
    console.log(`check-examples: ${smoke}`);

    // 3. Both sites in Chromium.
    const test = spawnSync(process.execPath, ['--test', 'tests/examples/chromium/built-examples.test.js'], {
      cwd: root, encoding: 'utf8', env: { PATH: process.env.PATH, HOME: process.env.HOME, DWARPAL_EXAMPLES_STAGE: stage },
    });
    process.stdout.write(test.stdout);
    process.stderr.write(test.stderr);
    if (test.status !== 0) fail('the built examples failed in Chromium');
    console.log('check-examples: OK');
  } finally {
    if (!keep && !option('--work-dir')) await rm(workDir, { recursive: true, force: true });
  }
}

main().catch((error) => {
  const detail = error instanceof CheckFailure ? error.message
    : error && typeof error.stderr === 'string' && error.stderr ? error.stderr.trim().split('\n').slice(-6).join('\n') : String(error?.message ?? error);
  console.error(`check-examples: FAIL ${detail}`);
  process.exitCode = 1;
});
