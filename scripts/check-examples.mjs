#!/usr/bin/env node
// Builds and exercises the reuse examples against the *packed* package, the way
// a consuming project would: pack, stage each example in a throwaway directory,
// install the tarball there (plus the example's own build tool), and then
//
//   1. build the CREDITONE example (esbuild) and the synthetic second brand
//      (Vite) with their shipped placeholder configuration and inspect the
//      output: one page per route under the configured prefix, `noindex`, no
//      inline script, no secret marker; a secret key in the configuration makes
//      the build fail and leaves a previous build untouched;
//   2. run the generic protected consumer against the installed package;
//   3. drive both built sites in Chromium against the loopback fixture.
//
// Usage: node scripts/check-examples.mjs [--tarball <file>] [--work-dir <empty dir>] [--keep] [--offline]
// Installing the example build tools (esbuild, Vite) uses the npm registry
// unless --offline is given and they are already in the npm cache. Nothing
// here contacts Supabase or any provider.

import { execFileSync, spawnSync } from 'node:child_process';
import { cp, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
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
    const installArgs = ['install', '--no-audit', '--no-fund', '--ignore-scripts', ...(offline ? ['--offline'] : []), tarball];
    const layout = { creditone: 'creditone', studio: 'example-studio', consumer: 'protected-consumer' };
    for (const [dir, source] of Object.entries(layout)) {
      await cp(join(root, 'examples', source), join(stage, dir), { recursive: true, filter: (path) => !/\/(node_modules|dist)(\/|$)/.test(path) });
    }
    // The protected consumer is a copy-and-own sample without a manifest of its own.
    await writeFile(join(stage, 'consumer/package.json'), JSON.stringify({ name: 'protected-consumer-check', private: true, type: 'module' }));
    await cp(join(root, 'tests/examples/support/installed-consumer-smoke.mjs'), join(stage, 'consumer/smoke.mjs'));
    for (const dir of Object.keys(layout)) {
      try {
        run('npm', installArgs, join(stage, dir));
      } catch (error) {
        fail(`npm install in ${dir} failed (environment, not an example result): ${String(error.stderr ?? error.message).trim().split('\n').slice(-3).join(' | ')}`);
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
