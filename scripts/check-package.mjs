#!/usr/bin/env node
// Packs the package, installs the tarball into a throwaway consumer and checks
// that (1) the tarball holds only the allowed files, every one of them tracked
// and unmodified in Git, and packing twice gives the same bytes, (2) the
// installed entry points import and behave, (3) runtime exports equal declared
// exports for the source and the packed copy and every exports-map target is
// packed, (4) the installed auth-kit executable finds the packed SQL migrations
// by default and sends them byte for byte through a stand-in Management API
// (no network), (5) a TypeScript consumer compiles against the packed
// declarations, including the optional Hono entry with Hono installed beside
// it, (6) the browser entry imports with its pinned supabase-js and refuses a
// secret key, (7) the prebuilt browser assets are current, secret-free, need no
// bundler, and run in Chromium against the loopback fixture, and (8) nothing
// private (home paths, key values, internal notes) is in the tarball.
//
// Usage: node scripts/check-package.mjs [--work-dir <empty dir>] [--keep]
// Without --work-dir a fresh temporary directory is used and removed at the end.
// Installs are --offline: jose, hono and supabase-js with its dependencies
// must already be in the npm cache (a normal `npm ci` in this repository puts
// them there).

import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile, copyFile, stat, appendFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { readdirSync } from 'node:fs';
import ts from 'typescript';
import { checkBrowser, scanForSecrets } from './build-browser.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const args = process.argv.slice(2);
const keep = args.includes('--keep');
const workIndex = args.indexOf('--work-dir');
if (workIndex !== -1 && !args[workIndex + 1]) {
  console.error('check-package: FAIL --work-dir needs a directory argument.');
  process.exit(1);
}
const ENTRIES = {
  '.': 'packages/core/index',
  './testing': 'packages/core/testing/index',
  './server': 'packages/server/index',
  './server/operator': 'packages/server/operator',
  './server/hono': 'packages/server/hono',
  './browser': 'packages/browser/index',
};
const ALLOWED_FILE = /^(package\.json|README\.md|LICENSE|docs\/[a-z-]+\.md|supabase\/migrations\/\d{14}_[a-z0-9_]+\.sql|packages\/core\/(testing\/)?[a-z-]+\.(js|d\.ts)|packages\/server\/(lib\/|cli\/)?[a-z-]+\.(js|d\.ts)|packages\/browser\/(lib\/)?[a-z-]+\.(js|d\.ts)|packages\/browser\/styles\.css|packages\/browser\/dist\/(dwarpal-browser\.(js|css)|build-manifest\.json))$/;
const MIGRATIONS = readdirSync(join(root, 'supabase/migrations')).filter((n) => n.endsWith('.sql')).sort();
const DIST_FILES = ['dwarpal-browser.js', 'dwarpal-browser.css', 'build-manifest.json'].map((n) => `packages/browser/dist/${n}`);
const REQUIRED_FILES = [
  'package.json', 'LICENSE', 'README.md', 'docs/manual.md', 'docs/design.md', 'docs/rbac-lld.md',
  ...Object.values(ENTRIES).flatMap((base) => [`${base}.js`, `${base}.d.ts`]),
  'packages/server/cli/auth-kit.js',
  'packages/browser/styles.css',
  ...MIGRATIONS.map((n) => `supabase/migrations/${n}`),
  ...DIST_FILES,
];
// Things that must never be in a published file: home paths, private notes and
// real key values. The private repository boundary policy checks owner names;
// they do not belong as literals in public package-check source.
const LEAK_PATTERNS = [
  ['a home directory path', /\/home\/[a-z][\w.-]*\//],
  ['a macOS or Windows user path', /(?:\/Users\/|[A-Z]:\\Users\\)[\w.-]+/],
  ['a private-notes path', /\b(?:internal|scratch)\/(?:records|scratch|agent)\b/],
  ['a secret key value', /sb_secret_[A-Za-z0-9_-]{20,}/],
  ['a Management token value', /sbp_[A-Za-z0-9]{30,}/],
  ['a service-role JWT', /eyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}/],
];
const MAX_PACKED_BYTES = 2 * 1024 * 1024;
const PINNED = { jose: '6.2.12', hono: '4.13.9', supabase: '2.117.2' };
// supabase-js 2.117.2 and what it installs; every one must carry a permissive licence.
const BROWSER_RUNTIME = ['@supabase/auth-js', '@supabase/functions-js', '@supabase/phoenix', '@supabase/postgrest-js', '@supabase/realtime-js', '@supabase/storage-js', '@supabase/supabase-js', 'iceberg-js', 'tslib'];
const PERMISSIVE = new Set(['MIT', '0BSD', 'Apache-2.0', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause']);

// A failed check throws, so the `finally` in main() still removes the throwaway
// directory; main's handler reports it and sets the exit status.
class CheckFailure extends Error {}

function fail(message) {
  throw new CheckFailure(message);
}

function run(command, commandArgs, cwd) {
  return execFileSync(command, commandArgs, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

function declaredExports(dtsPath) {
  const program = ts.createProgram([dtsPath], { module: ts.ModuleKind.NodeNext, moduleResolution: ts.ModuleResolutionKind.NodeNext, noEmit: true });
  const checker = program.getTypeChecker();
  const symbol = checker.getSymbolAtLocation(program.getSourceFile(dtsPath));
  // Value exports only: type-only names have no runtime counterpart. A
  // re-export is an alias; it counts when the symbol it names is a value.
  const isValue = (s) => ((s.flags & ts.SymbolFlags.Alias) !== 0 ? checker.getAliasedSymbol(s).flags : s.flags) & ts.SymbolFlags.Value;
  return checker.getExportsOfModule(symbol).filter(isValue).map((s) => s.getName()).sort();
}

async function runtimeExports(jsPath) {
  return Object.keys(await import(pathToFileURL(jsPath).href)).sort();
}

function sameList(label, a, b) {
  if (JSON.stringify(a) !== JSON.stringify(b)) fail(`${label}\n  left:  ${a.join(', ')}\n  right: ${b.join(', ')}`);
}

async function directorySize(dir) {
  let total = 0;
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    total += entry.isDirectory() ? await directorySize(path) : (await stat(path)).size;
  }
  return total;
}

// Runs the installed executable; its output must be free of the credential values given.
function runBin(consumer, binArgs, env) {
  const result = spawnSync(join(consumer, 'node_modules/.bin/auth-kit'), binArgs, { cwd: consumer, encoding: 'utf8', env: { PATH: process.env.PATH, ...env } });
  for (const value of Object.values(env)) {
    if (result.stdout.includes(value) || result.stderr.includes(value)) fail(`auth-kit ${binArgs[0]} printed a credential`);
  }
  return result;
}

async function main() {
  const workDir = workIndex !== -1 ? resolve(args[workIndex + 1]) : await mkdtemp(join(tmpdir(), 'dwarpal-pack-'));
  await mkdir(workDir, { recursive: true });
  if ((await readdir(workDir)).length > 0) fail('work directory must be empty.');
  try {
    // 1. Pack and inspect the file list.
    const packOut = JSON.parse(run('npm', ['pack', '--json', '--pack-destination', workDir], root));
    const { filename, files } = packOut[0];
    const names = files.map((f) => f.path).sort();
    const unexpected = names.filter((n) => !ALLOWED_FILE.test(n));
    if (unexpected.length > 0) fail(`unexpected files in tarball: ${unexpected.join(', ')}`);
    for (const required of REQUIRED_FILES) {
      if (!names.includes(required)) fail(`missing from tarball: ${required}`);
    }
    // npm packs the working tree; a packed file that Git ignores would be
    // missing from every commit, so the tarball could not be rebuilt from source.
    // The prebuilt browser assets are the one intended exception: they are generated
    // from tracked source by the prepack script (deterministic; verified below against a
    // fresh build), so they are ignored on purpose and rebuilt for every tarball.
    const generated = new Set(DIST_FILES);
    const ignored = spawnSync('git', ['check-ignore', '--no-index', '--stdin'], { cwd: root, input: names.filter((n) => !generated.has(n)).join('\n'), encoding: 'utf8' });
    if (ignored.status === 0) fail(`packed files ignored by Git: ${ignored.stdout.trim().split('\n').join(', ')}`);
    if (ignored.status !== 1 && !/not a git repository/i.test(ignored.stderr)) fail('git check-ignore failed');
    // Every packed file must be committed and unmodified: the tarball is then
    // reproducible from the commit, and no untracked or edited file rides along.
    const inGit = spawnSync('git', ['rev-parse', '--is-inside-work-tree'], { cwd: root, encoding: 'utf8' }).status === 0;
    if (inGit) {
      const sourceNames = names.filter((n) => !generated.has(n));
      const tracked = new Set(run('git', ['ls-files', '-z', '--', ...sourceNames], root).split('\0').filter(Boolean));
      const untracked = sourceNames.filter((n) => !tracked.has(n));
      if (untracked.length > 0) fail(`packed files are not tracked by Git: ${untracked.join(', ')}`);
      const modified = run('git', ['status', '--porcelain', '--untracked-files=no', '--', ...sourceNames], root).trim();
      if (modified !== '') fail(`packed files differ from the commit:\n${modified}`);
    }
    const binMode = files.find((f) => f.path === 'packages/server/cli/auth-kit.js').mode;
    if ((binMode & 0o111) === 0) fail('auth-kit is not executable in the tarball');
    const tarball = join(workDir, filename);
    const tarballSha256 = createHash('sha256').update(await readFile(tarball)).digest('hex');
    const packedBytes = (await stat(tarball)).size;
    if (packedBytes > MAX_PACKED_BYTES) fail(`tarball is ${packedBytes} bytes, over the ${MAX_PACKED_BYTES}-byte budget`);
    // Packing again gives the same bytes (npm normalizes file times).
    await mkdir(join(workDir, 'again'));
    const again = JSON.parse(run('npm', ['pack', '--json', '--pack-destination', join(workDir, 'again')], root))[0];
    const againSha256 = createHash('sha256').update(await readFile(join(workDir, 'again', again.filename))).digest('hex');
    if (againSha256 !== tarballSha256) fail(`packing twice gave different tarballs (${tarballSha256} vs ${againSha256})`);

    // 2. Install into a throwaway consumer; runtime dependencies are jose and the pinned supabase-js.
    const consumer = join(workDir, 'consumer');
    await mkdir(consumer);
    await writeFile(join(consumer, 'package.json'), JSON.stringify({ name: 'pack-consumer', private: true, type: 'module' }));
    run('npm', ['install', '--no-audit', '--no-fund', '--ignore-scripts', '--offline', tarball], consumer);
    const installed = join(consumer, 'node_modules/@briqvent/dwarpal');
    const topLevel = (await readdir(join(consumer, 'node_modules'))).filter((n) => !n.startsWith('.')).sort();
    sameList('installed packages (the optional hono peer must not be installed implicitly)', topLevel, ['@briqvent', '@supabase', 'iceberg-js', 'jose', 'tslib']);
    const joseManifest = JSON.parse(await readFile(join(consumer, 'node_modules/jose/package.json'), 'utf8'));
    if (joseManifest.version !== PINNED.jose || joseManifest.license !== 'MIT') fail('jose is not the pinned MIT release');
    const joseBytes = await directorySize(join(consumer, 'node_modules/jose'));
    const supabaseManifest = JSON.parse(await readFile(join(consumer, 'node_modules/@supabase/supabase-js/package.json'), 'utf8'));
    if (supabaseManifest.version !== PINNED.supabase || supabaseManifest.license !== 'MIT') fail('supabase-js is not the pinned MIT release');
    const scoped = (await readdir(join(consumer, 'node_modules/@supabase'))).map((n) => `@supabase/${n}`);
    const browserRuntime = [...scoped, ...topLevel.filter((n) => !n.startsWith('@') && n !== 'jose')].sort();
    sameList('browser runtime packages', browserRuntime, BROWSER_RUNTIME);
    let browserBytes = 0;
    const licences = [];
    for (const name of browserRuntime) {
      const manifest = JSON.parse(await readFile(join(consumer, 'node_modules', name, 'package.json'), 'utf8'));
      if (!PERMISSIVE.has(manifest.license)) fail(`${name} licence ${manifest.license} is not on the permissive list`);
      licences.push(`${name} ${manifest.version} (${manifest.license})`);
      browserBytes += await directorySize(join(consumer, 'node_modules', name));
    }

    // Installed content: no bundler dependency, SQL byte-identical to the
    // repository's, every exports-map target packed, prebuilt assets current
    // and secret-free, and nothing private in any file.
    const installedManifest = JSON.parse(await readFile(join(installed, 'package.json'), 'utf8'));
    const declaredDeps = Object.keys({ ...installedManifest.dependencies, ...installedManifest.peerDependencies, ...installedManifest.optionalDependencies });
    if (declaredDeps.includes('esbuild')) fail('esbuild must not be a dependency of the package: a consuming site never needs it');
    sameList('packed migration files', (await readdir(join(installed, 'supabase/migrations'))).sort(), MIGRATIONS);
    for (const name of MIGRATIONS) {
      const source = await readFile(join(root, 'supabase/migrations', name));
      if (!source.equals(await readFile(join(installed, 'supabase/migrations', name)))) fail(`installed ${name} differs from the repository file`);
    }
    const targets = [];
    (function collect(value) {
      if (typeof value === 'string') targets.push(value);
      else if (value && typeof value === 'object') Object.values(value).forEach(collect);
    })(installedManifest.exports);
    for (const target of new Set([...targets, installedManifest.bin['auth-kit']])) {
      if (!(await stat(join(installed, target)).catch(() => null))?.isFile()) fail(`exports or bin target ${target} is not in the installed package`);
    }
    const freshness = await checkBrowser({ outdir: join(installed, 'packages/browser/dist') });
    if (freshness.stale.length > 0) fail(`prebuilt browser assets are stale or altered: ${freshness.stale.join(', ')}`);
    for (const name of DIST_FILES) {
      const markers = scanForSecrets(await readFile(join(installed, name), 'utf8'));
      if (markers.length > 0) fail(`installed ${name} carries forbidden markers: ${markers.join(', ')}`);
    }
    for (const name of names) {
      if (name === 'LICENSE') continue;
      const text = await readFile(join(installed, name), 'utf8');
      for (const [what, pattern] of LEAK_PATTERNS) if (pattern.test(text)) fail(`${name} contains ${what}`);
    }
    // The packaged manual and README carry Max's D1 decision (doctor's catalog credential).
    for (const name of ['README.md', 'docs/manual.md']) {
      const text = await readFile(join(installed, name), 'utf8');
      if (!text.includes('SUPABASE_ACCESS_TOKEN') || !/`incomplete`/.test(text) || !/`not_run`/.test(text)) fail(`${name} does not state the doctor catalog credential rule (SUPABASE_ACCESS_TOKEN; secret-key-only is incomplete, checks not_run)`);
    }

    // 3. Exports: source runtime == packed runtime == source declarations == packed declarations.
    //    The Hono entry imports no Hono at runtime; its declarations need Hono, installed here.
    run('npm', ['install', '--no-audit', '--no-fund', '--ignore-scripts', '--offline', '--no-save', `hono@${PINNED.hono}`], consumer);
    for (const [entry, base] of Object.entries(ENTRIES)) {
      const src = await runtimeExports(join(root, `${base}.js`));
      const packed = await runtimeExports(join(installed, `${base}.js`));
      sameList(`runtime exports differ for ${entry} (source vs packed)`, src, packed);
      sameList(`declared exports differ from runtime for ${entry} (source)`, declaredExports(join(root, `${base}.d.ts`)), src);
      sameList(`declared exports differ from runtime for ${entry} (packed)`, declaredExports(join(installed, `${base}.d.ts`)), packed);
    }

    // 4. Import by package name from the consumer and exercise each entry.
    const probe = [
      "import { AUTH_CONTRACT_VERSION, can, explain } from '@briqvent/dwarpal';",
      "import { fixturePrincipals } from '@briqvent/dwarpal/testing';",
      "import { createAuthServer, requirePermission, AuthError } from '@briqvent/dwarpal/server';",
      "import { createOperatorClient, OperatorError } from '@briqvent/dwarpal/server/operator';",
      "import { honoMiddleware } from '@briqvent/dwarpal/server/hono';",
      "import { createAuthController, BROWSER_STATES, mountAuthScreens } from '@briqvent/dwarpal/browser';",
      "if (AUTH_CONTRACT_VERSION !== '0.5') throw new Error('contract');",
      "if (!can(fixturePrincipals.patron, 'records:read:own')) throw new Error('own');",
      "if (can(fixturePrincipals.patronClerkAal1, 'records:read:any')) throw new Error('withheld');",
      "if (explain(fixturePrincipals.patronClerkAal1, 'records:read:any').withheld[0]?.role !== 'clerk') throw new Error('explain');",
      "try { requirePermission(fixturePrincipals.patron, 'records:read:any'); throw new Error('guard'); } catch (e) { if (!(e instanceof AuthError) || e.code !== 'forbidden') throw e; }",
      "let refused = false; try { createAuthServer({ supabaseUrl: 'https://p.supabase.co', publishableKey: 'sb_secret_x', clientId: 'c' }); } catch (e) { refused = e.code === 'config_invalid'; }",
      "if (!refused) throw new Error('a secret key must be refused by the session server');",
      "const auth = createAuthServer({ supabaseUrl: 'https://p.supabase.co', publishableKey: 'sb_publishable_x', clientId: 'c', fetch: () => { throw new Error('no network expected'); } });",
      "if (await auth.resolveSession(new Request('https://x.test')) !== null) throw new Error('anonymous request');",
      "let operatorRefused = false; try { createOperatorClient({ supabaseUrl: 'https://p.supabase.co', secretKey: 'sb_publishable_x' }); } catch (e) { operatorRefused = e instanceof OperatorError; }",
      "if (!operatorRefused) throw new Error('a publishable key must be refused by the operator client');",
      "if (typeof honoMiddleware(auth) !== 'function') throw new Error('hono');",
      "if (BROWSER_STATES.length !== 12 || typeof mountAuthScreens !== 'function') throw new Error('browser entry');",
      "const env = { location: { href: 'https://s.test/account/sign-in' }, history: { replaceState() {} }, localStorage: null, sessionStorage: null, navigate() {} };",
      "let browserRefused = false; try { createAuthController({ env, config: { clientId: 'c', supabaseUrl: 'https://p.supabase.co', publishableKey: 'sb_secret_x', origin: 'https://s.test', allowedReturnPaths: ['/'], defaultReturnPath: '/', providers: { email: true, google: false }, selfSignup: true } }); } catch (e) { browserRefused = e.code === 'config_invalid'; }",
      "if (!browserRefused) throw new Error('a secret key must be refused by the browser controller');",
      "const css = await import('node:fs').then((fs) => fs.readFileSync(new URL(import.meta.resolve('@briqvent/dwarpal/browser/styles.css')), 'utf8'));",
      "if (!css.includes('.ak-root')) throw new Error('stylesheet entry');",
      "for (const deep of ['@briqvent/dwarpal/packages/core/model.js', '@briqvent/dwarpal/packages/server/lib/http.js']) {",
      "  let blocked = false; try { await import(deep); } catch { blocked = true; }",
      "  if (!blocked) throw new Error('deep import should be blocked by the exports map');",
      "}",
      "const distApi = await import('@briqvent/dwarpal/browser/dist/dwarpal-browser.js');",
      "const sourceApi = await import('@briqvent/dwarpal/browser');",
      "if (JSON.stringify(Object.keys(distApi).sort()) !== JSON.stringify(Object.keys(sourceApi).sort())) throw new Error('prebuilt module exports differ from the source entry');",
      "const dcss = await import('node:fs').then((fs) => fs.readFileSync(new URL(import.meta.resolve('@briqvent/dwarpal/browser/dist/dwarpal-browser.css')), 'utf8'));",
      "if (!dcss.includes('.ak-root')) throw new Error('prebuilt stylesheet entry');",
      "console.log('consumer import ok');",
    ].join('\n');
    await writeFile(join(consumer, 'probe.mjs'), probe);
    const probeOut = run(process.execPath, ['probe.mjs'], consumer).trim();

    // 5. The installed executable: help, a missing prerequisite, and its default SQL.
    const help = runBin(consumer, ['--help'], {});
    if (help.status !== 0 || !help.stdout.includes('bootstrap-manager')) fail('auth-kit --help');
    const missing = runBin(consumer, ['export-model', '--client', 'c'], {});
    if (missing.status !== 5) fail(`auth-kit without credentials exited ${missing.status}`);
    const credentials = { SUPABASE_URL: 'https://abcdefghijklmnopqrst.supabase.co', SUPABASE_SECRET_KEY: 'sb_secret_packcheckmarker', SUPABASE_ACCESS_TOKEN: 'sbp_packcheckmarker' };
    // No network: the run gets an in-process Management API stand-in that accepts each
    // migration only when its request body is byte-for-byte the repository's file.
    const fake = join(root, 'tests/package/support/fake-management.mjs');
    const standIn = (logName, installedVersions) => ({
      ...credentials,
      NODE_OPTIONS: `--import=${pathToFileURL(fake).href}`,
      FAKE_MANAGEMENT_LOG: join(workDir, logName),
      FAKE_MANAGEMENT_DIR: join(root, 'supabase/migrations'),
      ...(installedVersions ? { FAKE_MANAGEMENT_INSTALLED: JSON.stringify(installedVersions) } : {}),
    });
    const readLog = async (name) => (await readFile(join(workDir, name), 'utf8').catch(() => '')).split('\n').filter(Boolean).map((line) => JSON.parse(line));
    const versions = MIGRATIONS.map((n) => n.slice(0, 14));
    const first = runBin(consumer, ['migrate'], standIn('first.log'));
    const firstJson = JSON.parse(first.stdout || 'null');
    const firstLog = await readLog('first.log');
    if (first.status !== 0 || firstJson?.result !== 'migrated') fail(`installed auth-kit migrate did not apply the packed files (exit ${first.status}): ${first.stdout.slice(0, 300)}`);
    sameList('migrations sent by the installed CLI', firstLog.filter((e) => e.kind === 'migration').map((e) => e.version), versions);
    sameList('applied versions reported by the installed CLI', firstJson.applied.map((a) => a.version), versions);
    for (const name of MIGRATIONS) {
      const digest = createHash('sha256').update(await readFile(join(root, 'supabase/migrations', name))).digest('hex');
      if (firstJson.applied.find((a) => a.version === name.slice(0, 14))?.sha256 !== digest) fail(`the CLI reports a different SHA-256 for ${name}`);
    }
    if (firstLog.some((e) => e.kind === 'refused' || e.kind === 'unexpected_sql')) fail('the installed CLI made a request outside the Management API stand-in');
    if (!firstLog.some((e) => e.kind === 'grant_assertion')) fail('the installed CLI did not run the grant assertion');
    // The Nth run: everything is installed, so nothing is written.
    const second = runBin(consumer, ['migrate'], standIn('second.log', versions));
    const secondJson = JSON.parse(second.stdout || 'null');
    if (second.status !== 0 || secondJson?.result !== 'up_to_date' || (await readLog('second.log')).some((e) => e.kind === 'migration')) fail('a rerun of the installed migrate must report up_to_date and write nothing');
    // An explicit directory still overrides the packed default, and a bad one is a named prerequisite failure.
    const missingDir = runBin(consumer, ['migrate', '--migrations-dir', join(workDir, 'no-such-dir')], credentials);
    if (missingDir.status !== 5 || JSON.parse(missingDir.stdout || 'null')?.details?.stage !== 'migration_files') fail('auth-kit migrate with an unreadable --migrations-dir must report migration_files');

    // 6. TypeScript consumers compiled against the packed declarations.
    await mkdir(join(consumer, 'src'));
    await copyFile(join(root, 'tests/core/types/consumer.ts'), join(consumer, 'src/consumer.ts'));
    await copyFile(join(root, 'tests/server/types/consumer.ts'), join(consumer, 'src/server-consumer.ts'));
    await copyFile(join(root, 'tests/browser/types/consumer.ts'), join(consumer, 'src/browser-consumer.ts'));
    await writeFile(join(consumer, 'tsconfig.json'), JSON.stringify({
      compilerOptions: { target: 'ES2022', module: 'NodeNext', moduleResolution: 'NodeNext', strict: true, noEmit: true, types: [] },
      include: ['src/**/*.ts'],
    }));
    run(process.execPath, [join(root, 'node_modules/typescript/bin/tsc'), '-p', 'tsconfig.json'], consumer);

    // 7. The installed prebuilt assets in Chromium, served like a static host would.
    const chromium = spawnSync(process.execPath, ['--test', 'tests/package/chromium/prebuilt-assets.test.js'], {
      cwd: root, encoding: 'utf8', env: { PATH: process.env.PATH, HOME: process.env.HOME, DWARPAL_INSTALLED_PACKAGE: installed },
    });
    if (chromium.status !== 0) fail(`installed prebuilt assets failed in Chromium:\n${chromium.stdout.slice(-1500)}${chromium.stderr.slice(-500)}`);

    console.log(`check-package: node ${process.version}`);
    console.log(`check-package: tarball ${filename} sha256 ${tarballSha256} (${packedBytes} bytes packed, ${files.reduce((sum, f) => sum + f.size, 0)} bytes unpacked; a second pack gave the same bytes)`);
    console.log(`check-package: ${names.length} files: ${names.join(', ')}`);
    console.log(`check-package: runtime dependency jose ${joseManifest.version} (${joseManifest.license}), ${joseBytes} bytes installed`);
    console.log(`check-package: browser runtime ${licences.join(', ')}; ${browserBytes} bytes installed`);
    console.log(`check-package: ${probeOut}; exports and declarations agree for ${Object.keys(ENTRIES).length} entries`);
    console.log(`check-package: installed auth-kit migrate found its packed SQL by default and sent ${MIGRATIONS.length} file(s) byte for byte through a stand-in Management API (no network); a rerun wrote nothing; SQL files identical to the repository's`);
    console.log('check-package: prebuilt browser assets are current, secret-free, esbuild is not a dependency, and the installed module signs a user in under a strict CSP in Chromium (loopback fixture)');
    console.log('check-package: no home path, key value or private note in any packed file');
    console.log('check-package: packed TypeScript consumers compile (core, server, operator, hono, browser)');
    console.log('check-package: OK');
  } finally {
    if (!keep && workIndex === -1) await rm(workDir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  const detail = err instanceof CheckFailure ? err.message
    : err && typeof err.stderr === 'string' && err.stderr ? err.stderr.trim().split('\n').slice(-5).join('\n') : String(err?.message ?? err);
  console.error(`check-package: FAIL ${detail}`);
  process.exitCode = 1;
});
