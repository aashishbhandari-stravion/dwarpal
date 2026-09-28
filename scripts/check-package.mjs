#!/usr/bin/env node
// Packs the package, installs the tarball into a throwaway consumer and checks
// that (1) the tarball holds only the allowed files, (2) the installed entry
// points import and behave, (3) runtime exports equal declared exports for the
// source and the packed copy, (4) the installed auth-kit executable runs and
// reports that this package does not ship the SQL migrations, and (5) a
// TypeScript consumer compiles against the packed declarations, including the
// optional Hono entry with Hono installed beside it, and (6) the browser entry
// imports with its pinned supabase-js and refuses a secret key.
//
// Usage: node scripts/check-package.mjs [--work-dir <empty dir>] [--keep]
// Without --work-dir a fresh temporary directory is used and removed at the end.
// Installs are --offline: jose, hono and supabase-js with its dependencies
// must already be in the npm cache (a normal `npm ci` in this repository puts
// them there).

import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile, copyFile, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';

const root = fileURLToPath(new URL('..', import.meta.url));
const args = process.argv.slice(2);
const keep = args.includes('--keep');
const workIndex = args.indexOf('--work-dir');
if (workIndex !== -1 && !args[workIndex + 1]) fail('--work-dir needs a directory argument.');
const ENTRIES = {
  '.': 'packages/core/index',
  './testing': 'packages/core/testing/index',
  './server': 'packages/server/index',
  './server/operator': 'packages/server/operator',
  './server/hono': 'packages/server/hono',
  './browser': 'packages/browser/index',
};
const ALLOWED_FILE = /^(package\.json|README\.md|LICENSE|packages\/core\/(testing\/)?[a-z-]+\.(js|d\.ts)|packages\/server\/(lib\/|cli\/)?[a-z-]+\.(js|d\.ts)|packages\/browser\/(lib\/)?[a-z-]+\.(js|d\.ts)|packages\/browser\/styles\.css)$/;
const REQUIRED_FILES = [
  'package.json', 'LICENSE', 'README.md',
  ...Object.values(ENTRIES).flatMap((base) => [`${base}.js`, `${base}.d.ts`]),
  'packages/server/cli/auth-kit.js',
  'packages/browser/styles.css',
];
const PINNED = { jose: '6.2.12', hono: '4.13.9', supabase: '2.117.2' };
// supabase-js 2.117.2 and what it installs; every one must carry a permissive licence.
const BROWSER_RUNTIME = ['@supabase/auth-js', '@supabase/functions-js', '@supabase/phoenix', '@supabase/postgrest-js', '@supabase/realtime-js', '@supabase/storage-js', '@supabase/supabase-js', 'iceberg-js', 'tslib'];
const PERMISSIVE = new Set(['MIT', '0BSD', 'Apache-2.0', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause']);

function fail(message) {
  console.error(`check-package: FAIL ${message}`);
  process.exit(1);
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
    const ignored = spawnSync('git', ['check-ignore', '--no-index', '--stdin'], { cwd: root, input: names.join('\n'), encoding: 'utf8' });
    if (ignored.status === 0) fail(`packed files ignored by Git: ${ignored.stdout.trim().split('\n').join(', ')}`);
    if (ignored.status !== 1 && !/not a git repository/i.test(ignored.stderr)) fail('git check-ignore failed');
    const binMode = files.find((f) => f.path === 'packages/server/cli/auth-kit.js').mode;
    if ((binMode & 0o111) === 0) fail('auth-kit is not executable in the tarball');
    const tarball = join(workDir, filename);
    const tarballSha256 = createHash('sha256').update(await readFile(tarball)).digest('hex');

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
      "console.log('consumer import ok');",
    ].join('\n');
    await writeFile(join(consumer, 'probe.mjs'), probe);
    const probeOut = run(process.execPath, ['probe.mjs'], consumer).trim();

    // 5. The installed executable: help, a missing prerequisite, and SQL not shipped.
    const help = runBin(consumer, ['--help'], {});
    if (help.status !== 0 || !help.stdout.includes('bootstrap-manager')) fail('auth-kit --help');
    const missing = runBin(consumer, ['export-model', '--client', 'c'], {});
    if (missing.status !== 5) fail(`auth-kit without credentials exited ${missing.status}`);
    const credentials = { SUPABASE_URL: 'https://abcdefghijklmnopqrst.supabase.co', SUPABASE_SECRET_KEY: 'sb_secret_packcheckmarker', SUPABASE_ACCESS_TOKEN: 'sbp_packcheckmarker' };
    const migrate = runBin(consumer, ['migrate'], credentials);
    let migrateJson = null;
    try {
      migrateJson = JSON.parse(migrate.stdout);
    } catch {
      // reported below
    }
    if (migrate.status !== 5 || migrateJson?.error !== 'prerequisite_missing' || migrateJson?.details?.stage !== 'migration_files') {
      fail(`auth-kit migrate in the packed artifact must report missing migration files (exit ${migrate.status})`);
    }

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

    console.log(`check-package: node ${process.version}`);
    console.log(`check-package: tarball ${filename} sha256 ${tarballSha256}`);
    console.log(`check-package: ${names.length} files: ${names.join(', ')}`);
    console.log(`check-package: runtime dependency jose ${joseManifest.version} (${joseManifest.license}), ${joseBytes} bytes installed`);
    console.log(`check-package: browser runtime ${licences.join(', ')}; ${browserBytes} bytes installed`);
    console.log(`check-package: ${probeOut}; exports and declarations agree for ${Object.keys(ENTRIES).length} entries`);
    console.log('check-package: auth-kit bin runs; packed migrate reports migration files missing (SQL delivery is not part of this package)');
    console.log('check-package: packed TypeScript consumers compile (core, server, operator, hono, browser)');
    console.log('check-package: OK');
  } finally {
    if (!keep && workIndex === -1) await rm(workDir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  const detail = err && typeof err.stderr === 'string' && err.stderr ? err.stderr.trim().split('\n').slice(-5).join('\n') : String(err?.message ?? err);
  fail(detail);
});
