#!/usr/bin/env node
// Packs the package, installs the tarball into a throwaway consumer and checks
// that (1) the tarball holds only the allowed files, (2) the installed entry
// points import and behave, (3) runtime exports equal declared exports for the
// source and the packed copy, and (4) a TypeScript consumer compiles against
// the packed declarations.
//
// Usage: node scripts/check-package.mjs [--work-dir <empty dir>] [--keep]
// Without --work-dir a fresh temporary directory is used and removed at the end.

import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile, copyFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import ts from 'typescript';

const root = fileURLToPath(new URL('..', import.meta.url));
const args = process.argv.slice(2);
const keep = args.includes('--keep');
const workIndex = args.indexOf('--work-dir');
if (workIndex !== -1 && !args[workIndex + 1]) fail('--work-dir needs a directory argument.');
const ENTRIES = { '.': 'index', './testing': 'testing/index' };
const ALLOWED_FILE = /^(package\.json|README\.md|LICENSE|packages\/core\/(testing\/)?[a-z-]+\.(js|d\.ts))$/;

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
  // Value exports only: type-only names have no runtime counterpart.
  return checker.getExportsOfModule(symbol)
    .filter((s) => (s.flags & ts.SymbolFlags.Value) !== 0)
    .map((s) => s.getName())
    .sort();
}

async function runtimeExports(jsPath) {
  return Object.keys(await import(pathToFileURL(jsPath).href)).sort();
}

function sameList(label, a, b) {
  if (JSON.stringify(a) !== JSON.stringify(b)) fail(`${label}\n  left:  ${a.join(', ')}\n  right: ${b.join(', ')}`);
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
    for (const required of ['package.json', 'LICENSE', 'README.md', 'packages/core/index.js', 'packages/core/index.d.ts', 'packages/core/testing/index.js', 'packages/core/testing/index.d.ts']) {
      if (!names.includes(required)) fail(`missing from tarball: ${required}`);
    }
    const tarball = join(workDir, filename);
    const tarballSha256 = createHash('sha256').update(await readFile(tarball)).digest('hex');

    // 2. Install into a throwaway consumer.
    const consumer = join(workDir, 'consumer');
    await mkdir(consumer);
    await writeFile(join(consumer, 'package.json'), JSON.stringify({ name: 'pack-consumer', private: true, type: 'module' }));
    run('npm', ['install', '--no-audit', '--no-fund', '--ignore-scripts', '--offline', tarball], consumer);
    const installed = join(consumer, 'node_modules/@briqvent/dwarpal');

    // 3. Exports: source runtime == packed runtime == source declarations == packed declarations.
    for (const [entry, base] of Object.entries(ENTRIES)) {
      const src = await runtimeExports(join(root, 'packages/core', `${base}.js`));
      const packed = await runtimeExports(join(installed, 'packages/core', `${base}.js`));
      sameList(`runtime exports differ for ${entry} (source vs packed)`, src, packed);
      sameList(`declared exports differ from runtime for ${entry} (source)`, declaredExports(join(root, 'packages/core', `${base}.d.ts`)), src);
      sameList(`declared exports differ from runtime for ${entry} (packed)`, declaredExports(join(installed, 'packages/core', `${base}.d.ts`)), packed);
    }

    // 4. Import by package name from the consumer and exercise one decision.
    const probe = [
      "import { AUTH_CONTRACT_VERSION, can, explain } from '@briqvent/dwarpal';",
      "import { fixturePrincipals } from '@briqvent/dwarpal/testing';",
      "if (AUTH_CONTRACT_VERSION !== '0.5') throw new Error('contract');",
      "if (!can(fixturePrincipals.patron, 'records:read:own')) throw new Error('own');",
      "if (can(fixturePrincipals.patronClerkAal1, 'records:read:any')) throw new Error('withheld');",
      "if (explain(fixturePrincipals.patronClerkAal1, 'records:read:any').withheld[0]?.role !== 'clerk') throw new Error('explain');",
      "let blocked = false; try { await import('@briqvent/dwarpal/packages/core/model.js'); } catch { blocked = true; }",
      "if (!blocked) throw new Error('deep import should be blocked by the exports map');",
      "console.log('consumer import ok');",
    ].join('\n');
    await writeFile(join(consumer, 'probe.mjs'), probe);
    const probeOut = run(process.execPath, ['probe.mjs'], consumer).trim();

    // 5. TypeScript consumer compiled against the packed declarations.
    await mkdir(join(consumer, 'src'));
    await copyFile(join(root, 'tests/core/types/consumer.ts'), join(consumer, 'src/consumer.ts'));
    await writeFile(join(consumer, 'tsconfig.json'), JSON.stringify({
      compilerOptions: { target: 'ES2022', module: 'NodeNext', moduleResolution: 'NodeNext', strict: true, noEmit: true, types: [] },
      include: ['src/**/*.ts'],
    }));
    run(process.execPath, [join(root, 'node_modules/typescript/bin/tsc'), '-p', 'tsconfig.json'], consumer);

    console.log(`check-package: tarball ${filename} sha256 ${tarballSha256}`);
    console.log(`check-package: ${names.length} files: ${names.join(', ')}`);
    console.log(`check-package: ${probeOut}; exports and declarations agree; packed TypeScript consumer compiles`);
    console.log('check-package: OK');
  } finally {
    if (!keep && workIndex === -1) await rm(workDir, { recursive: true, force: true });
  }
}

main().catch((err) => {
  const detail = err && typeof err.stderr === 'string' && err.stderr ? err.stderr.trim().split('\n').slice(-5).join('\n') : String(err?.message ?? err);
  fail(detail);
});
