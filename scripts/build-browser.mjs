#!/usr/bin/env node
// Builds the prebuilt browser assets for static hosts (design D4, 9.5): one
// ES module with the pinned supabase-js inlined, and the `ak-` stylesheet.
// Consumers with their own bundler import `@briqvent/dwarpal/browser` source
// instead and never need esbuild.
//
//   node scripts/build-browser.mjs [--outdir <dir>]
//
// The default output directory is packages/browser/dist. After writing, the
// output is scanned for secret and operator markers and the build fails if
// any is present. A manifest lists every file with its size, gzip size and
// SHA-256, plus the esbuild and supabase-js versions that produced it.

import { build, version as esbuildVersion } from 'esbuild';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile, copyFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { gzipSync } from 'node:zlib';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ENTRY = join(ROOT, 'packages/browser/index.js');
const STYLES = join(ROOT, 'packages/browser/styles.css');
const BUNDLE = 'dwarpal-browser.js';
const STYLESHEET = 'dwarpal-browser.css';

// What must never reach a browser: secret-key and Management-token values,
// the operator's environment names, service-role JWTs, the private schema,
// and operator or manager RPC names (the browser calls only ensure_profile,
// effective_access and join_client).
export const FORBIDDEN_PATTERNS = Object.freeze([
  ['secret key value', /sb_secret_[A-Za-z0-9_-]{8,}/],
  ['management token value', /sbp_[A-Za-z0-9]{16,}/],
  ['secret key variable', /SUPABASE_SECRET_KEY/],
  ['management token variable', /SUPABASE_ACCESS_TOKEN/],
  ['service role key variable', /SUPABASE_SERVICE_ROLE_KEY/],
  ['management API host', /api\.supabase\.com/],
  ['private schema', /auth_kit_private/],
  ['operator RPC', /\b(?:register_client|apply_model|export_model|bootstrap_manager|revoke_manager|mfa_reset_begin|mfa_reset_note|mfa_reset_finish)\b/],
  ['manager RPC', /\b(?:grant_membership|revoke_membership)\b/],
]);

/** Returns the names of every forbidden marker found in `text`, including service-role JWTs. */
export function scanForSecrets(text) {
  const found = FORBIDDEN_PATTERNS.filter(([, pattern]) => pattern.test(text)).map(([name]) => name);
  for (const match of text.matchAll(/eyJ[A-Za-z0-9_-]{8,}\.(eyJ[A-Za-z0-9_-]{8,})\.[A-Za-z0-9_-]*/g)) {
    try {
      const payload = JSON.parse(Buffer.from(match[1], 'base64url').toString('utf8'));
      if (payload?.role === 'service_role') found.push('service-role JWT');
    } catch {
      // not a JWT
    }
  }
  return found;
}

/**
 * @param {{ outdir?: string }} [options]
 * @returns {Promise<{ outdir: string, manifest: object }>}
 */
export async function buildBrowser({ outdir = join(ROOT, 'packages/browser/dist') } = {}) {
  await mkdir(outdir, { recursive: true });
  const bundlePath = join(outdir, BUNDLE);
  const result = await build({
    entryPoints: [ENTRY],
    outfile: bundlePath,
    bundle: true,
    format: 'esm',
    platform: 'browser',
    target: ['es2022'],
    minify: true,
    sourcemap: false,
    legalComments: 'eof',
    // Deterministic output: no absolute paths, no build-time values.
    absWorkingDir: ROOT,
    charset: 'utf8',
    logLevel: 'silent',
    metafile: true,
  });
  // Everything is inlined: a static host serves one file with no imports.
  const externalImports = Object.values(result.metafile.outputs).flatMap((output) => output.imports.map((entry) => entry.path));
  if (externalImports.length > 0) throw new Error(`build-browser: unresolved imports: ${externalImports.join(', ')}`);
  await copyFile(STYLES, join(outdir, STYLESHEET));

  const files = [];
  for (const name of [BUNDLE, STYLESHEET]) {
    const bytes = await readFile(join(outdir, name));
    const markers = scanForSecrets(bytes.toString('utf8'));
    if (markers.length > 0) throw new Error(`build-browser: forbidden markers in ${name}: ${markers.join(', ')}`);
    files.push({
      name,
      bytes: bytes.length,
      gzipBytes: gzipSync(bytes, { level: 9 }).length,
      sha256: createHash('sha256').update(bytes).digest('hex'),
    });
  }
  const supabase = JSON.parse(await readFile(join(ROOT, 'node_modules/@supabase/supabase-js/package.json'), 'utf8'));
  const manifest = { esbuild: esbuildVersion, supabaseJs: supabase.version, externalImports, files };
  await writeFile(join(outdir, 'build-manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  return { outdir, manifest };
}

function parseArgs(argv) {
  const args = { outdir: undefined };
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--outdir' && i + 1 < argv.length) args.outdir = resolve(argv[++i]);
    else throw new Error(`build-browser: unknown argument ${JSON.stringify(argv[i])}`);
  }
  return args;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    const { outdir, manifest } = await buildBrowser(parseArgs(process.argv.slice(2)));
    for (const file of manifest.files) console.log(`${file.name}\t${file.bytes} B\t${file.gzipBytes} B gzip\t${file.sha256}`);
    console.log(`build-browser: wrote ${outdir} (esbuild ${manifest.esbuild}, supabase-js ${manifest.supabaseJs})`);
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
