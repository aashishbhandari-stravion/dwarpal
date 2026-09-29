#!/usr/bin/env node
// Builds the CREDITONE auth pages for a static host with esbuild.
//
//   node build.mjs              writes ./dist, laid out like the route prefix
//
// The output directory mirrors the configured route prefix: copy its contents
// to <web root><prefix>/ (for the default prefix, /account/). Public values
// can be overridden from the environment when building for a real project:
// SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, SITE_ORIGIN. A secret key is refused
// by the kit's own config validation and by the output scan below.

import { build } from 'esbuild';
import { createHash } from 'node:crypto';
import { mkdir, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { ROUTE_NAMES, validateClientConfig, validateModel } from '@briqvent/dwarpal';

const here = dirname(fileURLToPath(import.meta.url));
const readJson = async (name) => JSON.parse(await readFile(join(here, name), 'utf8'));

const TITLES = {
  signIn: 'Sign in', signUp: 'Create an account', verify: 'Confirm your e-mail address', callback: 'Signing you in',
  forgot: 'Reset your password', reset: 'Set a new password', mfa: 'Two-step verification', signOut: 'Sign out',
};
// The kit's own prebuilt-asset scan, applied to this site's output: secret-key
// and Management-token values, the operator's variable names, the Management
// API host and the private schema. (The word `sb_secret_` alone appears in the
// kit's validators, which refuse such keys; only a key value is a leak.)
const FORBIDDEN = [/sb_secret_[A-Za-z0-9_-]{8,}/, /sbp_[A-Za-z0-9]{16,}/, /SUPABASE_SECRET_KEY/, /SUPABASE_ACCESS_TOKEN/, /SUPABASE_SERVICE_ROLE_KEY/, /api\.supabase\.com/, /auth_kit_private/];

const raw = await readJson('auth-kit.config.json');
const env = process.env;
const input = {
  ...raw,
  ...(env.SUPABASE_URL ? { supabaseUrl: env.SUPABASE_URL } : {}),
  ...(env.SUPABASE_PUBLISHABLE_KEY ? { publishableKey: env.SUPABASE_PUBLISHABLE_KEY } : {}),
  ...(env.SITE_ORIGIN ? { origin: env.SITE_ORIGIN } : {}),
};
// Validated here to fail the build early (a secret key is refused); the page
// receives the same input and validates it again in the browser.
const config = validateClientConfig(input);
// The model and the page configuration must name the same client.
validateModel(await readJson('auth-model.json'), { clientId: config.clientId });

const outDir = resolve(here, env.OUT_DIR ?? 'dist');
const stage = `${outDir}.tmp-${process.pid}`;
await rm(stage, { recursive: true, force: true });
await mkdir(join(stage, 'assets'), { recursive: true });

await build({
  entryPoints: { account: join(here, 'src/account.js') },
  outdir: join(stage, 'assets'),
  bundle: true,
  format: 'esm',
  platform: 'browser',
  target: ['es2022'],
  minify: true,
  sourcemap: false,
  absWorkingDir: here,
  charset: 'utf8',
  logLevel: 'silent',
  define: { __AUTH_CONFIG__: JSON.stringify(input) },
});

// One small static page per route; each loads the same script. No inline
// script or style, so a strict Content-Security-Policy works unchanged.
const asset = (name) => `${config.routes.prefix}/assets/${name}`;
for (const name of ROUTE_NAMES) {
  const path = join(stage, relative(config.routes.prefix, config.routes[name]), 'index.html');
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${TITLES[name]} | ${config.brand.name}</title>
<meta name="description" content="${TITLES[name]} to your ${config.brand.name} account.">
<meta name="robots" content="noindex, nofollow">
<link rel="stylesheet" href="${asset('account.css')}">
</head>
<body>
<main id="dwarpal-auth"></main>
<script type="module" src="${asset('account.js')}"></script>
</body>
</html>
`);
}

// Nothing secret may reach the output.
const files = [];
for (const entry of await readdir(stage, { recursive: true, withFileTypes: true })) {
  if (entry.isFile()) files.push(join(entry.parentPath, entry.name));
}
files.sort();
for (const file of files) {
  const text = await readFile(file, 'utf8');
  const hit = FORBIDDEN.find((pattern) => pattern.test(text));
  if (hit) throw new Error(`build: forbidden marker ${hit} in ${relative(stage, file)}`);
}

// Swap in only a finished build: a failed run leaves the previous dist untouched.
await rm(outDir, { recursive: true, force: true });
await rename(stage, outDir);
for (const file of files) {
  const bytes = await readFile(join(outDir, relative(stage, file)));
  console.log(`${relative(stage, file)}\t${bytes.length} B\t${createHash('sha256').update(bytes).digest('hex').slice(0, 16)}`);
}
console.log(`build: ${config.clientId} pages for ${config.routes.prefix}/ in ${relative(process.cwd(), outDir) || '.'}`);
console.log(`build: Content-Security-Policy connect-src needs 'self' ${config.supabaseUrl}`);
