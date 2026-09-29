// Vite build of the Example Studio auth pages.
//
// `dist/` mirrors the route prefix: copy its contents to <web root><prefix>/
// (here /studio/account/). Public values can be overridden from the
// environment: SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, SITE_ORIGIN; OUT_DIR
// changes the output directory.

import { defineConfig } from 'vite';
import { readFileSync } from 'node:fs';
import { posix } from 'node:path';
import { ROUTE_NAMES, validateClientConfig, validateModel } from '@briqvent/dwarpal';

const readJson = (name) => JSON.parse(readFileSync(new URL(name, import.meta.url), 'utf8'));
const TITLES = {
  signIn: 'Log in', signUp: 'Join', verify: 'Confirm your e-mail address', callback: 'Signing you in',
  forgot: 'Reset your password', reset: 'Set a new password', mfa: 'Two-step verification', signOut: 'Log out',
};

const env = process.env;
const input = {
  ...readJson('auth-kit.config.json'),
  ...(env.SUPABASE_URL ? { supabaseUrl: env.SUPABASE_URL } : {}),
  ...(env.SUPABASE_PUBLISHABLE_KEY ? { publishableKey: env.SUPABASE_PUBLISHABLE_KEY } : {}),
  ...(env.SITE_ORIGIN ? { origin: env.SITE_ORIGIN } : {}),
};
// Validated here to fail the build early (a secret key is refused); the page
// receives the same input and validates it again in the browser.
const config = validateClientConfig(input);
// The model and the page configuration must name the same client.
validateModel(readJson('auth-model.json'), { clientId: config.clientId });

// One small static page per route, all loading the entry chunk and its stylesheet.
function routePages() {
  return {
    name: 'auth-route-pages',
    generateBundle(_options, bundle) {
      const entry = Object.values(bundle).find((item) => item.type === 'chunk' && item.isEntry);
      const sheet = Object.values(bundle).find((item) => item.type === 'asset' && item.fileName.endsWith('.css'));
      if (!entry || !sheet) throw new Error('auth-route-pages: the entry chunk or its stylesheet is missing');
      for (const name of ROUTE_NAMES) {
        this.emitFile({
          type: 'asset',
          fileName: `${posix.relative(config.routes.prefix, config.routes[name])}/index.html`,
          source: `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${TITLES[name]} | ${config.brand.name}</title>
<meta name="description" content="${TITLES[name]} for ${config.brand.name}.">
<meta name="robots" content="noindex, nofollow">
<link rel="stylesheet" href="${config.routes.prefix}/${sheet.fileName}">
</head>
<body>
<main id="dwarpal-auth"></main>
<script type="module" src="${config.routes.prefix}/${entry.fileName}"></script>
</body>
</html>
`,
        });
      }
    },
  };
}

export default defineConfig({
  base: `${config.routes.prefix}/`,
  define: { __AUTH_CONFIG__: JSON.stringify(input) },
  plugins: [routePages()],
  build: {
    outDir: env.OUT_DIR ?? 'dist',
    emptyOutDir: true,
    target: 'es2022',
    modulePreload: false,
    rollupOptions: { input: 'src/account.js' },
  },
});
