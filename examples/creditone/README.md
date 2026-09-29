# CREDITONE example

The CREDITONE **model**, page **configuration** and an esbuild **build** of the auth pages for a static-site host. This is an example of one deployment of the kit. It is not an integration into the real CREDITONE site, it edits no checkout, and the kit itself contains none of it.

| File | Purpose |
| --- | --- |
| [`auth-model.json`](auth-model.json) | Roles `admin`, `staff` (both `mfa_required`) and `customer` (self-assignable), with own/any permission keys (`orders:read:own`, `orders:read:any`, ...). Apply it with `auth-kit apply-model`. |
| [`auth-kit.config.json`](auth-kit.config.json) | Public page configuration. The project URL, key and origin are placeholders. |
| [`build.mjs`](build.mjs), [`src/account.js`](src/account.js) | esbuild build: one script, one stylesheet and one static page per route. |

## Build

Install the packed tarball and esbuild, then build:

```sh
npm install ./briqvent-dwarpal-0.0.0.tgz esbuild@0.28.2
SUPABASE_URL=https://<ref>.supabase.co SUPABASE_PUBLISHABLE_KEY=sb_publishable_... \
SITE_ORIGIN=https://www.example.com node build.mjs
```

`dist/` mirrors the route prefix (default `/account`): copy its contents to `<web root>/account/`. The build validates the configuration with the kit's own validators (a secret key is refused), checks that the model and the configuration name the same client, scans its output for secret markers, and replaces `dist/` only when the whole build succeeds.

## Host integration notes

- **Existing public pages are untouched.** This build only adds pages under the prefix. Your public pages' titles, descriptions, canonical URLs, `robots.txt`, sitemap and structured data (including the business locality) stay as they are; keep public content browsable without an account.
- **Auth pages are `noindex`.** Each generated page carries `<meta name="robots" content="noindex, nofollow">`. Do not disallow the prefix in `robots.txt`, or crawlers cannot see the `noindex`; you may add `X-Robots-Tag: noindex` as well.
- **Content-Security-Policy** for the auth pages: `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self' https://<ref>.supabase.co; img-src 'self' data:; base-uri 'none'; form-action 'self'`. The pages have no inline script or style. Add `Cache-Control: no-store` for the pages if you serve session-dependent content near them.
- **Nginx-style routing** needs `try_files $uri $uri/index.html =404;` for the prefix.
- **Add each return path** the pages may send a user to (`allowedReturnPaths`) and register the exact redirect URLs in the Supabase project.

## How it is checked

`npm run test:examples-built` packs the package, installs the tarball next to this example, runs the build with the shipped configuration (pages per route, `noindex`, no inline script, no secret marker, a refused secret key leaves `dist/` untouched) and then rebuilds it against a loopback Auth/RPC fixture and drives it in Chromium: sign-up, click-only verification, enrolment as `customer`, and the return path. Fixture evidence only; the real CREDITONE acceptance is a separate, later step.
