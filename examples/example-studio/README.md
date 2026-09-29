# Example Studio (synthetic second brand)

A made-up second site on the same unchanged package, to show that nothing brand-specific lives in the kit. Compared with the CREDITONE example it has **different role keys** (`owner`, `editor`, `member`), a **different route prefix and route names** (`/studio/account/log-in`, `/join`, `/log-out`), its own brand colours and copy override, and a **Vite** build instead of esbuild.

| File | Purpose |
| --- | --- |
| [`auth-model.json`](auth-model.json) | `owner` (manager, MFA), `editor`, and the self-assignable `member`. |
| [`auth-kit.config.json`](auth-kit.config.json) | Public page configuration with placeholders. |
| [`vite.config.js`](vite.config.js), [`src/account.js`](src/account.js) | Vite build; a small plugin emits one static page per route. |

## Build

Install Vite and its transitive tools exactly as [`package-lock.json`](package-lock.json) pins them, add the packed tarball without changing the lock, then build:

```sh
npm ci
npm install --no-save ./briqvent-dwarpal-0.0.0.tgz
SUPABASE_URL=https://<ref>.supabase.co SUPABASE_PUBLISHABLE_KEY=sb_publishable_... \
SITE_ORIGIN=https://studio.example.org npx vite build
```

`dist/` mirrors the route prefix: copy its contents to `<web root>/studio/account/`. As in the CREDITONE example, the configuration is validated at build time (a secret key stops the build before anything is written), the brand name is HTML-escaped in the generated pages, the pages are `noindex` with no inline script, and the same Content-Security-Policy and routing notes apply. Vite needs Node 20.19 or 22.12 and later.

## How it is checked

`npm run test:examples-built` installs Vite with `npm ci`, checks every locked version, builds it from the installed tarball (also with hostile and punctuated brand names, checked in Chromium) and drives it in Chromium against the loopback fixture: sign-up on `/studio/account/join`, click-only verification, enrolment as `member` (not `customer`), the return path and no request outside the loopback. Fixture evidence only.
