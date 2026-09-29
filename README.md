# Dwarpal

`@briqvent/dwarpal` is an authentication and authorization kit for websites built on **Supabase Auth**: a complete sign-in system and client-defined role-based access control for static or server-rendered sites with an optional Node.js back end, without running an auth service of its own.

> **Status:** pre-release. The package is private (`0.0.0`) and is not published to npm. Everything below is implemented in this repository and has been checked **locally**: unit tests, a real local PostgreSQL, real Chromium against a synthetic loopback fixture, and a clean install of the packed tarball. **No hosted Supabase project, real e-mail, Google sign-in or authenticator app has been exercised yet**, no consuming site has accepted the package, and no release has been accepted. See [Verification status](#verification-status).

Dwarpal requires **Supabase, Free plan or above**, and Node 22 or later for the server library and the CLI.

## What is in the package

- **Core** (`@briqvent/dwarpal`): contract 0.5, permission evaluation (`can`, `canAll`, `canAny`, `explain`, `requirePermission`, `requireRole`, `requireMfa`), model and client-configuration validators, redirect rules and request fingerprints. No network, database or framework code; it runs in Node 22+ and in browsers. `@briqvent/dwarpal/testing` exports a synthetic fixture so you can test your own guards against the principals the kit is tested with.
- **Server library** (`@briqvent/dwarpal/server`, Node 22+): `createAuthServer` turns a request's bearer token into a verified `Principal` (signature, live Supabase Auth session check and a fresh read of the user's access on **every** request) and forwards manager grants and revokes under the manager's own token. `@briqvent/dwarpal/server/hono` is an optional middleware; Hono stays an optional peer dependency. The operator client (`@briqvent/dwarpal/server/operator`) is a separate entry so a web server never imports secret-key code.
- **SQL migrations** for Supabase Postgres, shipped in the package (`supabase/migrations/`): roles, permissions, memberships, one-time enrollment, audited writes, and optional helpers for your own Row Level Security policies.
- **Operator CLI** `auth-kit`: `init`, `migrate`, `doctor`, `register-client`, `apply-model`, `export-model`, `bootstrap-manager`, `revoke-manager` and `mfa-reset`. An installed `auth-kit migrate` finds the packaged SQL by itself.
- **Browser kit** (`@briqvent/dwarpal/browser` and `.../browser/styles.css`): a headless controller and optional brandable default screens on the pinned `@supabase/supabase-js` 2.117.2. **Prebuilt static-site assets** (`packages/browser/dist/`: one ES module with supabase-js inlined, and the stylesheet) mean a site without a bundler never needs esbuild.
- **Documentation** (`docs/*.md`) is packed with the package.

The development emulator (`packages/emulator`) is a synthetic, development-only fixture. It is not part of the package.

## Install (pre-release)

Until a release is published, install the packed tarball that the checks build:

```sh
npm run check:package                       # builds and verifies the tarball in a throwaway consumer
npm pack                                    # writes briqvent-dwarpal-0.0.0.tgz
npm install ./briqvent-dwarpal-0.0.0.tgz    # in your project
npx auth-kit init                           # config skeleton, model skeleton, .env.example (no values)
```

Read the [user manual](docs/manual.md) before integrating.

## Operator CLI at a glance

`auth-kit` reads credentials from the environment (or a dotenv file passed with `--env-path`) and never prints them. `SUPABASE_URL` and `SUPABASE_SECRET_KEY` are the operator's; keep them out of any web server, browser and repository.

- `migrate` applies the packaged SQL files through the Management API and needs `SUPABASE_ACCESS_TOKEN`. Each file runs in one transaction and records its version, so a rerun applies only what is missing.
- `doctor`: **complete catalog checks (grants, schema version, exposed schemas, redirect settings) require `SUPABASE_ACCESS_TOKEN`** (the Management API token) as well as the secret key. With only the secret key, the privileged catalog checks are reported `not_run` and the overall result is `incomplete`, never healthy; the secret-key model export and the public signing-key check may still run. `doctor --probe` is a separate mode that signs in a disposable user and calls as `authenticated` and `anon`; it does not stand in for the catalog checks.
- Exit status: `0` done, `1` refused, `2` usage, `3` unavailable, `4` outcome unknown (a write may have been applied; the printed note names the command that converges), `5` prerequisite missing or `doctor` incomplete, `70` internal error.

## Entry points

| Import | Use |
| --- | --- |
| `@briqvent/dwarpal` | contract, evaluation, validators (browser and Node) |
| `@briqvent/dwarpal/testing` | synthetic principals for your guard tests |
| `@briqvent/dwarpal/server` | session resolution and manager operations (Node 22+) |
| `@briqvent/dwarpal/server/hono` | optional Hono middleware |
| `@briqvent/dwarpal/server/operator` | operator client (secret key; never in a web server) |
| `@briqvent/dwarpal/browser`, `.../browser/styles.css` | controller, default screens, stylesheet, for your own bundler |
| `@briqvent/dwarpal/browser/dist/dwarpal-browser.js`, `.css`, `build-manifest.json` | prebuilt assets for a static host |
| `auth-kit` (bin) | operator CLI |

## Example guard

```js
import { AuthError, can, requirePermission } from '@briqvent/dwarpal/server';

function readRecord(principal, record) {
  if (!can(principal, 'records:read:any')) {
    requirePermission(principal, 'records:read:own'); // throws forbidden or mfa_required
    if (record.ownerId !== principal.identity.userId) throw new AuthError('forbidden');
  }
  return record;
}
```

`own` refers to the row being acted on. When the narrow scope is "the principal is the target", use a `:self` key and compare the target with `principal.identity.userId`. A role counts only when it is *active*: it does not require MFA, or the session is `aal2`; permissions are the union over active roles.

## Examples

Examples are examples: none of them is part of the package, none is wired into a real site, and none carries credentials.

| Directory | What it shows | Checked by |
| --- | --- | --- |
| [`examples/protected-consumer`](examples/protected-consumer) | A generic Node endpoint with its **own SQLite** identity-to-record links (Node's built-in `node:sqlite`), the own/any guard, an audited link table, manager grants with request ids, and fail-closed 503s when SQLite or Supabase is unavailable | `tests/examples/protected-consumer.test.js` (loopback fixture) |
| [`examples/rls-consumer`](examples/rls-consumer) | One consumer table with Row Level Security policies that call the kit's real `auth_kit.has_permission` helper | `npm run test:examples-sql` (a real local PostgreSQL) |
| a client-specific example in [`examples/`](examples) | One deployment's model, page configuration and an esbuild static-site build. **Not** an integration into any real site | `npm run test:examples-built` |
| [`examples/example-studio`](examples/example-studio) | A synthetic second brand: different role keys (`owner`, `editor`, `member`), route prefix and route names, copy and a Vite build, on the same unchanged package | `npm run test:examples-built` |

## Verification status

Each result carries its evidence class. A synthetic result is never counted as hosted proof.

| Area | Implemented | Locally verified with | Not verified |
| --- | --- | --- | --- |
| Core, contract 0.5 | yes | unit tests; shared fixture against SQL | – |
| SQL migration and grants | yes | real PostgreSQL 15/17 via impersonated roles and claims | hosted PostgREST routing, hosted default privileges |
| Server library, Hono glue | yes | unit tests; SQL-backed tests; loopback fixture | live Supabase Auth (hosted) |
| Operator CLI | yes | unit and SQL-backed tests; installed `migrate` against a stand-in Management API | the real Management API, a real project migration |
| Browser kit, prebuilt assets | yes | unit tests; Chromium DOM tests; Chromium against the loopback fixture | real SMTP links, Google consent, a real authenticator app |
| Examples | yes | listed above | – |
| Package | yes | packed, installed and exercised in a clean consumer | publication |
| Hosted project (Lane 06) | – | – | not run |
| Consuming-site acceptance (Lane 07) | – | – | not started |
| Release acceptance | – | – | not done |

`npm run check` runs the unit tests, the declaration checks and the package check (which also rebuilds the prebuilt assets and compares them with the packed ones). The SQL, browser and example gates need a PostgreSQL build or Chromium and are listed below.

## Development

Requires Node 22 or later and npm.

```sh
npm ci
npm test                    # unit and fixture tests (core, server, CLI, browser, emulator, examples, package)
npm run check:types         # tsc against the published declarations
npm run build:browser       # (re)build packages/browser/dist; `npm pack` does this itself (prepack)
npm run check:package       # pack, install the tarball in a throwaway consumer, verify everything packed
npm run check               # test + check:types + check:package

npm run test:browser-dom          # Chromium DOM checks of the default screens
npm run test:browser-integration  # built bundle in Chromium against the emulator
npm run test:examples-built       # both example builds in Chromium: locked build tools (npm ci), the packed tarball, hostile brand names
DWARPAL_PG_BIN=<postgres bin dir> npm run test:sql-server    # server and CLI against a real PostgreSQL
DWARPAL_PG_BIN=<postgres bin dir> npm run test:examples-sql  # the RLS example
```

**Node versions.** The package check (pack, install, imports, CLI, prebuilt assets in Chromium) passes on Node 22 and 24, and the core, server, CLI, emulator, example and package tests pass on both. Known limit: on Node 22 seven Node-hosted browser-controller tests (`tests/browser/onboarding.test.js` and `signout.test.js`) are reported as cancelled, because the controller's request-deadline timer is `unref`'d and a deliberately hung fixture request then lets Node 22's event loop exit; they pass on Node 24. This affects the test suite, not the shipped browser code. The `protected-consumer` example uses `node:sqlite` and needs Node 22.13 or later.

The [SQL gates](tests/sql/README.md) start a disposable PostgreSQL cluster from separate PostgreSQL binaries; nothing is installed system-wide. Local SQL checks do not establish hosted PostgREST or live Supabase Auth behavior.

Build tooling is development-only: esbuild builds the prebuilt assets, TypeScript checks declarations, `playwright-core` drives Chromium. The package's runtime dependencies are `@supabase/supabase-js` (exact 2.117.2, MIT, for the browser kit) and `jose` (MIT, for the server); a consuming site never needs esbuild. The two example builds lock their own tools (esbuild; Vite and its transitive tree) in `examples/*/package-lock.json`; `npm run test:examples-built` installs exactly those with `npm ci` (from the npm registry, or the npm cache with `--offline`), and none of them is part of the package.

## Documentation

- [User manual](docs/manual.md): concepts, rules of engagement, integration steps, server and browser usage, errors, operations.
- [Design](docs/design.md): contract 0.5, the `Principal` shape, the server and SQL surfaces, security decisions and the test plan.
- [RBAC low-level design](docs/rbac-lld.md): the data model, invariants, sequence diagrams and failure modes.

PDF editions for offline reading are kept as [manual](docs/pdf/manual.pdf), [design](docs/pdf/design.pdf) and [RBAC low-level design](docs/pdf/rbac-lld.pdf). They are the **original design snapshots** and are not updated; the Markdown files are current where they differ.

## Licence

[MIT](LICENSE)
