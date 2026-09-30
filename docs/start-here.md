# Start here

Dwarpal provides reusable sign-in, account recovery, multi-factor authentication (MFA), and role-based access control for websites using Supabase Auth. Each website defines its own branding, roles and permissions. Its application continues to own its business data and the rules that decide which individual records a user may access.

This guide is for someone assessing Dwarpal and preparing an integration. The package is pre-release, version `0.0.0`, and is not published to npm. Read the [verification status](../README.md#verification-status) before treating an implemented feature as ready for a live site.

## Read in this order

| Document | What you will learn |
| --- | --- |
| [Business requirements](brd.md) | The problem, users, agreed scope, boundaries and acceptance outcomes. |
| [Architecture overview](architecture.md) | Components, trust boundaries, data ownership and the two ways to protect data. |
| [User manual](manual.md) | Configuration, installation, browser and server integration, errors and operations. |
| [RBAC low-level design](rbac-lld.md) | The data model, initialization, enrollment, authorization and membership sequence diagrams. |
| [Detailed design and contract](design.md) | Exact types, callable surfaces, security rules and verification cases. |

The first two documents provide the overview; use the manual for implementation and the LLD and contract for specific questions. Markdown is the maintained documentation. The [PDFs](pdf/) are historical design snapshots and may differ from the current implementation.

## What has been built

| Part | Responsibility | Source |
| --- | --- | --- |
| Core | Permission evaluation, contract types and validation, safe return paths | [`packages/core`](../packages/core/) |
| Browser kit | Sign-up, verification, password and Google sign-in, recovery, TOTP MFA, sign-out; default screens or a headless controller | [`packages/browser`](../packages/browser/) |
| Server library | Resolve a request into a verified principal; enforce permissions; forward manager grants and revokes | [`packages/server`](../packages/server/) |
| Database layer | Client-specific roles, permissions, enrollment and memberships, audited changes and optional RLS helpers | [`supabase/migrations`](../supabase/migrations/) |
| Operator CLI | Initialize configuration, migrate, diagnose setup, register clients, apply models, bootstrap or revoke managers, reset MFA | [`packages/server/cli`](../packages/server/cli/) |
| Integration examples | Protected Node endpoints, consumer-owned identity links, a consumer RLS policy, and configurable static-site builds | [`examples`](../examples/) |
| Verification tooling | Unit tests, local SQL and browser tests, package checks, and an explicitly authorized hosted test harness | [`tests`](../tests/) |

The development emulator is a synthetic fixture. It is excluded from the installable package. The examples demonstrate integration patterns; they do not establish acceptance by a real consuming site.

## Get the source

```sh
git clone https://github.com/aashishbhandari-stravion/dwarpal.git
cd dwarpal
git rev-parse HEAD
npm ci
npm test
npm run check:types
```

Use Node 22 or later and npm. Record the commit printed above when sharing questions or test results. The protected Node example uses `node:sqlite` and needs Node 22.13 or later.

For the fuller local checks, follow [Development](../README.md#development). The browser and installed-package checks require Chromium; the SQL gates require PostgreSQL binaries. The [SQL instructions](../tests/sql/README.md) explain their disposable test environment. These local checks do not require a live Supabase project.

Build a tarball when ready to try the package in a separate application:

```sh
npm pack
```

From that application's directory, install the generated `briqvent-dwarpal-0.0.0.tgz` using its actual path. The [manual](manual.md#5-integration-steps) explains configuration and provider setup. There is no published npm release to install by package name yet.

## Prepare an integration

Settle these choices before changing the consuming application:

1. Identify the website, its environment, its Supabase project and its fixed client ID. Decide its roles, permissions, public-enrollment rules and which roles require MFA.
2. Choose how protected data will be accessed. The Node path performs a live Auth check on every request; direct database RLS relies on token validity. Their different session-revocation guarantees are described in the [architecture](architecture.md#two-data-access-paths).
3. Define the application's record-ownership rules and explicit identity-to-record links. Matching a verified email to a historical contact is insufficient to grant access.
4. Prepare exact account routes and redirect URLs, SMTP and optional Google sign-in, and credential handling. Keep the project's secret key and Management API token in operator tooling.
5. Follow the manual, adapt the relevant example, and test both allowed and refused actions against the application's actual data model. Inspect the [integration checklist](manual.md#15-checklist-before-you-call-the-integration-done) before considering it complete.

## Current readiness

The repository records local verification of the core, SQL, server, CLI, browser kit, examples and installed tarball. The hosted harness is implemented and locally rehearsed. Hosted provider verification, consuming-site acceptance and release acceptance remain separate gates; the [README status table](../README.md#verification-status) is the public status reference.

When reporting a problem, include the source commit, Node version, the command or user action, expected and observed outcomes, and whether the test was local or hosted. Remove credentials, tokens and private user data from the report.
