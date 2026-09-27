# Dwarpal

`@briqvent/dwarpal` is an authentication and authorization kit for websites built on **Supabase Auth**. It gives a static or server-rendered site, with an optional Node.js back end, a complete sign-in system and client-defined role-based access control, without running an auth service of its own.

> **Status:** pre-release. The design is frozen at contract 0.5; the package is not yet published to npm.

## What it provides

- Email and password sign-up with verification, sign-in, password reset, Google sign-in and TOTP multi-factor authentication, with brandable default screens or a headless controller.
- A stateless Node server library that turns a request's bearer token into a verified `Principal` (identity, session, roles and permissions for your site), with a live session check on every request.
- Client-defined roles and permission keys, with three reserved role flags the kit enforces: `self_assignable`, `manages_members` and `mfa_required`.
- SQL migrations for Supabase Postgres, with every write going through audited SQL functions, and optional helpers for your own Row Level Security policies.
- An operator CLI (`auth-kit`) for migrations, client registration, the permission model, the first manager, MFA reset and diagnostics.

Dwarpal requires **Supabase, Free plan or above**, and Node 22 or later for the server library.

## Documentation

- [User manual](docs/manual.md): concepts, rules of engagement, integration steps, server and browser usage, errors, operations.
- [Design](docs/design.md): contract 0.5, the `Principal` shape, the server and SQL surfaces, security decisions and the test plan.
- [RBAC low-level design](docs/rbac-lld.md): the data model, invariants, sequence diagrams and failure modes.

PDF editions for offline reading: [manual](docs/pdf/manual.pdf), [design](docs/pdf/design.pdf), [RBAC low-level design](docs/pdf/rbac-lld.pdf). The Markdown files are the source; the PDFs are generated from them.

## Licence

[MIT](LICENSE)
