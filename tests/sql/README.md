# SQL gates

Executable checks for `supabase/migrations/` against a real PostgreSQL server. They cover the migration lifecycle, the complete grant table and its drift audit (column privileges and profile policies), role and claim impersonation, canonical JSON and hash parity with `packages/core`, opaque keys of any length, model apply/export, enrollment, request-id retries, per-client locking, the MFA-reset claim, and the runner's own cleanup. No emulator or in-memory imitation is involved.

## Requirements

- Node.js 22 or later (the runner uses `node:test` and only built-in modules; no npm dependency).
- A PostgreSQL 15 or later server build: a `bin` directory containing `initdb`, `postgres` and `pg_ctl`. Nothing else from the installation is used, and no existing server is contacted.

To build a pinned server from upstream source without touching the system:

```bash
tests/sql/runtime/build-postgres.sh <runtime-dir> [17.11|15.19]
```

The script verifies the tarball against a pinned SHA-256 before extracting it and installs into `<runtime-dir>/install`. It needs a C toolchain, `make`, `curl`, `tar` and `bzip2`; PostgreSQL 17 additionally needs `bison`, `flex` and `m4` because its tarballs no longer include generated parser files. Readline, zlib, ICU and OpenSSL are disabled.

## Running

```bash
DWARPAL_PG_BIN=<runtime-dir>/install/bin node tests/sql/run.js
```

Options: `--work-dir <dir>` (parent of the throwaway cluster; Unix socket paths are limited to 107 bytes, so keep it short), `--concurrency <n>`, `--timeout <seconds>`, `--tap <file>`, `--keep`, and individual case files as arguments.

Each run creates a new cluster in a fresh temporary directory, listening only on a Unix socket inside that directory (`listen_addresses` is empty and the directory is private to the user), prepares two template databases and runs `cases/*.test.js`. Every test clones its own database from a template and drops it afterwards. On exit, including after a failed start, the runner stops the postmaster running in the directory it created (a fast shutdown, then one immediate shutdown if that fails), checks that the process is gone, and only then removes that directory; it never touches another server or directory. SIGINT or SIGTERM stops the test run first and then tears down the same way; a second signal tears down at once.

Exit status: 128 plus the signal number when interrupted; otherwise the test run's status when tests failed; otherwise 1 when the harness or the teardown failed; 0 only when the tests passed and the cluster was verifiably stopped and removed. The last line states the status and its parts, for example `[sql-gates] exit status 0: tests 0, harness ok, teardown ok`. A teardown failure is printed as `TEARDOWN FAILED: ...` together with the postmaster pid and directory it left behind; a failed fast shutdown stays a failure even when the immediate one recovers.

Guard sensitivity:

```bash
DWARPAL_PG_BIN=<runtime-dir>/install/bin node tests/sql/sensitivity.js [--work-dir <dir>] [--report <file>]
```

For each critical guard it removes that guard from a disposable copy of the migration (or of the runner) and requires the named test to fail; an unmutated copy runs first and must pass. The repository is never modified.

## Layout

| Path | Purpose |
| --- | --- |
| `run.js` | Starts the throwaway cluster, prepares templates from the fixtures and the exact migration bytes, runs the cases. |
| `sensitivity.js` | Guard mutations in disposable copies. |
| `harness/pgwire.js` | Minimal PostgreSQL protocol client (trust over the private socket, simple queries, bounded timeouts with cancellation). |
| `harness/cluster.js` | Creates, starts, stops and removes the throwaway cluster. |
| `harness/db.js` | Per-test databases, actors, sessions for concurrency, lock-wait observation. |
| `harness/kit.js` | Kit calls through the exposed wrappers, a synthetic example model, whole-state snapshots. |
| `fixtures/supabase-roles.sql`, `fixtures/supabase-auth.sql` | The Supabase roles and `auth` schema slice the migration relies on. |
| `fixtures/faults.sql` | Test-only fault injection triggers, installed per test for rollback gates. |
| `cases/*.test.js` | The gates. `opaque-keys` covers keys over the index limit and a copy with a deliberately colliding key digest; `access-audit` covers drift the grant assertion must report; `teardown` runs the runner itself with injected `initdb`/`pg_ctl` failures and signals. |

## Fixture versus hosted Supabase

The fixtures create only what the migration needs, in the throwaway cluster:

- Roles `anon`, `authenticated`, `service_role` (BYPASSRLS) and `authenticator`, which tests connect as and then switch role with `set_config('role', ...)` and set `request.jwt.claims`, the way PostgREST does per request. Actors are therefore real database roles with real claims.
- A non-superuser `postgres` migration role with BYPASSRLS; the superuser is `supabase_admin`.
- `auth.uid()`, `auth.role()` and `auth.jwt()` reading the claim settings as Supabase's published definitions do; `auth.users` reduced to `id`, `email`, `email_confirmed_at` and `is_anonymous`, readable by the migration role.

Not present: PostgREST, GoTrue, JWT signing and verification, the exposed-schema setting, hosted default privileges, SMTP, Google sign-in and TOTP.

## What the gates do not prove

These remain hosted or later-lane gates: that PostgREST refuses RPC into `auth_kit_private` over HTTP, JWT and live Auth session behavior, the operator CLI's Auth calls with its 100-second claim deadline and 20-second call timeout, real passage of the 120-second MFA lease (tests move `started_at` back instead), provider flows (SMTP, Google, TOTP), and hosted catalog state.

## Error convention

A kit refusal raises SQLSTATE `DW001` with the refusal code as the message (and JSON in `DETAIL` for `model_invalid` and `model_refused`). Any other SQLSTATE is a database failure. Refusals write nothing, including no `request_log` row, so the same request id may be used again once the refusal no longer applies.
