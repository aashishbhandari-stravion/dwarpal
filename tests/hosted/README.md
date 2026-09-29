# Hosted verification harness

Checks the kit against a real, isolated Supabase project: HTTP routing versus SQL `EXECUTE`, the live actor and model matrix, the two revocation paths, enrollment, model refusals, request ids, client scope, manager bootstrap, `doctor` modes, manager authority, the operator MFA reset, and the provider flows (TOTP, real SMTP delivery, an interactive Google sign-in). The case list, with the design reference, access path, inputs and authorization each case needs, is in [`lib/inventory.js`](lib/inventory.js); print it with `node tests/hosted/run.js inventory`.

Nothing in this directory counts a fake, an emulator, a skipped case or a local PostgreSQL run as hosted proof. The self-tests and the local rehearsal below exercise the harness itself; their results are never hosted results.

## Statuses

| Status | Meaning |
| --- | --- |
| `passed` | Executed in `run` mode against the authorized target; every assertion held, each with an evidence reference. |
| `failed` | Executed and an assertion did not hold, the platform contradicted the design, or the harness broke after hosted effects began. |
| `blocked` | Could not execute: an input, credential, authorization or target prerequisite is missing, a rate limit was not lifted, or an outcome became unknown. |
| `not_run` | Not attempted in this run: not selected, or waiting for a recorded disposition. |

The run's verdict is `passed` only when every required case passed. Any failed required case, or any record the inventory does not know, makes it `failed`; otherwise it is `incomplete`. A case with no record is `not_run`; a case its procedure never reported is `failed` (`not_reported`); a pass without assertions or evidence references is `failed` (`invalid_pass_record`); a pass recorded without hosted provenance is `not_run` (`not_hosted`).

## Fail-closed gates

1. **No network before authorization.** Every request goes through one gate ([`lib/net.js`](lib/net.js)) that starts closed. It opens only for the origins [`lib/target.js`](lib/target.js) returns after checking the descriptor, the credentials and the confirmation. `inventory`, `plan` and a refused `run` make no network call.
2. **Authorization is explicit and per class.** The descriptor records where the owner authorized the target, that the project is isolated, disposable and free of production data, an expiry, and the classes of external action allowed. A case whose class is not listed is `blocked`.

   | Class | Allows |
   | --- | --- |
   | `connect` | read-only calls: signing keys, settings, Management API reads, PostgREST reads |
   | `create_users` | create, ban and delete disposable users through the Auth admin API (no e-mail is sent) |
   | `mutations` | kit writes, consumer rows, sign-in and sign-out of disposable users |
   | `totp` | enrol, challenge, verify and delete TOTP factors of disposable users |
   | `catalog_mutation` | temporary catalog changes reverted in the same run: widened grants (L33), a fault trigger (L27) |
   | `cleanup_sql` | Management API deletes of rows this harness created |
   | `send_email` | real SMTP deliveries to the authorized recipients |
   | `interactive_sign_in` | a human Google sign-in with the authorized test identity |

3. **The invocation names the project.** `DWARPAL_HOSTED_CONFIRM_REF` must equal the descriptor's project ref, and `SUPABASE_URL` must be exactly `https://<ref>.supabase.co`.
4. **The source is clean.** `run` refuses a public working tree with uncommitted or untracked changes, so evidence always names an exact commit and tree.
5. **Target prerequisites first.** `T.*` checks (signing keys, Auth settings, Management API and SQL probe channel, installed schema and grant assertion, exposed schemas, the example consumer's policies) run before anything else; a procedure whose prerequisites did not pass is `blocked`.

## Inputs

**Descriptor** (private JSON, no secrets; schema documented at the top of [`lib/target.js`](lib/target.js)): project ref and URL, the authorization record, a template for disposable addresses (`<local>+{tag}@<authorized domain>`; users are created confirmed through the admin API, so no mail is sent to them), SMTP recipients and the authorized sending domain, the Google test identity, the loopback callback port, and optional limits.

**Credentials** come from the environment or from `--env-path`, an owner-only (`0600`) file outside every Git working tree: `SUPABASE_URL`, `SUPABASE_PUBLISHABLE_KEY`, `SUPABASE_SECRET_KEY`, and `SUPABASE_ACCESS_TOKEN` (Management API; without it every catalog, SQL-impersonation and row-count case is `blocked`). No other variable is read.

**The operator prepares the target** before a run; the harness only checks it:

- apply `supabase/migrations/*.sql` (for example `auth-kit migrate`) and `examples/rls-consumer/policies.sql`;
- expose `auth_kit` and `app` and never `auth_kit_private`;
- enable TOTP enrolment and verification, require e-mail confirmation, and set the access-token lifetime (L25 waits one full lifetime);
- for the provider cases: custom SMTP on the authorized sending domain, the Google provider, and the exact redirect `http://localhost:<callbackPort>/hosted/callback`;
- consider raising the sign-in rate limit of the isolated project: a full run creates about 45 disposable users and makes about 50 password sign-ins; the harness paces sign-ins to the descriptor's `signInsPerFiveMinutes` (default 25) and treats an exhausted 429 budget as `blocked`.

## Commands

```bash
node tests/hosted/run.js inventory [--json]
node tests/hosted/run.js plan --target <descriptor> [--env-path <file>] [--interactive]
DWARPAL_HOSTED_CONFIRM_REF=<ref> node tests/hosted/run.js run --target <descriptor> --evidence-dir <new private dir> \
  [--env-path <file>] [--only <case ids, prefixes or procedures>] [--interactive]
DWARPAL_HOSTED_CONFIRM_REF=<ref> node tests/hosted/run.js cleanup --from <earlier evidence dir> --target <descriptor> \
  --evidence-dir <new private dir> [--env-path <file>]
node tests/hosted/run.js verify-evidence --evidence-dir <dir>
```

`plan` reports, offline, which cases the given inputs would gate and why. `--only` always keeps the target checks and cleanup. `--interactive` (on a terminal) enables the SMTP and Google cases, which prompt on stderr. Exit status: `0` passed, `1` failed or evidence leaked, `3` incomplete, `4` target or authorization refused (no network call), `2` usage, `70` internal.

## Evidence

A fresh, owner-only directory that must lie outside the public working tree or in a path the repository ignores:

| File | Content |
| --- | --- |
| `run.json` | source commit, tree and cleanliness; Node version; target ref and URL; authorization record id; authorized classes; capabilities; selection; migration file hashes |
| `calls.jsonl` | every outbound request: method, origin, sanitised path, status, duration |
| `observations.jsonl` | what each procedure observed; every assertion points at a line here |
| `cases.jsonl` | one normalised record per case |
| `summary.json` | verdict, counts, per-case status and reason, residue |
| `state/ledger.jsonl` | the residue ledger (below) |
| `manifest.json` | SHA-256 and size of every file, and the leak-scan result |

Every written value is sanitised ([`lib/redact.js`](lib/redact.js)): credentials, tokens, passwords, TOTP secrets, link tokens and auth codes are replaced as they appear; test addresses and user and factor ids become actor aliases; JWTs, Supabase keys, Management tokens, `otpauth` URIs, e-mail addresses and long hex runs are removed by shape. After the run every file is scanned again for registered secrets and refused shapes; a hit quarantines the file and fails the run. Raw response bodies are never kept. The `auth-kit` CLI runs as a child process with credentials in its environment only, and its output is sanitised the same way; its own requests are not in `calls.jsonl`.

## Residue and cleanup

Every run uses a fresh run id: client ids are `hv<run>-<letter>` and disposable addresses carry `hv<run>-<alias>`, so runs never share kit state except the fixed client `rls-demo` that the example policies name. Before anything is created, an intent line is written and flushed to `state/ledger.jsonl` (kinds, aliases, ids and fixed statement names only; no address, password or token). Cleanup runs last in every run and can be rerun from the ledger after a crash (`run.js cleanup --from`): it deletes the ledger's users (a user whose create answer was lost is found again by its regenerated address), revokes widened grants, drops fault triggers, deletes this run's notes with `cleanup_sql`, and counts what remains. Kit rows of the run's clients (clients, memberships, enrollments, events, request log) cannot be removed through any kit function, because enrollments and events are append-only by design; they are counted and reported as residue. Deleting a whole disposable project is the complete cleanup.

## Design-time failure analysis

- **Retries.** No write is retried blindly. Kit writes carry request ids, and every L30 retry is itself an assertion. A lost answer to a user creation is resolved by the ledger and the address sweep, never by creating again. Sign-ins and reads are the only calls retried, on 429 only, with a bounded wait; exhaustion is `blocked`.
- **Partial failure.** Each case runs in isolation: an exception blocks or fails that case alone (or, during a procedure's shared setup, that procedure's unreported cases) with a fixed reason and the sanitised error in the evidence. Catalog mutations are reverted in `finally` blocks and again by cleanup from the ledger.
- **Stale tokens and clocks.** Sessions are obtained inside the procedure that uses them; a session shared by several cases is renewed when it is within two minutes of its `exp`. Reuse is deliberate only where it is the subject (L25, and the S1-to-S2 model change read with the same tokens). L25 waits for the server-issued `exp` plus a margin and records the clock offset seen at sign-in; TOTP codes are never reused within one time step.
- **Concurrency.** Cases run sequentially except the deliberate concurrent ones (L27 joins, L29 applies, L35 claims). L35(d) starts the second runner only after the first runner's claim is committed, so the outcome is determined rather than timing-dependent. Two harness runs against one project do not share clients or users; they share only `rls-demo`, whose assertions count only the run's own rows.
- **Hostile but valid states.** Earlier runs' residue is excluded by run-scoped ids; an unreadable or group-readable env file, an env file inside a Git working tree, an existing evidence directory and an expired authorization refuse the run; an unexpected answer from Auth, PostgREST or the Management API fails or blocks the case with a fixed reason. None is treated as success.
- **Secret leakage.** Two layers (sanitise on write, scan every finished file) plus the network gate's origin allow-list, which also fences the library under test.

## Self-tests and rehearsal (not hosted evidence)

```bash
node --test tests/hosted/selftest/*.test.js
DWARPAL_PG_BIN=<postgres bin> node tests/sql/run.js tests/hosted/selftest/sql/probes.test.js tests/hosted/selftest/sql/rehearsal.test.js
```

The first suite needs no database and no network. The second runs on the throwaway PostgreSQL of `tests/sql`: `probes.test.js` executes the harness's own catalog and impersonation SQL against the real migration (every function and role against the design grant table, rollback of everything a probe did, refusal codes), and `rehearsal.test.js` runs every procedure, in order, against the server tests' synthetic Supabase stand-in bridged to that database, with hosted provenance off. The rehearsal requires every rehearsable case to reach its expected outcome while recording all of them `not_run` (`not_hosted`), and a sensitivity rehearsal shows that a widened grant and an Auth that forgets signed-out sessions fail the cases that must catch them. PostgREST, GoTrue, the Management API envelope, provider behavior and hosted timing are not part of either.

## Known limitations

- The first hosted run is also the first contact with the real Management API error envelope; the SQL probe channel is checked first (`T.management`) and blocks the dependent cases if the envelope differs.
- The harness runs the kit from this source tree, not from a packed tarball.
- `L32.email_two_matches` cannot normally be created on a hosted project (Auth keeps addresses unique); it is attempted and, when refused, recorded `not_run` with that reason.
- `doctor` redirect and registration checks run only when the descriptor names a consumer config (`doctor.configFile`).
- Browser-kit screens are not driven against the hosted project; the Google and SMTP cases use the Auth API with a human in the loop.
