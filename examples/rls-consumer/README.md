# RLS consumer (example)

One consumer table (`app.notes`) protected by Row Level Security policies that call the kit's real helpers, `auth_kit.has_permission(client_id, key)` (and `has_role`, `has_aal2`). [`policies.sql`](policies.sql) is the file to adapt; [`auth-model.json`](auth-model.json) is a model that gives its keys to `manager`, `staff` and `member` roles.

Read [`policies.sql`](policies.sql)'s header before using the pattern. In short:

- The helpers read the caller's memberships **live**, so a membership revoke or a model change is effective on the next query, with the same token.
- A role that requires MFA counts only when the JWT's `aal` is `aal2`.
- PostgREST checks the token's signature and expiry, and **nothing here asks Supabase Auth whether the session still exists**. A user who signed out or was banned keeps access on this path until the access token expires. Put only data behind these policies that such a user may keep seeing for up to one token lifetime; anything more sensitive belongs on a Node endpoint that calls `resolveSession` (see `examples/protected-consumer`).
- Ownership (`owner_id = auth.uid()`) is the table's own rule; the kit only answers "may this user act on `notes` of this kind".
- `anon` has no grant. `auth_kit_private` must never be added to the project's exposed schemas.

## How it is checked

`tests/examples/sql/rls-consumer.test.js` applies `policies.sql` unchanged to the real migration on a disposable PostgreSQL and impersonates database roles with JWT claims the way PostgREST does: a member sees only their own rows; a customer who also holds an MFA-required staff role sees their own row at `aal1` and every row at `aal2`; a user of another client sees nothing; forged `app_metadata` grants nothing; writes follow the same keys (forged owners and moved rows are refused); and a revoke changes the answer on the next query. Run it with `DWARPAL_PG_BIN=<postgres bin dir> npm run test:examples-sql`.

This is SQL evidence only. PostgREST routing, JWT verification and the JWT-expiry bound on revocation are hosted checks that have not been run.
