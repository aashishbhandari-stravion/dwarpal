# Protected consumer (example)

A minimal Node endpoint that protects its data with `@briqvent/dwarpal`. It is a sample to copy from, not part of the package, and it knows nothing about any particular application: the roles and keys are in [`auth-model.json`](auth-model.json).

What it shows:

- **Every request is authenticated live.** `auth.resolveSession(req)` checks the token's signature and time claims, asks Supabase Auth whether the session still exists, and reads this client's access afresh. A signed-out token gets `401` on the very next request. Nothing is cached between requests, and responses carry `Cache-Control: no-store`.
- **The own/any guard with the consumer's own links.** `records:read:any` needs an *active* role. Without it, `records:read:own` is required and the record must be linked to the caller in this application's own SQLite table (`record_links`, with the linking staff member and time, and an append-only `link_events` table). The kit stores none of this; it is keyed by `identity.userId` only. A caller without the broad key cannot tell an absent record from one that is not theirs.
- **Idempotent, audited links.** `PUT`/`DELETE /records/:id/links/:userId` need `records:link:any`; repeating a request changes nothing and writes no second event.
- **Manager grants with request ids.** `PUT`/`DELETE /members/:userId/roles/:role` forward to `auth.grantMembership` / `revokeMembership` under the caller's own token; the `Idempotency-Key` header is the request id, so a retry returns the stored result and a reused key with another payload is `409 request_conflict`.
- **Fail closed.** If Supabase cannot be reached, or the SQLite file is unreadable, locked past the busy timeout, or closed, the answer is `503 { "error": "unavailable" }`: never a guessed grant or denial, and a failed write leaves nothing behind. A store that cannot be opened stops the server from starting.
- **Routes.** `GET /records`, `GET /records/:id`, `GET /health`. Answers are fixed JSON; tokens, ids you sent and provider text are never echoed. When a broader role is held but withheld for lack of MFA, a `403` names it (`"withheld": ["staff"]`) so a page can offer MFA.

## Run it

It needs Node 22.13 or later (24 recommended) for the built-in `node:sqlite`, which is still marked experimental in Node.

```sh
npm install ./briqvent-dwarpal-0.0.0.tgz
SUPABASE_URL=https://<ref>.supabase.co SUPABASE_PUBLISHABLE_KEY=sb_publishable_... \
CLIENT_ID=protected-demo DATA_FILE=./records.sqlite node server.js
```

The server holds only the publishable key. Apply the model with the operator CLI (`auth-kit register-client --client protected-demo ...`, `apply-model --model auth-model.json`, `bootstrap-manager`); see the manual. Records are your data: seed them with `store.createRecord`.

## How it is checked

`tests/examples/protected-consumer.test.js` runs this code against the real `createAuthServer` and the synthetic loopback Auth/RPC fixture: the literal own/any sequence for a customer who also holds an MFA-required staff role (at `aal1`, then `aal2`), sign-out revocation, request-id replay and conflict, idempotent links, a lock held by another connection, a closed and an unopenable store, and an unavailable Supabase. `npm run test:examples-built` also runs it against the installed tarball. This is fixture evidence, not hosted Supabase proof.
