# Development Auth emulator

`packages/emulator` is a **development-only, synthetic** HTTP fixture. It serves
the part of the Supabase Auth API and the `auth_kit` PostgREST RPCs that the
dwarpal browser kit calls through `@supabase/supabase-js` **2.117.2**. It exists
so browser flows, retries and failures can be tested without a Supabase project.

Results against this fixture are **fixture evidence, not proof of hosted
Supabase behaviour**. The fixture never sends mail, never calls Google or a
TOTP provider, never makes an outbound request and never mutates a hosted
project. Hosted behaviour is verified separately.

## Starting it

```js
import { startAuthEmulator } from './packages/emulator/index.js';

const emulator = await startAuthEmulator();          // http://127.0.0.1:<ephemeral port>
const { origin, publishableKey, controls } = emulator;
// ... point supabase-js (or a browser config) at origin with publishableKey ...
await emulator.close();                               // awaitable, idempotent
```

| Option | Default | Rule |
| --- | --- | --- |
| `host` | `'127.0.0.1'` | `'127.0.0.1'` or `'::1'` only |
| `port` | `0` (ephemeral) | integer 0–65535 |
| `now` | real time at start | initial fixture clock (epoch ms); the clock then moves **only** through `advanceTime` |
| `accessTokenTtlSeconds` | `3600` | 60–86400 |
| `linkTtlSeconds` | `3600` | lifetime of email and recovery links, 1–86400 |
| `siteUrl` | the fixture origin | loopback URL used when an OAuth `redirect_to` is not a loopback URL |
| `log` | none | receives `{ method, route, operation?, status, fault? }` per request: fixed names only, never bodies, tokens, addresses or query values |

`publishableKey` is a fresh synthetic `sb_publishable_fixture_…` key per
instance. It passes core `validateClientConfig`, and it is the only `apikey` the
fixture accepts. `close()` closes only this instance's listener and its own
connections. The fixture keeps no global state, starts no timers and holds a
separate ES256 signing key per instance.

## Transport and gateway rules

- The fixture binds a loopback address only. Every request must carry a `Host`
  of `127.0.0.1:<port>`, `localhost:<port>` or `[::1]:<port>`; anything else
  gets 421, which guards against DNS rebinding.
- CORS allows loopback page origins only, with the headers supabase-js sends. A
  request carrying any other `Origin` gets 403.
- Every route except `GET /auth/v1/authorize` and the JWKS needs
  `apikey: <publishableKey>`. A missing key gets 401 `No API key found in
  request`; a wrong key gets 401 `Invalid API key`.
- **Operator credentials are refused** with 401, in the `apikey` header or as
  a bearer token: `sb_secret_…` keys, `sbp_…` Management tokens, and any token
  whose `role` claim is neither `authenticated` nor `anon`.
- Bounds: request bodies are limited to 64 KiB (413), URLs to 8 KiB (414) and
  headers to 16 KiB. Only JSON bodies are accepted (415 otherwise); malformed
  JSON gets 400. Emails are limited to 254 characters and passwords to 6–72
  bytes. User metadata is limited to 4 KiB.
- There is **no control, admin or snapshot endpoint over HTTP**. Tests drive the
  fixture through `controls` in process.

## Auth routes (`/auth/v1`)

Auth answers carry `x-supabase-api-version: 2024-01-01`. Errors use the body
`{ code, message }`, which auth-js 2.117.2 reads for its error codes.

| Route | Fault operation | Behaviour |
| --- | --- | --- |
| `GET /.well-known/jwks.json` | – | This instance's ES256 public key. Access tokens verify against it with issuer `<origin>/auth/v1` and audience `authenticated`. |
| `GET /settings` | – | Email and Google enabled; confirmations required (no autoconfirm). |
| `POST /signup` | `signup` | New address: creates an unconfirmed user and counts one mail; the answer has a user and no session. An address that is already confirmed gets a neutral user-shaped answer with a fresh id and `identities: []`, and nothing is written or sent (L1, as hosted). An unconfirmed address gets the confirmation mail again. A mail supersedes the previous email link. |
| `POST /resend` (`type: 'signup'`) | – | Always `{}`. Counts a mail and supersedes the previous link only for an unconfirmed address. |
| `POST /token?grant_type=password` | `password_sign_in` | 400 `invalid_credentials` for an unknown address or a wrong password (the same answer); 400 `email_not_confirmed` for an unconfirmed address. Otherwise an `aal1` session with `amr` `password`. |
| `POST /recover` | `recovery_request` | Always `{}`; for a known address, counts a mail and supersedes the previous recovery link. |
| `POST /verify` with `token_hash` | `verify_email` (`email`/`signup`/`magiclink`), `verify_recovery` (`recovery`) | Consumes a link from `issueLink`. A link can be used once; a superseded, expired, used or wrong-type link gets 403 `otp_expired`. Success confirms the address and returns an `aal1` session (`amr` `otp` or `recovery`). Six-digit `token` verification is not emulated (400). |
| `GET /authorize?provider=google` | – | Synthetic consent. PKCE with S256 is required (400 otherwise; the implicit flow is not emulated). Redirects (303) to `redirect_to` when it is a loopback URL, else to `siteUrl`, keeping its query (including supabase-js `sb_flow_id`) and adding `code`. The code is bound to the challenge and expires after 5 minutes. With no `setOAuthAccount` it redirects with `error=access_denied` and creates nothing. An existing address gains the `google` identity and is confirmed; a new one is created confirmed. |
| `POST /token?grant_type=pkce` | `oauth_exchange` | 404 `flow_state_not_found` (unknown or used code); 400 `flow_state_expired`; 403 `bad_code_verifier` (the flow stays usable by its own verifier). Success consumes the code and returns an `aal1` session (`amr` `oauth`). |
| `POST /token?grant_type=refresh_token` | – | Rotates the refresh token. A used token gets 400 `refresh_token_already_used`; an unknown token or a revoked session gets 400 `refresh_token_not_found`. The access token keeps the session's current `aal`. |
| `GET /user` | – | Needs a valid, unexpired access token of a live session: 401 `no_authorization`, 403 `bad_jwt` or 403 `session_not_found` otherwise. |
| `PUT /user` | `update_password` | Updates `password` and/or `data` only: 422 `same_password`, 422 `weak_password` (`reasons: ['length']`), 422 `validation_failed` for more than 72 bytes. Other attributes get 400. |
| `POST /logout?scope=global\|local\|others` | `global_sign_out` | Revokes the user's sessions for that scope (global by default) and answers 204. Revoked sessions fail `GET /user` and refresh. |
| `POST /factors` | `mfa_enroll` | TOTP only. Returns `{ id, type, friendly_name, totp: { qr_code, secret, uri } }`; `qr_code` is a synthetic placeholder SVG. Refusals: 422 `mfa_factor_name_conflict`; 403 `insufficient_aal` when a verified factor exists and the session is `aal1`; 422 `too_many_enrolled_mfa_factors` beyond 10. |
| `POST /factors/:id/challenge` | – | 404 `mfa_factor_not_found` for another user's or an unknown factor. A challenge lasts 5 minutes. |
| `POST /factors/:id/verify` | `mfa_verify` | RFC 6238 TOTP (SHA-1, 30 s, 6 digits, ±1 step) at the fixture clock. 422 `mfa_verification_failed` for a wrong code (the challenge stays); 422 `mfa_challenge_expired` for an expired, used or foreign challenge. Success verifies the factor, raises the session to `aal2` (`amr` starts with `totp`) and returns new tokens. |

Access tokens are ES256 JWTs. Their claims are `aud`, `exp`, `iat`, `iss`,
`sub`, `email`, `phone`, `app_metadata`, `user_metadata`, `role:
authenticated`, `aal`, `amr`, `session_id` and `is_anonymous`. Expiry and link,
flow and challenge lifetimes all use the fixture clock. supabase-js compares
`expires_at` with the real clock, so after a large `advanceTime` a stored token
can look valid to the client while the fixture treats it as expired.

## PostgREST RPC (`/rest/v1/rpc/<fn>`, schema `auth_kit`)

Results, argument names, order of checks and refusals follow
`supabase/migrations/20260927000000_dwarpal_auth_kit.sql`.

| Function | Fault operation | Behaviour |
| --- | --- | --- |
| `ensure_profile()` | `ensure_profile` | Upserts the caller's profile; `{ user_id, display_name, contact_email, contact_phone, updated_at }`. |
| `effective_access(client_id)` | `effective_access` | Read-only; also answers GET. `{ client_id, enrolled_at, memberships[{ role_key, flags, granted_at, granted_via, permissions }], active_roles, permissions, mfa_pending }` for the requested client only. A role is active when it is not `mfa_required` or the token's `aal` claim is exactly `aal2`. |
| `join_client(client_id)` | `join_client` | In SQL order: `email_unverified` (read from the user record, never the token), `unknown_client`, `already_enrolled` (+`enrolled_at`; nothing written or re-granted, whatever memberships exist now), `closed`, `no_default_role` (nothing written), otherwise `enrolled` (+`enrolled_at`, `granted_roles`). An enrollment row, one membership and one `join` event are written per self-assignable role not already held. There is no request id and no request log row. |
| `grant_membership(user_id, client_id, role_key, request_id)` | `grant_membership` | Request-id check first: the stored result for the same fingerprint, `request_conflict` for another. The fingerprint is core `requestFingerprint`, so it includes the actor. Then, in order: manager authority (`forbidden`/`mfa_required`), `unknown_role`, `forbidden` for a manager role, `unknown_user`, `email_unverified`, `forbidden` for self. The outcome is `granted` or `already_member`, with one event only if something changed and a request log row either way. |
| `revoke_membership(...)` | `revoke_membership` | Same authority and role checks; `revoked` or `not_member`. |

Wire rules:

- A kit refusal is HTTP 400 with `{ code: 'DW001', message: <refusal>, details: null, hint: null }`.
- Type errors are PostgreSQL errors, never DW001: 22P02 for a bad uuid, 22P05 for NUL, 22P02 for an unpaired surrogate.
- A call without `Content-Profile: auth_kit` (or `Accept-Profile` for GET) resolves in `public` and gets 404 `PGRST202`. `auth_kit_private` or any other unexposed schema gets 406 `PGRST106`.
- Operator wrappers (`register_client`, `apply_model`, `bootstrap_manager`, …) get `42501`: 401 for anon, 403 for authenticated. Unknown functions and wrong argument names get 404 `PGRST202`. A volatile function called with GET gets 405. `has_permission`, `has_role` and `has_aal2` are not emulated (404).
- Anon callers (no token, or the publishable key as bearer) get 401 `42501` from the user wrappers.
- A bad or foreign signature gets 401 `PGRST301`; an expired token gets 401 `PGRST303`. As in hosted PostgREST, the Auth session is **not** checked, so a signed-out user's unexpired token still reaches the RPCs (L25b).

Each request's state change runs synchronously after its body is read and its
fingerprint is hashed. Concurrent calls therefore serialise the way the SQL
per-client lock serialises them: concurrent first joins give one enrollment,
and concurrent grants with one request id give one event.

## Controls

The first seven controls are the frozen shared contract. The last three are
documented additions for frozen cases.

| Control | Contract |
| --- | --- |
| `seedClient({ clientId, signupPolicy, model, state?, managerUserId?, managerRoleKey?, displayName? })` | The model is validated by core `validateModel(model, { clientId })` and throws core `AuthError('model_invalid')`. `model: null` is allowed for a `registered` client only (join before model → `no_default_role`). A `live` seed must name a previously seeded, confirmed user and a model role with `manages_members`. That writes an operator membership and one `bootstrap` event, as `bootstrap_manager` would. A registered seed may not name a manager. Duplicate client ids are refused. |
| `seedUser({ email, password, confirmed = true, aal = 'aal1' })` | Returns `{ userId }`. `aal: 'aal2'` seeds a verified TOTP factor and also returns `factorId`: password sessions start at `aal1` (next level `aal2`) and are raised by challenge/verify. No shortcut mints `aal2`. Passwords are held only as scrypt hashes. |
| `issueLink({ type: 'email' \| 'recovery', email })` | Returns `{ tokenHash }` (56 hex characters) and supersedes the previous link of that type. Issuing, prefetching or any GET never consumes a link; only a successful `POST /verify` does. |
| `setMembership({ userId, clientId, roleKey, present })` | A direct fixture edit that returns `{ changed }`. It never touches the enrollment ledger, writes no event or request log row and resets no counter. Added rows have `granted_via: 'operator'`. |
| `setFault({ operation, mode })` | One-shot; replaces a pending fault for the same operation. The operations are listed in the tables above. Modes: `http_503` (503, nothing applied); `transport_loss` (connection dropped before any work); `lost_after_commit` (the request is fully applied, then the connection is dropped instead of answering; refused for the read-only `effective_access`); `failed_before_commit` (addition: 500 with `XX000` for RPCs or `unexpected_failure` for Auth, nothing written; for the L27 injected-failure case). Unknown operations or modes throw. |
| `advanceTime(ms)` | Adds a finite nonnegative duration to the fixture clock. |
| `snapshot()` | A detached, secret-free object with `synthetic: true`, the fixture time, counts (users, profiles, enrollments, memberships, events, request log, active sessions, mails, links issued and used), users (`userId`, `email`, `confirmed`, `providers`, factor ids and status), profiles, and per client its roles, enrollments, memberships, events and request-log outcomes. It also holds HTTP request counts per operation or route (`httpRequests`) and pending faults. It never contains passwords, link hashes, access or refresh tokens, factor secrets, codes or request bodies. |
| `totpCode({ factorId })` | Addition: the current TOTP code of a factor at the fixture clock. |
| `setOAuthAccount({ email } \| null)` | Addition: the account the synthetic Google consent signs in; `null` (the default) denies consent. |
| `setEmailConfirmed({ userId, confirmed })` | Addition: clears or restores the Auth record's confirmation while sessions stay valid. This is the only way to reach the `email_unverified` join outcome, which reads `auth.users` rather than the token. |

## Not emulated

- Rate limits and CAPTCHA.
- Real email, six-digit email OTP, magic-link GET verification and phone.
- Anonymous users; identity linking beyond the Google auto-link; admin and
  Management APIs.
- Refresh-token reuse intervals and session-family revocation.
- Other sessions being signed out on a password change.
- Unenrolling a factor; recovery codes; WebAuthn.
- The RLS helper RPCs.
- Any hosted routing, SMTP, Google or TOTP provider behaviour.
