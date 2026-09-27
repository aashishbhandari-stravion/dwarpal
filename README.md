# dwarpal

Authentication and role-based access kit for sites that use Supabase Auth. Package name: `@briqvent/dwarpal`.

**Status: under development, not published.** This repository currently contains only the pure core (contract `0.5`). The SQL migrations, server library, browser kit, emulator, CLI and examples are not here yet, and nothing in this README describes them as available.

## What the core provides

The core has no network, database, storage or framework code. It runs on Node 22+ and in browsers.

- Contract: `AUTH_CONTRACT_VERSION === '0.5'` and the types `Identity`, `Membership`, `Access`, `Principal` and `Profile` (`packages/core/index.d.ts`).
- Evaluation over a resolved principal: `can`, `canAll`, `canAny`, `explain`, `requirePermission`, `requireRole`, `requireMfa`. A role counts only when it is *active*: it does not require MFA, or the session is `aal2`. Permissions are the union over active roles. `access.roles` is display data and never grants anything. Unknown keys and empty key lists are never granted.
- `createPrincipal(snapshot)`: builds a frozen principal from one access snapshot for one client. Malformed or cross-client input fails with `AuthError('unavailable')`.
- `validateModel`, `canonicalModelJson`, `modelHash` and `planModelChange` for the permission model file. `planModelChange` compares two models and refuses these changes: removing a role that users hold, giving `manages_members` to a role that already has holders, and leaving a live client without an assigned manager.
- `validateClientConfig`: validates the per-client configuration. It refuses secret keys and legacy `service_role` keys in place of a publishable key.
- `resolveReturnPath(next, config)`: validates a return path against the configured origin and an exact allow-list. Anything else falls back to the default path.
- `canonicalJson`, `sha256Hex` and `requestFingerprint`: canonical JSON and request fingerprints for idempotent commands.
- `AuthError`, with a closed set of codes (`AUTH_ERROR_CODES`). Messages are fixed per code and never include input values.

### Example guard

```js
import { AuthError, can, requirePermission } from '@briqvent/dwarpal';

function readRecord(principal, record) {
  if (!can(principal, 'records:read:any')) {
    requirePermission(principal, 'records:read:own'); // throws forbidden or mfa_required
    if (record.ownerId !== principal.identity.userId) throw new AuthError('forbidden');
  }
  return record;
}
```

`own` refers to the row being acted on. When the narrow scope is "the principal is the target", use a `:self` key and compare the target with `principal.identity.userId`.

### `explain` provenance

`explain(principal, key)` returns `{ allowed, via, withheld }`. The role names come from the optional `Membership.permissions` field, which `createPrincipal` fills from the same snapshot. `allowed` is decided only by `access.permissions`. If a membership lacks the field, its role is not named, and `requirePermission` then reports `forbidden` instead of guessing `mfa_required`.

## Testing entry point

`@briqvent/dwarpal/testing` exports a synthetic, deeply frozen fixture so consumers can test their guards against the same principals the kit tests with: `FIXTURE_MODEL`, `FIXTURE_CLIENT_ID`, `FIXTURE_USER_IDS`, `fixturePrincipals` (per role and MFA state) and `fixturePrincipal({ roles, aal })`, which returns a fresh principal on each call. All users, clients and addresses in the fixture are synthetic.

## Development

Requires Node 22 or later and npm.

```sh
npm ci
npm test              # node --test over tests/core
npm run check:types   # tsc against the published declarations
npm run check:package # npm pack, install the tarball in a temporary consumer, compare exports and declarations
npm run check         # all of the above
```

TypeScript (`typescript`, pinned) is the only development dependency. The package has no runtime dependencies.

## Licence

MIT, see [LICENSE](LICENSE).
