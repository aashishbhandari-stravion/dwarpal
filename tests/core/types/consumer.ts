// Compile-only consumer check of the published declarations. Imports go
// through the package name, so the `exports` map and its `types` conditions
// are exercised as a consumer would see them.

import {
  AUTH_CONTRACT_VERSION,
  AuthError,
  can,
  canAll,
  explain,
  requirePermission,
  requireRole,
  requireMfa,
  resolveReturnPath,
  validateClientConfig,
  validateModel,
  planModelChange,
  requestFingerprint,
  type Principal,
  type Explanation,
  type AuthErrorCode,
} from '@briqvent/dwarpal';
import { fixturePrincipals, fixturePrincipal, FIXTURE_MODEL } from '@briqvent/dwarpal/testing';

const version: '0.5' = AUTH_CONTRACT_VERSION;

function guard(principal: Principal, ownerId: string): void {
  if (!can(principal, 'records:read:any')) {
    requirePermission(principal, 'records:read:own');
    if (ownerId !== principal.identity.userId) throw new AuthError('forbidden');
  }
}

guard(fixturePrincipals.patron, fixturePrincipals.patron.identity.userId);
const why: Explanation = explain(fixturePrincipals.patronClerkAal1, 'records:read:any');
const withheldRole: string | undefined = why.withheld[0]?.role;
const all: boolean = canAll(fixturePrincipals.clerkAal2, ['records:read:any', 'records:update:any']);
const same: Principal = requireRole(fixturePrincipal({ roles: ['coordinator'] }), ['coordinator']);
requireMfa(fixturePrincipals.leadAal2);

const config = validateClientConfig({});
const next: string = resolveReturnPath('/x', config);
const flag: boolean = validateModel(FIXTURE_MODEL).roles['lead']!.manages_members;
const plan = planModelChange(FIXTURE_MODEL, FIXTURE_MODEL, { state: 'live' });
const refused: boolean = plan.refusals.length > 0;
const fingerprint: Promise<string> = requestFingerprint({ operation: 'op', clientId: null, actorId: 'operator', payload: {} });

let code: AuthErrorCode = 'forbidden';
// @ts-expect-error codes outside the closed set are rejected at compile time
code = 'not_a_code';
// @ts-expect-error AuthError takes a known code
new AuthError('teapot');
// @ts-expect-error model state is closed
planModelChange(null, FIXTURE_MODEL, { state: 'archived' });
// @ts-expect-error the fixture principals are read-only records
fixturePrincipals.patron = fixturePrincipals.clerkAal1;

export { version, withheldRole, all, same, next, flag, refused, fingerprint, code };
