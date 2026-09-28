// Compile-only consumer of the server declarations, checked against the
// source (tsconfig.json) and against the packed artifact (check-package).
// Imports use the package name so both checks resolve through `exports`.

import { Hono } from 'hono';
import { createAuthServer, requirePermission, can, explain, AuthError, isAuthError, AUTH_CONTRACT_VERSION } from '@briqvent/dwarpal/server';
import type { Principal, AuthServer, MembershipChange } from '@briqvent/dwarpal/server';
import { honoMiddleware } from '@briqvent/dwarpal/server/hono';
import { createOperatorClient, OperatorError, isOperatorError } from '@briqvent/dwarpal/server/operator';
import type { OperatorErrorCode, DoctorReport, MfaResetOutcome } from '@briqvent/dwarpal/server/operator';

const version: '0.5' = AUTH_CONTRACT_VERSION;

const auth: AuthServer = createAuthServer({ supabaseUrl: 'https://abc.supabase.co', publishableKey: 'sb_publishable_x', clientId: 'example' });

export async function handler(request: Request, authorId: string): Promise<Response> {
  let principal: Principal | null;
  try {
    principal = await auth.resolveSession(request);
  } catch (error) {
    if (isAuthError(error) && error.code === 'unavailable') return new Response(null, { status: 503 });
    return new Response(null, { status: 401 });
  }
  if (principal === null) return new Response(null, { status: 401 });
  if (!can(principal, 'posts:edit:any')) {
    try {
      requirePermission(principal, 'posts:edit:own');
    } catch (error) {
      if (error instanceof AuthError) return Response.json({ error: error.code, why: explain(principal, 'posts:edit:any') }, { status: 403 });
      throw error;
    }
    if (authorId !== principal.identity.userId) return new Response(null, { status: 403 });
  }
  const change: MembershipChange<'granted' | 'already_member'> = await auth.grantMembership(authorId, 'editor', crypto.randomUUID(), request);
  return Response.json({ result: change.result, version });
}

const app = new Hono<{ Variables: { principal: Principal } }>();
app.use('/api/*', honoMiddleware(auth));
app.get('/api/me', (c) => c.json({ user: c.var.principal.identity.userId }));

export async function operate(): Promise<void> {
  const operator = createOperatorClient({ supabaseUrl: 'https://abc.supabase.co', secretKey: 'sb_secret_x', management: { token: null } });
  try {
    const reset: MfaResetOutcome = await operator.mfaReset({ userId: crypto.randomUUID(), requestId: crypto.randomUUID() });
    const deleted: readonly string[] = reset.factorsDeleted;
    const report: DoctorReport = await operator.doctor({ clientId: 'example' });
    void deleted;
    void report.checks.filter((c) => c.status === 'not_run');
  } catch (error) {
    if (isOperatorError(error)) {
      const code: OperatorErrorCode = error.code;
      void code;
    }
    if (error instanceof OperatorError && error.code === 'lease_expired') return;
  }
}

// @ts-expect-error the consumer AuthError set does not include operator codes
new AuthError('lease_expired');
// @ts-expect-error a manager write needs the request that carries the manager's token
void auth.grantMembership('u', 'r', 'id');
