// The post-sign-in pass (design 7): live Auth user check, MFA challenge when
// a factor is enrolled, ensure_profile, effective_access, join_client only
// while not enrolled, a reread, then the MFA-enrolment prompt for withheld
// roles. It returns one outcome and changes nothing in the page; the
// controller alone owns the view.
//
// Every step is safe to run again from the top. ensure_profile is an upsert,
// effective_access only reads, and join_client runs only while the durable
// enrollment is absent: a join that committed but whose answer was lost is
// seen as enrolled by the next pass and never sent again, and if it were,
// the server answers `already_enrolled` without writing (L4, L27). Nothing
// here retries on its own; a retry is always the user's explicit action.

import { AuthError } from '../../core/errors.js';
import { readAuthUser, principalFromAccess } from '../../server/lib/access.js';
import { authCall, callKitRpc, readAccessClaims, verifiedTotpFactors } from './answers.js';

const CONTINUE_JOIN = new Set(['enrolled', 'already_enrolled']);
const SETUP_PENDING_JOIN = new Set(['unknown_client', 'no_default_role']);

/**
 * @param {{ client: any, storage: any, config: any, now: () => number, mfaSkipped: boolean }} ctx
 * @param {(value?: unknown) => void} guard throws when the pass has been superseded
 */
export async function onboard(ctx, guard) {
  const read = await authCall(() => ctx.client.auth.getSession());
  guard();
  // A refresh that Auth refused leaves no usable session; a lost one may recover.
  if (read.failure) return read.failure.kind === 'api' ? { kind: 'session_ended' } : failureOutcome(read.failure);
  const session = read.data?.session ?? null;
  if (!session) return { kind: 'no_session' };

  let claims;
  try {
    claims = readAccessClaims(session.access_token);
  } catch {
    return { kind: 'unavailable' };
  }
  const token = session.access_token;

  // Live check: a session signed out elsewhere, banned or deleted ends here.
  const userRead = await authCall(() => ctx.client.auth.getUser(token));
  guard();
  if (userRead.failure) return failureOutcome(userRead.failure);
  const user = userRead.data?.user ?? null;
  let identity;
  let factors;
  try {
    identity = readAuthUser(user, claims.sub, ctx.now());
    factors = verifiedTotpFactors(user);
  } catch (error) {
    return error instanceof AuthError && error.code === 'invalid_token' ? { kind: 'session_ended' } : { kind: 'unavailable' };
  }

  // A recovery session may only set a new password (L13).
  if (ctx.storage.readRecovery() !== null) return { kind: 'recovery_pending' };

  if (claims.aal === 'aal1' && factors.length > 0) return { kind: 'mfa_challenge', factorId: factors[0] };

  const profile = await callKitRpc(ctx.client, 'ensure_profile', {}, token);
  guard();
  if (profile.kind !== 'value') return rpcFailure(profile);
  if (profile.value.user_id !== claims.sub) return { kind: 'unavailable' };

  const sessionInfo = {
    id: claims.sessionId,
    aal: claims.aal,
    issuedAt: new Date(claims.iat * 1000).toISOString(),
    expiresAt: new Date(claims.exp * 1000).toISOString(),
    checkedAt: new Date(ctx.now()).toISOString(),
  };
  const readAccess = async () => {
    const answer = await callKitRpc(ctx.client, 'effective_access', { client_id: ctx.config.clientId }, token);
    guard();
    if (answer.kind !== 'value') return { outcome: rpcFailure(answer) };
    try {
      return { principal: principalFromAccess(answer.value, { clientId: ctx.config.clientId, identity, session: sessionInfo }) };
    } catch {
      return { outcome: { kind: 'unavailable' } };
    }
  };

  let access = await readAccess();
  if (access.outcome) return access.outcome;

  if (access.principal.access.enrolledAt === null) {
    const join = await callKitRpc(ctx.client, 'join_client', { client_id: ctx.config.clientId }, token);
    guard();
    // An unknown outcome is transient setup, retried only by the user (L4).
    if (join.kind !== 'value') return join.kind === 'refusal' ? { kind: 'unavailable' } : { kind: 'setup_pending', reason: 'unavailable' };
    const result = join.value.result;
    if (SETUP_PENDING_JOIN.has(result)) return { kind: 'setup_pending', reason: result };
    if (result === 'closed') return { kind: 'no_access', principal: access.principal };
    if (result === 'email_unverified') return { kind: 'verify_email' };
    if (!CONTINUE_JOIN.has(result)) return { kind: 'unavailable' };
    access = await readAccess();
    if (access.outcome) return access.outcome;
    // The server said enrolled; a reread that disagrees is not trusted.
    if (access.principal.access.enrolledAt === null) return { kind: 'unavailable' };
  }

  const { principal } = access;
  // Enrolled but holding nothing (revoked, or nothing self-assignable was
  // left to grant): signed in, no access, and never re-granted by a join.
  if (principal.access.roles.length === 0) return { kind: 'no_access', principal };
  if (principal.access.mfaPending && factors.length === 0 && !ctx.mfaSkipped) return { kind: 'mfa_enrol', principal };
  return { kind: 'signed_in', principal };
}

export function failureOutcome(failure) {
  if (failure.kind === 'offline') return { kind: 'offline' };
  if (failure.kind === 'session_missing') return { kind: 'session_ended' };
  if (failure.kind === 'api' && (failure.status === 401 || failure.status === 403 || failure.status === 404)) return { kind: 'session_ended' };
  return { kind: 'unavailable' };
}

function rpcFailure(answer) {
  return answer.kind === 'failure' && answer.transport ? { kind: 'offline' } : { kind: 'unavailable' };
}
