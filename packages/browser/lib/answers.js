// Classifies what Auth and PostgREST answered, as seen through supabase-js,
// into a small closed set the controller decides on. Nothing here trusts the
// peer: an answer that is not exactly the expected shape is `unavailable`,
// never success, and no peer text is carried into a view or a log.

import { AuthError } from '../../core/errors.js';
import { UUID_PATTERN } from '../../core/shape.js';

const REFUSAL_CODE = /^[a-z_]{1,64}$/;
const AAL_LEVELS = new Set(['aal1', 'aal2']);

/**
 * An Auth call failure, from the `error` supabase-js returned or from
 * anything it threw.
 * @returns {{ kind: 'offline' } | { kind: 'unavailable' } | { kind: 'session_missing' } | { kind: 'api', status: number, code: string }}
 */
export function authFailure(error) {
  const name = error?.name;
  const status = typeof error?.status === 'number' ? error.status : null;
  if (name === 'AuthRetryableFetchError') return status === 0 ? { kind: 'offline' } : { kind: 'unavailable' };
  if (name === 'AuthSessionMissingError') return { kind: 'session_missing' };
  if ((name === 'AuthApiError' || name === 'AuthWeakPasswordError') && status !== null && status >= 400 && status < 500) {
    const code = typeof error.code === 'string' && REFUSAL_CODE.test(error.code) ? error.code : '';
    return { kind: 'api', status, code };
  }
  return { kind: 'unavailable' };
}

/**
 * Runs one supabase-js Auth call and returns `{ data }` or `{ failure }`.
 * A throw from supabase-js or from storage is a failure, never a success.
 */
export async function authCall(fn) {
  try {
    const result = await fn();
    if (result?.error) return { failure: authFailure(result.error) };
    return { data: result?.data ?? null };
  } catch (error) {
    return { failure: authFailure(error) };
  }
}

/**
 * One exposed `auth_kit` RPC, sent with the exact access token the caller
 * read, so every read of one onboarding pass speaks for the same session.
 *
 *   { kind: 'value', value }          2xx with a JSON object body
 *   { kind: 'refusal', code }         SQLSTATE DW001, the kit refused
 *   { kind: 'failure', transport }    anything else; `transport` when no HTTP answer arrived
 *
 * A failure never says whether a write committed.
 */
export async function callKitRpc(client, fn, args, accessToken) {
  let response;
  try {
    response = await client.schema('auth_kit').rpc(fn, args)
      .setHeader('Authorization', `Bearer ${accessToken}`)
      .retry(false);
  } catch {
    return { kind: 'failure', transport: true };
  }
  const { data, error, status } = response ?? {};
  if (status === 0) return { kind: 'failure', transport: true };
  if (error) {
    if (error.code === 'DW001' && typeof error.message === 'string' && REFUSAL_CODE.test(error.message)) {
      return { kind: 'refusal', code: error.message };
    }
    return { kind: 'failure', transport: false };
  }
  if (typeof status !== 'number' || status < 200 || status > 299) return { kind: 'failure', transport: false };
  if (data === null || typeof data !== 'object' || Array.isArray(data)) return { kind: 'failure', transport: false };
  return { kind: 'value', value: data };
}

/**
 * The claims the browser needs from its own access token: whose it is, which
 * Auth session, and the assurance level PostgREST will see. The token is not
 * verified here (the browser holds it; servers verify it); a malformed one
 * fails closed.
 */
export function readAccessClaims(token) {
  if (typeof token !== 'string') throw new AuthError('unavailable');
  const parts = token.split('.');
  if (parts.length !== 3) throw new AuthError('unavailable');
  let payload;
  try {
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '='));
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    throw new AuthError('unavailable');
  }
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) throw new AuthError('unavailable');
  const { sub, session_id: sessionId, aal, iat, exp } = payload;
  if (typeof sub !== 'string' || !UUID_PATTERN.test(sub)) throw new AuthError('unavailable');
  if (typeof sessionId !== 'string' || sessionId === '' || sessionId.length > 128) throw new AuthError('unavailable');
  if (!AAL_LEVELS.has(aal)) throw new AuthError('unavailable');
  if (!Number.isSafeInteger(iat) || !Number.isSafeInteger(exp) || exp <= iat) throw new AuthError('unavailable');
  return { sub: sub.toLowerCase(), sessionId, aal, iat, exp };
}

/** Verified TOTP factors from an Auth user record; a malformed list fails closed. */
export function verifiedTotpFactors(user) {
  const factors = user?.factors;
  if (factors === undefined || factors === null) return [];
  if (!Array.isArray(factors) || factors.length > 64) throw new AuthError('unavailable');
  const out = [];
  for (const factor of factors) {
    if (factor === null || typeof factor !== 'object') throw new AuthError('unavailable');
    if (factor.status === 'verified' && factor.factor_type === 'totp') {
      if (typeof factor.id !== 'string' || !UUID_PATTERN.test(factor.id)) throw new AuthError('unavailable');
      out.push(factor.id);
    }
  }
  return out;
}
