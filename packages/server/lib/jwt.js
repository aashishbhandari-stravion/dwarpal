// Access-token verification (design 4.1 step 1). jose checks the signature
// against the project's JWKS and the registered claims; this module adds the
// Supabase-specific claims and maps every failure to one closed outcome:
// `expired`, `invalid_token` (the token is wrong) or `unavailable` (the key
// set could not be obtained or used). The JWKS public keys are the only state
// kept between requests; a key set that cannot be refreshed is never replaced
// by an older copy once jose considers it stale.

import { createRemoteJWKSet, jwtVerify, decodeProtectedHeader, customFetch } from 'jose';
import { AuthError } from '../../core/index.js';
import { UUID_PATTERN } from '../../core/shape.js';
import { request } from './http.js';

// Supabase asymmetric signing keys are ES256 or RS256. HS256 (the legacy
// shared secret) is refused outright: this library never holds that secret.
export const ALGORITHMS = Object.freeze(['ES256', 'RS256']);
const MAX_TOKEN_CHARS = 16 * 1024;
const MAX_JWKS_BYTES = 64 * 1024;
const TOKEN_PATTERN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

const INVALID = new Set([
  'ERR_JWT_CLAIM_VALIDATION_FAILED',
  'ERR_JWS_SIGNATURE_VERIFICATION_FAILED',
  'ERR_JWS_INVALID',
  'ERR_JWT_INVALID',
  'ERR_JOSE_ALG_NOT_ALLOWED',
  'ERR_JWKS_NO_MATCHING_KEY',
  'ERR_JWKS_MULTIPLE_MATCHING_KEYS',
]);

/**
 * @param {{ origin: string, fetch: typeof fetch, timers?: object, clockToleranceSeconds: number,
 *           now: () => number, jwksTimeoutMs: number, jwksCooldownMs?: number, jwksMaxAgeMs?: number }} options
 */
export function createVerifier(options) {
  const issuer = `${options.origin}/auth/v1`;
  // jose fetches through this wrapper so the key set response is size-bounded
  // and uses the injected fetch; jose's own timeout still applies.
  const boundedFetch = async (url, init) => {
    const response = await request(options.fetch, url, {
      method: 'GET',
      headers: Object.fromEntries(new Headers(init?.headers)),
      timeoutMs: options.jwksTimeoutMs,
      maxBytes: MAX_JWKS_BYTES,
      signal: init?.signal,
      timers: options.timers,
    });
    return new Response(response.text, { status: response.status });
  };
  const jwks = createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`), {
    timeoutDuration: options.jwksTimeoutMs,
    cooldownDuration: options.jwksCooldownMs ?? 30_000,
    cacheMaxAge: options.jwksMaxAgeMs ?? 600_000,
    [customFetch]: boundedFetch,
  });

  /**
   * @param {string} token
   * @returns {Promise<{ sub: string, sessionId: string, aal: 'aal1' | 'aal2', iat: number, exp: number }>}
   */
  return async function verify(token) {
    if (typeof token !== 'string' || token.length > MAX_TOKEN_CHARS || !TOKEN_PATTERN.test(token)) {
      throw new AuthError('invalid_token');
    }
    let header;
    try {
      header = decodeProtectedHeader(token);
    } catch {
      throw new AuthError('invalid_token');
    }
    if (!ALGORITHMS.includes(header.alg)) throw new AuthError('invalid_token');
    const nowMs = options.now();
    // jose refetches the key set for an unknown key id unless it fetched it
    // within the cooldown. A token whose key could not be looked up in a fresh
    // set (typically one signed just after a key rotation) was not judged:
    // unavailable, so the caller retries instead of signing the user out.
    const coolingDown = jwks.coolingDown;
    let payload;
    try {
      ({ payload } = await jwtVerify(token, jwks, {
        algorithms: [...ALGORITHMS],
        issuer,
        audience: 'authenticated',
        clockTolerance: options.clockToleranceSeconds,
        currentDate: new Date(nowMs),
        requiredClaims: ['exp', 'iat', 'sub'],
      }));
    } catch (error) {
      if (error?.code === 'ERR_JWKS_NO_MATCHING_KEY' && coolingDown) throw new AuthError('unavailable');
      throw mapJoseError(error);
    }
    return readClaims(payload, nowMs, options.clockToleranceSeconds);
  };
}

function mapJoseError(error) {
  if (error instanceof AuthError) return error;
  const code = typeof error?.code === 'string' ? error.code : '';
  if (code === 'ERR_JWT_EXPIRED') return new AuthError('expired');
  if (INVALID.has(code)) return new AuthError('invalid_token');
  // Key set timeout, a non-200 or unparseable key set, an unusable key, a
  // network fault: the token was not judged, so the answer is unavailable.
  return new AuthError('unavailable');
}

// Claims jose does not know about. A token that lacks any of them, or holds
// a value outside its closed set, is not a Supabase user session token.
function readClaims(payload, nowMs, toleranceSeconds) {
  const { sub, session_id: sessionId, aal, iat, exp, role, is_anonymous: anonymous } = payload;
  if (typeof sub !== 'string' || !UUID_PATTERN.test(sub)) throw new AuthError('invalid_token');
  if (role !== 'authenticated') throw new AuthError('invalid_token');
  if (anonymous !== false) throw new AuthError('invalid_token');
  if (typeof sessionId !== 'string' || sessionId === '' || sessionId.length > 128) throw new AuthError('invalid_token');
  if (aal !== 'aal1' && aal !== 'aal2') throw new AuthError('invalid_token');
  if (!Number.isSafeInteger(iat) || !Number.isSafeInteger(exp) || exp <= iat) throw new AuthError('invalid_token');
  // jose checks iat only as a number; a token issued in the future beyond the
  // tolerance comes from a skewed or forged issuer.
  if (iat > nowMs / 1000 + toleranceSeconds) throw new AuthError('invalid_token');
  return { sub: sub.toLowerCase(), sessionId, aal, iat, exp };
}
