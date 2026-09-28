// Credential and endpoint checks shared by the session server and the
// operator client. The publishable-key rule is core's: the check runs core's
// own config validator over a minimal config and keeps only the issues for
// the fields this package supplies, so there is one implementation of "is
// this a browser-safe key". A secret key must never reach createAuthServer,
// and a publishable key never authorises operator calls.

import { validateClientConfig, isAuthError } from '../../core/index.js';

const KEY_BODY_PATTERN = /^[A-Za-z0-9_.-]{1,2048}$/;
const SECRET_PREFIX = 'sb_secret_';
const SERVER_FIELDS = new Set(['clientId', 'supabaseUrl', 'publishableKey']);

/**
 * Issues (path and rule only) for the three fields the session server takes.
 * @returns {{ path: string, rule: string }[]}
 */
export function serverConfigIssues({ clientId, supabaseUrl, publishableKey }) {
  try {
    validateClientConfig({
      clientId,
      supabaseUrl,
      publishableKey,
      origin: 'https://placeholder.invalid',
      allowedReturnPaths: ['/'],
      defaultReturnPath: '/',
      providers: { email: true, google: false },
      selfSignup: false,
    });
    return [];
  } catch (error) {
    if (!isAuthError(error)) throw error;
    return error.issues.filter((issue) => SERVER_FIELDS.has(issue.path.split(/[.[#]/)[0]));
  }
}

/** The origin of a Supabase project URL, or null when it is not a bare https (or loopback http) origin. */
export function projectOrigin(value) {
  const issues = serverConfigIssues({ clientId: 'x', supabaseUrl: value, publishableKey: 'sb_publishable_x' });
  return issues.length === 0 ? new URL(value).origin : null;
}

/**
 * Classifies an operator credential without echoing it.
 * @returns {'secret' | 'legacy_service_role' | null}
 */
export function secretKeyKind(value) {
  if (typeof value !== 'string' || !KEY_BODY_PATTERN.test(value)) return null;
  if (value.startsWith(SECRET_PREFIX) && value.length > SECRET_PREFIX.length) return 'secret';
  return legacyJwtRole(value) === 'service_role' ? 'legacy_service_role' : null;
}

function legacyJwtRole(value) {
  const parts = value.split('.');
  if (parts.length !== 3 || parts.some((part) => part === '')) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    return payload !== null && typeof payload === 'object' && typeof payload.role === 'string' ? payload.role : null;
  } catch {
    return null;
  }
}
