// The closed set of screen error codes and the tables that map Auth's error
// codes onto them per operation. Unknown Auth codes map to `unavailable`, so a
// new or unexpected answer is never shown as a success or as a misleading
// specific reason. `sent` marks the neutral outcomes that must look exactly
// like success, so an address's existence is never revealed (L1).

export const BROWSER_ERROR_CODES = Object.freeze([
  'invalid_input',
  'invalid_credentials',
  'email_unverified',
  'weak_password',
  'same_password',
  'rate_limited',
  'mfa_invalid_code',
  'provider_unavailable',
  'method_disabled',
  'session_ended',
  'unavailable',
]);

const TABLES = Object.freeze({
  signIn: {
    // Older Auth answers a failed password sign-in with 400 and no code.
    '': 'invalid_credentials',
    invalid_credentials: 'invalid_credentials',
    user_banned: 'invalid_credentials',
    email_not_confirmed: 'email_unverified',
    validation_failed: 'invalid_input',
    email_address_invalid: 'invalid_input',
    email_provider_disabled: 'method_disabled',
  },
  signUp: {
    user_already_exists: 'sent',
    email_exists: 'sent',
    weak_password: 'weak_password',
    signup_disabled: 'method_disabled',
    email_provider_disabled: 'method_disabled',
    validation_failed: 'invalid_input',
    email_address_invalid: 'invalid_input',
    email_address_not_authorized: 'invalid_input',
  },
  recovery: {
    user_not_found: 'sent',
    validation_failed: 'invalid_input',
    email_address_invalid: 'invalid_input',
  },
  password: {
    weak_password: 'weak_password',
    same_password: 'same_password',
    validation_failed: 'invalid_input',
  },
  mfa: {
    mfa_verification_failed: 'mfa_invalid_code',
    mfa_verification_rejected: 'mfa_invalid_code',
    mfa_challenge_expired: 'mfa_invalid_code',
    mfa_totp_enroll_not_enabled: 'method_disabled',
    mfa_totp_verify_not_enabled: 'method_disabled',
  },
});

/**
 * @param {'signIn' | 'signUp' | 'recovery' | 'password' | 'mfa'} table
 * @param {{ kind: string, status?: number, code?: string }} failure from answers.authFailure
 * @returns {string} a BROWSER_ERROR_CODES member, or 'sent'
 */
export function authErrorCode(table, failure) {
  if (failure.kind !== 'api') return 'unavailable';
  if (failure.status === 429 || failure.code.startsWith('over_')) return 'rate_limited';
  if (table === 'signIn' && failure.code === '' && failure.status !== 400) return 'unavailable';
  return Object.hasOwn(TABLES[table], failure.code) ? TABLES[table][failure.code] : 'unavailable';
}

/**
 * Auth's refusal of an e-mail or recovery token hash: expired, already used,
 * unknown or malformed all look alike (4xx). Rate limiting is not a refusal.
 */
export function linkRejected(failure) {
  return failure.kind === 'api' && failure.status >= 400 && failure.status < 500 && failure.status !== 429;
}
