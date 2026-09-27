// Closed error taxonomy of contract 0.5. Messages are fixed per code and never
// carry caller data, so an error can be logged or returned without echoing
// tokens, keys, e-mail addresses or attacker-controlled strings.

export const AUTH_ERROR_CODES = Object.freeze([
  'no_token',
  'invalid_token',
  'expired',
  'email_unverified',
  'mfa_required',
  'forbidden',
  'unavailable',
  'provider_unavailable',
  'config_invalid',
  'model_invalid',
  'request_conflict',
]);

const MESSAGES = Object.freeze({
  no_token: 'No session token was supplied.',
  invalid_token: 'The session token is not valid.',
  expired: 'The session has expired.',
  email_unverified: 'The e-mail address has not been verified.',
  mfa_required: 'This action needs a multi-factor authenticated session.',
  forbidden: 'The principal is not allowed to perform this action.',
  unavailable: 'The authorization service is unavailable.',
  provider_unavailable: 'The sign-in provider is unavailable.',
  config_invalid: 'The client configuration is invalid.',
  model_invalid: 'The permission model is invalid.',
  request_conflict: 'The request id was already used with a different payload.',
});

const CODE_SET = new Set(AUTH_ERROR_CODES);
const DETAIL_CODES = new Set(['config_invalid', 'model_invalid']);
const MAX_ISSUES = 50;

export class AuthError extends Error {
  /**
   * @param {string} code one of AUTH_ERROR_CODES
   * @param {{ issues?: Array<{ path: string, rule: string }> }} [options]
   */
  constructor(code, options) {
    if (typeof code !== 'string' || !CODE_SET.has(code)) {
      // The rejected value is deliberately not echoed.
      throw new TypeError('AuthError code must be one of AUTH_ERROR_CODES.');
    }
    super(MESSAGES[code]);
    const issues = DETAIL_CODES.has(code) ? copyIssues(options?.issues) : [];
    Object.defineProperties(this, {
      name: { value: 'AuthError', enumerable: false },
      code: { value: code, enumerable: true },
      issues: { value: Object.freeze(issues), enumerable: true },
    });
  }

  toJSON() {
    return this.issues.length > 0
      ? { name: this.name, code: this.code, message: this.message, issues: this.issues }
      : { name: this.name, code: this.code, message: this.message };
  }
}

export function isAuthError(value) {
  return value instanceof AuthError;
}

// Issues are produced by the validators in this package from sanitized paths
// and fixed rule names; copying keeps only those two string fields.
function copyIssues(issues) {
  if (!Array.isArray(issues)) return [];
  const out = [];
  for (const issue of issues.slice(0, MAX_ISSUES)) {
    if (issue && typeof issue.path === 'string' && typeof issue.rule === 'string') {
      out.push(Object.freeze({ path: issue.path, rule: issue.rule }));
    }
  }
  return out;
}
