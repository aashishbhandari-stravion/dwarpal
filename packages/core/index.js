// Public entry of the pure core: contract types, validators, redirect rules,
// permission evaluation and the closed error set. No I/O.

export const AUTH_CONTRACT_VERSION = '0.5';

export { AUTH_ERROR_CODES, AuthError, isAuthError } from './errors.js';
export { canonicalJson, sha256Hex, requestFingerprint } from './canonical.js';
export { createPrincipal, PROVIDERS, AAL_LEVELS, GRANTED_VIA } from './principal.js';
export { can, canAll, canAny, explain, requirePermission, requireRole, requireMfa } from './evaluate.js';
export { validateModel, canonicalModelJson, modelHash, planModelChange, ROLE_FLAGS, CLIENT_STATES } from './model.js';
export { validateClientConfig, ROUTE_NAMES } from './config.js';
export { resolveReturnPath } from './redirect.js';
