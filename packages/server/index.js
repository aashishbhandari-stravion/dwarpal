// Node entry of @briqvent/dwarpal (`@briqvent/dwarpal/server`), Node 22+.
// Session resolution and manager operations run with the publishable key and
// the request's own token; the operator client lives in its own entry
// (`./server/operator`) so a web server never imports secret-key code. The
// pure guards are core's, re-exported so a handler needs one import.

export { createAuthServer } from './session.js';
export {
  AUTH_CONTRACT_VERSION,
  AUTH_ERROR_CODES,
  AuthError,
  isAuthError,
  can,
  canAll,
  canAny,
  explain,
  requirePermission,
  requireRole,
  requireMfa,
} from '../core/index.js';
