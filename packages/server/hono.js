// Optional Hono glue (`@briqvent/dwarpal/server/hono`). It resolves the
// session of each request and either sets `c.var.principal` or answers with a
// fixed JSON error: 401 for a missing or rejected token, 503 when the kit
// could not decide. It holds no client or consumer knowledge and does not
// import Hono, which stays an optional peer dependency.

import { isAuthError } from '../core/index.js';

const UNAUTHENTICATED = new Set(['no_token', 'invalid_token', 'expired']);

/**
 * @param {{ resolveSession(request: Request): Promise<unknown> }} authServer
 */
export function honoMiddleware(authServer) {
  if (!authServer || typeof authServer.resolveSession !== 'function') {
    throw new TypeError('honoMiddleware: expected an auth server from createAuthServer.');
  }
  return async function dwarpalSession(c, next) {
    let principal;
    try {
      principal = await authServer.resolveSession(c.req.raw);
    } catch (error) {
      // Anything that is not a recognized refusal fails closed as unavailable.
      const code = isAuthError(error) && UNAUTHENTICATED.has(error.code) ? error.code : 'unavailable';
      return c.json({ error: code }, code === 'unavailable' ? 503 : 401);
    }
    if (principal === null) return c.json({ error: 'no_token' }, 401);
    c.set('principal', principal);
    await next();
  };
}
