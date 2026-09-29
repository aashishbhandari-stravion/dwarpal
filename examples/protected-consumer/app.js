// A protected Node endpoint built only from the kit's public entries. Each
// request is authenticated by `resolveSession` (signature, expiry, a live
// check with Supabase Auth, and a fresh read of this client's access), then
// authorized by the kit's permission keys and this application's own link
// table. Nothing is cached between requests.
//
//   GET    /records                       records the caller may read
//   GET    /records/:id                   one record: the own/any guard
//   PUT    /records/:id/links/:userId     records:link:any; idempotent
//   DELETE /records/:id/links/:userId     records:link:any; idempotent
//   PUT    /members/:userId/roles/:role   manager grant; Idempotency-Key required
//   DELETE /members/:userId/roles/:role   manager revoke; Idempotency-Key required

import { AuthError, can, explain, isAuthError, requirePermission } from '@briqvent/dwarpal/server';
import { StoreUnavailableError } from './store.js';

const STATUS = {
  no_token: 401,
  invalid_token: 401,
  expired: 401,
  email_unverified: 403,
  mfa_required: 403,
  forbidden: 403,
  request_conflict: 409,
  unavailable: 503,
};
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SEGMENT = /^[A-Za-z0-9._:@-]{1,128}$/;

/**
 * @param {{ auth: import('@briqvent/dwarpal/server').AuthServer, store: ReturnType<typeof import('./store.js').createStore> }} deps
 * @returns {(req: import('node:http').IncomingMessage, res: import('node:http').ServerResponse) => Promise<void>}
 */
export function createApp({ auth, store }) {
  function send(res, status, body, headers = {}) {
    res.writeHead(status, {
      'content-type': 'application/json; charset=utf-8',
      // Sensitive answers are never stored by a browser or an intermediary.
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff',
      ...headers,
    });
    res.end(JSON.stringify(body));
  }

  // Maps an error to a fixed answer; no message, id or token is ever echoed.
  // `key` is the broad permission the request needed: roles that hold it but
  // are withheld for lack of MFA are named so the page can offer MFA.
  function fail(res, error, principal, key) {
    if (error instanceof StoreUnavailableError) return send(res, 503, { error: 'unavailable' });
    if (isAuthError(error) && Object.hasOwn(STATUS, error.code)) {
      const status = STATUS[error.code];
      const headers = status === 401 ? { 'www-authenticate': 'Bearer' } : {};
      const body = { error: error.code };
      if ((error.code === 'forbidden' || error.code === 'mfa_required') && principal && key) {
        const withheld = explain(principal, key).withheld.map((entry) => entry.role);
        if (withheld.length > 0) body.withheld = withheld;
      }
      return send(res, status, body, headers);
    }
    return send(res, 500, { error: 'internal' });
  }

  function routeOf(req) {
    const url = new URL(req.url ?? '/', 'http://localhost');
    return { method: req.method ?? 'GET', parts: url.pathname.split('/').filter(Boolean) };
  }

  return async function handle(req, res) {
    let principal = null;
    let key = null;
    try {
      const { method, parts } = routeOf(req);
      if (method === 'GET' && parts.length === 1 && parts[0] === 'health') return send(res, 200, { ok: true });
      const known = (parts[0] === 'records' && parts.length <= 4) || (parts[0] === 'members' && parts.length === 4);
      if (!known || parts.slice(1).some((part) => !SEGMENT.test(part))) return send(res, 404, { error: 'not_found' });

      principal = await auth.resolveSession(req);
      if (principal === null) throw new AuthError('no_token');

      if (parts[0] === 'records' && parts.length === 1 && method === 'GET') {
        key = 'records:read:any';
        if (can(principal, key)) return send(res, 200, { records: store.listAll() });
        requirePermission(principal, 'records:read:own');
        return send(res, 200, { records: store.listLinked(principal.identity.userId) });
      }
      if (parts[0] === 'records' && parts.length === 2 && method === 'GET') {
        // The own/any guard of design 4.3. The broad branch needs an ACTIVE
        // role that grants it; otherwise the own key and this application's
        // link decide. A caller without the broad key learns nothing about
        // other records: an absent record and an unlinked one look the same.
        key = 'records:read:any';
        if (!can(principal, key)) {
          requirePermission(principal, 'records:read:own');
          if (!store.isLinked(parts[1], principal.identity.userId)) throw new AuthError('forbidden');
        }
        const record = store.getRecord(parts[1]);
        return record === null ? send(res, 404, { error: 'not_found' }) : send(res, 200, record);
      }
      if (parts[0] === 'records' && parts.length === 4 && parts[2] === 'links' && (method === 'PUT' || method === 'DELETE')) {
        key = 'records:link:any';
        requirePermission(principal, key);
        const result = method === 'PUT'
          ? store.link(parts[1], parts[3], principal.identity.userId)
          : store.unlink(parts[1], parts[3], principal.identity.userId);
        return result === 'unknown_record' ? send(res, 404, { error: 'not_found' }) : send(res, 200, { result });
      }
      if (parts[0] === 'members' && parts[2] === 'roles' && (method === 'PUT' || method === 'DELETE')) {
        key = 'members:manage';
        const requestId = req.headers['idempotency-key'];
        if (typeof requestId !== 'string' || !UUID.test(requestId)) return send(res, 400, { error: 'idempotency_key_required' });
        // The manager check and the write run in the database under the manager's own token; reuse the key on retry.
        const change = method === 'PUT'
          ? await auth.grantMembership(parts[1], parts[3], requestId, req)
          : await auth.revokeMembership(parts[1], parts[3], requestId, req);
        return send(res, 200, { result: change.result });
      }
      return send(res, 404, { error: 'not_found' });
    } catch (error) {
      return fail(res, error, principal, key);
    }
  };
}
