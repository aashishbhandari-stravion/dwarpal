// The only way the harness reaches the network. The gate starts closed and
// opens only for the origins `target.authorize` returned; any other origin,
// or any call while closed, throws before a socket is opened. Every request
// is logged (method, origin kind, sanitised path, status, duration) through
// `onCall`. The library under test receives this fetch too, so its calls are
// fenced and logged the same way. Loopback is allowed separately for the
// harness's own local endpoint and callback server.

export class NetworkClosedError extends Error {
  constructor(reason) {
    super(`network gate: ${reason}`);
    this.name = 'NetworkClosedError';
    this.reason = reason;
  }
}

const LOOPBACK = /^http:\/\/(127\.0\.0\.1|localhost):\d{1,5}$/;

export function createGate({ fetch: inner = globalThis.fetch, onCall = () => {}, now = () => performance.now() } = {}) {
  let allowed = null;
  let tap = null;
  const counts = { total: 0, byOrigin: new Map() };

  async function gatedFetch(input, init = {}) {
    const url = new URL(typeof input === 'string' ? input : input.url);
    const origin = url.origin;
    const loopback = LOOPBACK.test(origin);
    if (!loopback && (allowed === null || !allowed.has(origin))) throw new NetworkClosedError(allowed === null ? 'closed' : 'origin_not_authorized');
    counts.total += 1;
    counts.byOrigin.set(origin, (counts.byOrigin.get(origin) ?? 0) + 1);
    const method = (init.method ?? 'GET').toUpperCase();
    const started = now();
    let status = 0;
    try {
      if (tap) await tap({ method, url, init });
      const response = await inner(input, init);
      status = response.status;
      return response;
    } finally {
      onCall({ method, origin: loopback ? 'loopback' : origin, path: `${url.pathname}${url.search}`, status, ms: Math.round(now() - started) });
    }
  }

  return {
    fetch: gatedFetch,
    /** @param {string[]} origins from target.authorize */
    open(origins) {
      allowed = new Set(origins);
    },
    close() {
      allowed = null;
    },
    get isOpen() {
      return allowed !== null;
    },
    /**
     * For a browser the harness drives: whether it may reach `origin` (only
     * while open, and only an authorized origin or one of the harness's own
     * loopback sites), and a log entry for each request it made.
     */
    admits(origin, loopbackSites = []) {
      if (allowed === null) return false;
      return allowed.has(origin) || loopbackSites.includes(origin);
    },
    record({ method, url, status, blocked = false }) {
      const u = new URL(url);
      const loopback = LOOPBACK.test(u.origin);
      if (!blocked) {
        counts.total += 1;
        counts.byOrigin.set(u.origin, (counts.byOrigin.get(u.origin) ?? 0) + 1);
      }
      // A loopback page address can carry a link token: its query is never logged.
      onCall({ via: 'browser', method, origin: loopback ? 'loopback' : u.origin, path: loopback ? u.pathname : `${u.pathname}${u.search}`, status, ...(blocked ? { blocked: true } : {}) });
    },
    /** A hook run before each request is sent (tests of in-flight state use it). */
    setTap(fn) {
      tap = fn;
    },
    counts,
  };
}

/** Wraps a fetch to count and optionally hold requests matching a predicate. */
export function observeFetch(inner, { match = () => false, before } = {}) {
  const seen = [];
  const wrapped = async (input, init = {}) => {
    const url = new URL(typeof input === 'string' ? input : input.url);
    const method = (init.method ?? 'GET').toUpperCase();
    const hit = match(method, url);
    if (hit) {
      seen.push({ method, path: url.pathname });
      if (before) await before(method, url);
    }
    return inner(input, init);
  };
  wrapped.seen = seen;
  return wrapped;
}
