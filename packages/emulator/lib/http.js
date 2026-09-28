// Transport helpers: loopback Host and Origin checks, CORS for loopback pages,
// bounded request bodies and JSON answers. Answers never echo request data.

export const MAX_BODY_BYTES = 64 * 1024;
export const MAX_URL_CHARS = 8 * 1024;
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]']);
const ALLOWED_HEADERS = new Set([
  'accept', 'accept-profile', 'apikey', 'authorization', 'baggage', 'content-profile', 'content-type', 'prefer',
  'traceparent', 'tracestate', 'x-client-info', 'x-retry-count', 'x-supabase-api-version',
]);
const ALLOWED_METHODS = 'GET, POST, PUT, DELETE, OPTIONS';

export class BodyError extends Error {
  constructor(status, code) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

/** True for `http://<loopback>:<port>` style origins (and https), the only pages allowed to call the fixture. */
export function isLoopbackOrigin(value) {
  if (typeof value !== 'string' || value.length > 256) return false;
  let url;
  try {
    url = new URL(value);
  } catch {
    return false;
  }
  return (url.protocol === 'http:' || url.protocol === 'https:') && LOOPBACK_HOSTS.has(url.hostname)
    && url.origin === value;
}

/** A redirect target is honoured only when it points back to a loopback page. */
export function isLoopbackUrl(value) {
  if (typeof value !== 'string' || value.length > 2048) return false;
  try {
    const url = new URL(value);
    return (url.protocol === 'http:' || url.protocol === 'https:') && LOOPBACK_HOSTS.has(url.hostname)
      && url.username === '' && url.password === '';
  } catch {
    return false;
  }
}

/** The Host header must name this listener through a loopback name (a DNS-rebinding guard). */
export function hostAllowed(hostHeader, port) {
  if (typeof hostHeader !== 'string') return false;
  return [...LOOPBACK_HOSTS].some((host) => hostHeader === `${host}:${port}`);
}

export function corsHeaders(request) {
  const origin = request.headers.origin;
  if (!isLoopbackOrigin(origin)) return {};
  return {
    'access-control-allow-origin': origin,
    'access-control-expose-headers': 'x-supabase-api-version, content-range, retry-after',
    vary: 'Origin',
  };
}

/** Answers a CORS preflight; only loopback origins and the headers supabase-js sends are allowed. */
export function preflight(request, response) {
  const origin = request.headers.origin;
  const requested = String(request.headers['access-control-request-headers'] ?? '')
    .split(',').map((h) => h.trim().toLowerCase()).filter(Boolean);
  if (!isLoopbackOrigin(origin) || requested.some((h) => !ALLOWED_HEADERS.has(h))) {
    response.writeHead(403, { 'content-length': '0' });
    response.end();
    return;
  }
  response.writeHead(204, {
    ...corsHeaders(request),
    'access-control-allow-methods': ALLOWED_METHODS,
    'access-control-allow-headers': [...ALLOWED_HEADERS].join(', '),
    'access-control-max-age': '600',
    'content-length': '0',
  });
  response.end();
}

/** Reads at most MAX_BODY_BYTES; an empty body reads as null. Only JSON bodies are accepted. */
export function readBody(request) {
  return new Promise((resolve, reject) => {
    const declared = Number(request.headers['content-length'] ?? 0);
    if (Number.isFinite(declared) && declared > MAX_BODY_BYTES) {
      reject(new BodyError(413, 'body_too_large'));
      request.resume();
      return;
    }
    const chunks = [];
    let size = 0;
    let failed = false;
    request.on('data', (chunk) => {
      if (failed) return;
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        failed = true;
        reject(new BodyError(413, 'body_too_large'));
        return;
      }
      chunks.push(chunk);
    });
    request.on('end', () => {
      if (failed) return;
      if (size === 0) {
        resolve(null);
        return;
      }
      const type = String(request.headers['content-type'] ?? '').toLowerCase();
      if (!type.startsWith('application/json')) {
        reject(new BodyError(415, 'unsupported_media_type'));
        return;
      }
      const text = Buffer.concat(chunks).toString('utf8');
      try {
        resolve(JSON.parse(text));
      } catch {
        reject(new BodyError(400, 'malformed_json'));
      }
    });
    request.on('error', () => {
      if (!failed) {
        failed = true;
        reject(new BodyError(400, 'aborted'));
      }
    });
  });
}

/** A JSON answer; `undefined` body means no content. */
export function send(request, response, status, body, headers = {}) {
  const payload = body === undefined ? '' : JSON.stringify(body);
  response.writeHead(status, {
    ...corsHeaders(request),
    ...(body === undefined ? {} : { 'content-type': 'application/json; charset=utf-8' }),
    'cache-control': 'no-store',
    'content-length': String(Buffer.byteLength(payload)),
    ...headers,
  });
  response.end(payload);
}

export function redirect(request, response, location) {
  response.writeHead(303, { ...corsHeaders(request), location, 'cache-control': 'no-store', 'content-length': '0' });
  response.end();
}
