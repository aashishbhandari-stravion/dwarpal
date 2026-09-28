// Bounded outbound HTTP for every call the server library and the operator
// client make. Each call owns an AbortController that fires on the call's own
// deadline or on the caller's signal, and the call is raced against that
// abort: a fetch implementation that ignores its signal still cannot hold the
// caller past the deadline. The body is read under the same deadline with a
// byte cap. Redirects are never followed, so a credential header is only ever
// sent to the URL that was built for it.

export const DEFAULT_TIMERS = Object.freeze({
  setTimeout: (fn, ms) => globalThis.setTimeout(fn, ms),
  clearTimeout: (handle) => globalThis.clearTimeout(handle),
});

/** A failed exchange. `reason` is a fixed tag, never text from the peer. */
export class TransportError extends Error {
  /** @param {'timeout' | 'aborted' | 'network' | 'too_large' | 'malformed'} reason */
  constructor(reason) {
    super(`transport failure: ${reason}`);
    this.name = 'TransportError';
    this.reason = reason;
  }
}

/**
 * @param {typeof fetch} fetchImpl
 * @param {string} url
 * @param {{ method?: string, headers?: Record<string, string>, body?: string, timeoutMs: number, maxBytes: number,
 *           signal?: AbortSignal, timers?: typeof DEFAULT_TIMERS }} options
 * @returns {Promise<{ status: number, headers: Headers, text: string }>}
 */
export async function request(fetchImpl, url, options) {
  const { method = 'GET', headers, body, timeoutMs, maxBytes, signal: outer, timers = DEFAULT_TIMERS } = options;
  const controller = new AbortController();
  let timedOut = false;
  const timer = timers.setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, timeoutMs);
  const onOuter = () => controller.abort();
  if (outer) {
    if (outer.aborted) controller.abort();
    else outer.addEventListener('abort', onOuter, { once: true });
  }
  const abortReason = () => new TransportError(timedOut ? 'timeout' : 'aborted');
  const aborted = new Promise((_, reject) => {
    if (controller.signal.aborted) reject(abortReason());
    else controller.signal.addEventListener('abort', () => reject(abortReason()), { once: true });
  });
  aborted.catch(() => {});
  try {
    const response = await Promise.race([
      Promise.resolve().then(() => fetchImpl(url, { method, headers, body, signal: controller.signal, redirect: 'manual' })),
      aborted,
    ]);
    const text = await Promise.race([readBounded(response, maxBytes, controller.signal), aborted]);
    return { status: response.status, headers: response.headers, text };
  } catch (error) {
    if (error instanceof TransportError) throw error;
    if (controller.signal.aborted) throw abortReason();
    throw new TransportError('network');
  } finally {
    timers.clearTimeout(timer);
    outer?.removeEventListener('abort', onOuter);
  }
}

async function readBounded(response, maxBytes, signal) {
  if (!response || typeof response.status !== 'number') throw new TransportError('malformed');
  if (response.body === null || response.body === undefined) return '';
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      if (signal.aborted) throw new TransportError('aborted');
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) throw new TransportError('too_large');
      chunks.push(value);
    }
  } catch (error) {
    reader.cancel().catch(() => {});
    throw error instanceof TransportError ? error : new TransportError('network');
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new TransportError('malformed');
  }
}

/** Parses JSON text; a peer that sent something else is malformed, not a value. */
export function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    throw new TransportError('malformed');
  }
}

/** Like parseJson, but returns undefined for unparseable error bodies. */
export function tryParseJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}
