// supabase-js sets no deadline on its requests. Every Auth and PostgREST call
// the kit makes goes through this wrapper, so a peer that never answers ends
// as an aborted request (supabase-js reports it as a transport failure, the
// kit shows `offline`) instead of a screen stuck in `submitting`.

/**
 * @param {typeof fetch} fetchImpl
 * @param {number} timeoutMs
 * @returns {typeof fetch}
 */
export function timedFetch(fetchImpl, timeoutMs) {
  return (input, init = {}) => {
    const controller = new AbortController();
    const outer = init.signal;
    const onOuter = () => controller.abort();
    if (outer) {
      if (outer.aborted) controller.abort();
      else outer.addEventListener('abort', onOuter, { once: true });
    }
    // The timer covers the body too: aborting a request whose body has been
    // read already has no effect, so it is left to expire rather than tracked.
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    if (typeof timer === 'object' && typeof timer?.unref === 'function') timer.unref();
    const aborted = new Promise((_, reject) => {
      controller.signal.addEventListener('abort', () => reject(new DOMException('The request was aborted.', 'AbortError')), { once: true });
    });
    aborted.catch(() => {});
    // Raced against the abort, so an implementation that ignores its signal
    // still cannot hold the caller past the deadline.
    return Promise.race([
      Promise.resolve().then(() => fetchImpl(input, { ...init, signal: controller.signal })),
      aborted,
    ]).catch((error) => {
      clearTimeout(timer);
      outer?.removeEventListener('abort', onOuter);
      throw error;
    });
  };
}
