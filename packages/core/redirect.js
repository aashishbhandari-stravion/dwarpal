// Return-path (`next`) validation. The value arrives from a query string or
// storage an attacker can influence, so anything unusual falls back to the
// client default instead of being repaired.

const MAX_NEXT_LENGTH = 2048;
// Controls (C0, DEL, C1) and every Unicode whitespace character.
const CONTROL_OR_SPACE = /[\u0000-\u001f\u007f-\u009f\s\u200b\u2028\u2029\ufeff]/u;
const ENCODED_SEPARATOR = /%(2f|5c)/i;

/**
 * Structural rules for a configured path (allow-list entry, default, route
 * prefix): absolute, already normalized, no query, fragment, encoding,
 * backslash, dot segment, control or space.
 */
export function isSafeConfiguredPath(path) {
  if (typeof path !== 'string' || path.length === 0 || path.length > 512) return false;
  if (!path.startsWith('/') || path.startsWith('//')) return false;
  if (/[\\?#%]/.test(path) || CONTROL_OR_SPACE.test(path)) return false;
  if (path.split('/').some((segment) => segment === '.' || segment === '..')) return false;
  return new URL(path, 'https://normalize.invalid').pathname === path;
}

/**
 * Returns the validated return path for `next`, or `config.defaultReturnPath`.
 * Rules: parse relative to the configured origin; reject a different origin,
 * a raw value starting with `//`, a backslash, an encoded slash or backslash,
 * control characters, whitespace or a fragment; normalize the pathname and
 * require an exact match against `config.allowedReturnPaths`. Only the
 * pathname is returned; query and fragment are never carried over.
 *
 * @param {unknown} next
 * @param {{ origin: string, allowedReturnPaths: readonly string[], defaultReturnPath: string }} config
 *   a config returned by `validateClientConfig`
 * @returns {string}
 */
export function resolveReturnPath(next, config) {
  const fallback = config.defaultReturnPath;
  if (typeof next !== 'string' || next.length === 0 || next.length > MAX_NEXT_LENGTH) return fallback;
  if (next.startsWith('//') || next.includes('\\') || ENCODED_SEPARATOR.test(next)) return fallback;
  if (CONTROL_OR_SPACE.test(next) || next.includes('#')) return fallback;
  let url;
  try {
    url = new URL(next, config.origin);
  } catch {
    return fallback;
  }
  if (url.origin !== config.origin || url.username !== '' || url.password !== '') return fallback;
  return config.allowedReturnPaths.includes(url.pathname) ? url.pathname : fallback;
}
