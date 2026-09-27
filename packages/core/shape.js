// Shape helpers shared by the validators. Keys that pass these patterns are
// safe to place in error paths; anything else is reported by position only.

export const CLIENT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
export const ROLE_KEY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;
export const PERMISSION_KEY_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;
export const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;

export function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

export function isStringArray(value) {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

export function safeSegment(key, pattern) {
  return typeof key === 'string' && pattern.test(key) ? key : '<invalid-key>';
}

/** Returns own enumerable keys not in the allowed list. */
export function extraKeys(object, allowed) {
  return Object.keys(object).filter((key) => !allowed.includes(key));
}

export function deepFreeze(value) {
  if (value !== null && typeof value === 'object' && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const key of Object.keys(value)) deepFreeze(value[key]);
  }
  return value;
}

export function sortedUnique(values) {
  return [...new Set(values)].sort(compareCodeUnits);
}

// Plain code-unit order, the same order canonical JSON uses for object keys.
export function compareCodeUnits(a, b) {
  if (a < b) return -1;
  if (a > b) return 1;
  return 0;
}
