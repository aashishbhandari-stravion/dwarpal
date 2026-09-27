// Shape helpers shared by the validators. Validation issues never carry caller
// data: a path names fixed field names, array indexes and, for keys the caller
// chose, only their position (see `memberPath`).

export const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?(Z|[+-]\d{2}:\d{2})$/;

export function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Client ids, role keys and permission keys are opaque client-defined strings
 * (contract 4); naming conventions are recommendations only. The empty string
 * is a literal key like any other, never a wildcard or an absent value. A key
 * must be storable in the text and jsonb columns that hold the same keys (4.2),
 * so it may not contain NUL or an unpaired surrogate.
 */
export function isOpaqueKey(value) {
  return typeof value === 'string' && !value.includes('\u0000') && value.isWellFormed();
}

/** An array whose every index below `length` is an own property: no holes. */
export function isDenseArray(value) {
  if (!Array.isArray(value)) return false;
  for (let i = 0; i < value.length; i += 1) {
    if (!Object.hasOwn(value, i)) return false;
  }
  return true;
}

export function isStringArray(value) {
  return isDenseArray(value) && value.every((item) => typeof item === 'string');
}

/** Reads an own property only; inherited names such as `constructor` read as absent. */
export function own(object, key) {
  return Object.hasOwn(object, key) ? object[key] : undefined;
}

/** A dictionary for caller-chosen keys: no prototype, so no key is inherited or special. */
export function dictionary() {
  return Object.create(null);
}

/** Own enumerable keys in canonical (UTF-16 code unit) order. */
export function sortedKeys(object) {
  return Object.keys(object).sort(compareCodeUnits);
}

/**
 * Path of the member at `position` in `sortedKeys(object)`. The key itself is
 * never placed in a path: a well-formed key can still be a pasted secret.
 */
export function memberPath(prefix, position) {
  return prefix ? `${prefix}.#${position}` : `#${position}`;
}

/** True when `object` has an own enumerable key outside the allowed list. */
export function hasExtraKeys(object, allowed) {
  return Object.keys(object).some((key) => !allowed.includes(key));
}

/** Positions, in `sortedKeys(object)`, of own keys not in the allowed list. */
export function extraKeyPositions(object, allowed) {
  const out = [];
  sortedKeys(object).forEach((key, position) => {
    if (!allowed.includes(key)) out.push(position);
  });
  return out;
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
