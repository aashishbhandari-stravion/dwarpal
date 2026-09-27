// Canonical JSON and SHA-256 helpers. The canonical form is shared with the SQL
// layer, which computes request fingerprints and model hashes from the same
// bytes, so the encoding is deliberately narrow: plain objects with keys sorted
// by UTF-16 code unit, arrays in their given order, strings and finite numbers
// encoded as JSON.stringify encodes them, no whitespace.

import { isPlainObject, compareCodeUnits } from './shape.js';

const MAX_DEPTH = 64;

/**
 * @param {unknown} value
 * @returns {string}
 */
export function canonicalJson(value) {
  return encode(value, 0, new Set());
}

function encode(value, depth, seen) {
  if (depth > MAX_DEPTH) throw new TypeError('canonicalJson: value is nested too deeply.');
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'string':
      return JSON.stringify(value);
    case 'number':
      if (!Number.isFinite(value)) throw new TypeError('canonicalJson: numbers must be finite.');
      return JSON.stringify(value);
    case 'object':
      break;
    default:
      throw new TypeError('canonicalJson: unsupported value type.');
  }
  if (seen.has(value)) throw new TypeError('canonicalJson: value is cyclic.');
  seen.add(value);
  let out;
  if (Array.isArray(value)) {
    const parts = [];
    for (let i = 0; i < value.length; i += 1) {
      if (!Object.hasOwn(value, i)) throw new TypeError('canonicalJson: sparse arrays are not supported.');
      parts.push(encode(value[i], depth + 1, seen));
    }
    out = `[${parts.join(',')}]`;
  } else if (isPlainObject(value)) {
    const keys = Object.keys(value).sort(compareCodeUnits);
    const parts = keys.map((key) => `${JSON.stringify(key)}:${encode(value[key], depth + 1, seen)}`);
    out = `{${parts.join(',')}}`;
  } else {
    throw new TypeError('canonicalJson: only plain objects and arrays are supported.');
  }
  seen.delete(value);
  return out;
}

/**
 * Lower-case hex SHA-256 of the UTF-8 bytes of `text`, via Web Crypto
 * (available in Node 22+ and browsers), so the core stays free of Node-only
 * imports.
 * @param {string} text
 * @returns {Promise<string>}
 */
export async function sha256Hex(text) {
  if (typeof text !== 'string') throw new TypeError('sha256Hex: text must be a string.');
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Fingerprint of a request-bearing command: sha256 of the canonical JSON of
 * {operation, client_id, actor_id, payload}. `payload` is the command's
 * arguments without the request id. `clientId` is null only for project-wide
 * operations.
 * @param {{ operation: string, clientId: string | null, actorId: string, payload: unknown }} input
 * @returns {Promise<string>}
 */
export async function requestFingerprint(input) {
  if (!isPlainObject(input)) throw new TypeError('requestFingerprint: input must be an object.');
  const { operation, clientId, actorId, payload } = input;
  if (typeof operation !== 'string' || operation === '') {
    throw new TypeError('requestFingerprint: operation must be a non-empty string.');
  }
  if (clientId !== null && (typeof clientId !== 'string' || clientId === '')) {
    throw new TypeError('requestFingerprint: clientId must be a non-empty string or null.');
  }
  if (typeof actorId !== 'string' || actorId === '') {
    throw new TypeError('requestFingerprint: actorId must be a non-empty string.');
  }
  if (payload === undefined) throw new TypeError('requestFingerprint: payload is required.');
  return sha256Hex(canonicalJson({ operation, client_id: clientId, actor_id: actorId, payload }));
}
