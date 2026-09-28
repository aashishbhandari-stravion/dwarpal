// One PostgREST RPC into the exposed `auth_kit` schema. The result is a
// discriminated outcome, never an exception for a peer's answer:
//
//   { kind: 'value', value }            2xx with a JSON body
//   { kind: 'refusal', code, detail }   SQLSTATE DW001: the kit refused; nothing was written
//   { kind: 'failure', status, reason } anything else: another SQLSTATE, an HTTP or
//                                       gateway error, a malformed body or a transport fault
//
// Only DW001 is a refusal (tests/sql/README.md, error convention). A failure
// never says whether a write committed; callers of write functions treat it
// as an unknown outcome and retry with the same request id.

import { request, parseJson, tryParseJson, TransportError } from './http.js';

const FUNCTION_NAME = /^[a-z_]{1,64}$/;
const REFUSAL_CODE = /^[a-z_]{1,64}$/;
const DETAIL_CODES = new Set(['model_invalid', 'model_refused']);
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
const MAX_DETAIL_CHARS = 256 * 1024;

/**
 * `bearer` null sends the apikey alone (an anonymous call with a new-style
 * publishable key). `profile` other than auth_kit is used only by doctor's
 * probe to show that a schema is unreachable.
 * @param {{ fetch: typeof fetch, timers?: object, origin: string, apikey: string, bearer: string | null,
 *           fn: string, args: Record<string, unknown>, timeoutMs: number, signal?: AbortSignal, profile?: string }} call
 */
export async function callRpc(call) {
  if (!FUNCTION_NAME.test(call.fn)) throw new TypeError('callRpc: invalid function name.');
  let response;
  try {
    response = await request(call.fetch, `${call.origin}/rest/v1/rpc/${call.fn}`, {
      method: 'POST',
      headers: {
        apikey: call.apikey,
        ...(call.bearer === null ? {} : { Authorization: `Bearer ${call.bearer}` }),
        'Content-Type': 'application/json',
        Accept: 'application/json',
        'Content-Profile': call.profile ?? 'auth_kit',
        'Accept-Profile': call.profile ?? 'auth_kit',
      },
      body: JSON.stringify(call.args),
      timeoutMs: call.timeoutMs,
      maxBytes: MAX_RESPONSE_BYTES,
      signal: call.signal,
      timers: call.timers,
    });
  } catch (error) {
    if (error instanceof TransportError) return { kind: 'failure', status: 0, reason: error.reason };
    throw error;
  }
  if (response.status >= 200 && response.status < 300) {
    try {
      return { kind: 'value', value: parseJson(response.text) };
    } catch {
      return { kind: 'failure', status: response.status, reason: 'malformed' };
    }
  }
  const body = tryParseJson(response.text);
  if (body !== null && typeof body === 'object' && body.code === 'DW001'
      && typeof body.message === 'string' && REFUSAL_CODE.test(body.message)) {
    return { kind: 'refusal', code: body.message, detail: readDetail(body.message, body.details) };
  }
  return { kind: 'failure', status: response.status, reason: failureReason(response.status, body) };
}

// DETAIL is JSON only for model refusals; anything else is dropped rather
// than passed on, because a detail string can carry database text.
function readDetail(code, details) {
  if (!DETAIL_CODES.has(code) || typeof details !== 'string' || details.length > MAX_DETAIL_CHARS) return null;
  const value = tryParseJson(details);
  return value !== null && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

// A fixed tag for diagnostics: the HTTP class and, for PostgREST's own
// errors, its PGRST code; never the message.
function failureReason(status, body) {
  const code = body !== null && typeof body === 'object' && typeof body.code === 'string' ? body.code : '';
  if (/^PGRST\d{3}$/.test(code)) return `postgrest_${code.slice(5)}`;
  if (/^[0-9A-Z]{5}$/.test(code)) return `sqlstate_${code}`;
  return `http_${status}`;
}
