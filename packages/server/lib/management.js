// Supabase Management API transport for the operator's catalog work
// (design 9 step 2, LLD S1): SQL through POST /v1/projects/{ref}/database/query
// with a personal access token, and the project's PostgREST and Auth
// configuration. An ordinary secret-key PostgREST connection cannot read
// pg_catalog, call auth_kit_private.grant_violations() or apply migration SQL,
// so migrate and the doctor catalog checks need this transport or report it
// missing. Database and API error text is reduced to a fixed tag: the
// migration's own precondition messages map to named reasons, anything else
// is `sql_error`.

import { request, parseJson, tryParseJson, TransportError } from './http.js';
import { OperatorError } from './operator-error.js';

const MAX_BYTES = 16 * 1024 * 1024;
const REF_PATTERN = /^[a-z0-9]{1,64}$/;

// Messages the migration raises before or after doing any work (its section 0
// preconditions and section 9 assertion). Only the tag leaves this module.
const KNOWN_FAILURES = [
  ['auth_kit is already installed', 'already_installed'],
  ['PostgreSQL 15 or later is required', 'server_version'],
  ['database encoding must be UTF8', 'encoding'],
  ['Supabase auth schema', 'auth_schema_missing'],
  ['roles anon, authenticated and service_role are required', 'roles_missing'],
  ['grant assertion failed', 'grant_assertion_failed'],
];

/** A SQL string literal that is independent of standard_conforming_strings. */
export function textLiteral(value) {
  return `convert_from(decode('${Buffer.from(value, 'utf8').toString('hex')}', 'hex'), 'UTF8')`;
}

function failureTag(response) {
  const body = tryParseJson(response.text);
  const message = body !== null && typeof body === 'object' && typeof body.message === 'string' ? body.message : '';
  for (const [needle, tag] of KNOWN_FAILURES) if (message.includes(needle)) return tag;
  return 'sql_error';
}

/**
 * @param {{ fetch: typeof fetch, timers: object, baseUrl: string, token: string, projectRef: string, timeoutMs: number }} options
 */
export function createManagementApi({ fetch: fetchImpl, timers, baseUrl, token, projectRef, timeoutMs }) {
  if (!REF_PATTERN.test(projectRef)) throw new OperatorError('config_invalid', { issues: [{ path: 'projectRef', rule: 'syntax' }] });
  const base = `${baseUrl}/v1/projects/${projectRef}`;

  async function call(stage, method, path, { body, uncertain = false, callTimeoutMs = timeoutMs } = {}) {
    try {
      return await request(fetchImpl, `${base}${path}`, {
        method,
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: 'application/json',
          ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        timeoutMs: callTimeoutMs,
        maxBytes: MAX_BYTES,
        timers,
      });
    } catch (error) {
      if (!(error instanceof TransportError)) throw error;
      throw new OperatorError(uncertain ? 'outcome_unknown' : 'unavailable', { stage, reason: error.reason });
    }
  }

  function readJson(stage, response) {
    try {
      return parseJson(response.text);
    } catch {
      throw new OperatorError('unavailable', { stage, reason: 'malformed' });
    }
  }

  return Object.freeze({
    /**
     * Runs SQL and returns the rows of its last statement. A 4xx answer is a
     * refused statement (the query ran and rolled back); a 5xx or transport
     * fault after sending a write leaves the outcome unknown.
     */
    async query(sql, { stage, write = false, callTimeoutMs } = {}) {
      const response = await call(stage, 'POST', '/database/query', { body: { query: sql }, uncertain: write, callTimeoutMs });
      if (response.status === 200 || response.status === 201) {
        const rows = readJson(stage, response);
        if (!Array.isArray(rows)) throw new OperatorError('unavailable', { stage, reason: 'malformed' });
        return rows;
      }
      if (response.status === 401 || response.status === 403) {
        throw new OperatorError('prerequisite_missing', { stage, reason: 'management_token_refused' });
      }
      if (response.status === 400 || response.status === 422) {
        throw new OperatorError(write ? 'migration_failed' : 'unavailable', { stage, reason: failureTag(response) });
      }
      const reason = `http_${response.status}`;
      if (response.status >= 500) throw new OperatorError(write ? 'outcome_unknown' : 'unavailable', { stage, reason });
      throw new OperatorError('unavailable', { stage, reason });
    },

    /** Exposed API schemas from the project's PostgREST configuration. */
    async exposedSchemas() {
      const response = await call('postgrest_config', 'GET', '/postgrest');
      if (response.status !== 200) throw new OperatorError('unavailable', { stage: 'postgrest_config', reason: `http_${response.status}` });
      const body = readJson('postgrest_config', response);
      if (body === null || typeof body !== 'object' || typeof body.db_schema !== 'string') {
        throw new OperatorError('unavailable', { stage: 'postgrest_config', reason: 'malformed' });
      }
      return body.db_schema.split(',').map((name) => name.trim()).filter((name) => name !== '');
    },

    /**
     * Site URL and redirect allow-list from the Auth configuration. The same
     * answer holds provider secrets; only these two fields are read and the
     * rest is dropped here.
     */
    async redirectSettings() {
      const response = await call('auth_config', 'GET', '/config/auth');
      if (response.status !== 200) throw new OperatorError('unavailable', { stage: 'auth_config', reason: `http_${response.status}` });
      const body = readJson('auth_config', response);
      if (body === null || typeof body !== 'object' || (body.uri_allow_list != null && typeof body.uri_allow_list !== 'string')) {
        throw new OperatorError('unavailable', { stage: 'auth_config', reason: 'malformed' });
      }
      return {
        siteUrl: typeof body.site_url === 'string' ? body.site_url : null,
        allowList: (body.uri_allow_list ?? '').split(',').map((entry) => entry.trim()).filter((entry) => entry !== ''),
      };
    },
  });
}

/** Rows whose single `result` column holds JSON text (the queries below all use this shape). */
export function jsonResult(stage, rows) {
  if (rows.length !== 1 || rows[0] === null || typeof rows[0] !== 'object' || typeof rows[0].result !== 'string') {
    throw new OperatorError('unavailable', { stage, reason: 'malformed' });
  }
  try {
    return JSON.parse(rows[0].result);
  } catch {
    throw new OperatorError('unavailable', { stage, reason: 'malformed' });
  }
}
