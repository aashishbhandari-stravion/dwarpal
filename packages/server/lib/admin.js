// Supabase Auth admin API calls made by the operator client, each bounded by
// its own abort deadline (20 s by default, design 4.1 / G4). Answers are
// validated to the fields the kit uses; a peer's text is never kept. A
// failure is an OperatorError with a fixed stage and reason tag.

import { UUID_PATTERN } from '../../core/shape.js';
import { request, parseJson, tryParseJson, TransportError } from './http.js';
import { OperatorError } from './operator-error.js';

const MAX_BYTES = 8 * 1024 * 1024;
const MAX_FACTORS = 100;
const NEXT_LINK = /<[^>]*>\s*;\s*rel="?next"?/i;
// The admin users collection; single users and their factors are paths below it.
const USERS = '/admin/users';

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isTimestamp(value) {
  return typeof value === 'string' && value !== '' && !Number.isNaN(Date.parse(value));
}

/**
 * @param {{ fetch: typeof fetch, timers: object, origin: string, secretKey: string, timeoutMs: number }} options
 */
export function createAdminApi({ fetch: fetchImpl, timers, origin, secretKey, timeoutMs }) {
  async function call(stage, method, path, { body, uncertain = false } = {}) {
    try {
      return await request(fetchImpl, `${origin}/auth/v1${path}`, {
        method,
        headers: {
          apikey: secretKey,
          Authorization: `Bearer ${secretKey}`,
          Accept: 'application/json',
          ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        timeoutMs,
        maxBytes: MAX_BYTES,
        timers,
      });
    } catch (error) {
      if (!(error instanceof TransportError)) throw error;
      throw new OperatorError(uncertain ? 'outcome_unknown' : 'unavailable', { stage, reason: error.reason });
    }
  }

  function json(stage, response) {
    try {
      return parseJson(response.text);
    } catch {
      throw new OperatorError('unavailable', { stage, reason: 'malformed' });
    }
  }

  function errorCode(response) {
    const body = tryParseJson(response.text);
    return isObject(body) && typeof body.error_code === 'string' ? body.error_code : null;
  }

  function unexpected(stage, response) {
    return new OperatorError('unavailable', { stage, reason: `http_${response.status}` });
  }

  function readUser(stage, value) {
    if (!isObject(value) || typeof value.id !== 'string' || !UUID_PATTERN.test(value.id)) {
      throw new OperatorError('unavailable', { stage, reason: 'malformed' });
    }
    return {
      id: value.id.toLowerCase(),
      email: typeof value.email === 'string' ? value.email : null,
      confirmed: isTimestamp(value.email_confirmed_at),
      anonymous: value.is_anonymous === true,
    };
  }

  return Object.freeze({
    /** The user, or null when Auth reports that no such user exists. */
    async getUserById(userId) {
      const response = await call('get_user', 'GET', `${USERS}/${userId}`);
      if (response.status === 404 && errorCode(response) === 'user_not_found') return null;
      if (response.status !== 200) throw unexpected('get_user', response);
      const user = readUser('get_user', json('get_user', response));
      if (user.id !== userId) throw new OperatorError('unavailable', { stage: 'get_user', reason: 'mismatch' });
      return user;
    },

    /** One page of the user listing; `hasNext` reflects Auth's Link header. */
    async listUsersPage(page, perPage) {
      const response = await call('list_users', 'GET', `${USERS}?page=${page}&per_page=${perPage}`);
      if (response.status !== 200) throw unexpected('list_users', response);
      const body = json('list_users', response);
      if (!isObject(body) || !Array.isArray(body.users) || body.users.length > perPage) {
        throw new OperatorError('unavailable', { stage: 'list_users', reason: 'malformed' });
      }
      const totalHeader = response.headers.get('x-total-count');
      const total = totalHeader !== null && /^\d{1,12}$/.test(totalHeader) ? Number(totalHeader) : null;
      return {
        users: body.users.map((user) => readUser('list_users', user)),
        hasNext: NEXT_LINK.test(response.headers.get('link') ?? ''),
        total,
      };
    },

    /** Sends an invitation. A lost answer may still have sent the e-mail. */
    async inviteUserByEmail(email) {
      const response = await call('invite', 'POST', '/invite', { body: { email }, uncertain: true });
      if (response.status !== 200) throw unexpected('invite', response);
      return readUser('invite', json('invite', response));
    },

    /** Ids of the user's verified TOTP factors, sorted. */
    async listFactors(userId) {
      const response = await call('list_factors', 'GET', `${USERS}/${userId}/factors`);
      if (response.status !== 200) throw unexpected('list_factors', response);
      const factors = json('list_factors', response);
      if (!Array.isArray(factors) || factors.length > MAX_FACTORS) {
        throw new OperatorError('unavailable', { stage: 'list_factors', reason: 'malformed' });
      }
      const ids = [];
      for (const factor of factors) {
        if (!isObject(factor) || typeof factor.id !== 'string' || !UUID_PATTERN.test(factor.id)
            || typeof factor.factor_type !== 'string' || typeof factor.status !== 'string') {
          throw new OperatorError('unavailable', { stage: 'list_factors', reason: 'malformed' });
        }
        if (factor.factor_type === 'totp' && factor.status === 'verified') ids.push(factor.id.toLowerCase());
      }
      return [...new Set(ids)].sort();
    },

    /**
     * Deletes one factor. Only Auth's factor-not-found answer counts as
     * already deleted; a missing user or any other answer is a failure.
     * @returns {Promise<'deleted' | 'not_found'>}
     */
    async deleteFactor(userId, factorId) {
      const response = await call('delete_factor', 'DELETE', `${USERS}/${userId}/factors/${factorId}`);
      if (response.status === 200) return 'deleted';
      if (response.status === 404 && errorCode(response) === 'mfa_factor_not_found') return 'not_found';
      throw unexpected('delete_factor', response);
    },
  });
}
