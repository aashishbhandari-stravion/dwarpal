// Operator client (`@briqvent/dwarpal/server/operator`, design 4.1). It holds
// the project's secret key in its own instance and never accepts a user
// token: every call it makes is as the service role (PostgREST, Auth admin)
// or, for catalog work, with a Management API token. The CLI is a thin
// wrapper over these methods.
//
// Outcomes: a kit refusal (SQLSTATE DW001) becomes an OperatorError with its
// own code; any other answer to a read is `unavailable`; any other answer to
// a write is `outcome_unknown`, because the write may have committed before
// the answer was lost, and the same request id then returns the stored
// result. Results are validated against the exact wire shape before they are
// reported.

import { isAuthError, validateModel, validateClientConfig, modelHash, canonicalModelJson, sha256Hex } from '../core/index.js';
import { isOpaqueKey, UUID_PATTERN, compareCodeUnits, deepFreeze } from '../core/shape.js';
import { DEFAULT_TIMERS } from './lib/http.js';
import { projectOrigin, secretKeyKind, serverConfigIssues } from './lib/keys.js';
import { callRpc } from './lib/postgrest.js';
import { createAdminApi } from './lib/admin.js';
import { createManagementApi } from './lib/management.js';
import { OperatorError, OPERATOR_ERROR_CODES, isOperatorError } from './lib/operator-error.js';
import { scanForEmail } from './lib/lookup.js';
import { runMfaReset } from './lib/mfa-reset.js';
import { readMigrations, migrate as runMigrations, DEFAULT_MIGRATIONS_DIR } from './lib/migrate.js';
import { runDoctor } from './lib/doctor.js';

export { OperatorError, OPERATOR_ERROR_CODES, isOperatorError };

export const ADMIN_CALL_TIMEOUT_MS = 20_000;
const HASH = /^[0-9a-f]{64}$/;
const EMAIL = /^[^\s@\u0000-\u001f]{1,256}@[^\s@\u0000-\u001f]{1,256}$/;
const ISSUE_PATH = /^[A-Za-z0-9_.#[\]$]{0,256}$/;
const RULE = /^[a-z_]{1,64}$/;

// Refusals each operator wrapper can raise (migration, section 6). Any other
// DW001 code means this client and the database disagree.
const REFUSALS = Object.freeze({
  register_client: ['invalid_argument'],
  apply_model: ['invalid_argument', 'model_invalid', 'model_refused', 'unknown_client', 'request_conflict'],
  export_model: ['invalid_argument', 'unknown_client'],
  bootstrap_manager: ['invalid_argument', 'unknown_client', 'unknown_role', 'not_manager_role', 'unknown_user', 'email_unverified', 'request_conflict'],
  revoke_manager: ['invalid_argument', 'unknown_client', 'unknown_role', 'not_manager_role', 'last_manager', 'request_conflict'],
  mfa_reset_begin: ['invalid_argument', 'request_conflict', 'request_in_progress'],
  mfa_reset_note: ['invalid_argument', 'request_conflict', 'run_superseded'],
  mfa_reset_finish: ['invalid_argument', 'request_conflict', 'run_superseded'],
});

function configIssue(path, rule) {
  return new OperatorError('config_invalid', { issues: [{ path, rule }] });
}

function argument(path) {
  return new OperatorError('invalid_argument', { issues: [{ path, rule: 'invalid' }] });
}

function uuidArg(value, path) {
  if (typeof value !== 'string' || !UUID_PATTERN.test(value)) throw argument(path);
  return value.toLowerCase();
}

function keyArg(value, path) {
  if (!isOpaqueKey(value)) throw argument(path);
  return value;
}

function isObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value, keys) {
  return isObject(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function malformed(stage) {
  return new OperatorError('unavailable', { stage, reason: 'malformed' });
}

// Validation issues keep only structural paths and rule names.
function sanitizeIssues(issues) {
  if (!Array.isArray(issues)) return [];
  return issues.slice(0, 50)
    .filter((issue) => isObject(issue) && typeof issue.path === 'string' && ISSUE_PATH.test(issue.path) && typeof issue.rule === 'string' && RULE.test(issue.rule))
    .map((issue) => ({ path: issue.path, rule: issue.rule }));
}

// Model refusals name a role of the operator's own file; the report refers to
// it by position (`roles.#i`, core's issue-path convention) and keeps the
// holders' user ids, which the operator needs to act.
function sanitizeRefusals(refusals, roleOrder) {
  if (!Array.isArray(refusals)) return [];
  return refusals.slice(0, 50).filter(isObject).map((refusal) => {
    const rule = typeof refusal.rule === 'string' && RULE.test(refusal.rule) ? refusal.rule : 'unknown';
    const out = { rule };
    if (typeof refusal.role === 'string') {
      const position = roleOrder.indexOf(refusal.role);
      out.role = position === -1 ? 'roles.#?' : `roles.#${position}`;
    }
    if (Array.isArray(refusal.holders)) {
      const holders = refusal.holders.filter((id) => typeof id === 'string' && UUID_PATTERN.test(id));
      out.holderCount = holders.length;
      out.holders = holders.slice(0, 50).map((id) => id.toLowerCase());
    }
    return out;
  });
}

/**
 * @param {{ supabaseUrl: string, secretKey: string, fetch?: typeof fetch, timers?: object, monotonicNow?: () => number,
 *           adminTimeoutMs?: number, rpcTimeoutMs?: number, publishableKey?: string,
 *           management?: { token?: string | null, projectRef?: string | null, url?: string } | null,
 *           onWarning?: (code: string) => void }} options
 */
export function createOperatorClient(options) {
  if (!isObject(options)) throw configIssue('$', 'not_object');
  const origin = projectOrigin(options.supabaseUrl);
  if (origin === null) throw configIssue('supabaseUrl', 'not_origin');
  const kind = secretKeyKind(options.secretKey);
  if (kind === null) throw configIssue('secretKey', 'not_secret_key');
  if (kind === 'legacy_service_role') options.onWarning?.('legacy_service_role_key');
  const secretKey = options.secretKey;
  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== 'function') throw configIssue('fetch', 'type');
  const timers = options.timers ?? DEFAULT_TIMERS;
  const monotonicNow = options.monotonicNow ?? (() => performance.now());
  const adminTimeoutMs = options.adminTimeoutMs ?? ADMIN_CALL_TIMEOUT_MS;
  const rpcTimeoutMs = options.rpcTimeoutMs ?? ADMIN_CALL_TIMEOUT_MS;
  for (const [path, value] of [['adminTimeoutMs', adminTimeoutMs], ['rpcTimeoutMs', rpcTimeoutMs]]) {
    if (!Number.isInteger(value) || value < 1 || value > ADMIN_CALL_TIMEOUT_MS) throw configIssue(path, 'out_of_range');
  }
  // Used only by doctor's probe for anon and user calls; a secret key here
  // would silently turn the anon probe into a service-role one.
  const publishableKey = options.publishableKey ?? null;
  if (publishableKey !== null && serverConfigIssues({ clientId: 'x', supabaseUrl: origin, publishableKey }).length > 0) {
    throw configIssue('publishableKey', 'not_publishable_key');
  }
  const admin = createAdminApi({ fetch: fetchImpl, timers, origin, secretKey, timeoutMs: adminTimeoutMs });
  const management = managementFor(options.management, origin, fetchImpl, timers, rpcTimeoutMs);

  // `details` turns a refusal's JSON DETAIL into sanitized fields; without it
  // the detail is dropped.
  async function rpc(fn, args, { write, details }) {
    const outcome = await callRpc({ fetch: fetchImpl, timers, origin, apikey: secretKey, bearer: secretKey, fn, args, timeoutMs: rpcTimeoutMs });
    if (outcome.kind === 'value') return outcome.value;
    if (outcome.kind === 'refusal') {
      if (!REFUSALS[fn].includes(outcome.code)) throw new OperatorError('unavailable', { stage: fn, reason: 'unexpected_refusal' });
      throw new OperatorError(outcome.code, { stage: fn, ...(details ? details(outcome.code, outcome.detail) : {}) });
    }
    throw new OperatorError(write ? 'outcome_unknown' : 'unavailable', { stage: fn, reason: outcome.reason });
  }

  function membershipResult(stage, value, results, expected) {
    if (!exactKeys(value, ['result', 'user_id', 'client_id', 'role_key']) || !results.includes(value.result)
        || typeof value.user_id !== 'string' || value.user_id.toLowerCase() !== expected.userId
        || value.client_id !== expected.clientId || value.role_key !== expected.roleKey) {
      throw malformed(stage);
    }
    return deepFreeze({ result: value.result, userId: expected.userId, clientId: expected.clientId, roleKey: expected.roleKey });
  }

  async function exportModel(clientId) {
    keyArg(clientId, 'clientId');
    const value = await rpc('export_model', { client_id: clientId }, { write: false });
    if (!exactKeys(value, ['client_id', 'model_json', 'model_hash', 'last_applied_hash']) || value.client_id !== clientId
        || !(value.model_json === null || typeof value.model_json === 'string')
        || !(value.model_hash === null || HASH.test(value.model_hash))
        || !(value.last_applied_hash === null || HASH.test(value.last_applied_hash))) {
      throw malformed('export_model');
    }
    if (value.model_json === null) {
      if (value.model_hash !== null) throw malformed('export_model');
    } else {
      // The export is the file text itself: it must be exactly core's
      // canonical form of the model it describes, and hash to model_hash.
      let parsed;
      try {
        parsed = JSON.parse(value.model_json);
      } catch {
        throw malformed('export_model');
      }
      let canonical;
      try {
        canonical = canonicalModelJson(parsed);
      } catch {
        throw new OperatorError('unavailable', { stage: 'export_model', reason: 'noncanonical_export' });
      }
      if (canonical !== value.model_json || (await sha256Hex(value.model_json)) !== value.model_hash) {
        throw new OperatorError('unavailable', { stage: 'export_model', reason: 'noncanonical_export' });
      }
    }
    return deepFreeze({ clientId, modelJson: value.model_json, modelHash: value.model_hash, lastAppliedHash: value.last_applied_hash });
  }

  // A consumer config for this project: core-valid and naming this project's URL.
  function checkConfig(config) {
    let validated;
    try {
      validated = validateClientConfig(config);
    } catch (error) {
      if (isAuthError(error)) throw new OperatorError('config_invalid', { issues: sanitizeIssues(error.issues) });
      throw error;
    }
    if (validated.supabaseUrl !== origin) throw configIssue('supabaseUrl', 'project_mismatch');
    return validated;
  }

  async function lookupByEmail(email, invite) {
    if (typeof email !== 'string' || !EMAIL.test(email)) throw argument('email');
    const { confirmed, unconfirmed } = await scanForEmail(admin, email);
    if (confirmed.length > 1) throw new OperatorError('ambiguous_user', { matches: confirmed.length });
    if (confirmed.length === 1) return { userId: confirmed[0] };
    if (unconfirmed.length > 0) throw new OperatorError('email_unverified', { stage: 'lookup' });
    if (!invite) throw new OperatorError('unknown_user', { stage: 'lookup' });
    const invited = await admin.inviteUserByEmail(email);
    return { setupPending: invited.id };
  }

  return Object.freeze({
    async registerClient({ clientId, displayName, signupPolicy }) {
      keyArg(clientId, 'clientId');
      if (typeof displayName !== 'string' || displayName.length === 0 || displayName.length > 256) throw argument('displayName');
      if (signupPolicy !== 'open' && signupPolicy !== 'closed') throw argument('signupPolicy');
      const value = await rpc('register_client', { client_id: clientId, display_name: displayName, signup_policy: signupPolicy }, { write: true });
      if (!exactKeys(value, ['result', 'client_id', 'state']) || !['registered', 'updated', 'unchanged'].includes(value.result)
          || value.client_id !== clientId || !['registered', 'live'].includes(value.state)) {
        throw malformed('register_client');
      }
      return deepFreeze({ result: value.result, clientId, state: value.state });
    },

    async applyModel(model, { dryRun = false, requestId = null } = {}) {
      let canonical;
      try {
        canonical = validateModel(model);
      } catch (error) {
        if (isAuthError(error) && error.code === 'model_invalid') throw new OperatorError('model_invalid', { stage: 'local', issues: sanitizeIssues(error.issues) });
        throw error;
      }
      const id = dryRun && requestId === null ? null : uuidArg(requestId, 'requestId');
      const localHash = await modelHash(canonical);
      const roleOrder = Object.keys(canonical.roles).sort(compareCodeUnits);
      const details = (code, detail) => (code === 'model_invalid' ? { issues: sanitizeIssues(detail?.issues) }
        : code === 'model_refused' ? { refusals: sanitizeRefusals(detail?.refusals, roleOrder) } : {});
      const value = await rpc('apply_model', { client_id: canonical.client, model: canonical, request_id: id, dry_run: dryRun }, { write: !dryRun, details });
      const expected = dryRun ? ['result', 'model_hash', 'changed', 'diff', 'refusals'] : ['result', 'model_hash', 'diff'];
      const results = dryRun ? ['dry_run'] : ['applied', 'unchanged'];
      if (!exactKeys(value, expected) || !results.includes(value.result) || !HASH.test(value.model_hash) || !Array.isArray(value.diff)
          || (dryRun && (typeof value.changed !== 'boolean' || !Array.isArray(value.refusals)))) {
        throw malformed('apply_model');
      }
      return deepFreeze({
        result: value.result,
        clientId: canonical.client,
        requestId: id,
        modelHash: value.model_hash,
        // The database hashed the same canonical bytes core did; a mismatch is a
        // parity defect the operator must see even though the call succeeded.
        hashMatchesFile: value.model_hash === localHash,
        diff: value.diff,
        ...(dryRun ? { changed: value.changed, refusals: sanitizeRefusals(value.refusals, roleOrder) } : {}),
      });
    },

    exportModel,

    async bootstrapManager({ clientId, roleKey, requestId, userId, email, invite = false }) {
      keyArg(clientId, 'clientId');
      keyArg(roleKey, 'roleKey');
      const id = uuidArg(requestId, 'requestId');
      if ((userId === undefined) === (email === undefined)) throw argument('userId');
      if (invite && email === undefined) throw argument('invite');
      let target = userId === undefined ? undefined : uuidArg(userId, 'userId');
      if (target === undefined) {
        const found = await lookupByEmail(email, invite);
        if (found.setupPending) return deepFreeze({ result: 'setup_pending', userId: found.setupPending, clientId, roleKey });
        target = found.userId;
      }
      // The canonical input is verified with getUserById, even after a lookup.
      const user = await admin.getUserById(target);
      if (user === null || user.anonymous) throw new OperatorError('unknown_user', { stage: 'get_user' });
      if (!user.confirmed) throw new OperatorError('email_unverified', { stage: 'get_user' });
      const value = await rpc('bootstrap_manager', { user_id: target, client_id: clientId, role_key: roleKey, request_id: id }, { write: true });
      return membershipResult('bootstrap_manager', value, ['granted', 'already_member'], { userId: target, clientId, roleKey });
    },

    async revokeManager({ clientId, roleKey, userId, requestId }) {
      keyArg(clientId, 'clientId');
      keyArg(roleKey, 'roleKey');
      const target = uuidArg(userId, 'userId');
      const id = uuidArg(requestId, 'requestId');
      const value = await rpc('revoke_manager', { user_id: target, client_id: clientId, role_key: roleKey, request_id: id }, { write: true });
      return membershipResult('revoke_manager', value, ['revoked', 'not_member'], { userId: target, clientId, roleKey });
    },

    async mfaReset({ userId, requestId }) {
      const target = uuidArg(userId, 'userId');
      const id = uuidArg(requestId, 'requestId');
      return runMfaReset({ userId: target, requestId: id }, {
        rpcWrite: (fn, args) => rpc(fn, args, { write: true }),
        admin,
        monotonicNow,
      });
    },

    checkConfig,

    async migrate({ migrationsDir = DEFAULT_MIGRATIONS_DIR } = {}) {
      if (management === null) throw new OperatorError('prerequisite_missing', { stage: 'migrate', reason: 'management_token_missing' });
      return runMigrations(management, readMigrations(migrationsDir));
    },

    async doctor({ clientId = null, config = null, model = null, probe = null, hostOrigin = null, migrationsDir = DEFAULT_MIGRATIONS_DIR } = {}) {
      let migrations = null;
      try {
        migrations = readMigrations(migrationsDir);
      } catch (error) {
        if (!isOperatorError(error)) throw error;
      }
      const validated = config === null ? null : checkConfig(config);
      const host = hostOrigin === null ? null : projectOrigin(hostOrigin);
      if (hostOrigin !== null && host === null) throw argument('origin');
      return runDoctor(
        { management, exportModel, fetch: fetchImpl, timers, origin, timeoutMs: rpcTimeoutMs, migrations, publishableKey },
        { clientId: clientId ?? validated?.clientId ?? null, config: validated, model, probe, hostOrigin: host },
      );
    },
  });
}

function managementFor(settings, origin, fetchImpl, timers, timeoutMs) {
  if (!settings || !settings.token) return null;
  if (typeof settings.token !== 'string' || !/^[A-Za-z0-9_.-]{1,4096}$/.test(settings.token)) throw configIssue('management.token', 'syntax');
  const baseUrl = projectOrigin(settings.url ?? 'https://api.supabase.com');
  if (baseUrl === null) throw configIssue('management.url', 'not_origin');
  // Hosted project URLs are https://<ref>.supabase.co; a custom domain needs the ref explicitly.
  const ref = settings.projectRef ?? /^https:\/\/([a-z0-9]+)\.supabase\.co$/.exec(origin)?.[1] ?? null;
  if (ref === null) throw new OperatorError('prerequisite_missing', { stage: 'management', reason: 'project_ref_missing' });
  return createManagementApi({ fetch: fetchImpl, timers, baseUrl, token: settings.token, projectRef: ref, timeoutMs });
}
