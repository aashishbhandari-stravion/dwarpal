// Permission model: static validation, canonical form, hash and the pure
// comparison used to preview or refuse a change. The database repeats every
// rule authoritatively under its per-client lock; this module lets the CLI and
// tests reach the same verdict from the same inputs without I/O.

import { AuthError } from './errors.js';
import { canonicalJson, sha256Hex } from './canonical.js';
import {
  CLIENT_ID_PATTERN,
  ROLE_KEY_PATTERN,
  PERMISSION_KEY_PATTERN,
  UUID_PATTERN,
  isPlainObject,
  extraKeys,
  safeSegment,
  deepFreeze,
  sortedUnique,
  compareCodeUnits,
} from './shape.js';

export const ROLE_FLAGS = Object.freeze(['self_assignable', 'manages_members', 'mfa_required']);
export const CLIENT_STATES = Object.freeze(['registered', 'live']);

const MODEL_FIELDS = ['client', 'roles', 'permissions'];
const ROLE_FIELDS = ['description', 'permissions', ...ROLE_FLAGS];
const MAX_ROLES = 256;
const MAX_PERMISSIONS = 2048;
const MAX_DESCRIPTION = 1024;

/**
 * Validates a model file and returns its frozen canonical form.
 * @param {unknown} model
 * @param {{ clientId?: string }} [options] when given, `model.client` must equal it
 * @returns {import('./index.js').CanonicalModel}
 */
export function validateModel(model, options = {}) {
  const issues = [];
  const result = checkModel(model, '', issues);
  if (result && options.clientId !== undefined && result.client !== options.clientId) {
    issues.push({ path: 'client', rule: 'client_mismatch' });
  }
  if (issues.length > 0) throw new AuthError('model_invalid', { issues });
  return deepFreeze(result);
}

/** Canonical JSON text of a valid model; the bytes the model hash covers. */
export function canonicalModelJson(model) {
  return canonicalJson(validateModel(model));
}

/** sha256 hex of the canonical model JSON. */
export function modelHash(model) {
  return sha256Hex(canonicalModelJson(model));
}

function checkModel(model, prefix, issues) {
  if (!isPlainObject(model)) {
    issues.push({ path: prefix || '$', rule: 'not_object' });
    return null;
  }
  for (const key of extraKeys(model, MODEL_FIELDS)) {
    issues.push({ path: join(prefix, safeSegment(key, ROLE_KEY_PATTERN)), rule: 'unknown_field' });
  }
  if (typeof model.client !== 'string' || !CLIENT_ID_PATTERN.test(model.client)) {
    issues.push({ path: join(prefix, 'client'), rule: model.client === undefined ? 'required' : 'key_syntax' });
  }
  const permissions = checkPermissions(model.permissions, join(prefix, 'permissions'), issues);
  const roles = checkRoles(model.roles, join(prefix, 'roles'), permissions, issues);
  // Judge the manager rule only when every role parsed; otherwise an invalid
  // manager role would also be reported as a missing one.
  const allRolesParsed = roles && Object.keys(roles).length === Object.keys(model.roles).length;
  if (allRolesParsed && !Object.values(roles).some((role) => role.manages_members)) {
    issues.push({ path: join(prefix, 'roles'), rule: 'no_manager_role' });
  }
  if (issues.length > 0) return null;
  return { client: model.client, roles, permissions };
}

function checkPermissions(value, path, issues) {
  if (!isPlainObject(value)) {
    issues.push({ path, rule: value === undefined ? 'required' : 'not_object' });
    return null;
  }
  const keys = Object.keys(value);
  if (keys.length > MAX_PERMISSIONS) {
    issues.push({ path, rule: 'too_many' });
    return null;
  }
  const out = {};
  for (const key of keys.sort(compareCodeUnits)) {
    const keyPath = join(path, safeSegment(key, PERMISSION_KEY_PATTERN));
    if (!PERMISSION_KEY_PATTERN.test(key)) {
      issues.push({ path: keyPath, rule: 'key_syntax' });
      continue;
    }
    const description = value[key];
    if (typeof description !== 'string') issues.push({ path: keyPath, rule: 'type' });
    else if (description.length > MAX_DESCRIPTION) issues.push({ path: keyPath, rule: 'too_long' });
    else out[key] = description;
  }
  return out;
}

function checkRoles(value, path, permissions, issues) {
  if (!isPlainObject(value)) {
    issues.push({ path, rule: value === undefined ? 'required' : 'not_object' });
    return null;
  }
  const keys = Object.keys(value);
  if (keys.length > MAX_ROLES) {
    issues.push({ path, rule: 'too_many' });
    return null;
  }
  const out = {};
  for (const key of keys.sort(compareCodeUnits)) {
    const rolePath = join(path, safeSegment(key, ROLE_KEY_PATTERN));
    if (!ROLE_KEY_PATTERN.test(key)) {
      issues.push({ path: rolePath, rule: 'key_syntax' });
      continue;
    }
    const role = checkRole(value[key], rolePath, permissions, issues);
    if (role) out[key] = role;
  }
  return out;
}

function checkRole(role, path, permissions, issues) {
  if (!isPlainObject(role)) {
    issues.push({ path, rule: 'not_object' });
    return null;
  }
  const before = issues.length;
  for (const key of extraKeys(role, ROLE_FIELDS)) {
    issues.push({ path: join(path, safeSegment(key, ROLE_KEY_PATTERN)), rule: 'unknown_field' });
  }
  const flags = {};
  for (const flag of ROLE_FLAGS) {
    const flagValue = role[flag] === undefined ? false : role[flag];
    // Booleans only: "true", 1 or null must never acquire a meaning.
    if (typeof flagValue !== 'boolean') issues.push({ path: join(path, flag), rule: 'type' });
    flags[flag] = flagValue;
  }
  if (flags.self_assignable === true && flags.manages_members === true) {
    // Public join grants self-assignable roles, so such a role would let any
    // verified user manage members.
    issues.push({ path, rule: 'self_assignable_manager' });
  }
  const description = role.description === undefined ? '' : role.description;
  if (typeof description !== 'string') issues.push({ path: join(path, 'description'), rule: 'type' });
  else if (description.length > MAX_DESCRIPTION) issues.push({ path: join(path, 'description'), rule: 'too_long' });

  const listPath = join(path, 'permissions');
  const list = role.permissions === undefined ? [] : role.permissions;
  if (!Array.isArray(list)) {
    issues.push({ path: listPath, rule: 'type' });
  } else {
    const seen = new Set();
    list.forEach((key, index) => {
      const itemPath = `${listPath}[${index}]`;
      if (typeof key !== 'string' || !PERMISSION_KEY_PATTERN.test(key)) issues.push({ path: itemPath, rule: 'key_syntax' });
      else if (seen.has(key)) issues.push({ path: itemPath, rule: 'duplicate' });
      // A typo must not silently create a permission: every mapped key is declared.
      else if (permissions && !Object.hasOwn(permissions, key)) issues.push({ path: itemPath, rule: 'undeclared_permission' });
      seen.add(key);
    });
  }
  if (issues.length > before) return null;
  return {
    description,
    manages_members: flags.manages_members,
    mfa_required: flags.mfa_required,
    permissions: sortedUnique(list),
    self_assignable: flags.self_assignable,
  };
}

function join(prefix, segment) {
  return prefix ? `${prefix}.${segment}` : segment;
}

/**
 * Compares the current model with a proposed one. Pure: the caller supplies
 * the client state and current holders read under the same lock that the
 * write will take.
 *
 * @param {unknown} current current model, or null when none is applied yet
 * @param {unknown} next proposed model
 * @param {{ state: 'registered' | 'live', holders?: Record<string, string[]> }} context
 * @returns {import('./index.js').ModelChangePlan}
 */
export function planModelChange(current, next, context) {
  const issues = [];
  const cur = current === null ? null : checkModel(current, 'current', issues);
  const nxt = checkModel(next, 'next', issues);
  if (cur && nxt && cur.client !== nxt.client) issues.push({ path: 'next.client', rule: 'client_mismatch' });
  const state = isPlainObject(context) ? context.state : undefined;
  if (!CLIENT_STATES.includes(state)) issues.push({ path: 'context.state', rule: 'type' });
  const holders = checkHolders(isPlainObject(context) ? context.holders : undefined, cur, issues);
  if (issues.length > 0) throw new AuthError('model_invalid', { issues });

  const before = cur ?? { roles: {}, permissions: {} };
  const holderCount = (role) => (holders[role] ? holders[role].length : 0);
  const diff = [];
  const refusals = [];

  for (const key of Object.keys(before.permissions)) {
    if (!Object.hasOwn(nxt.permissions, key)) diff.push({ kind: 'permission_removed', permission: key });
    else if (before.permissions[key] !== nxt.permissions[key]) diff.push({ kind: 'permission_description_changed', permission: key });
  }
  for (const key of Object.keys(nxt.permissions)) {
    if (!Object.hasOwn(before.permissions, key)) diff.push({ kind: 'permission_added', permission: key });
  }

  for (const role of Object.keys(before.roles)) {
    if (Object.hasOwn(nxt.roles, role)) continue;
    diff.push({ kind: 'role_removed', role });
    if (holderCount(role) > 0) refusals.push({ rule: 'role_held', role, holders: holders[role] });
  }
  for (const role of Object.keys(nxt.roles)) {
    const after = nxt.roles[role];
    const prior = before.roles[role];
    if (!prior) {
      diff.push(after.self_assignable ? { kind: 'role_added', role, reach: 'future_joiners' } : { kind: 'role_added', role });
      for (const permission of after.permissions) diff.push({ kind: 'mapping_added', role, permission, reach: { holders: 0 } });
      continue;
    }
    for (const flag of ROLE_FLAGS) {
      if (prior[flag] === after[flag]) continue;
      // Enrollment is once per user, so a self-assignable change reaches only
      // users who have not joined yet.
      const reach = flag === 'self_assignable' ? 'future_joiners' : { holders: holderCount(role) };
      diff.push({ kind: 'role_flag_changed', role, flag, from: prior[flag], to: after[flag], reach });
      if (flag === 'manages_members' && after[flag] && holderCount(role) > 0) {
        // Promotion to a manager role is operator-only via bootstrap; a model
        // change must not promote everyone who already holds the role.
        refusals.push({ rule: 'promotes_holders', role, holders: holders[role] });
      }
    }
    if (prior.description !== after.description) diff.push({ kind: 'role_description_changed', role });
    for (const permission of prior.permissions) {
      if (!after.permissions.includes(permission)) diff.push({ kind: 'mapping_removed', role, permission, reach: { holders: holderCount(role) } });
    }
    for (const permission of after.permissions) {
      if (!prior.permissions.includes(permission)) diff.push({ kind: 'mapping_added', role, permission, reach: { holders: holderCount(role) } });
    }
  }

  if (state === 'live') {
    const managerRemains = Object.keys(nxt.roles).some(
      (role) => nxt.roles[role].manages_members && before.roles[role]?.manages_members && holderCount(role) > 0,
    );
    if (!managerRemains) refusals.push({ rule: 'no_manager_would_remain' });
  }

  return deepFreeze({ changed: diff.length > 0, diff, refusals, model: nxt });
}

function checkHolders(value, current, issues) {
  if (value === undefined) return {};
  if (!isPlainObject(value)) {
    issues.push({ path: 'context.holders', rule: 'not_object' });
    return {};
  }
  const out = {};
  for (const role of Object.keys(value)) {
    const path = `context.holders.${safeSegment(role, ROLE_KEY_PATTERN)}`;
    // Memberships reference roles by foreign key, so a holder of a role the
    // current model lacks means the snapshot is inconsistent.
    if (!current || !Object.hasOwn(current.roles, role)) {
      issues.push({ path, rule: 'unknown_role' });
      continue;
    }
    const list = value[role];
    if (!Array.isArray(list) || !list.every((id) => typeof id === 'string' && UUID_PATTERN.test(id))) {
      issues.push({ path, rule: 'type' });
      continue;
    }
    if (list.length > 0) out[role] = sortedUnique(list.map((id) => id.toLowerCase()));
  }
  return out;
}
