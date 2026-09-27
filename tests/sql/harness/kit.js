// Domain helpers for the SQL gates: kit calls through the real wrappers as the
// real roles, a synthetic example model, and whole-state snapshots used to
// prove that a refused or replayed call wrote nothing.

import { actors, jsonLit, arrayLit, sqlArg, uuid } from './db.js';

export const service = actors.service();

/** A synthetic model: two manager roles (one MFA), an MFA role, two self-assignable roles. */
export function exampleModel(client = 'studio') {
  return {
    client,
    roles: {
      owner: { manages_members: true, mfa_required: true, description: 'runs the studio',
        permissions: ['members:manage', 'posts:edit:any', 'posts:publish', 'reports:read'] },
      steward: { manages_members: true, permissions: ['members:manage', 'posts:edit:any'] },
      editor: { mfa_required: true, permissions: ['posts:edit:any', 'posts:publish'] },
      member: { self_assignable: true, permissions: ['posts:edit:own', 'posts:read'] },
      reader: { self_assignable: true, permissions: ['posts:read'] },
    },
    permissions: {
      'members:manage': 'grant and revoke non-manager roles',
      'posts:edit:any': 'edit any post',
      'posts:edit:own': 'edit posts the user authored',
      'posts:publish': '',
      'posts:read': '',
      'reports:read': 'read reports',
    },
  };
}

export function register(db, client, { name = 'Example client', policy = 'open' } = {}) {
  return db.call(service, 'auth_kit.register_client', { client_id: client, display_name: name, signup_policy: policy });
}

export function applyModel(db, client, model, { requestId = uuid(), dryRun = false, actor = service } = {}) {
  return db.call(actor, 'auth_kit.apply_model', { client_id: client, model: sqlArg(jsonLit(JSON.stringify(model))), request_id: requestId, dry_run: dryRun });
}

export function exportModel(db, client) {
  return db.call(service, 'auth_kit.export_model', { client_id: client });
}

export function bootstrap(db, userId, client, role, requestId = uuid()) {
  return db.call(service, 'auth_kit.bootstrap_manager', { user_id: userId, client_id: client, role_key: role, request_id: requestId });
}

export function revokeManager(db, userId, client, role, requestId = uuid()) {
  return db.call(service, 'auth_kit.revoke_manager', { user_id: userId, client_id: client, role_key: role, request_id: requestId });
}

export function grant(db, actor, userId, client, role, requestId = uuid()) {
  return db.call(actor, 'auth_kit.grant_membership', { user_id: userId, client_id: client, role_key: role, request_id: requestId });
}

export function revoke(db, actor, userId, client, role, requestId = uuid()) {
  return db.call(actor, 'auth_kit.revoke_membership', { user_id: userId, client_id: client, role_key: role, request_id: requestId });
}

export function join(db, userId, client, aal = 'aal1') {
  return db.call(actors.user(userId, aal), 'auth_kit.join_client', { client_id: client });
}

export function access(db, userId, client, aal = 'aal1') {
  return db.call(actors.user(userId, aal), 'auth_kit.effective_access', { client_id: client });
}

export function mfaBegin(db, userId, requestId) {
  return db.call(service, 'auth_kit.mfa_reset_begin', { user_id: userId, request_id: requestId });
}

export function mfaNote(db, requestId, token, factors) {
  return db.call(service, 'auth_kit.mfa_reset_note', { request_id: requestId, run_token: token, factor_ids: sqlArg(arrayLit(factors, 'uuid')) });
}

export function mfaFinish(db, requestId, token, deleted) {
  return db.call(service, 'auth_kit.mfa_reset_finish', { request_id: requestId, run_token: token, factors_deleted: sqlArg(arrayLit(deleted, 'uuid')) });
}

/**
 * Registers `client`, applies `model` and bootstraps one confirmed manager per
 * entry of `managers` ({ role }). Returns the manager user ids.
 */
export async function setupClient(db, client, model = exampleModel(client), { managers = [{ role: 'steward' }], policy = 'open' } = {}) {
  await register(db, client, { policy });
  await applyModel(db, client, model);
  const ids = [];
  for (const { role } of managers) {
    const id = await db.createUser();
    await bootstrap(db, id, client, role);
    ids.push(id);
  }
  return ids;
}

const STATE_TABLES = [
  'auth_kit_private.clients', 'auth_kit_private.roles', 'auth_kit_private.permissions', 'auth_kit_private.role_permissions',
  'auth_kit_private.memberships', 'auth_kit_private.enrollments', 'auth_kit_private.membership_events',
  'auth_kit_private.model_events', 'auth_kit_private.request_log', 'auth_kit.profiles',
];

/** Every row of every kit table, for exact before/after comparisons. */
export async function snapshot(db) {
  const parts = STATE_TABLES.map((t) => `'${t}', (select coalesce(jsonb_agg(to_jsonb(x) order by x::text), '[]'::jsonb) from ${t} x)`);
  const rows = await db.rows(`select jsonb_build_object(${parts.join(', ')}) as s`);
  return JSON.parse(rows[0].s);
}

export async function requestRow(db, requestId) {
  const rows = await db.rows(`select to_jsonb(r) as r from auth_kit_private.request_log r where request_id = '${requestId}'`);
  return rows.length ? JSON.parse(rows[0].r) : null;
}

export async function events(db, where = 'true') {
  const rows = await db.rows(`select coalesce(jsonb_agg(to_jsonb(e) order by e.id), '[]'::jsonb) as e from auth_kit_private.membership_events e where ${where}`);
  return JSON.parse(rows[0].e);
}
