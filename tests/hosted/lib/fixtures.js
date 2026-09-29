// Per-run clients and models. Every client id carries the run prefix, so
// runs never share kit state except for the fixed `rls-demo` client that the
// example consumer's policies name. Models are stated here, next to the
// cases that depend on their exact roles and keys.

import fs from 'node:fs';
import path from 'node:path';
import { PUBLIC_ROOT } from './paths.js';

export const RLS_CLIENT = 'rls-demo';

export function clientIds(runId) {
  const p = `hv${runId}`;
  return { A: `${p}-a`, B: `${p}-b`, D: `${p}-d`, E: `${p}-e`, F: `${p}-f`, F2: `${p}-f2`, G: `${p}-g`, R: `${p}-r`, RLS: RLS_CLIENT };
}

function readModel(rel) {
  return JSON.parse(fs.readFileSync(path.join(PUBLIC_ROOT, rel), 'utf8'));
}

/** The example model (examples/creditone) under another client id. */
export function exampleModel(clientId) {
  return { ...readModel('examples/creditone/auth-model.json'), client: clientId };
}

/** The example model changed: one key added to staff, one customer key unmapped and removed. */
export function changedModel(clientId) {
  const m = structuredClone(exampleModel(clientId));
  m.permissions['reports:read:any'] = 'read reports';
  m.roles.staff.permissions = [...m.roles.staff.permissions, 'reports:read:any'];
  m.roles.customer.permissions = m.roles.customer.permissions.filter((k) => k !== 'documents:download:own');
  delete m.permissions['documents:download:own'];
  for (const role of Object.values(m.roles)) role.permissions = role.permissions.filter((k) => k !== 'documents:download:own');
  return m;
}

export function rlsModel() {
  return readModel('examples/rls-consumer/auth-model.json');
}

/** L34: two manager roles, one without and one with MFA. */
export function managersModel(clientId) {
  return {
    client: clientId,
    roles: {
      lead: { manages_members: true, permissions: ['members:manage', 'items:read:any'] },
      chief: { manages_members: true, mfa_required: true, permissions: ['members:manage', 'items:read:any'] },
      worker: { permissions: ['items:read:any'] },
      member: { self_assignable: true, permissions: ['items:read:own'] },
    },
    permissions: { 'members:manage': 'grant and revoke', 'items:read:any': 'all items', 'items:read:own': 'own items' },
  };
}

/** L27 enrollment client; `withExtra` adds a second self-assignable role. */
export function enrollModel(clientId, { withExtra = false } = {}) {
  const m = {
    client: clientId,
    roles: {
      keeper: { manages_members: true, permissions: ['members:manage'] },
      member: { self_assignable: true, permissions: ['e:read:own'] },
    },
    permissions: { 'members:manage': 'grant and revoke', 'e:read:own': 'own entries' },
  };
  if (withExtra) {
    m.roles.extra = { self_assignable: true, permissions: ['e:extra:own'] };
    m.permissions['e:extra:own'] = 'extra entries';
  }
  return m;
}

/** L29 base model and its two refused-on-live variants. */
export function l29Model(clientId, variant = 'base') {
  const m = {
    client: clientId,
    roles: {
      admin: { manages_members: true, permissions: ['members:manage', 'x:read:any'] },
      staff: { permissions: ['x:read:any'] },
      member: { self_assignable: true, permissions: ['x:read:own'] },
    },
    permissions: { 'members:manage': 'grant and revoke', 'x:read:any': 'all', 'x:read:own': 'own' },
  };
  if (variant === 'no_manager') {
    // admin keeps its holders but no longer manages; the only manager role has none.
    m.roles.admin = { permissions: ['x:read:any'] };
    m.roles.owner = { manages_members: true, permissions: ['members:manage'] };
  } else if (variant === 'promotion') {
    m.roles.staff = { manages_members: true, permissions: ['members:manage', 'x:read:any'] };
  } else if (variant !== 'base') {
    throw new TypeError(`unknown L29 variant ${variant}`);
  }
  return m;
}

/** L30 requests client: a manager role without MFA so every command runs at aal1. */
export function requestsModel(clientId, { extraKey = false } = {}) {
  const m = {
    client: clientId,
    roles: {
      steward: { manages_members: true, permissions: ['members:manage'] },
      helper: { permissions: ['r:read:any'] },
      visitor: { self_assignable: true, permissions: ['r:read:own'] },
    },
    permissions: { 'members:manage': 'grant and revoke', 'r:read:any': 'all', 'r:read:own': 'own' },
  };
  if (extraKey) {
    m.permissions['r:write:any'] = 'write';
    m.roles.helper.permissions = [...m.roles.helper.permissions, 'r:write:any'];
  }
  return m;
}
