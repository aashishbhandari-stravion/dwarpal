import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  AuthError,
  validateModel,
  canonicalModelJson,
  modelHash,
  planModelChange,
} from '@briqvent/dwarpal';

const U1 = '10000000-0000-4000-8000-000000000001';
const U2 = '10000000-0000-4000-8000-000000000002';

function base() {
  return {
    client: 'shop',
    roles: {
      boss: { manages_members: true, mfa_required: true, permissions: ['team:manage', 'items:read:any'] },
      helper: { mfa_required: true, permissions: ['items:read:any'] },
      visitor: { self_assignable: true, permissions: ['items:read:own'] },
    },
    permissions: {
      'team:manage': 'manage people',
      'items:read:any': 'read all',
      'items:read:own': 'read own',
    },
  };
}

function issuesOf(fn) {
  try {
    fn();
  } catch (err) {
    assert.ok(err instanceof AuthError, 'expected AuthError');
    assert.equal(err.code, 'model_invalid');
    return err.issues.map((i) => `${i.path}:${i.rule}`);
  }
  assert.fail('expected model_invalid');
}

test('validateModel returns the canonical form with explicit flags and sorted keys', () => {
  const m = validateModel(base());
  assert.deepEqual(m.roles.visitor, {
    description: '',
    manages_members: false,
    mfa_required: false,
    permissions: ['items:read:own'],
    self_assignable: true,
  });
  assert.deepEqual(m.roles.boss.permissions, ['items:read:any', 'team:manage']);
  assert.ok(Object.isFrozen(m.roles.boss.permissions));
  assert.deepEqual(validateModel(base(), { clientId: 'shop' }), m);
});

test('flags must be real booleans', () => {
  for (const bad of ['true', 1, 0, null, 'false']) {
    const model = base();
    model.roles.helper.mfa_required = bad;
    assert.deepEqual(issuesOf(() => validateModel(model)), ['roles.helper.mfa_required:type']);
  }
});

test('undeclared keys, unknown fields and syntax are refused', () => {
  const undeclared = base();
  undeclared.roles.helper.permissions.push('items:delete:any');
  assert.deepEqual(issuesOf(() => validateModel(undeclared)), ['roles.helper.permissions[1]:undeclared_permission']);

  const extra = base();
  extra.roles.helper.is_admin = true;
  extra.version = 2;
  assert.deepEqual(issuesOf(() => validateModel(extra)).sort(), ['roles.helper.is_admin:unknown_field', 'version:unknown_field']);

  const dup = base();
  dup.roles.boss.permissions.push('team:manage');
  assert.deepEqual(issuesOf(() => validateModel(dup)), ['roles.boss.permissions[2]:duplicate']);

  const syntax = base();
  syntax.roles['bad role'] = { permissions: [] };
  syntax.permissions['with space'] = 'x';
  assert.deepEqual(issuesOf(() => validateModel(syntax)).sort(), ['permissions.<invalid-key>:key_syntax', 'roles.<invalid-key>:key_syntax']);

  assert.deepEqual(issuesOf(() => validateModel({ ...base(), client: 'other' }, { clientId: 'shop' })), ['client:client_mismatch']);
  assert.deepEqual(issuesOf(() => validateModel([])), ['$:not_object']);
  assert.deepEqual(issuesOf(() => validateModel({ roles: {}, permissions: {} })).sort(), ['client:required', 'roles:no_manager_role']);
});

test('self-assignable managers and models without a manager role are refused', () => {
  const selfManager = base();
  selfManager.roles.visitor.manages_members = true;
  assert.deepEqual(issuesOf(() => validateModel(selfManager)), ['roles.visitor:self_assignable_manager']);

  const noManager = base();
  delete noManager.roles.boss;
  assert.deepEqual(issuesOf(() => validateModel(noManager)), ['roles:no_manager_role']);
});

test('canonical JSON and hash ignore key and list order but track content', async () => {
  const a = base();
  const b = {
    permissions: { 'items:read:own': 'read own', 'team:manage': 'manage people', 'items:read:any': 'read all' },
    roles: {
      visitor: { permissions: ['items:read:own'], self_assignable: true, mfa_required: false },
      helper: { permissions: ['items:read:any'], mfa_required: true },
      boss: { permissions: ['items:read:any', 'team:manage'], mfa_required: true, manages_members: true },
    },
    client: 'shop',
  };
  assert.equal(canonicalModelJson(a), canonicalModelJson(b));
  assert.equal(await modelHash(a), await modelHash(b));
  const changed = base();
  changed.permissions['items:read:own'] = 'read own records';
  assert.notEqual(await modelHash(changed), await modelHash(a));
  assert.match(await modelHash(a), /^[0-9a-f]{64}$/);
});

test('unchanged model: empty diff and no refusals (L17)', () => {
  const plan = planModelChange(base(), base(), { state: 'live', holders: { boss: [U1] } });
  assert.equal(plan.changed, false);
  assert.deepEqual(plan.diff, []);
  assert.deepEqual(plan.refusals, []);
});

test('removing a held role is refused with holders; unheld removal is allowed (L18)', () => {
  const next = base();
  delete next.roles.helper;
  const held = planModelChange(base(), next, { state: 'live', holders: { boss: [U1], helper: [U2, U1] } });
  assert.deepEqual(held.refusals, [{ rule: 'role_held', role: 'helper', holders: [U1, U2] }]);
  const free = planModelChange(base(), next, { state: 'live', holders: { boss: [U1] } });
  assert.deepEqual(free.refusals, []);
  assert.deepEqual(free.diff, [{ kind: 'role_removed', role: 'helper' }]);
});

test('removing a still-mapped permission is refused by static validation (L18)', () => {
  const next = base();
  delete next.permissions['items:read:any'];
  assert.throws(() => planModelChange(base(), next, { state: 'registered' }), (err) => err.code === 'model_invalid');
});

test('live client: removing manages_members from the only held manager role is refused (L29)', () => {
  const next = base();
  next.roles.boss.manages_members = false;
  next.roles.helper.manages_members = true;
  const plan = planModelChange(base(), next, { state: 'live', holders: { boss: [U1] } });
  assert.deepEqual(plan.refusals, [{ rule: 'no_manager_would_remain' }]);
  // Same change on a registered client with no holders is accepted.
  const registered = planModelChange(base(), next, { state: 'registered', holders: {} });
  assert.deepEqual(registered.refusals, []);
});

test('promotion by model is refused when the role has holders, even on a registered client (L29)', () => {
  const next = base();
  next.roles.helper.manages_members = true;
  const plan = planModelChange(base(), next, { state: 'live', holders: { boss: [U1], helper: [U2] } });
  assert.deepEqual(plan.refusals, [{ rule: 'promotes_holders', role: 'helper', holders: [U2] }]);
  const registeredHeld = planModelChange(base(), next, { state: 'registered', holders: { helper: [U2] } });
  assert.deepEqual(registeredHeld.refusals, [{ rule: 'promotes_holders', role: 'helper', holders: [U2] }]);
  const registeredFree = planModelChange(base(), next, { state: 'registered' });
  assert.deepEqual(registeredFree.refusals, []);
});

test('live client with no assigned manager at all is refused; a new manager role cannot count', () => {
  const next = base();
  next.roles.chief = { manages_members: true, permissions: ['team:manage'] };
  const plan = planModelChange(base(), next, { state: 'live', holders: {} });
  assert.deepEqual(plan.refusals, [{ rule: 'no_manager_would_remain' }]);
});

test('diff annotates reach: future joiners for self-assignable, holders for mappings', () => {
  const next = base();
  next.roles.helper.self_assignable = true;
  next.roles.helper.permissions.push('items:read:own');
  next.roles.guest = { self_assignable: true, permissions: [] };
  next.permissions['items:read:all'] = 'renamed';
  next.roles.boss.permissions = ['team:manage', 'items:read:all'];
  const plan = planModelChange(base(), next, { state: 'live', holders: { boss: [U1], helper: [U2] } });
  assert.deepEqual(plan.refusals, []);
  assert.deepEqual(plan.diff, [
    { kind: 'permission_added', permission: 'items:read:all' },
    { kind: 'mapping_removed', role: 'boss', permission: 'items:read:any', reach: { holders: 1 } },
    { kind: 'mapping_added', role: 'boss', permission: 'items:read:all', reach: { holders: 1 } },
    { kind: 'role_added', role: 'guest', reach: 'future_joiners' },
    { kind: 'role_flag_changed', role: 'helper', flag: 'self_assignable', from: false, to: true, reach: 'future_joiners' },
    { kind: 'mapping_added', role: 'helper', permission: 'items:read:own', reach: { holders: 1 } },
  ]);
});

test('first apply against no current model lists every addition', () => {
  const plan = planModelChange(null, base(), { state: 'registered' });
  assert.equal(plan.changed, true);
  assert.equal(plan.diff.filter((d) => d.kind === 'role_added').length, 3);
  assert.equal(plan.diff.filter((d) => d.kind === 'permission_added').length, 3);
});

test('planModelChange validates its context', () => {
  const bad = [
    [{ state: 'archived' }, 'context.state:type'],
    [{ state: 'live', holders: { ghost: [U1] } }, 'context.holders.ghost:unknown_role'],
    [{ state: 'live', holders: { boss: ['not-a-uuid'] } }, 'context.holders.boss:type'],
    [{ state: 'live', holders: [] }, 'context.holders:not_object'],
  ];
  for (const [context, expected] of bad) {
    assert.deepEqual(issuesOf(() => planModelChange(base(), base(), context)), [expected]);
  }
  assert.deepEqual(issuesOf(() => planModelChange(base(), { ...base(), client: 'other' }, { state: 'live' })), ['next.client:client_mismatch']);
});
