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

// Issue paths name caller-chosen keys by position in canonical key order
// (roles: boss #0, helper #1, visitor #2), never by the key itself.

test('flags must be real booleans', () => {
  for (const bad of ['true', 1, 0, null, 'false']) {
    const model = base();
    model.roles.helper.mfa_required = bad;
    assert.deepEqual(issuesOf(() => validateModel(model)), ['roles.#1.mfa_required:type']);
  }
});

test('undeclared keys, unknown fields and invalid keys are refused', () => {
  const undeclared = base();
  undeclared.roles.helper.permissions.push('items:delete:any');
  assert.deepEqual(issuesOf(() => validateModel(undeclared)), ['roles.#1.permissions[1]:undeclared_permission']);

  const extra = base();
  extra.roles.helper.is_admin = true;
  extra.version = 2;
  // is_admin is #0 of helper's own keys; version is #3 of the model's.
  assert.deepEqual(issuesOf(() => validateModel(extra)).sort(), ['#3:unknown_field', 'roles.#1.#0:unknown_field']);

  const dup = base();
  dup.roles.boss.permissions.push('team:manage');
  assert.deepEqual(issuesOf(() => validateModel(dup)), ['roles.#0.permissions[2]:duplicate']);

  // Keys are opaque; only a non-string, NUL or an unpaired surrogate is invalid.
  const invalid = base();
  invalid.roles['r\u0000'] = { permissions: [] };
  invalid.permissions['\ud800'] = 'x';
  invalid.roles.helper.permissions.push('a\u0000b', 7);
  assert.deepEqual(issuesOf(() => validateModel(invalid)).sort(), [
    'permissions.#3:invalid_key',
    'roles.#1.permissions[1]:invalid_key',
    'roles.#1.permissions[2]:invalid_key',
    'roles.#2:invalid_key',
  ]);
  for (const bad of [5, null, 'a\u0000b', '\udc00']) {
    assert.deepEqual(issuesOf(() => validateModel({ ...base(), client: bad })), ['client:invalid_key']);
  }

  assert.deepEqual(issuesOf(() => validateModel({ ...base(), client: 'other' }, { clientId: 'shop' })), ['client:client_mismatch']);
  assert.deepEqual(issuesOf(() => validateModel([])), ['$:not_object']);
  assert.deepEqual(issuesOf(() => validateModel({ roles: {}, permissions: {} })).sort(), ['client:required', 'roles:no_manager_role']);
});

test('self-assignable managers and models without a manager role are refused', () => {
  const selfManager = base();
  selfManager.roles.visitor.manages_members = true;
  assert.deepEqual(issuesOf(() => validateModel(selfManager)), ['roles.#2:self_assignable_manager']);

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
  assert.deepEqual(plan.refusals, [{ rule: 'no_manager_would_remain', holders: [U1] }]);
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
  assert.deepEqual(plan.refusals, [{ rule: 'no_manager_would_remain', holders: [] }]);
});

test('last-manager refusal names distinct current manager holders in sorted order (L29)', () => {
  const current = base();
  current.roles.helper.manages_members = true;
  const next = structuredClone(current);
  next.roles.boss.manages_members = false;
  next.roles.helper.manages_members = false;
  next.roles.visitor.manages_members = true;
  next.roles.visitor.self_assignable = false;
  const plan = planModelChange(current, next, {
    state: 'live', holders: { boss: [U2, U1], helper: [U1], visitor: [] },
  });
  assert.deepEqual(plan.refusals, [{ rule: 'no_manager_would_remain', holders: [U1, U2] }]);
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
    [{ state: 'live', holders: { ghost: [U1] } }, 'context.holders.#0:unknown_role'],
    [{ state: 'live', holders: { boss: ['not-a-uuid'] } }, 'context.holders.#0:type'],
    [{ state: 'live', holders: [] }, 'context.holders:not_object'],
  ];
  for (const [context, expected] of bad) {
    assert.deepEqual(issuesOf(() => planModelChange(base(), base(), context)), [expected]);
  }
  assert.deepEqual(issuesOf(() => planModelChange(base(), { ...base(), client: 'other' }, { state: 'live' })), ['next.client:client_mismatch']);
});

// Role and permission keys are opaque, so names that exist on Object.prototype
// are ordinary keys. `__proto__` is defined as an own property, as JSON.parse does.
const INHERITED_NAMES = ['constructor', 'toString', 'valueOf', 'hasOwnProperty', '__proto__'];

function setOwn(object, key, value) {
  Object.defineProperty(object, key, { value, enumerable: true, writable: true, configurable: true });
  return object;
}

function withRole(key, role, model = base()) {
  setOwn(model.roles, key, role);
  return model;
}

test('prototype-named roles are ordinary roles: validation and canonical form', async () => {
  for (const key of INHERITED_NAMES) {
    const m = validateModel(withRole(key, { permissions: ['items:read:own'] }));
    assert.ok(Object.hasOwn(m.roles, key), key);
    assert.deepEqual(m.roles[key].permissions, ['items:read:own'], key);
    assert.equal(Object.getPrototypeOf(m.roles), null, key);
    assert.ok(canonicalModelJson(withRole(key, {})).includes(`${JSON.stringify(key)}:{`), key);
    assert.match(await modelHash(withRole(key, {})), /^[0-9a-f]{64}$/);
    // Absent names are absent, not inherited.
    assert.equal(Object.hasOwn(validateModel(base()).roles, key), false, key);
  }
  const parsed = JSON.parse('{"client":"shop","roles":{"__proto__":{"manages_members":true}},"permissions":{"__proto__":"p"}}');
  const m = validateModel(parsed);
  assert.equal(m.roles.__proto__.manages_members, true);
  assert.equal(m.permissions.__proto__, 'p');
  assert.equal(Object.getPrototypeOf(m.roles), null);
  assert.equal({}.manages_members, undefined, 'Object.prototype untouched');
});

test('adding and removing prototype-named roles plans like any other role', () => {
  for (const key of INHERITED_NAMES) {
    const added = planModelChange(base(), withRole(key, { permissions: ['items:read:own'] }), { state: 'live', holders: { boss: [U1] } });
    assert.deepEqual(added.refusals, [], key);
    assert.deepEqual(added.diff, [
      { kind: 'role_added', role: key },
      { kind: 'mapping_added', role: key, permission: 'items:read:own', reach: { holders: 0 } },
    ], key);

    const unheld = planModelChange(withRole(key, {}), base(), { state: 'live', holders: { boss: [U1] } });
    assert.deepEqual(unheld.diff, [{ kind: 'role_removed', role: key }], key);
    assert.deepEqual(unheld.refusals, [], key);

    const held = planModelChange(withRole(key, {}), base(), { state: 'live', holders: setOwn({ boss: [U1] }, key, [U2]) });
    assert.deepEqual(held.refusals, [{ rule: 'role_held', role: key, holders: [U2] }], key);
  }
});

test('promotion checks count only real holders of prototype-named roles', () => {
  for (const key of INHERITED_NAMES) {
    const promoted = withRole(key, { manages_members: true });
    const free = planModelChange(withRole(key, {}), promoted, { state: 'live', holders: { boss: [U1] } });
    assert.deepEqual(free.refusals, [], key);
    const held = planModelChange(withRole(key, {}), promoted, { state: 'live', holders: setOwn({ boss: [U1] }, key, [U2]) });
    assert.deepEqual(held.refusals, [{ rule: 'promotes_holders', role: key, holders: [U2] }], key);
  }
});

test('an unheld prototype-named manager role never counts as the last manager', () => {
  for (const key of INHERITED_NAMES) {
    const current = withRole(key, { manages_members: true });
    const demoted = withRole(key, { manages_members: true });
    demoted.roles.boss.manages_members = false;
    const plan = planModelChange(current, demoted, { state: 'live', holders: { boss: [U1] } });
    assert.ok(plan.refusals.some((r) => r.rule === 'no_manager_would_remain'), key);

    // When the prototype-named role is the one actually held, it does count.
    const kept = planModelChange(current, demoted, { state: 'live', holders: setOwn({ boss: [U1] }, key, [U2]) });
    assert.deepEqual(kept.refusals, [], key);
    // Demoting the only held manager role is refused although boss stays a manager role.
    const refused = planModelChange(current, withRole(key, { manages_members: false }), { state: 'live', holders: setOwn({}, key, [U2]) });
    assert.deepEqual(refused.refusals, [{ rule: 'no_manager_would_remain', holders: [U2] }], key);
  }
});

test('sparse arrays in a model or holder list are refused, empty lists are not', () => {
  const sparse = base();
  sparse.roles.helper.permissions = Array(1);
  assert.deepEqual(issuesOf(() => validateModel(sparse)), ['roles.#1.permissions:sparse_array']);
  const mixed = base();
  mixed.roles.helper.permissions.length = 2;
  assert.deepEqual(issuesOf(() => validateModel(mixed)), ['roles.#1.permissions:sparse_array']);
  const empty = base();
  empty.roles.helper.permissions = [];
  assert.deepEqual(validateModel(empty).roles.helper.permissions, []);

  const holes = [U1];
  holes.length = 2;
  assert.deepEqual(issuesOf(() => planModelChange(base(), base(), { state: 'live', holders: { boss: holes } })), ['context.holders.#0:sparse_array']);
  assert.deepEqual(planModelChange(base(), base(), { state: 'live', holders: { boss: [U1], helper: [] } }).refusals, []);
});

test('permission and role keys are opaque: declared and mapped is the only rule', async () => {
  const keys = ['invoice/read', 'façade:lire', 'orders:read:own!', '🔑 key', 'x'.repeat(300), 'a\nb'];
  const model = {
    client: 'shop/eu 1',
    roles: { 'Área de gestión': { manages_members: true, permissions: keys }, 'Role.With/Slash': {} },
    permissions: Object.fromEntries(keys.map((key) => [key, 'described'])),
  };
  const m = validateModel(model, { clientId: 'shop/eu 1' });
  assert.deepEqual([...m.roles['Área de gestión'].permissions].sort(), [...keys].sort());
  assert.deepEqual(Object.keys(m.roles).sort(), ['Role.With/Slash', 'Área de gestión']);
  const text = canonicalModelJson(model);
  assert.deepEqual(JSON.parse(text).permissions, Object.fromEntries(keys.map((key) => [key, 'described'])));
  assert.match(await modelHash(model), /^[0-9a-f]{64}$/);
  const plan = planModelChange(null, model, { state: 'registered' });
  assert.equal(plan.diff.filter((d) => d.kind === 'permission_added').length, keys.length);

  // Declared-and-mapped still applies to opaque keys.
  const undeclared = structuredClone(model);
  undeclared.roles['Role.With/Slash'].permissions = ['invoice/write'];
  assert.deepEqual(issuesOf(() => validateModel(undeclared)), ['roles.#0.permissions[0]:undeclared_permission']);
});

// The empty string is a literal key: declared and mapped like any other, never
// a wildcard, a default or an absent value.

test('an explicitly declared and mapped empty permission is canonical and hashed', async () => {
  const model = base();
  model.permissions[''] = 'explicit';
  model.roles.helper.permissions.push('');
  const m = validateModel(model);
  assert.equal(m.permissions[''], 'explicit');
  assert.deepEqual(m.roles.helper.permissions, ['', 'items:read:any']);
  const text = canonicalModelJson(model);
  assert.ok(text.includes('"permissions":{"":"explicit","items:read:any":"read all"'));
  assert.deepEqual(JSON.parse(text).roles.helper.permissions, ['', 'items:read:any']);
  const declaredOnly = base();
  declaredOnly.permissions[''] = 'explicit';
  const hashes = new Set([await modelHash(base()), await modelHash(declaredOnly), await modelHash(model)]);
  assert.equal(hashes.size, 3);

  const plan = planModelChange(declaredOnly, model, { state: 'live', holders: { boss: [U1], helper: [U2] } });
  assert.deepEqual(plan.diff, [{ kind: 'mapping_added', role: 'helper', permission: '', reach: { holders: 1 } }]);
  assert.deepEqual(plan.refusals, []);

  // Mapping it without declaring it, or twice, is refused like any other key.
  const undeclared = base();
  undeclared.roles.helper.permissions.push('');
  assert.deepEqual(issuesOf(() => validateModel(undeclared)), ['roles.#1.permissions[1]:undeclared_permission']);
  const twice = structuredClone(model);
  twice.roles.helper.permissions.push('');
  assert.deepEqual(issuesOf(() => validateModel(twice)), ['roles.#1.permissions[2]:duplicate']);
});

test('an empty client id and an empty role key are literal keys in the model and planner', () => {
  const current = { ...base(), client: '' };
  const model = { ...base(), client: '' };
  model.roles[''] = { permissions: ['items:read:own'] };
  const m = validateModel(model, { clientId: '' });
  assert.equal(m.client, '');
  assert.deepEqual(m.roles[''].permissions, ['items:read:own']);
  assert.deepEqual(issuesOf(() => validateModel(model, { clientId: 'shop' })), ['client:client_mismatch']);
  assert.deepEqual(issuesOf(() => validateModel(base(), { clientId: '' })), ['client:client_mismatch']);
  assert.deepEqual(issuesOf(() => planModelChange(current, base(), { state: 'live' })), ['next.client:client_mismatch']);

  const added = planModelChange(current, model, { state: 'live', holders: { boss: [U1] } });
  assert.deepEqual(added.diff, [
    { kind: 'role_added', role: '' },
    { kind: 'mapping_added', role: '', permission: 'items:read:own', reach: { holders: 0 } },
  ]);
  assert.deepEqual(added.refusals, []);
  const held = planModelChange(model, current, { state: 'live', holders: { boss: [U1], '': [U2] } });
  assert.deepEqual(held.refusals, [{ rule: 'role_held', role: '', holders: [U2] }]);
  const promoted = structuredClone(model);
  promoted.roles[''].manages_members = true;
  assert.deepEqual(planModelChange(model, promoted, { state: 'live', holders: { boss: [U1], '': [U2] } }).refusals, [
    { rule: 'promotes_holders', role: '', holders: [U2] },
  ]);
  // A holder list for an empty role the current model lacks is inconsistent.
  assert.deepEqual(issuesOf(() => planModelChange(current, current, { state: 'live', holders: { '': [U1] } })), ['context.holders.#0:unknown_role']);
});
