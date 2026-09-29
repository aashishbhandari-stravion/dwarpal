// The example models and configurations validate with the kit's own validators,
// agree with each other, and the second brand really differs from the first.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { planModelChange, validateClientConfig, validateModel } from '@briqvent/dwarpal';

const EXAMPLES = ['protected-consumer', 'rls-consumer', 'creditone', 'example-studio'];
const load = async (example, name) => JSON.parse(await readFile(new URL(`../../examples/${example}/${name}`, import.meta.url), 'utf8'));

test('every example model is valid, and a fresh client can apply it with a manager', async () => {
  for (const example of EXAMPLES) {
    const model = validateModel(await load(example, 'auth-model.json'));
    const plan = planModelChange(null, model, { state: 'registered' });
    assert.deepEqual(plan.refusals, [], example);
    assert.ok(Object.values(model.roles).some((role) => role.manages_members), `${example} has a manager role`);
    assert.ok(Object.values(model.roles).some((role) => role.self_assignable), `${example} has a self-assignable role`);
    for (const [key, role] of Object.entries(model.roles)) {
      assert.ok(!(role.self_assignable && role.manages_members), `${example}: ${key} is not both`);
    }
  }
});

test('one key means one thing: a scoped key never shares its resource and action with an unscoped one', async () => {
  for (const example of EXAMPLES) {
    const keys = Object.keys(validateModel(await load(example, 'auth-model.json')).permissions);
    const scoped = new Set(keys.filter((key) => /:(?:own|any|self)$/.test(key)).map((key) => key.replace(/:[a-z]+$/, '')));
    for (const key of keys.filter((k) => k.split(':').length === 2)) assert.ok(!scoped.has(key), `${example}: ${key} is also used with a scope`);
    // Whoever holds an ":own" key of an action and the same action's ":any" key is a broader role's holder, never the other way round.
    const model = validateModel(await load(example, 'auth-model.json'));
    for (const [name, role] of Object.entries(model.roles)) {
      if (role.self_assignable) assert.ok(!role.permissions.some((key) => key.endsWith(':any')), `${example}: public sign-up role ${name} holds a broad :any key`);
    }
  }
});

test('the CREDITONE model keeps its frozen semantics: MFA staff, leads:assign:self, no unused own keys', async () => {
  const model = validateModel(await load('creditone', 'auth-model.json'), { clientId: 'creditone' });
  assert.deepEqual(Object.keys(model.roles).sort(), ['admin', 'customer', 'staff']);
  assert.equal(model.roles.admin.mfa_required && model.roles.admin.manages_members, true);
  assert.equal(model.roles.staff.mfa_required, true);
  assert.equal(model.roles.customer.self_assignable, true);
  assert.ok(model.roles.customer.permissions.every((key) => key.endsWith(':own')));
  assert.ok(model.roles.admin.permissions.includes('leads:assign:self') && model.roles.staff.permissions.includes('leads:assign:self'));
  for (const key of ['leads:assign:own', 'leads:create:own', 'orders:create:own']) assert.ok(!(key in model.permissions), `${key} was removed from the model`);
  assert.ok(model.roles.admin.permissions.includes('orders:reopen:any') && !model.roles.staff.permissions.includes('orders:reopen:any'), 'reopen is admin only');
  assert.ok(!model.roles.staff.permissions.includes('leads:assign:any') && !model.roles.staff.permissions.includes('contacts:update:any'));
});

test('the page configurations validate, name their model\'s client, and hold no secret', async () => {
  for (const example of ['creditone', 'example-studio']) {
    const config = await load(example, 'auth-kit.config.json');
    const validated = validateClientConfig(config);
    const model = validateModel(await load(example, 'auth-model.json'));
    assert.equal(validated.clientId, model.client, example);
    assert.match(validated.publishableKey, /^sb_publishable_/);
    assert.ok(!/sb_secret_|sbp_|service_role/.test(JSON.stringify(config)));
  }
  await assert.rejects(async () => validateClientConfig({ ...(await load('creditone', 'auth-kit.config.json')), publishableKey: 'sb_secret_shouldberefused0000' }), (e) => e.code === 'config_invalid');
});

test('the second brand differs in role keys, route prefix, route names and build tool', async () => {
  const [a, b] = await Promise.all(['creditone', 'example-studio'].map(async (example) => ({
    model: validateModel(await load(example, 'auth-model.json')),
    config: validateClientConfig(await load(example, 'auth-kit.config.json')),
    pkg: await load(example, 'package.json'),
  })));
  assert.deepEqual(Object.keys(a.model.roles).filter((key) => key in b.model.roles), [], 'no shared role keys');
  assert.notEqual(a.config.routes.prefix, b.config.routes.prefix);
  assert.notEqual(a.config.routes.signIn, b.config.routes.signIn);
  assert.ok('esbuild' in a.pkg.devDependencies && !('vite' in a.pkg.devDependencies));
  assert.ok('vite' in b.pkg.devDependencies && !('esbuild' in b.pkg.devDependencies));
  assert.notEqual(a.config.brand.name, b.config.brand.name);
});
