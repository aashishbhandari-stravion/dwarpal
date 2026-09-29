// Runs inside a staged copy of examples/protected-consumer whose
// @briqvent/dwarpal comes from the packed tarball (see scripts/check-examples.mjs).
// The example's own app.js and store.js import the installed package by name;
// only the loopback fixture is taken from the repository (REPO_ROOT), because
// the emulator is development-only and never packed. Synthetic fixture
// evidence, not hosted proof.

import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { join } from 'node:path';
import { createClient } from '@supabase/supabase-js';
import { createAuthServer } from '@briqvent/dwarpal/server';
import { validateModel } from '@briqvent/dwarpal';
import { createApp } from './app.js';
import { createStore } from './store.js';

const repo = process.env.REPO_ROOT;
assert.ok(repo, 'REPO_ROOT is required');
const { startAuthEmulator } = await import(pathToFileURL(join(repo, 'packages/emulator/index.js')).href);

const model = validateModel(JSON.parse(await readFile(new URL('./auth-model.json', import.meta.url), 'utf8')));
const emulator = await startAuthEmulator();
const store = createStore(':memory:');
const memoryStorage = () => { const m = new Map(); return { getItem: (k) => m.get(k) ?? null, setItem: (k, v) => m.set(k, v), removeItem: (k) => m.delete(k) }; };
let server;
try {
  emulator.controls.seedClient({ clientId: model.client, signupPolicy: 'open', model });
  const { userId } = emulator.controls.seedUser({ email: 'smoke@example.test', password: 'fixture-password-1' });
  const supabase = createClient(emulator.origin, emulator.publishableKey, { auth: { storage: memoryStorage(), autoRefreshToken: false, detectSessionInUrl: false, flowType: 'pkce' } });
  assert.equal((await supabase.auth.signInWithPassword({ email: 'smoke@example.test', password: 'fixture-password-1' })).error, null);
  assert.equal((await supabase.schema('auth_kit').rpc('join_client', { client_id: model.client })).error, null);
  const token = (await supabase.auth.getSession()).data.session.access_token;

  store.createRecord({ id: 'mine', title: 'linked' });
  store.createRecord({ id: 'other', title: 'not linked' });
  assert.equal(store.link('mine', userId, userId), 'linked');

  const auth = createAuthServer({ supabaseUrl: emulator.origin, publishableKey: emulator.publishableKey, clientId: model.client, now: () => Date.parse(emulator.controls.snapshot().now) });
  server = createServer(createApp({ auth, store }));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const get = (path, bearer) => fetch(`${base}${path}`, { headers: bearer ? { authorization: `Bearer ${bearer}` } : {} });
  assert.equal((await get('/records/mine')).status, 401);
  assert.equal((await get('/records/mine', token)).status, 200);
  assert.equal((await get('/records/other', token)).status, 403);
  console.log('installed-consumer-smoke: protected consumer runs against the installed package (401 / 200 own / 403 other)');
} finally {
  store.close();
  server?.closeAllConnections();
  server?.close();
  await emulator.close();
}
