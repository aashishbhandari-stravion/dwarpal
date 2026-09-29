// Shared world for the example tests: a loopback Auth/RPC emulator (synthetic
// fixture, never hosted proof), the real createAuthServer against it, and the
// protected-consumer example served on an ephemeral loopback port.

import { createServer } from 'node:http';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createAuthServer } from '../../../packages/server/index.js';
import { startAuthEmulator } from '../../../packages/emulator/index.js';
import { createApp } from '../../../examples/protected-consumer/app.js';
import { createStore } from '../../../examples/protected-consumer/store.js';
import { client, raiseToAal2, signedIn } from '../../emulator/support.js';

export const CLIENT_ID = 'protected-demo';
export { raiseToAal2 };

export async function loadModel() {
  return JSON.parse(await readFile(new URL('../../../examples/protected-consumer/auth-model.json', import.meta.url), 'utf8'));
}

/**
 * @param {import('node:test').TestContext} t
 * @param {{ busyTimeoutMs?: number }} [options]
 */
export async function consumerWorld(t, { busyTimeoutMs = 50 } = {}) {
  const emulator = await startAuthEmulator();
  t.after(() => emulator.close());
  const manager = await signedIn(emulator, 'manager@example.test', { aal: 'aal2' });
  emulator.controls.seedClient({
    clientId: CLIENT_ID, signupPolicy: 'open', model: await loadModel(), state: 'live', managerUserId: manager.userId, managerRoleKey: 'manager',
  });
  await raiseToAal2(emulator, manager.supabase, manager.factorId);

  const dir = await mkdtemp(join(tmpdir(), 'dwarpal-consumer-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = join(dir, 'records.sqlite');
  const store = createStore(file, { busyTimeoutMs });
  t.after(() => store.close());

  const auth = createAuthServer({
    supabaseUrl: emulator.origin,
    publishableKey: emulator.publishableKey,
    clientId: CLIENT_ID,
    now: () => Date.parse(emulator.controls.snapshot().now),
  });
  const server = createServer(createApp({ auth, store }));
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((done) => { server.closeAllConnections(); server.close(done); }));
  const origin = `http://127.0.0.1:${server.address().port}`;

  async function token(user) {
    return (await user.supabase.auth.getSession()).data.session.access_token;
  }
  async function call(user, method, path, { headers = {}, rawToken } = {}) {
    const bearer = rawToken ?? (user ? await token(user) : null);
    const response = await fetch(`${origin}${path}`, { method, headers: { ...(bearer ? { authorization: `Bearer ${bearer}` } : {}), ...headers } });
    const text = await response.text();
    return { status: response.status, headers: response.headers, body: text === '' ? null : JSON.parse(text), text };
  }
  /** A confirmed user who has joined the client (and so holds the self-assignable `member` role). */
  async function member(email, { aal = 'aal1' } = {}) {
    const user = await signedIn(emulator, email, { aal });
    const joined = await user.kit.rpc('join_client', { client_id: CLIENT_ID });
    if (joined.error) throw new Error('join failed in test setup');
    return user;
  }
  return { emulator, manager, store, file, origin, call, member, token, client };
}
