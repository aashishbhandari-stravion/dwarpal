// Shared helpers for the emulator tests. Everything here is synthetic: the
// fixture's answers are fixture evidence, not hosted Supabase proof. Requests
// come from the exact pinned @supabase/supabase-js 2.117.2 (asserted below),
// installed without saving for these checks.

import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
import { createClient } from '@supabase/supabase-js';
import { startAuthEmulator } from '../../packages/emulator/index.js';

export const SUPABASE_JS_VERSION = '2.117.2';
const require = createRequire(import.meta.url);
for (const name of ['supabase-js', 'auth-js', 'postgrest-js']) {
  assert.equal(require(`@supabase/${name}/package.json`).version, SUPABASE_JS_VERSION, `@supabase/${name} must be exactly ${SUPABASE_JS_VERSION}`);
}

export const PASSWORD = 'fixture-password-1';

/** A generic synthetic model: one MFA manager role, one plain manager role, one MFA role, two self-assignable roles. */
export function studioModel(client = 'studio') {
  return {
    client,
    roles: {
      steward: { manages_members: true, mfa_required: true, permissions: ['people:manage', 'records:read:any'] },
      convener: { manages_members: true, permissions: ['people:manage'] },
      curator: { mfa_required: true, permissions: ['records:read:any', 'records:update:any'] },
      member: { self_assignable: true, permissions: ['records:read:own'] },
      reader: { self_assignable: true, permissions: ['records:read:own', 'files:read:own'] },
    },
    permissions: {
      'people:manage': 'grant and revoke non-manager roles',
      'records:read:own': 'read own records',
      'records:read:any': 'read any record',
      'records:update:any': 'update any record',
      'files:read:own': 'read own files',
    },
  };
}

/** Starts a fixture that is closed when the test ends. */
export async function start(t, options) {
  const emulator = await startAuthEmulator(options);
  t.after(() => emulator.close());
  return emulator;
}

export function memoryStorage() {
  const items = new Map();
  return {
    items,
    getItem: (key) => (items.has(key) ? items.get(key) : null),
    setItem: (key, value) => { items.set(key, value); },
    removeItem: (key) => { items.delete(key); },
  };
}

let clientCount = 0;
/** A supabase-js client as the browser kit configures it: PKCE, no auto refresh, no URL detection. */
export function client(emulator, auth = {}) {
  clientCount += 1;
  return createClient(emulator.origin, emulator.publishableKey, {
    auth: {
      storage: memoryStorage(), storageKey: `fixture-${clientCount}`, autoRefreshToken: false,
      detectSessionInUrl: false, flowType: 'pkce', persistSession: true, ...auth,
    },
  });
}

/** Seeds a confirmed user and returns a signed-in client for them. */
export async function signedIn(emulator, email, { aal = 'aal1', password = PASSWORD } = {}) {
  const seeded = emulator.controls.seedUser({ email, password, aal });
  const supabase = client(emulator);
  const { error } = await supabase.auth.signInWithPassword({ email, password });
  assert.equal(error, null);
  return { supabase, kit: supabase.schema('auth_kit'), ...seeded };
}

/** Raises a signed-in client's session to aal2 through challenge and verify. */
export async function raiseToAal2(emulator, supabase, factorId) {
  const challenge = await supabase.auth.mfa.challenge({ factorId });
  assert.equal(challenge.error, null);
  const verified = await supabase.auth.mfa.verify({ factorId, challengeId: challenge.data.id, code: emulator.controls.totpCode({ factorId }) });
  assert.equal(verified.error, null);
  return verified.data;
}

/** A live client with a steward manager at aal2 capability and a convener manager without MFA. */
export async function liveStudio(emulator, clientId = 'studio') {
  const steward = await signedIn(emulator, `steward@${clientId}.example.test`, { aal: 'aal2' });
  emulator.controls.seedClient({ clientId, signupPolicy: 'open', model: studioModel(clientId), state: 'live', managerUserId: steward.userId, managerRoleKey: 'steward' });
  return { steward };
}

export function clientSnapshot(emulator, clientId = 'studio') {
  return emulator.controls.snapshot().clients.find((c) => c.clientId === clientId);
}

/** Raw request to the fixture with the publishable key unless headers override it. */
export function raw(emulator, path, { method = 'GET', headers = {}, body } = {}) {
  // An undefined header value removes the header (fetch would send the text "undefined").
  const merged = { apikey: emulator.publishableKey, ...(body === undefined ? {} : { 'content-type': 'application/json' }), ...headers };
  return fetch(`${emulator.origin}${path}`, {
    method,
    redirect: 'manual',
    headers: Object.fromEntries(Object.entries(merged).filter(([, value]) => value !== undefined)),
    body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
  });
}

export function randomUuid() {
  return globalThis.crypto.randomUUID();
}
