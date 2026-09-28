// The integrated server library (unchanged) against the development fixture:
// its JWKS, live-session check and effective_access read accept the fixture's
// tokens and answers. Synthetic fixture evidence of wire compatibility only.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createAuthServer } from '../../packages/server/index.js';
import { can } from '@briqvent/dwarpal';
import { liveStudio, raiseToAal2, randomUuid, signedIn, start } from './support.js';

const bearer = async (supabase) => ({ headers: { authorization: `Bearer ${(await supabase.auth.getSession()).data.session.access_token}` } });

test('resolveSession builds the principal from fixture tokens; a globally signed-out token is refused on the Node path (L25a)', async (t) => {
  const emulator = await start(t);
  const { steward } = await liveStudio(emulator);
  const fixtureNow = () => Date.parse(emulator.controls.snapshot().now);
  const server = createAuthServer({ supabaseUrl: emulator.origin, publishableKey: emulator.publishableKey, clientId: 'studio', now: fixtureNow });
  const user = await signedIn(emulator, 'node@example.test');
  await user.kit.rpc('join_client', { client_id: 'studio' });

  const principal = await server.resolveSession(await bearer(user.supabase));
  assert.equal(principal.identity.userId, user.userId);
  assert.equal(principal.session.aal, 'aal1');
  assert.deepEqual(principal.access.activeRoles, ['member', 'reader']);
  assert.ok(can(principal, 'records:read:own'));
  assert.ok(!can(principal, 'records:read:any'));

  await raiseToAal2(emulator, steward.supabase, steward.factorId);
  const request = await bearer(steward.supabase);
  const granted = await server.grantMembership(user.userId, 'curator', randomUuid(), request);
  assert.equal(granted.result, 'granted');

  const stale = await bearer(user.supabase);
  await user.supabase.auth.signOut();
  await assert.rejects(server.resolveSession(stale), (error) => error.code === 'invalid_token');
});
