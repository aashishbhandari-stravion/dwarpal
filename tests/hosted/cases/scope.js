// L31 client scope on the Node path: a user who manages A and is a customer
// of B, resolved by a server configured for B. Every outbound request the
// server library makes is recorded (URL and body) and none may mention A.

import { attempt, ensureClient, bootstrap, signedInMember } from '../lib/world.js';
import { exampleModel } from '../lib/fixtures.js';

export const procedures = [{
  id: 'scope',
  group: 'scope',
  requiresTargets: ['T.identity', 'T.signing_keys'],
  async run(ctx) {
    await ensureClient(ctx, 'A', { model: exampleModel(ctx.ids.A) });
    await ensureClient(ctx, 'B', { model: exampleModel(ctx.ids.B) });
    await bootstrap(ctx, 'A', 'cross_ab', 'admin');
    const session = await signedInMember(ctx, 'cross_ab', 'B');
    const sent = [];
    const recording = async (input, init = {}) => {
      sent.push(`${typeof input === 'string' ? input : input.url} ${typeof init.body === 'string' ? init.body : ''}`);
      return ctx.gate.fetch(input, init);
    };
    const node = await ctx.hosted.nodeEndpoint(ctx.ids.B, { fetch: recording });
    let response;
    try {
      response = await node.get(session.accessToken);
    } finally {
      await node.close();
    }
    const p = response.body?.principal;
    ctx.observe('L31 outbound requests while resolving', sent.map((line) => line.replace(/\?.*$/, '')));

    await attempt(ctx, 'L31.scoped_principal', async (check) => {
      check.assert('resolved', 200, response.status);
      check.assert('memberships are B\'s only', [{ clientId: ctx.ids.B, roleKey: 'customer' }], (p?.memberships ?? []).map((m) => ({ clientId: m.clientId, roleKey: m.roleKey })));
      check.assert('access is B\'s', { clientId: ctx.ids.B, roles: ['customer'] }, { clientId: p?.access?.clientId, roles: p?.access?.roles });
      check.assert('identity is the user', ctx.actors.get('cross_ab').id, p?.identity?.userId);
    });
    await attempt(ctx, 'L31.no_other_client_call', async (check) => {
      check.assert('requests were made', true, sent.length >= 2);
      check.assert('no request mentions A', [], sent.filter((line) => line.includes(ctx.ids.A)).map(() => 'mentions A'));
    });
  },
}];
