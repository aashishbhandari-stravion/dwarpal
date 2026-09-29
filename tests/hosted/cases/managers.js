// L34 manager authority with two manager roles on client D (design 4.2 R2):
// `lead` manages members without MFA, `chief` with it. Each grant targets a
// different user so an earlier grant cannot turn a later one into a no-op.

import { attempt, ensureClient, bootstrap, signedInMember, managerWrite, counts } from '../lib/world.js';
import { managersModel } from '../lib/fixtures.js';
import { explain } from '../../../packages/core/index.js';

const outcome = (o) => (o.kind === 'value' ? `value:${o.value?.result}` : o.kind === 'refusal' ? `refusal:${o.code}` : `failure:${o.status}`);

export const procedures = [{
  id: 'managers',
  group: 'managers',
  requiresTargets: ['T.identity', 'T.signing_keys', 'T.management', 'T.auth_settings'],
  async run(ctx) {
    const D = ctx.ids.D;
    await ensureClient(ctx, 'D', { model: managersModel(D) });
    await bootstrap(ctx, 'D', 'l34_u1', 'lead');
    await bootstrap(ctx, 'D', 'l34_u1', 'chief');
    await bootstrap(ctx, 'D', 'l34_u2', 'chief');
    await bootstrap(ctx, 'D', 'l34_u3', 'lead');
    const none = await signedInMember(ctx, 'l34_none', 'D');
    for (const t of ['l34_t1', 'l34_t2', 'l34_t3']) await signedInMember(ctx, t, 'D');
    const rowsFor = async (alias) => counts(ctx, { clientId: D, userId: ctx.actors.get(alias).id });

    await attempt(ctx, 'L34.u1', async (check) => {
      const u1 = await ctx.actors.signIn('l34_u1');
      check.assert('U1 at aal1 grants via lead', 'value:granted', outcome(await managerWrite(ctx, 'grant_membership', u1.accessToken, 'D', 'l34_t1', 'worker')));
      const lead = await ctx.hosted.rest.rpc(u1.accessToken, 'has_role', { client_id: D, role_key: 'lead' });
      const chief = await ctx.hosted.rest.rpc(u1.accessToken, 'has_role', { client_id: D, role_key: 'chief' });
      check.assert('has_role lead true, chief false', { lead: true, chief: false }, { lead: lead.value, chief: chief.value });
      const node = await ctx.hosted.nodeEndpoint(D);
      try {
        const r = await node.get(u1.accessToken);
        const e = r.body?.principal ? explain(r.body.principal, 'members:manage') : null;
        check.assert('explain: allowed via lead, chief withheld', { allowed: true, via: ['lead'], withheld: [{ role: 'chief', reason: 'mfa_required' }] }, e);
      } finally {
        await node.close();
      }
    });

    await attempt(ctx, 'L34.u2_aal1', async (check) => {
      const u2 = await ctx.actors.signIn('l34_u2');
      const before = await rowsFor('l34_t2');
      check.assert('U2 at aal1: mfa_required', 'refusal:mfa_required', outcome(await managerWrite(ctx, 'grant_membership', u2.accessToken, 'D', 'l34_t2', 'worker')));
      check.assert('nothing written', before, await rowsFor('l34_t2'));
    });

    await attempt(ctx, 'L34.u3', async (check) => {
      const u3 = await ctx.actors.signIn('l34_u3');
      check.assert('U3 at aal1 grants', 'value:granted', outcome(await managerWrite(ctx, 'grant_membership', u3.accessToken, 'D', 'l34_t3', 'worker')));
    });

    await attempt(ctx, 'L34.u2_aal2', async (check) => {
      const u2 = await ctx.actors.aal2('l34_u2');
      check.assert('U2 at aal2 grants', 'value:granted', outcome(await managerWrite(ctx, 'grant_membership', u2.accessToken, 'D', 'l34_t2', 'worker')));
    });

    await attempt(ctx, 'L34.no_manager', async (check) => {
      const before = await rowsFor('l34_t3');
      check.assert('no manager role: forbidden', 'refusal:forbidden', outcome(await managerWrite(ctx, 'grant_membership', none.accessToken, 'D', 'l34_t3', 'member')));
      check.assert('nothing written', before, await rowsFor('l34_t3'));
    });
  },
}];
