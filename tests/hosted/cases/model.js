// L29 model refusals on a live client and acceptance on a registered one,
// plus apply_model concurrency (design 4.2 apply_model, D17, 8). Refusals
// must name the affected holders and write nothing: the export hash, model
// events and request log for the client are compared before and after.

import { randomUUID } from 'node:crypto';
import { attempt, ensureClient, bootstrap, signedInMember, managerWrite, counts, op } from '../lib/world.js';
import { l29Model } from '../lib/fixtures.js';
import { isOperatorError } from '../../../packages/server/operator.js';

async function refusal(ctx, model) {
  try {
    const r = await op(ctx).applyModel(model, { requestId: randomUUID() });
    return { refused: false, result: r.result };
  } catch (error) {
    if (!isOperatorError(error)) throw error;
    return { refused: true, code: error.code, refusals: error.details?.refusals ?? null };
  }
}

async function snapshot(ctx, clientId) {
  const exported = await op(ctx).exportModel(clientId);
  const c = await counts(ctx, { clientId });
  return { modelHash: exported.modelHash, model_events: c.model_events, request_log: c.request_log, memberships: c.memberships };
}

export const procedures = [{
  id: 'model',
  group: 'model',
  requiresTargets: ['T.identity', 'T.management', 'T.schema'],
  async run(ctx) {
    const F = ctx.ids.F;
    const F2 = ctx.ids.F2;
    await ensureClient(ctx, 'F', { model: l29Model(F) });
    await bootstrap(ctx, 'F', 'f_admin', 'admin');
    const admin = await ctx.actors.signIn('f_admin');
    await signedInMember(ctx, 'f_staff', 'F');
    const g = await managerWrite(ctx, 'grant_membership', admin.accessToken, 'F', 'f_staff', 'staff');
    ctx.observe('L29 setup: staff granted on the live client', { kind: g.kind, result: g.value?.result ?? g.code });
    const adminId = ctx.actors.get('f_admin').id;
    const staffId = ctx.actors.get('f_staff').id;

    await attempt(ctx, 'L29.live.no_manager_refused', async (check) => {
      const before = await snapshot(ctx, F);
      const r = await refusal(ctx, l29Model(F, 'no_manager'));
      check.assert('refused as model_refused', { refused: true, code: 'model_refused' }, { refused: r.refused, code: r.code });
      const text = JSON.stringify(r.refusals ?? []);
      check.assert('refusal names no_manager_would_remain', true, text.includes('no_manager_would_remain'));
      check.assert('refusal names the holder', true, text.includes(adminId));
      check.assert('nothing written', before, await snapshot(ctx, F));
    });

    await attempt(ctx, 'L29.live.promotion_refused', async (check) => {
      const before = await snapshot(ctx, F);
      const r = await refusal(ctx, l29Model(F, 'promotion'));
      check.assert('refused as model_refused', { refused: true, code: 'model_refused' }, { refused: r.refused, code: r.code });
      check.assert('refusal names the staff holder', true, JSON.stringify(r.refusals ?? []).includes(staffId));
      check.assert('nothing written', before, await snapshot(ctx, F));
    });

    await attempt(ctx, 'L29.registered.accepted', async (check) => {
      await ensureClient(ctx, 'F2', { model: l29Model(F2) });
      check.assert('no-manager model accepted without holders', { refused: false, result: 'applied' }, await refusal(ctx, l29Model(F2, 'no_manager')));
      check.assert('base model back', { refused: false, result: 'applied' }, await refusal(ctx, l29Model(F2)));
      check.assert('promotion model accepted without holders', { refused: false, result: 'applied' }, await refusal(ctx, l29Model(F2, 'promotion')));
    });

    await attempt(ctx, 'L29.concurrent_apply', async (check) => {
      const target = l29Model(F2);
      const before = await counts(ctx, { clientId: F2 });
      const results = await Promise.all([
        op(ctx).applyModel(target, { requestId: randomUUID() }),
        op(ctx).applyModel(target, { requestId: randomUUID() }),
      ]);
      check.assert('one applied and one unchanged', ['applied', 'unchanged'], results.map((r) => r.result).sort());
      const after = await counts(ctx, { clientId: F2 });
      check.assert('one model event, two request rows', { model_events: before.model_events + 1, request_log: before.request_log + 2 }, { model_events: after.model_events, request_log: after.request_log });
    });
  },
}];
