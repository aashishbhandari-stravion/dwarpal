// L30 request-bearing commands on client R (design 4.2 locking and request
// semantics, R1). For every command: a mutating first call and a no-op
// first call, each retried with the same id and (a) the same payload, (b) a
// different payload. Rows are counted by request id before and after each
// retry. Manager commands go over PostgREST with the manager's own token;
// operator commands through the operator client.

import { randomUUID } from 'node:crypto';
import { attempt, ensureClient, bootstrap, signedInMember, managerWrite, counts, op } from '../lib/world.js';
import { requestsModel } from '../lib/fixtures.js';
import { isOperatorError } from '../../../packages/server/operator.js';

async function opOutcome(fn) {
  try {
    const r = await fn();
    return `value:${r.result}`;
  } catch (error) {
    if (isOperatorError(error)) return `refusal:${error.code}`;
    throw error;
  }
}

const restOutcome = (o) => (o.kind === 'value' ? `value:${o.value?.result}` : o.kind === 'refusal' ? `refusal:${o.code}` : `failure:${o.status}:${o.code ?? ''}`);

/**
 * first -> retry same -> retry different, counting rows for the id.
 * @param {{ first: () => Promise<string>, same: () => Promise<string>, different: () => Promise<string> }} calls
 */
async function idempotent(ctx, check, requestId, calls, { firstResult, events, table = 'membership_events' }) {
  check.assert('first call', firstResult, await calls.first());
  const afterFirst = await counts(ctx, { requestId });
  check.assert('first call rows', { request_log: 1, [table]: events }, { request_log: afterFirst.request_log, [table]: afterFirst[table] });
  check.assert('same id, same payload: the stored result', firstResult, await calls.same());
  check.assert('no new rows after the same retry', afterFirst, await counts(ctx, { requestId }));
  check.assert('same id, different payload: request_conflict', 'refusal:request_conflict', await calls.different());
  check.assert('no new rows after the conflicting retry', afterFirst, await counts(ctx, { requestId }));
}

export const procedures = [{
  id: 'requests',
  group: 'requests',
  requiresTargets: ['T.identity', 'T.management', 'T.schema'],
  async run(ctx) {
    const R = ctx.ids.R;
    await ensureClient(ctx, 'R', { model: requestsModel(R) });
    await bootstrap(ctx, 'R', 'r_steward1', 'steward');
    await bootstrap(ctx, 'R', 'r_steward2', 'steward');
    const m1 = await ctx.actors.signIn('r_steward1');
    const m2 = await ctx.actors.signIn('r_steward2');
    await signedInMember(ctx, 'r_target', 'R');
    await signedInMember(ctx, 'r_other', 'R');
    await ctx.actors.user('r_target2');
    const grant = (token, alias, role, id) => managerWrite(ctx, 'grant_membership', token, 'R', alias, role, id).then(restOutcome);
    const revoke = (token, alias, role, id) => managerWrite(ctx, 'revoke_membership', token, 'R', alias, role, id).then(restOutcome);
    const boot = (alias, id) => opOutcome(() => op(ctx).bootstrapManager({ clientId: R, roleKey: 'steward', requestId: id, userId: ctx.actors.get(alias).id }));
    const unboot = (alias, id) => opOutcome(() => op(ctx).revokeManager({ clientId: R, roleKey: 'steward', requestId: id, userId: ctx.actors.get(alias).id }));
    const apply = (model, id) => opOutcome(() => op(ctx).applyModel(model, { requestId: id }));
    let grantId = null;

    await attempt(ctx, 'L30.grant_membership.mutating', async (check) => {
      const id = randomUUID();
      grantId = id;
      await idempotent(ctx, check, id, {
        first: () => grant(m1.accessToken, 'r_target', 'helper', id),
        same: () => grant(m1.accessToken, 'r_target', 'helper', id),
        different: () => grant(m1.accessToken, 'r_other', 'helper', id),
      }, { firstResult: 'value:granted', events: 1 });
    });
    await attempt(ctx, 'L30.grant_membership.noop', async (check) => {
      const id = randomUUID();
      await idempotent(ctx, check, id, {
        first: () => grant(m1.accessToken, 'r_target', 'helper', id),
        same: () => grant(m1.accessToken, 'r_target', 'helper', id),
        different: () => grant(m1.accessToken, 'r_target', 'visitor', id),
      }, { firstResult: 'value:already_member', events: 0 });
    });
    await attempt(ctx, 'L30.cross_manager_id', async (check) => {
      if (grantId === null) throw new Error('the mutating grant did not run');
      const before = await counts(ctx, { requestId: grantId });
      check.assert('another manager reusing the id with the same payload', 'refusal:request_conflict', await grant(m2.accessToken, 'r_target', 'helper', grantId));
      check.assert('nothing written', before, await counts(ctx, { requestId: grantId }));
    });
    await attempt(ctx, 'L30.revoke_membership.mutating', async (check) => {
      const id = randomUUID();
      await idempotent(ctx, check, id, {
        first: () => revoke(m1.accessToken, 'r_target', 'helper', id),
        same: () => revoke(m1.accessToken, 'r_target', 'helper', id),
        different: () => revoke(m1.accessToken, 'r_target', 'visitor', id),
      }, { firstResult: 'value:revoked', events: 1 });
    });
    await attempt(ctx, 'L30.revoke_membership.noop', async (check) => {
      const id = randomUUID();
      await idempotent(ctx, check, id, {
        first: () => revoke(m1.accessToken, 'r_target', 'helper', id),
        same: () => revoke(m1.accessToken, 'r_target', 'helper', id),
        different: () => revoke(m1.accessToken, 'r_other', 'helper', id),
      }, { firstResult: 'value:not_member', events: 0 });
    });
    await attempt(ctx, 'L30.bootstrap_manager.mutating', async (check) => {
      const id = randomUUID();
      await idempotent(ctx, check, id, {
        first: () => boot('r_target2', id),
        same: () => boot('r_target2', id),
        different: () => boot('r_other', id),
      }, { firstResult: 'value:granted', events: 1 });
    });
    await attempt(ctx, 'L30.bootstrap_manager.noop', async (check) => {
      const id = randomUUID();
      await idempotent(ctx, check, id, {
        first: () => boot('r_steward1', id),
        same: () => boot('r_steward1', id),
        different: () => boot('r_other', id),
      }, { firstResult: 'value:already_member', events: 0 });
    });
    await attempt(ctx, 'L30.revoke_manager.mutating', async (check) => {
      const id = randomUUID();
      await idempotent(ctx, check, id, {
        first: () => unboot('r_target2', id),
        same: () => unboot('r_target2', id),
        different: () => unboot('r_steward2', id),
      }, { firstResult: 'value:revoked', events: 1 });
    });
    await attempt(ctx, 'L30.revoke_manager.noop', async (check) => {
      const id = randomUUID();
      await idempotent(ctx, check, id, {
        first: () => unboot('r_target2', id),
        same: () => unboot('r_target2', id),
        different: () => unboot('r_other', id),
      }, { firstResult: 'value:not_member', events: 0 });
    });
    await attempt(ctx, 'L30.apply_model.mutating', async (check) => {
      const id = randomUUID();
      await idempotent(ctx, check, id, {
        first: () => apply(requestsModel(R, { extraKey: true }), id),
        same: () => apply(requestsModel(R, { extraKey: true }), id),
        different: () => apply(requestsModel(R), id),
      }, { firstResult: 'value:applied', events: 1, table: 'model_events' });
    });
    await attempt(ctx, 'L30.apply_model.noop', async (check) => {
      const id = randomUUID();
      await idempotent(ctx, check, id, {
        first: () => apply(requestsModel(R, { extraKey: true }), id),
        same: () => apply(requestsModel(R, { extraKey: true }), id),
        different: () => apply(requestsModel(R), id),
      }, { firstResult: 'value:unchanged', events: 0, table: 'model_events' });
    });
    await attempt(ctx, 'L30.natural_keys', async (check) => {
      const before = await counts(ctx, { clientId: R });
      const t = await signedInMember(ctx, 'r_joiner', 'R');
      const again = await ctx.hosted.rest.rpc(t.accessToken, 'join_client', { client_id: R });
      check.assert('second join is already_enrolled', 'value:already_enrolled', restOutcome(again));
      const same = await opOutcome(() => op(ctx).registerClient({ clientId: R, displayName: 'Hosted check R', signupPolicy: 'open' }));
      check.assert('register_client with the same arguments', 'value:unchanged', same);
      check.assert('no request_log row from joins or registration', before.request_log, (await counts(ctx, { clientId: R })).request_log);
    });
  },
}];
