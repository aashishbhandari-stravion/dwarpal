// L35 hosted cases (a)-(d): the operator's MFA reset against the real Auth
// admin API and the real claim functions. Each run gets its own observing
// fetch, so admin API calls are counted per runner; the in-flight checks run
// from that fetch just before the runner's first admin call.

import { randomUUID } from 'node:crypto';
import { attempt, counts, requestRow, eventsOf } from '../lib/world.js';
import { observeFetch } from '../lib/net.js';
import { isOperatorError } from '../../../packages/server/operator.js';

const isAdmin = (method, url) => url.pathname.startsWith('/auth/v1/admin/');
const isListFactors = (method, url) => method === 'GET' && /\/auth\/v1\/admin\/users\/[0-9a-f-]{36}\/factors$/.test(url.pathname);

function runner(ctx, before) {
  const fetch = observeFetch(ctx.gate.fetch, { match: isAdmin, before: before ? async (method, url) => { if (isListFactors(method, url)) await before(); } : undefined });
  return { fetch, operator: ctx.hosted.operator(fetch) };
}

async function reset(r, userId, requestId) {
  try {
    const value = await r.operator.mfaReset({ userId, requestId });
    return { ok: true, outcome: value.outcome, replayed: value.replayed, result: value.result, factorsSeen: [...value.factorsSeen], factorsDeleted: [...value.factorsDeleted] };
  } catch (error) {
    if (!isOperatorError(error)) throw error;
    return { ok: false, code: error.code };
  }
}

async function verifiedTotp(ctx, userId) {
  return (await ctx.hosted.admin.factors(userId)).filter((f) => f.type === 'totp' && f.status === 'verified').map((f) => f.id).sort();
}

export const procedures = [{
  id: 'mfa_reset',
  group: 'mfa_reset',
  requiresTargets: ['T.identity', 'T.management', 'T.schema', 'T.auth_settings'],
  async run(ctx) {
    const u = await ctx.actors.user('mfa_u');
    const u2 = await ctx.actors.user('mfa_u2');
    await ctx.actors.aal2('mfa_u');
    await ctx.actors.aal2('mfa_u2');
    const R = randomUUID();
    let aResult = null;

    await attempt(ctx, 'L35.a', async (check) => {
      const factors = await verifiedTotp(ctx, u.id);
      check.assert('U holds one verified TOTP factor', 1, factors.length);
      let inFlight = null;
      const r = runner(ctx, async () => { inFlight ??= await requestRow(ctx, R); });
      aResult = await reset(r, u.id, R);
      check.assert('a pending row existed before listFactors', { state: 'pending', has_token: true }, inFlight && { state: inFlight.state, has_token: inFlight.has_token });
      check.assert('completed with the factor', { ok: true, outcome: 'proceed', replayed: false, result: 'reset', factorsSeen: factors, factorsDeleted: factors }, aResult);
      const row = await requestRow(ctx, R);
      check.assert('row completed with both lists', { state: 'completed', client_id: null, result: { result: 'reset', factors_seen: factors, factors_deleted: factors } },
        { state: row?.state, client_id: row?.client_id, result: row?.result });
      check.assert('one event with client_id null', [{ action: 'mfa_reset', role: null, client_id: null, actor_kind: 'operator' }], await eventsOf(ctx, { userId: u.id, requestId: R }));
      check.assert('the factor is gone from Auth', [], await verifiedTotp(ctx, u.id));
    });

    await attempt(ctx, 'L35.b', async (check) => {
      const before = await counts(ctx, { requestId: R });
      const r = runner(ctx);
      const replay = await reset(r, u.id, R);
      check.assert('stored result returned', { ...aResult, outcome: 'completed', replayed: true }, replay);
      check.assert('no admin API call', [], r.fetch.seen);
      check.assert('nothing written', before, await counts(ctx, { requestId: R }));
    });

    await attempt(ctx, 'L35.c', async (check) => {
      const factors = await verifiedTotp(ctx, u2.id);
      const before = await counts(ctx, { requestId: R });
      const r = runner(ctx);
      check.assert('another user with the same id: request_conflict', { ok: false, code: 'request_conflict' }, await reset(r, u2.id, R));
      check.assert('no admin API call', [], r.fetch.seen);
      check.assert('nothing written', before, await counts(ctx, { requestId: R }));
      check.assert('U2 factors untouched', factors, await verifiedTotp(ctx, u2.id));
    });

    await attempt(ctx, 'L35.d', async (check) => {
      const R2 = randomUUID();
      const second = runner(ctx);
      let secondResult = null;
      // The first runner holds its claim; the second starts once the first's begin is committed.
      const first = runner(ctx, async () => { secondResult ??= await reset(second, u2.id, R2); });
      const firstResult = await reset(first, u2.id, R2);
      check.assert('the second concurrent run is refused before Auth', { ok: false, code: 'request_in_progress' }, secondResult);
      check.assert('the second runner made no admin call', [], second.fetch.seen);
      check.assert('the first run completes', { ok: true, outcome: 'proceed', result: 'reset' }, { ok: firstResult.ok, outcome: firstResult.outcome, result: firstResult.result });
      check.assert('one event for the id', 1, (await eventsOf(ctx, { userId: u2.id, requestId: R2 })).length);
    });
  },
}];
