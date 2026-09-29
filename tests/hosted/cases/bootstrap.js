// L32 bootstrap-manager lookups against the real Auth admin API (design 4.1,
// R5). The CLI runs as a child process with credentials in its environment
// only. The forced small-page listing (page size 1, cap 2) uses the same
// scan the CLI uses, because the CLI's page size is fixed.

import { randomUUID } from 'node:crypto';
import { attempt, ensureClient, counts, uuidLit } from '../lib/world.js';
import { requestsModel } from '../lib/fixtures.js';
import { textLiteral } from '../lib/sqlprobe.js';
import { scanForEmail } from '../../../packages/server/lib/lookup.js';
import { createAdminApi } from '../../../packages/server/lib/admin.js';
import { isOperatorError } from '../../../packages/server/operator.js';

async function clientState(ctx, clientId) {
  return ctx.hosted.management.read(`select coalesce((select to_jsonb(c.state) from auth_kit_private.clients c where c.client_id = ${textLiteral(clientId)}), 'null'::jsonb)::text as result`);
}

async function membershipCount(ctx, userId, clientId) {
  return Number(await ctx.hosted.management.read(`select pg_catalog.count(*)::text as result from auth_kit_private.memberships
    where user_id = ${uuidLit(userId)} and client_id = ${textLiteral(clientId)}`));
}

export const procedures = [{
  id: 'bootstrap',
  group: 'bootstrap',
  requiresTargets: ['T.identity', 'T.management', 'T.schema'],
  async run(ctx) {
    const G = ctx.ids.G;
    await ensureClient(ctx, 'G', { model: requestsModel(G) });
    const cli = (args) => ctx.hosted.cli(['bootstrap-manager', '--client', G, '--role', 'steward', ...args]);
    const outcome = (r) => ({ exit: r.code, result: r.json?.result ?? null, error: r.json?.error ?? null });

    await attempt(ctx, 'L32.email_zero_matches', async (check) => {
      const id = randomUUID();
      const r = await cli(['--email', ctx.actors.email('nobody'), '--request-id', id]);
      check.assert('refused unknown_user', { exit: 1, result: null, error: 'unknown_user' }, outcome(r));
      check.assert('nothing written', { request_log: 0, membership_events: 0 }, (({ request_log, membership_events }) => ({ request_log, membership_events }))(await counts(ctx, { requestId: id })));
    });

    await attempt(ctx, 'L32.email_two_matches', async (check) => {
      const first = await ctx.actors.user('dup_one');
      ctx.ledger.intent('user', 'dup_two');
      const second = await ctx.hosted.admin.createUserRaw(first.email.toUpperCase(), `${randomUUID()}Aa1`);
      ctx.observe('L32 second user with the same address (different case)', { status: second.status, errorCode: second.errorCode, created: second.id !== null });
      if (second.id === null) {
        ctx.ledger.removed('user', 'dup_two', { reason: 'never_created' });
        ctx.notRun('L32.email_two_matches', 'platform_precludes', 'Auth refused a second user with the same address; ambiguous_user is covered by unit tests only');
        return;
      }
      ctx.ledger.created('user', 'dup_two', { id: second.id });
      const r = await cli(['--email', first.email, '--request-id', randomUUID()]);
      check.assert('refused ambiguous_user', { exit: 1, result: null, error: 'ambiguous_user' }, outcome(r));
    });

    await attempt(ctx, 'L32.lookup_incomplete', async (check) => {
      const target = await ctx.actors.user('lookup_confirmed');
      const page = await ctx.hosted.admin.listPage(1, 3);
      check.assert('the project has at least three users', true, page.length === 3);
      const before = await counts(ctx, { clientId: G });
      const admin = createAdminApi({ fetch: ctx.gate.fetch, timers: undefined, origin: ctx.hosted.origin, secretKey: ctx.creds.SUPABASE_SECRET_KEY, timeoutMs: 20_000 });
      let error = null;
      try {
        await scanForEmail(admin, target.email, { pageSize: 1, pageCap: 2 });
      } catch (e) {
        if (!isOperatorError(e)) throw e;
        error = e;
      }
      check.assert('refused lookup_incomplete at the page cap', { code: 'lookup_incomplete', reason: 'page_cap' }, { code: error?.code, reason: error?.details?.reason });
      check.assert('the message names --user-id', true, typeof error?.message === 'string' && error.message.includes('--user-id'));
      check.assert('nothing written', before, await counts(ctx, { clientId: G }));
    });

    await attempt(ctx, 'L32.user_id_unconfirmed', async (check) => {
      const u = await ctx.actors.user('lookup_unconfirmed', { confirm: false });
      const id = randomUUID();
      const r = await cli(['--user-id', u.id, '--request-id', id]);
      check.assert('refused email_unverified', { exit: 1, result: null, error: 'email_unverified' }, outcome(r));
      check.assert('no membership', 0, await membershipCount(ctx, u.id, G));
      check.assert('no request row', 0, (await counts(ctx, { requestId: id })).request_log);
    });

    await attempt(ctx, 'L32.user_id_confirmed', async (check) => {
      const u = await ctx.actors.user('lookup_confirmed');
      check.assert('client registered before', 'registered', await clientState(ctx, G));
      const r = await cli(['--user-id', u.id, '--request-id', randomUUID()]);
      check.assert('granted', { exit: 0, result: 'granted', error: null }, outcome(r));
      check.assert('client live', 'live', await clientState(ctx, G));
      check.assert('one membership', 1, await membershipCount(ctx, u.id, G));
    });

    await attempt(ctx, 'L32.email_unique_match', async (check) => {
      const u = await ctx.actors.user('lookup_email');
      const r = await cli(['--email', u.email, '--request-id', randomUUID()]);
      check.assert('granted by a unique confirmed match', { exit: 0, result: 'granted', error: null }, outcome(r));
      check.assert('one membership', 1, await membershipCount(ctx, u.id, G));
    });
  },
}];
