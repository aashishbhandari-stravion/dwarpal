// L25 and the two revocation guarantees (design 5.14, D20).
//
// Start (early in the run): three rls-demo members each hold an unexpired
// aal1 token and one note. One signs out (global), one is banned, one loses
// their membership. The Node path (createAuthServer behind a loopback
// endpoint) and the direct PostgREST path are read with the same tokens at
// once. Finish (late in the run, so the wait overlaps other work): after
// each token's `exp` plus a margin, both paths are read again.
//
// Expected: Node refuses the signed-out and banned tokens on the very next
// request; PostgREST keeps returning the rows until expiry and then refuses;
// the membership revoke is immediate on the direct path.

import { attempt, signedInMember, managerWrite, fresh } from '../lib/world.js';
import { rlsWorld, insertNote, visibleNotes } from './policy.js';

const MARGIN_MS = 30_000;

export const procedures = [
  {
    id: 'revocation_start',
    group: 'revocation',
    requiresTargets: ['T.identity', 'T.signing_keys', 'T.rls_consumer', 'T.exposed_schemas', 'T.auth_settings'],
    async run(ctx) {
      const w = await rlsWorld(ctx);
      const users = {};
      for (const alias of ['revoke_signout', 'revoke_ban', 'revoke_member']) {
        const session = await signedInMember(ctx, alias, 'RLS');
        const note = await insertNote(ctx, alias, session.accessToken);
        users[alias] = { session, note, iat: session.claims.iat, exp: session.claims.exp, localAtSignIn: ctx.clock.now() };
      }
      const node = await ctx.hosted.nodeEndpoint('rls-demo', { now: ctx.clock.now });
      const s = { users, node, results: {} };
      ctx.state.revocation = s;

      // Baseline: every token works on both paths.
      const baseline = {};
      for (const [alias, u] of Object.entries(users)) {
        baseline[alias] = { node: (await node.get(u.session.accessToken)).status, direct: await visibleNotes(ctx, u.session.accessToken, [u.note]) };
      }
      ctx.observe('L25 baseline', baseline);
      s.baselineOk = Object.entries(users).every(([alias, u]) => baseline[alias].node === 200 && JSON.stringify(baseline[alias].direct) === JSON.stringify([u.note]));

      const so = users.revoke_signout;
      s.results.signoutStatus = await ctx.hosted.auth.logout(so.session.accessToken, 'global');
      s.results.signoutAt = ctx.clock.now();
      await attempt(ctx, 'L25.signout.node', async (check) => {
        check.assert('baseline: every token accepted on both paths', true, s.baselineOk);
        check.assert('sign-out accepted', 204, s.results.signoutStatus);
        const r = await node.get(so.session.accessToken);
        s.results.signoutNode = { status: r.status, error: r.body?.error };
        check.assert('next Node request refused', { status: 401, error: 'invalid_token' }, s.results.signoutNode);
      });
      await attempt(ctx, 'L25.signout.postgrest_live', async (check) => {
        s.results.signoutDirectLive = await visibleNotes(ctx, so.session.accessToken, [so.note]);
        check.assert('direct path still returns the row before expiry', [so.note], s.results.signoutDirectLive);
      });

      const ban = users.revoke_ban;
      s.results.banStatus = await ctx.hosted.admin.update(ctx.actors.get('revoke_ban').id, { ban_duration: '24h' });
      await attempt(ctx, 'L25.ban.node', async (check) => {
        check.assert('ban accepted', 200, s.results.banStatus);
        const r = await node.get(ban.session.accessToken);
        s.results.banNode = { status: r.status, error: r.body?.error };
        check.assert('next Node request refused', { status: 401, error: 'invalid_token' }, s.results.banNode);
      });
      await attempt(ctx, 'L25.ban.postgrest_live', async (check) => {
        s.results.banDirectLive = await visibleNotes(ctx, ban.session.accessToken, [ban.note]);
        check.assert('direct path still returns the row before expiry', [ban.note], s.results.banDirectLive);
      });

      await attempt(ctx, 'L25.membership_revoke_direct', async (check) => {
        const mem = users.revoke_member;
        const manager = await fresh(ctx, 'rls_manager', w.manager);
        const r = await managerWrite(ctx, 'revoke_membership', manager.accessToken, 'RLS', 'revoke_member', 'member');
        check.assert('manager revoke accepted', 'value:revoked', `${r.kind}:${r.value?.result}`);
        check.assert('same token sees nothing on the next direct read', [], await visibleNotes(ctx, mem.session.accessToken, [mem.note]));
      });
    },
  },
  {
    id: 'revocation_finish',
    group: 'revocation',
    requiresTargets: ['T.identity'],
    async run(ctx) {
      const s = ctx.state.revocation;
      if (!s) return;
      const { users, node } = s;
      try {
        const expiry = Math.max(users.revoke_signout.exp, users.revoke_ban.exp) * 1000;
        const wait = expiry + MARGIN_MS - ctx.clock.now();
        ctx.observe('L25 waiting for token expiry', { waitSeconds: Math.max(0, Math.round(wait / 1000)) });
        if (wait > 0) await ctx.clock.sleep(wait);
        await attempt(ctx, 'L25.signout.postgrest_expired', async (check) => {
          const so = users.revoke_signout;
          s.results.signoutDirectExpired = await visibleNotes(ctx, so.session.accessToken, [so.note]);
          check.assert('direct path refuses after expiry', true, typeof s.results.signoutDirectExpired === 'string' && s.results.signoutDirectExpired.startsWith('401:'));
          s.results.signoutNodeExpired = (await node.get(so.session.accessToken)).status;
          check.assert('Node path still refuses', 401, s.results.signoutNodeExpired);
        });
        await attempt(ctx, 'L25.ban.postgrest_expired', async (check) => {
          const b = users.revoke_ban;
          s.results.banDirectExpired = await visibleNotes(ctx, b.session.accessToken, [b.note]);
          check.assert('direct path refuses after expiry', true, typeof s.results.banDirectExpired === 'string' && s.results.banDirectExpired.startsWith('401:'));
        });
        await attempt(ctx, 'L25.side_by_side', async (check) => {
          const so = users.revoke_signout;
          const table = {
            tokenLifetimeSeconds: so.exp - so.iat,
            clockOffsetSecondsAtSignIn: Math.round(so.iat - so.localAtSignIn / 1000),
            signout: { node: s.results.signoutNode, directBeforeExpiry: s.results.signoutDirectLive, directAfterExpiry: s.results.signoutDirectExpired },
            ban: { node: s.results.banNode, directBeforeExpiry: s.results.banDirectLive, directAfterExpiry: s.results.banDirectExpired },
          };
          ctx.observe('L25 outcomes side by side', table);
          check.assert('token lifetime recorded', true, Number.isInteger(table.tokenLifetimeSeconds) && table.tokenLifetimeSeconds > 0);
          check.assert('every cell recorded', true, [table.signout.node, table.signout.directBeforeExpiry, table.signout.directAfterExpiry,
            table.ban.node, table.ban.directBeforeExpiry, table.ban.directAfterExpiry].every((v) => v !== undefined));
        });
      } finally {
        await node.close();
      }
    },
  },
];
