// Cleanup and residue, always attempted last (and by `run.js cleanup` after
// a crashed run, from the same ledger). Users are deleted through the Auth
// admin API; a user whose create answer was lost is found again by its
// regenerated address. Widened grants and fault triggers are reverted.
// Consumer rows (notes, orders) are found by the run marker in their title,
// including one whose insert answer was lost, deleted only with
// `cleanup_sql`, and counted again; an unknown count fails the case rather
// than reading as zero (lib/rows.js). Kit rows of the run's clients cannot
// be deleted through any kit function (enrollments and events are
// append-only by design); they are counted and reported.

import { attempt, uuidLit } from '../lib/world.js';
import { emailFor } from '../lib/actors.js';
import { WIDENINGS, revertWidenings } from './doctor.js';
import { faultSql } from './enrollment.js';
import { smtpAddress } from './providers.js';
import { clientIds, FIXED_CLIENTS } from '../lib/fixtures.js';
import { GRANT_VIOLATIONS_SQL, textLiteral } from '../lib/sqlprobe.js';
import { ROW_TABLES, settleRows } from '../lib/rows.js';

const SWEEP_PAGES = 20;

async function findByEmail(ctx, email) {
  for (let page = 1; page <= SWEEP_PAGES; page += 1) {
    const users = await ctx.hosted.admin.listPage(page, 1000);
    const hit = users.find((u) => u.email?.toLowerCase() === email.toLowerCase());
    if (hit) return hit.id;
    if (users.length < 1000) return null;
  }
  return undefined;
}

function addressOf(ctx, alias) {
  if (alias === 'smtp_user') return smtpAddress(ctx.descriptor.identities.smtpRecipients[0], ctx.runId);
  if (alias === 'google_user') return ctx.descriptor.identities.google.email;
  return emailFor(ctx.descriptor.identities.emailTemplate, ctx.runId, alias);
}

export const procedures = [{
  id: 'cleanup',
  group: 'cleanup',
  always: true,
  async run(ctx) {
    const outstanding = ctx.ledger.outstanding();
    ctx.observe('ledger outstanding before cleanup', outstanding.map((e) => ({ kind: e.kind, key: e.key, op: e.op, id: e.id ?? null })));

    await attempt(ctx, 'C.users_deleted', async (check) => {
      const residue = [];
      for (const entry of outstanding.filter((e) => e.kind === 'user')) {
        let id = entry.id;
        if (!id) id = await findByEmail(ctx, addressOf(ctx, entry.key));
        if (id === null) {
          ctx.ledger.removed('user', entry.key, { reason: 'never_created' });
          continue;
        }
        if (id === undefined) {
          ctx.ledger.residue('user', entry.key, 'sweep_incomplete');
          residue.push(entry.key);
          continue;
        }
        const r = await ctx.hosted.admin.deleteUser(id);
        const gone = r.status === 200 || (r.status === 404 && r.errorCode === 'user_not_found');
        if (gone && (await ctx.hosted.admin.getUser(id)).status === 404) ctx.ledger.removed('user', entry.key, { id });
        else {
          ctx.ledger.residue('user', entry.key, `delete_${r.status}`);
          residue.push(entry.key);
        }
      }
      check.assert('every ledger user deleted', [], residue);
    });

    await attempt(ctx, 'C.catalog_restored', async (check) => {
      const widenings = outstanding.filter((e) => e.kind === 'grant_widening').map((e) => e.key).filter((k) => Object.hasOwn(WIDENINGS, k));
      if (widenings.length > 0) await revertWidenings(ctx, widenings);
      for (const entry of outstanding.filter((e) => e.kind === 'fault_trigger')) {
        const fault = faultSql(ctx.runId, '00000000-0000-4000-8000-000000000000');
        await ctx.hosted.management.exec(fault.drop);
        if (await ctx.hosted.management.read(fault.present) === false) ctx.ledger.removed('fault_trigger', entry.key);
      }
      check.assert('grant assertion empty', 0, Number(await ctx.hosted.management.read(GRANT_VIOLATIONS_SQL)));
      check.assert('no harness fault schema remains', 0, Number(await ctx.hosted.management.read(
        `select pg_catalog.count(*)::text as result from pg_catalog.pg_namespace where nspname like 'hv\\_fault\\_%'`)));
    });

    await attempt(ctx, 'C.rows_reported', async (check) => {
      const rows = {};
      for (const kind of Object.keys(ROW_TABLES)) rows[kind] = await settleRows(ctx, kind);
      ctx.observe('consumer rows of this run', rows);
      const ids = Object.values(clientIds(ctx.runId)).filter((id) => !FIXED_CLIENTS.includes(id));
      const list = `array[${ids.map((id) => textLiteral(id)).join(', ')}]`;
      const users = outstanding.filter((e) => e.kind === 'user' && e.id).map((e) => uuidLit(e.id));
      const userList = users.length > 0 ? `array[${users.join(', ')}]` : `array[]::uuid[]`;
      let kit = null;
      try {
        kit = await ctx.hosted.management.read(`select jsonb_build_object(
          'clients', (select pg_catalog.count(*) from auth_kit_private.clients where client_id = any(${list})),
          'memberships', (select pg_catalog.count(*) from auth_kit_private.memberships where client_id = any(${list}) or user_id = any(${userList})),
          'enrollments', (select pg_catalog.count(*) from auth_kit_private.enrollments where client_id = any(${list}) or user_id = any(${userList})),
          'membership_events', (select pg_catalog.count(*) from auth_kit_private.membership_events where client_id = any(${list}) or user_id = any(${userList})),
          'request_log', (select pg_catalog.count(*) from auth_kit_private.request_log where client_id = any(${list})),
          'profiles', (select pg_catalog.count(*) from auth_kit.profiles where user_id = any(${userList})))::text as result`);
      } catch (error) {
        ctx.observe('kit residue unreadable', { stage: error?.stage ?? null, status: error?.status ?? null });
      }
      const remaining = Object.fromEntries(Object.entries(rows).map(([kind, r]) => [kind, r.remaining]));
      ctx.state.residue = { rows: remaining, kit };
      ctx.observe('residue after cleanup (kit rows are append-only by design)', ctx.state.residue);
      check.assert('kit residue counted', true, typeof kit === 'object' && kit !== null);
      check.assert('every consumer row count known (never assumed zero)', [], Object.keys(remaining).filter((kind) => remaining[kind] === null));
      if (ctx.actions.has('cleanup_sql')) check.assert('this run\'s consumer rows deleted', Object.fromEntries(Object.keys(rows).map((k) => [k, 0])), remaining);
    });
  },
}];
