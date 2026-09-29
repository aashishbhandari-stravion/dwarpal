// Cleanup and residue, always attempted last (and by `run.js cleanup` after
// a crashed run, from the same ledger). Users are deleted through the Auth
// admin API; a user whose create answer was lost is found again by its
// regenerated address. Widened grants and fault triggers are reverted. Notes
// rows are deleted only with `cleanup_sql` authorization. Kit rows of the
// run's clients cannot be deleted through any kit function (enrollments and
// events are append-only by design); they are counted and reported.

import { attempt, uuidLit } from '../lib/world.js';
import { emailFor } from '../lib/actors.js';
import { WIDENINGS, revertWidenings } from './doctor.js';
import { faultSql } from './enrollment.js';
import { smtpAddress } from './providers.js';
import { clientIds } from '../lib/fixtures.js';
import { GRANT_VIOLATIONS_SQL, textLiteral } from '../lib/sqlprobe.js';

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
      const noteIds = outstanding.filter((e) => e.kind === 'notes' && Number.isInteger(e.noteId)).map((e) => e.noteId);
      if (noteIds.length > 0 && ctx.actions.has('cleanup_sql')) {
        await ctx.hosted.management.exec(`delete from app.notes where id = any(array[${noteIds.join(',')}]::bigint[])`);
        for (const e of outstanding.filter((x) => x.kind === 'notes')) ctx.ledger.removed('notes', e.key, { noteId: e.noteId ?? null });
      }
      const remainingNotes = noteIds.length === 0 ? 0 : Number(await ctx.hosted.management.read(
        `select pg_catalog.count(*)::text as result from app.notes where id = any(array[${noteIds.join(',')}]::bigint[])`));
      const ids = Object.values(clientIds(ctx.runId)).filter((id) => id !== 'rls-demo');
      const list = `array[${ids.map((id) => textLiteral(id)).join(', ')}]`;
      const users = outstanding.filter((e) => e.kind === 'user' && e.id).map((e) => uuidLit(e.id));
      const userList = users.length > 0 ? `array[${users.join(', ')}]` : `array[]::uuid[]`;
      const kit = await ctx.hosted.management.read(`select jsonb_build_object(
        'clients', (select pg_catalog.count(*) from auth_kit_private.clients where client_id = any(${list})),
        'memberships', (select pg_catalog.count(*) from auth_kit_private.memberships where client_id = any(${list}) or user_id = any(${userList})),
        'enrollments', (select pg_catalog.count(*) from auth_kit_private.enrollments where client_id = any(${list}) or user_id = any(${userList})),
        'membership_events', (select pg_catalog.count(*) from auth_kit_private.membership_events where client_id = any(${list}) or user_id = any(${userList})),
        'request_log', (select pg_catalog.count(*) from auth_kit_private.request_log where client_id = any(${list})),
        'profiles', (select pg_catalog.count(*) from auth_kit.profiles where user_id = any(${userList})))::text as result`);
      ctx.state.residue = { notes: remainingNotes, kit };
      ctx.observe('residue after cleanup (kit rows are append-only by design)', ctx.state.residue);
      check.assert('residue counted', true, typeof kit === 'object' && kit !== null);
      if (ctx.actions.has('cleanup_sql')) check.assert('this run\'s notes deleted', 0, remainingNotes);
    });
  },
}];
