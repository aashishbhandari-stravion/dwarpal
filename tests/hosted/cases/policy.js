// The real consumer policy (L28 policy results): examples/rls-consumer's
// app.notes on the fixed client `rls-demo`, read over PostgREST as each
// actor. Only this run's notes are counted, so earlier runs' rows cannot
// change an answer.

import { attempt, ensureClient, bootstrap, signedInMember, managerWrite, fresh } from '../lib/world.js';
import { rlsModel, exampleModel } from '../lib/fixtures.js';
import { HostedError } from '../lib/hosted.js';
import { rowTitle } from '../lib/rows.js';

const KEYS = ['notes:read:own', 'notes:read:any', 'notes:write:own', 'notes:write:any', 'members:manage'];
const UNKNOWN = 'notes:unknown:key';

async function helperAnswers(ctx, token) {
  const out = {};
  for (const key of [...KEYS, UNKNOWN]) {
    const o = await ctx.hosted.rest.rpc(token, 'has_permission', { client_id: 'rls-demo', permission_key: key });
    out[key] = o.kind === 'value' ? o.value : `${o.status}:${o.code ?? o.kind}`;
  }
  for (const role of ['manager', 'staff', 'member']) {
    const o = await ctx.hosted.rest.rpc(token, 'has_role', { client_id: 'rls-demo', role_key: role });
    out[`role:${role}`] = o.kind === 'value' ? o.value : `${o.status}:${o.code ?? o.kind}`;
  }
  return out;
}

function expectHelpers(granted, roles) {
  const out = {};
  for (const key of KEYS) out[key] = granted.includes(key);
  out[UNKNOWN] = false;
  for (const role of ['manager', 'staff', 'member']) out[`role:${role}`] = roles.includes(role);
  return out;
}

/**
 * One note owned by the token's user. The intent is on disk before the
 * insert; the title carries the run marker, so a note whose insert committed
 * but whose answer was lost is still found and settled by cleanup.
 */
export async function insertNote(ctx, alias, token) {
  ctx.ledger.intent('notes', alias);
  const o = await ctx.hosted.rest.insert(token, 'app', 'notes', { title: rowTitle(ctx.runId, alias), body: '' });
  if (o.kind !== 'value' || !Array.isArray(o.value) || o.value.length !== 1 || !Number.isInteger(o.value[0]?.id)) {
    throw new HostedError('insert_note', o.status, o.code ?? null);
  }
  ctx.ledger.created('notes', alias, { rowId: o.value[0].id });
  return o.value[0].id;
}

export async function visibleNotes(ctx, token, ids) {
  const o = await ctx.hosted.rest.select(token, 'app', 'notes', `select=id&id=in.(${ids.join(',')})&order=id`);
  return o.kind === 'value' ? o.value.map((r) => r.id) : `${o.status}:${o.code ?? o.kind}`;
}

/** rls-demo with its model, a manager at aal2, a member, a staff member, and one note each. */
export async function rlsWorld(ctx) {
  if (ctx.state.rls) return ctx.state.rls;
  await ensureClient(ctx, 'RLS', { model: rlsModel() });
  await bootstrap(ctx, 'RLS', 'rls_manager', 'manager');
  const manager = await ctx.actors.aal2('rls_manager');
  const member = await signedInMember(ctx, 'rls_member', 'RLS');
  await signedInMember(ctx, 'rls_staff', 'RLS');
  const granted = await managerWrite(ctx, 'grant_membership', manager.accessToken, 'RLS', 'rls_staff', 'staff');
  if (granted.kind !== 'value') throw new HostedError('grant_staff', granted.status, granted.code ?? null);
  const staff1 = await ctx.actors.signIn('rls_staff');
  const staff2 = await ctx.actors.aal2('rls_staff');
  const notes = {
    member: await insertNote(ctx, 'rls_member', member.accessToken),
    staff: await insertNote(ctx, 'rls_staff', staff1.accessToken),
    manager: await insertNote(ctx, 'rls_manager', manager.accessToken),
  };
  ctx.state.rls = { manager, member, staff1, staff2, notes, ids: Object.values(notes).sort((a, b) => a - b) };
  return ctx.state.rls;
}

export const procedures = [{
  id: 'policy',
  group: 'policy',
  requiresTargets: ['T.identity', 'T.signing_keys', 'T.rls_consumer', 'T.exposed_schemas', 'T.auth_settings'],
  async run(ctx) {
    const shared = await rlsWorld(ctx);
    const w = {
      ...shared,
      member: await fresh(ctx, 'rls_member', shared.member),
      staff1: await fresh(ctx, 'rls_staff', shared.staff1),
      staff2: await fresh(ctx, 'rls_staff', shared.staff2),
      manager: await fresh(ctx, 'rls_manager', shared.manager),
    };
    const all = w.ids;

    await attempt(ctx, 'L28.policy.anon', async (check) => {
      const helpers = await helperAnswers(ctx, null);
      check.assert('anon: every helper false without error', expectHelpers([], []), helpers);
      const o = await ctx.hosted.rest.select(null, 'app', 'notes', 'select=id&limit=1');
      check.assert('anon: notes refused', 'failure:401', `${o.kind}:${o.status}`);
    });
    await attempt(ctx, 'L28.policy.member', async (check) => {
      check.assert('member helpers', expectHelpers(['notes:read:own', 'notes:write:own'], ['member']), await helperAnswers(ctx, w.member.accessToken));
      check.assert('member sees only their own note', [w.notes.member], await visibleNotes(ctx, w.member.accessToken, all));
    });
    await attempt(ctx, 'L28.policy.other_client', async (check) => {
      await ensureClient(ctx, 'B', { model: exampleModel(ctx.ids.B) });
      const other = await signedInMember(ctx, 'rls_other', 'B');
      check.assert('other-client member helpers all false', expectHelpers([], []), await helperAnswers(ctx, other.accessToken));
      check.assert('other-client member sees no note', [], await visibleNotes(ctx, other.accessToken, all));
    });
    await attempt(ctx, 'L28.policy.staff_aal1', async (check) => {
      check.assert('MFA-pending staff: staff keys withheld, member keys kept', expectHelpers(['notes:read:own', 'notes:write:own'], ['member']), await helperAnswers(ctx, w.staff1.accessToken));
      check.assert('MFA-pending staff sees only their own note', [w.notes.staff], await visibleNotes(ctx, w.staff1.accessToken, all));
    });
    await attempt(ctx, 'L28.policy.staff_aal2', async (check) => {
      check.assert('staff at aal2 helpers', expectHelpers(['notes:read:own', 'notes:write:own', 'notes:read:any', 'notes:write:any'], ['member', 'staff']), await helperAnswers(ctx, w.staff2.accessToken));
      check.assert('staff at aal2 sees every run note', all, await visibleNotes(ctx, w.staff2.accessToken, all));
    });
    await attempt(ctx, 'L28.policy.manager_aal2', async (check) => {
      check.assert('manager at aal2 helpers', expectHelpers(['members:manage', 'notes:read:any', 'notes:write:any'], ['manager']), await helperAnswers(ctx, w.manager.accessToken));
      check.assert('manager at aal2 sees every run note', all, await visibleNotes(ctx, w.manager.accessToken, all));
    });
    await attempt(ctx, 'L28.policy.unknown_key', async (check) => {
      for (const [who, token] of [['anon', null], ['member', w.member.accessToken], ['staff_aal2', w.staff2.accessToken], ['manager_aal2', w.manager.accessToken]]) {
        const o = await ctx.hosted.rest.rpc(token, 'has_permission', { client_id: 'rls-demo', permission_key: UNKNOWN });
        check.assert(`unknown key false (${who})`, 'value:false', `${o.kind}:${o.value}`);
      }
      const o = await ctx.hosted.rest.rpc(w.manager.accessToken, 'has_permission', { client_id: 'no-such-client', permission_key: 'notes:read:any' });
      check.assert('unknown client false', 'value:false', `${o.kind}:${o.value}`);
    });
  },
}];
