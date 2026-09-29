// L27 enrollment matrix on client E (design 4.2 join_client, D19). Joins go
// over PostgREST with each user's own token; rows are counted read-only
// through the Management API. The injected failure is a temporary trigger in
// a harness-only schema that refuses the join event of one run user, so the
// join fails after its enrollment insert; it is recorded in the ledger
// before it is created and dropped in the same case.

import { attempt, ensureClient, applyModel, bootstrap, join, managerWrite, counts, membershipsOf, eventsOf, access, requireAction, uuidLit } from '../lib/world.js';
import { enrollModel } from '../lib/fixtures.js';

export function faultSql(runId, userId) {
  const schema = `hv_fault_${runId}`;
  return {
    schema,
    create: `create schema ${schema};
create function ${schema}.refuse_event() returns trigger language plpgsql as $f$
begin
  if new.user_id = ${uuidLit(userId)} then raise exception 'hosted harness injected failure'; end if;
  return new;
end
$f$;
create trigger ${schema}_refuse before insert on auth_kit_private.membership_events
  for each row execute function ${schema}.refuse_event();`,
    drop: `drop trigger if exists ${schema}_refuse on auth_kit_private.membership_events; drop schema if exists ${schema} cascade;`,
    present: `select (exists (select 1 from pg_catalog.pg_trigger where tgname = '${schema}_refuse')
      or pg_catalog.to_regnamespace('${schema}') is not null)::text as result`,
  };
}

const joinResult = (o) => (o.kind === 'value' ? o.value?.result : `${o.kind}:${o.status}:${o.code ?? ''}`);

export const procedures = [{
  id: 'enrollment',
  group: 'enrollment',
  requiresTargets: ['T.identity', 'T.signing_keys', 'T.management', 'T.schema'],
  async run(ctx) {
    const E = ctx.ids.E;
    await ensureClient(ctx, 'E', { model: enrollModel(E) });
    await bootstrap(ctx, 'E', 'e_manager', 'keeper');
    const manager = await ctx.actors.signIn('e_manager');
    const u1 = await ctx.actors.user('e_user1');
    let t1 = await ctx.actors.signIn('e_user1');

    await attempt(ctx, 'L27.first', async (check) => {
      check.assert('first join enrolls', 'enrolled', joinResult(await join(ctx, t1.accessToken, 'E')));
      const c = await counts(ctx, { clientId: E, userId: u1.id });
      check.assert('one enrollment row, one membership', { enrollments: 1, memberships: 1 }, { enrollments: c.enrollments, memberships: c.memberships });
      check.assert('one join event per self-assignable role', [{ action: 'join', role: 'member', client_id: E, actor_kind: 'user' }], await eventsOf(ctx, { userId: u1.id, clientId: E }));
    });

    await attempt(ctx, 'L27.retry', async (check) => {
      const before = await counts(ctx, { clientId: E, userId: u1.id });
      check.assert('retry is already_enrolled', 'already_enrolled', joinResult(await join(ctx, t1.accessToken, 'E')));
      check.assert('nothing written', before, await counts(ctx, { clientId: E, userId: u1.id }));
    });

    await attempt(ctx, 'L27.revoke_then_signin', async (check) => {
      const r = await managerWrite(ctx, 'revoke_membership', manager.accessToken, 'E', 'e_user1', 'member');
      check.assert('manager revoke', 'value:revoked', `${r.kind}:${r.value?.result}`);
      t1 = await ctx.actors.signIn('e_user1');
      check.assert('join after a new sign-in is already_enrolled', 'already_enrolled', joinResult(await join(ctx, t1.accessToken, 'E')));
      check.assert('membership stays absent', [], await membershipsOf(ctx, u1.id, E));
      const a = await access(ctx, t1.accessToken, 'E');
      check.assert('effective_access: enrolled, no membership', { enrolled: true, memberships: 0 }, { enrolled: typeof a.value?.enrolled_at === 'string', memberships: a.value?.memberships?.length });
    });

    await attempt(ctx, 'L27.concurrent', async (check) => {
      const u2 = await ctx.actors.user('e_user2');
      const t2 = await ctx.actors.signIn('e_user2');
      const results = await Promise.all([join(ctx, t2.accessToken, 'E'), join(ctx, t2.accessToken, 'E')]);
      check.assert('one enrolled, one already_enrolled', ['already_enrolled', 'enrolled'], results.map(joinResult).sort());
      const c = await counts(ctx, { clientId: E, userId: u2.id });
      check.assert('one enrollment row', 1, c.enrollments);
      check.assert('one event per role in total', [{ action: 'join', role: 'member', client_id: E, actor_kind: 'user' }], await eventsOf(ctx, { userId: u2.id, clientId: E }));
    });

    await attempt(ctx, 'L27.injected_failure', async (check) => {
      requireAction(ctx, 'catalog_mutation');
      const u3 = await ctx.actors.user('e_user3');
      const t3 = await ctx.actors.signIn('e_user3');
      const fault = faultSql(ctx.runId, u3.id);
      ctx.ledger.intent('fault_trigger', fault.schema);
      try {
        await ctx.hosted.management.exec(fault.create);
        ctx.ledger.created('fault_trigger', fault.schema);
        const failed = await join(ctx, t3.accessToken, 'E');
        check.assert('join fails as a database failure, not a kit answer', 'failure', failed.kind);
        const c = await counts(ctx, { clientId: E, userId: u3.id });
        check.assert('no enrollment, membership or event left behind', { enrollments: 0, memberships: 0, membership_events: 0 }, { enrollments: c.enrollments, memberships: c.memberships, membership_events: c.membership_events });
      } finally {
        await ctx.hosted.management.exec(fault.drop);
        if (await ctx.hosted.management.read(fault.present) === false) ctx.ledger.removed('fault_trigger', fault.schema);
      }
      check.assert('fault trigger removed', false, await ctx.hosted.management.read(fault.present));
      check.assert('the next join enrolls', 'enrolled', joinResult(await join(ctx, t3.accessToken, 'E')));
      check.assert('one enrollment row now', 1, (await counts(ctx, { clientId: E, userId: u3.id })).enrollments);
    });

    await attempt(ctx, 'L27.new_role_future_only', async (check) => {
      const applied = await applyModel(ctx, enrollModel(E, { withExtra: true }));
      check.assert('model with a second self-assignable role applied', 'applied', applied.result);
      check.assert('enrolled user unchanged (revoked stays revoked)', [], await membershipsOf(ctx, u1.id, E));
      check.assert('enrolled user unchanged (member only)', [{ role: 'member', via: 'join' }], await membershipsOf(ctx, ctx.actors.get('e_user2').id, E));
      const u4 = await ctx.actors.user('e_user4');
      const t4 = await ctx.actors.signIn('e_user4');
      check.assert('new user enrolls', 'enrolled', joinResult(await join(ctx, t4.accessToken, 'E')));
      check.assert('new user gets both self-assignable roles', [{ role: 'extra', via: 'join' }, { role: 'member', via: 'join' }], await membershipsOf(ctx, u4.id, E));
    });

    await attempt(ctx, 'L27.regrant', async (check) => {
      const g = await managerWrite(ctx, 'grant_membership', manager.accessToken, 'E', 'e_user1', 'member');
      check.assert('manager re-grant', 'value:granted', `${g.kind}:${g.value?.result}`);
      check.assert('membership back via manager', [{ role: 'member', via: 'manager' }], await membershipsOf(ctx, u1.id, E));
      const events = await eventsOf(ctx, { userId: u1.id, clientId: E });
      check.assert('event history join, revoke, grant', ['join', 'revoke', 'grant'], events.map((e) => e.action));
    });
  },
}];
