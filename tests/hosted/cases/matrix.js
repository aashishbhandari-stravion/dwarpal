// The live actor matrix (design 5.1, 8) on client A across three model
// states: S0 registered with no model, S1 the example model, S2 a changed
// model. Every actor is read over PostgREST with its own token (or none):
// effective_access, the three helpers for every model key and role, its own
// profile, the public client list and one private table. Expectations come
// from lib/expected.js (design 4.3), never from the code under test. S2 is
// read with the same tokens as S1, so a model change must show on the next
// request. The M.* cases add forged metadata and tokens, wrong-client calls
// and manager overreach.

import { randomUUID } from 'node:crypto';
import { SignJWT, generateKeyPair } from 'jose';
import { attempt, ensureClient, applyModel, bootstrap, signedInMember, managerWrite, counts, access } from '../lib/world.js';
import { exampleModel, changedModel } from '../lib/fixtures.js';
import { expectedAccess, sortKeys } from '../lib/expected.js';
import { MATRIX_ACTORS } from '../lib/inventory.js';
import { HostedError } from '../lib/hosted.js';

const UNKNOWN_KEY = 'matrix:unknown:key';

function shapeAccess(o) {
  if (o.kind !== 'value') return `${o.kind}:${o.status}:${o.code ?? ''}`;
  const v = o.value;
  return { memberships: sortKeys((v.memberships ?? []).map((m) => m.role_key)), active_roles: v.active_roles, permissions: v.permissions, mfa_pending: v.mfa_pending };
}

async function helpers(ctx, token, clientId, model) {
  const keys = sortKeys([...Object.keys(model?.permissions ?? {}), UNKNOWN_KEY]);
  const roles = sortKeys(Object.keys(model?.roles ?? {}));
  const out = {};
  for (const k of keys) {
    const o = await ctx.hosted.rest.rpc(token, 'has_permission', { client_id: clientId, permission_key: k });
    out[`perm:${k}`] = o.kind === 'value' ? o.value : `${o.kind}:${o.status}`;
  }
  for (const r of roles) {
    const o = await ctx.hosted.rest.rpc(token, 'has_role', { client_id: clientId, role_key: r });
    out[`role:${r}`] = o.kind === 'value' ? o.value : `${o.kind}:${o.status}`;
  }
  const aal = await ctx.hosted.rest.rpc(token, 'has_aal2', {});
  out.aal2 = aal.kind === 'value' ? aal.value : `${aal.kind}:${aal.status}`;
  return out;
}

function expectedHelpers(model, exp, aal) {
  const out = {};
  for (const k of sortKeys([...Object.keys(model?.permissions ?? {}), UNKNOWN_KEY])) out[`perm:${k}`] = exp.permissions.includes(k);
  for (const r of sortKeys(Object.keys(model?.roles ?? {}))) out[`role:${r}`] = exp.activeRoles.includes(r);
  out.aal2 = aal === 'aal2';
  return out;
}

/** Tokens per matrix actor; roles each holds on A (null for anon and service). */
async function actorsFor(ctx, state) {
  const t = {};
  t.anon = { token: null, held: null };
  t.service = { token: ctx.creds.SUPABASE_SECRET_KEY, apikey: ctx.creds.SUPABASE_SECRET_KEY, held: null };
  if (state === 'S0') {
    for (const alias of ['member_a', 'staff_a', 'manager_a', 'manager_b', 'member_b']) {
      const s = await ctx.actors.signIn(alias);
      t[alias] = { token: s.accessToken, held: [], aal: 'aal1' };
    }
    t['staff_a@aal1'] = t.staff_a;
    t['staff_a@aal2'] = { ...t.staff_a, unreachable: 'no_mfa_role_to_verify' };
    t['manager_a@aal1'] = t.manager_a;
    t['manager_a@aal2'] = { ...t.manager_a, unreachable: 'no_mfa_role_to_verify' };
    return t;
  }
  const w = ctx.state.matrix;
  t.member_a = { token: w.member.accessToken, held: ['customer'], aal: 'aal1' };
  t['staff_a@aal1'] = { token: w.staff1.accessToken, held: ['customer', 'staff'], aal: 'aal1' };
  t['staff_a@aal2'] = { token: w.staff2.accessToken, held: ['customer', 'staff'], aal: 'aal2' };
  t['manager_a@aal1'] = { token: w.manager1.accessToken, held: ['admin'], aal: 'aal1' };
  t['manager_a@aal2'] = { token: w.manager2.accessToken, held: ['admin'], aal: 'aal2' };
  t.manager_b = { token: w.managerB.accessToken, held: [], aal: 'aal2' };
  t.member_b = { token: w.memberB.accessToken, held: [], aal: 'aal1' };
  return t;
}

async function readActor(ctx, state, actor, a, model) {
  const clientId = ctx.ids.A;
  const obs = {};
  const opts = a.apikey ? { apikey: a.apikey } : {};
  obs.effective_access = shapeAccess(await ctx.hosted.rest.rpc(a.token, 'effective_access', { client_id: clientId }, opts));
  if (a.held !== null || actor === 'anon' || actor === 'service') {
    const profile = await ctx.hosted.rest.rpc(a.token, 'ensure_profile', {}, opts);
    // A void function answers 200 or 204 depending on the PostgREST version; only the kind matters.
    obs.ensure_profile = profile.kind === 'value' ? 'value' : `${profile.kind}:${profile.status}`;
    const profiles = await ctx.hosted.rest.select(a.token, 'auth_kit', 'profiles', 'select=user_id', opts);
    obs.profiles = profiles.kind === 'value' ? profiles.value.length : `${profiles.kind}:${profiles.status}`;
    const clients = await ctx.hosted.rest.select(a.token, 'auth_kit', 'public_clients', `select=client_id,display_name&client_id=eq.${clientId}`, opts);
    obs.public_clients = clients.kind === 'value' ? clients.value.map((c) => c.client_id) : `${clients.kind}:${clients.status}`;
    const priv = await ctx.hosted.rest.select(a.token, 'auth_kit_private', 'memberships', 'select=*&limit=1', opts);
    obs.private_table = `${priv.status}:${priv.code ?? priv.kind}`;
  }
  if (a.held !== null) obs.helpers = await helpers(ctx, a.token, clientId, model);
  return obs;
}

function expectActor(actor, a, model) {
  if (actor === 'anon') {
    return { effective_access: 'failure:401:42501', ensure_profile: 'failure:401', profiles: 'failure:401', public_clients: 'failure:401', private_table: '406:PGRST106' };
  }
  if (actor === 'service') {
    // The service role has no user: effective_access refuses, the tables are readable (it bypasses RLS).
    return { effective_access: 'refusal:400:forbidden', ensure_profile: 'refusal:400', profiles: 'any', public_clients: [/* registered A */], private_table: '406:PGRST106' };
  }
  const exp = expectedAccess(model, a.held, a.aal);
  return {
    effective_access: { memberships: exp.roles, active_roles: exp.activeRoles, permissions: exp.permissions, mfa_pending: exp.mfaPending },
    ensure_profile: 'value', profiles: 1, public_clients: [], private_table: '406:PGRST106',
    helpers: expectedHelpers(model, exp, a.aal),
  };
}

async function matrixState(ctx, state, model) {
  const tokens = await actorsFor(ctx, state);
  for (const actor of MATRIX_ACTORS) {
    await attempt(ctx, `M.${state}.${actor}`, async (check) => {
      const a = tokens[actor];
      if (a.unreachable) {
        // In S0 no role requires MFA and no factor exists yet, so aal2 cannot be reached; the aal1 row covers the state.
        check.assert('aal2 not reachable in the empty state; the aal1 row stands for it', true, true);
        return;
      }
      const observed = await readActor(ctx, state, actor, a, model);
      const expected = expectActor(actor, a, model);
      expected.public_clients = [ctx.ids.A];
      if (actor === 'anon') expected.public_clients = 'failure:401';
      if (actor === 'service') expected.profiles = observed.profiles;
      check.assert(`${state} ${actor}`, expected, observed);
    });
  }
}

export const procedures = [{
  id: 'matrix',
  group: 'matrix',
  requiresTargets: ['T.identity', 'T.signing_keys', 'T.auth_settings'],
  async run(ctx) {
    // S0: registered, no model.
    await ensureClient(ctx, 'A');
    for (const alias of ['member_a', 'staff_a', 'manager_a', 'manager_a2', 'manager_b', 'member_b']) await ctx.actors.user(alias);
    await matrixState(ctx, 'S0', null);

    // S1: the example model, then the actors' memberships.
    const s1 = exampleModel(ctx.ids.A);
    await applyModel(ctx, s1);
    await ensureClient(ctx, 'B', { model: exampleModel(ctx.ids.B) });
    await bootstrap(ctx, 'A', 'manager_a', 'admin');
    await bootstrap(ctx, 'A', 'manager_a2', 'admin');
    await bootstrap(ctx, 'B', 'manager_b', 'admin');
    const manager2 = await ctx.actors.aal2('manager_a');
    const member = await signedInMember(ctx, 'member_a', 'A');
    await signedInMember(ctx, 'staff_a', 'A');
    const granted = await managerWrite(ctx, 'grant_membership', manager2.accessToken, 'A', 'staff_a', 'staff');
    if (granted.kind !== 'value') throw new HostedError('grant_staff', granted.status, granted.code ?? null);
    ctx.state.matrix = {
      member,
      manager2,
      manager1: await ctx.actors.signIn('manager_a'),
      staff1: await ctx.actors.signIn('staff_a'),
      staff2: await ctx.actors.aal2('staff_a'),
      managerB: await ctx.actors.aal2('manager_b'),
      memberB: await signedInMember(ctx, 'member_b', 'B'),
    };
    await matrixState(ctx, 'S1', s1);

    // S2: a changed model, read with the same tokens.
    const s2 = changedModel(ctx.ids.A);
    await applyModel(ctx, s2);
    await matrixState(ctx, 'S2', s2);

    const w = ctx.state.matrix;
    const m = ctx.actors.get('member_a');

    await attempt(ctx, 'M.forged_metadata', async (check) => {
      check.assert('user_metadata update accepted', 200, await ctx.hosted.auth.updateUserMetadata(w.member.accessToken, { role: 'admin', roles: ['admin', 'staff'], permissions: ['orders:read:any'] }));
      check.assert('app_metadata update accepted (operator)', 200, await ctx.hosted.admin.update(m.id, { app_metadata: { role: 'admin', roles: ['admin'], permissions: ['orders:read:any'] } }));
      const fresh = await ctx.actors.signIn('member_a');
      const exp = expectedAccess(s2, ['customer'], 'aal1');
      check.assert('access unchanged with a token carrying the forged metadata', { memberships: exp.roles, active_roles: exp.activeRoles, permissions: exp.permissions, mfa_pending: exp.mfaPending }, shapeAccess(await access(ctx, fresh.accessToken, 'A')));
      const any = await ctx.hosted.rest.rpc(fresh.accessToken, 'has_permission', { client_id: ctx.ids.A, permission_key: 'orders:read:any' });
      check.assert('helper ignores forged metadata', 'value:false', `${any.kind}:${any.value}`);
      const node = await ctx.hosted.nodeEndpoint(ctx.ids.A);
      try {
        const r = await node.get(fresh.accessToken);
        check.assert('Node principal roles from memberships only', { status: 200, roles: ['customer'], activeRoles: ['customer'] }, { status: r.status, roles: r.body?.principal?.access?.roles, activeRoles: r.body?.principal?.access?.activeRoles });
      } finally {
        await node.close();
      }
    });

    await attempt(ctx, 'M.forged_jwt', async (check) => {
      const { privateKey } = await generateKeyPair('ES256');
      const jwks = (await ctx.hosted.auth.jwks()).json?.keys ?? [];
      const now = Math.floor(ctx.clock.now() / 1000);
      const forged = await new SignJWT({ sub: m.id, role: 'authenticated', aud: 'authenticated', aal: 'aal2', session_id: randomUUID(), is_anonymous: false, iss: `${ctx.hosted.origin}/auth/v1` })
        .setProtectedHeader({ alg: 'ES256', kid: jwks[0]?.kid ?? randomUUID(), typ: 'JWT' }).setIssuedAt(now).setExpirationTime(now + 600).sign(privateKey);
      ctx.redactor.secret(forged, 'forged_jwt');
      const rest = await access(ctx, forged, 'A');
      check.assert('PostgREST refuses the foreign signature', 'failure:401', `${rest.kind}:${rest.status}`);
      const node = await ctx.hosted.nodeEndpoint(ctx.ids.A);
      try {
        const r = await node.get(forged);
        check.assert('Node path refuses the foreign signature', { status: 401, error: 'invalid_token' }, { status: r.status, error: r.body?.error });
      } finally {
        await node.close();
      }
    });

    await attempt(ctx, 'M.wrong_client', async (check) => {
      check.assert('A member asking for B: no membership', { memberships: [], active_roles: [], permissions: [], mfa_pending: false }, shapeAccess(await access(ctx, w.member.accessToken, 'B')));
      const h = await ctx.hosted.rest.rpc(w.member.accessToken, 'has_permission', { client_id: ctx.ids.B, permission_key: 'orders:read:own' });
      check.assert('A member: B helper false', 'value:false', `${h.kind}:${h.value}`);
      const before = await counts(ctx, { clientId: ctx.ids.B, userId: m.id });
      const g = await managerWrite(ctx, 'grant_membership', w.manager2.accessToken, 'B', 'member_a', 'customer');
      check.assert('A manager writing on B refused', 'refusal:forbidden', `${g.kind}:${g.code}`);
      check.assert('nothing written for B', before, await counts(ctx, { clientId: ctx.ids.B, userId: m.id }));
    });

    await attempt(ctx, 'M.manager_promotes_manager', async (check) => {
      const before = await counts(ctx, { clientId: ctx.ids.A, userId: m.id });
      const g = await managerWrite(ctx, 'grant_membership', w.manager2.accessToken, 'A', 'member_a', 'admin');
      check.assert('manager granting admin refused', 'refusal:forbidden', `${g.kind}:${g.code}`);
      check.assert('nothing written', before, await counts(ctx, { clientId: ctx.ids.A, userId: m.id }));
    });

    await attempt(ctx, 'M.self_target', async (check) => {
      const self = ctx.actors.get('manager_a');
      const before = await counts(ctx, { clientId: ctx.ids.A, userId: self.id });
      const g = await managerWrite(ctx, 'grant_membership', w.manager2.accessToken, 'A', 'manager_a', 'staff');
      check.assert('manager granting to self refused', 'refusal:forbidden', `${g.kind}:${g.code}`);
      check.assert('nothing written', before, await counts(ctx, { clientId: ctx.ids.A, userId: self.id }));
    });

    await attempt(ctx, 'M.operator_wrappers_as_user', async (check) => {
      const id = randomUUID();
      const calls = {
        register_client: { client_id: ctx.ids.A, display_name: 'x', signup_policy: 'open' },
        apply_model: { client_id: ctx.ids.A, model: s2, request_id: id, dry_run: true },
        export_model: { client_id: ctx.ids.A },
        bootstrap_manager: { user_id: m.id, client_id: ctx.ids.A, role_key: 'admin', request_id: id },
        revoke_manager: { user_id: m.id, client_id: ctx.ids.A, role_key: 'admin', request_id: id },
        mfa_reset_begin: { user_id: m.id, request_id: id },
        mfa_reset_note: { request_id: id, run_token: id, factor_ids: [] },
        mfa_reset_finish: { request_id: id, run_token: id, factors_deleted: [] },
      };
      const seen = {};
      const expected = {};
      for (const [fn, args] of Object.entries(calls)) {
        for (const [who, token, status] of [['anon', null, 401], ['member', w.member.accessToken, 403]]) {
          const o = await ctx.hosted.rest.rpc(token, fn, args);
          seen[`${who}:${fn}`] = `${o.status}:${o.code ?? o.kind}`;
          expected[`${who}:${fn}`] = `${status}:42501`;
        }
      }
      check.assert('operator wrappers refused for anon and authenticated', expected, seen);
    });
  },
}];
