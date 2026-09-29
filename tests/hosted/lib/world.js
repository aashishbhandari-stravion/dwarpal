// Shared steps the procedures build on: one operator client, client
// registration and model application with ledger entries, joins, manager
// writes over HTTP, and read-only SQL counts. Each case runs inside
// `attempt`, so one case's failure is recorded against that case alone.

import { randomUUID } from 'node:crypto';
import { Blocked } from './status.js';
import { HostedError } from './hosted.js';
import { errorTag } from './runner.js';
import { textLiteral } from './sqlprobe.js';

export async function attempt(ctx, id, fn) {
  if (!ctx.wants(id)) return;
  const check = ctx.check(id);
  try {
    await fn(check);
  } catch (error) {
    const blocked = error instanceof Blocked;
    const reason = blocked ? error.reason : errorTag(error);
    ctx.observe(`${id}: error`, { name: error?.name, reason, stage: error?.stage ?? error?.details?.stage ?? null, status: error?.status ?? null, code: error?.code ?? null,
      cause: error?.details?.reason ?? null, message: String(error?.message ?? '').slice(0, 500) });
    if (!ctx.wants(id)) return;
    if (blocked) ctx.block(id, reason);
    else ctx.fail(id, reason);
    return;
  }
  // The case may have recorded itself (for example not_run with a disposition).
  if (ctx.wants(id)) ctx.finish(check);
}

export function op(ctx) {
  ctx.state.operator ??= ctx.hosted.operator();
  return ctx.state.operator;
}

export function requireAction(ctx, action) {
  if (!ctx.actions.has(action)) throw new Blocked(`${action}_not_authorized`);
}

/** Registers the client (idempotent) and applies `model` when given; memoised per client key. */
export async function ensureClient(ctx, key, { model = null, policy = 'open' } = {}) {
  requireAction(ctx, 'mutations');
  ctx.state.clients ??= new Map();
  if (ctx.state.clients.has(key)) return ctx.state.clients.get(key);
  const clientId = ctx.ids[key];
  ctx.ledger.intent('client', clientId);
  const registered = await op(ctx).registerClient({ clientId, displayName: `Hosted check ${key}`, signupPolicy: policy });
  ctx.ledger.created('client', clientId);
  let applied = null;
  if (model) applied = await op(ctx).applyModel(model, { requestId: randomUUID() });
  const info = { clientId, registered, applied };
  ctx.state.clients.set(key, info);
  return info;
}

export async function applyModel(ctx, model, requestId = randomUUID()) {
  requireAction(ctx, 'mutations');
  return op(ctx).applyModel(model, { requestId });
}

export async function bootstrap(ctx, clientKey, alias, role, requestId = randomUUID()) {
  const actor = await ctx.actors.user(alias);
  return op(ctx).bootstrapManager({ clientId: ctx.ids[clientKey], roleKey: role, requestId, userId: actor.id });
}

export async function join(ctx, token, clientKey) {
  return ctx.hosted.rest.rpc(token, 'join_client', { client_id: ctx.ids[clientKey] });
}

export async function access(ctx, token, clientKey) {
  return ctx.hosted.rest.rpc(token, 'effective_access', { client_id: ctx.ids[clientKey] });
}

export async function managerWrite(ctx, fn, token, clientKey, targetAlias, role, requestId = randomUUID()) {
  const target = ctx.actors.get(targetAlias);
  return ctx.hosted.rest.rpc(token, fn, { user_id: target.id, client_id: ctx.ids[clientKey], role_key: role, request_id: requestId });
}

/**
 * A session shared by several cases, renewed (at the same assurance level)
 * when it is within two minutes of its expiry.
 */
export async function fresh(ctx, alias, session) {
  if (session.claims?.exp * 1000 - ctx.clock.now() > 120_000) return session;
  return session.claims?.aal === 'aal2' ? ctx.actors.aal2(alias) : ctx.actors.signIn(alias);
}

/** Signs the user in and joins the client; returns the session. */
export async function signedInMember(ctx, alias, clientKey) {
  await ctx.actors.user(alias);
  const session = await ctx.actors.signIn(alias);
  const joined = await join(ctx, session.accessToken, clientKey);
  if (joined.kind !== 'value' || !['enrolled', 'already_enrolled'].includes(joined.value?.result)) {
    throw new HostedError('join_setup', joined.status, joined.code ?? joined.value?.result ?? null);
  }
  return session;
}

// Read-only SQL counts ---------------------------------------------------------

function uuidLit(id) {
  if (!/^[0-9a-f-]{36}$/i.test(id)) throw new TypeError('uuid expected');
  return `'${id.toLowerCase()}'::uuid`;
}

/** Rows touching one request id, one client, or one user and client. */
export async function counts(ctx, { requestId = null, clientId = null, userId = null } = {}) {
  const where = (col) => {
    const parts = [];
    if (requestId) parts.push(`${col.request} = ${uuidLit(requestId)}`);
    if (clientId && col.client) parts.push(`${col.client} = ${textLiteral(clientId)}`);
    if (userId && col.user) parts.push(`${col.user} = ${uuidLit(userId)}`);
    return parts.length === 0 ? 'true' : parts.join(' and ');
  };
  const sql = `select jsonb_build_object(
    'request_log', (select pg_catalog.count(*) from auth_kit_private.request_log where ${where({ request: 'request_id', client: 'client_id', user: null })}),
    'membership_events', (select pg_catalog.count(*) from auth_kit_private.membership_events where ${where({ request: 'request_id', client: 'client_id', user: 'user_id' })}),
    'model_events', (select pg_catalog.count(*) from auth_kit_private.model_events where ${where({ request: 'request_id', client: 'client_id', user: null })}),
    'memberships', (select pg_catalog.count(*) from auth_kit_private.memberships where ${requestId ? 'false' : where({ request: 'x', client: 'client_id', user: 'user_id' })}),
    'enrollments', (select pg_catalog.count(*) from auth_kit_private.enrollments where ${requestId ? 'false' : where({ request: 'x', client: 'client_id', user: 'user_id' })})
  )::text as result`;
  return ctx.hosted.management.read(sql);
}

export async function requestRow(ctx, requestId) {
  return ctx.hosted.management.read(`select coalesce((select jsonb_build_object('state', r.state, 'operation', r.operation,
      'client_id', r.client_id, 'result', r.result, 'factors_seen', r.factors_seen, 'has_token', r.run_token is not null)
    from auth_kit_private.request_log r where r.request_id = ${uuidLit(requestId)}), 'null'::jsonb)::text as result`);
}

export async function membershipsOf(ctx, userId, clientId) {
  return ctx.hosted.management.read(`select coalesce(jsonb_agg(jsonb_build_object('role', m.role_key, 'via', m.granted_via) order by m.role_key), '[]'::jsonb)::text as result
    from auth_kit_private.memberships m where m.user_id = ${uuidLit(userId)} and m.client_id = ${textLiteral(clientId)}`);
}

export async function eventsOf(ctx, { userId, clientId = null, requestId = null }) {
  const filters = [`e.user_id = ${uuidLit(userId)}`];
  if (clientId !== null) filters.push(`e.client_id = ${textLiteral(clientId)}`);
  if (requestId !== null) filters.push(`e.request_id = ${uuidLit(requestId)}`);
  return ctx.hosted.management.read(`select coalesce(jsonb_agg(jsonb_build_object('action', e.action, 'role', e.role_key, 'client_id', e.client_id,
      'actor_kind', e.actor_kind) order by e.id), '[]'::jsonb)::text as result
    from auth_kit_private.membership_events e where ${filters.join(' and ')}`);
}

export { uuidLit };
