// L26: the own/any order guard on both access paths (design 4.2, 4.3, 5.14;
// LLD S4 and S4b). On the fixed client `orders-demo` (the policy in
// tests/hosted/fixtures/orders-consumer names it), a user holding `customer`
// and MFA-required `staff` requests (i) another customer's order and (ii) an
// order they own:
//
//   (a) through a Node endpoint running the literal S4 sequence: resolveSession,
//       load the order (404 if absent), then the design 4.3 guard; no
//       unscoped key is checked first, so a leftover `orders:read` would fail;
//   (b) through the installed RLS policy over PostgREST with the same token.
//
// At aal1: (i)(a) 403 forbidden with `staff` withheld, (i)(b) zero rows,
// (ii)(a) 200, (ii)(b) the row. At aal2 all four succeed. The orders are
// consumer rows written by Management SQL with the run marker in their
// title; cleanup finds and settles them (lib/rows.js).

import { attempt, ensureClient, bootstrap, signedInMember, managerWrite, fresh, requireAction, uuidLit } from '../lib/world.js';
import { ordersModel } from '../lib/fixtures.js';
import { HostedError } from '../lib/hosted.js';
import { rowTitle } from '../lib/rows.js';
import { textLiteral } from '../lib/sqlprobe.js';
import { AuthError, can, explain, isAuthError, requirePermission } from '../../../packages/server/index.js';

/**
 * The consumer's own route for GET /orders/:id, exactly as design 4.3 and
 * LLD S4 state it. `store` maps an order id to { id, userId }.
 */
export function ordersGuard(store) {
  return async (principal, url) => {
    if (principal === null) throw new AuthError('no_token');
    const parts = url.pathname.split('/').filter(Boolean);
    if (parts.length !== 2 || parts[0] !== 'orders') return { status: 404, body: { error: 'not_found' } };
    const order = store.get(parts[1]);
    if (order === undefined) return { status: 404, body: { error: 'not_found' } };
    try {
      if (!can(principal, 'orders:read:any')) {          // broad branch needs an ACTIVE role that grants it
        requirePermission(principal, 'orders:read:own');  // throws forbidden or mfa_required
        if (order.userId !== principal.identity.userId) throw new AuthError('forbidden');
      }
    } catch (error) {
      if (!isAuthError(error)) throw error;
      return { status: 403, body: { error: error.code, withheld: explain(principal, 'orders:read:any').withheld.map((w) => w.role) } };
    }
    return { status: 200, body: { id: order.id } };
  };
}

async function insertOrder(ctx, key, ownerAlias) {
  requireAction(ctx, 'mutations');
  const owner = ctx.actors.get(ownerAlias).id;
  ctx.ledger.intent('orders', key);
  const id = await ctx.hosted.management.read(`with ins as (insert into app.orders (owner_id, title)
      values (${uuidLit(owner)}, ${textLiteral(rowTitle(ctx.runId, key))}) returning id)
    select (select id from ins)::text as result`);
  if (!Number.isInteger(id)) throw new HostedError('insert_order', 200, 'no_id');
  ctx.ledger.created('orders', key, { rowId: id });
  return { id: String(id), userId: owner };
}

async function visibleOrders(ctx, token, ids) {
  const o = await ctx.hosted.rest.select(token, 'app', 'orders', `select=id&id=in.(${ids.join(',')})&order=id`);
  return o.kind === 'value' ? o.value.map((r) => String(r.id)) : `${o.status}:${o.code ?? o.kind}`;
}

export const procedures = [{
  id: 'orders',
  group: 'orders',
  requiresTargets: ['T.identity', 'T.signing_keys', 'T.management', 'T.orders_consumer', 'T.exposed_schemas'],
  async run(ctx) {
    await ensureClient(ctx, 'ORD', { model: ordersModel() });
    await bootstrap(ctx, 'ORD', 'ord_manager', 'manager');
    const manager = await ctx.actors.aal2('ord_manager');
    await signedInMember(ctx, 'ord_other', 'ORD');
    const first = await signedInMember(ctx, 'ord_customer', 'ORD');
    const granted = await managerWrite(ctx, 'grant_membership', manager.accessToken, 'ORD', 'ord_customer', 'staff');
    if (granted.kind !== 'value') throw new HostedError('grant_staff', granted.status, granted.code ?? null);

    const other = await insertOrder(ctx, 'ord_other_order', 'ord_other');
    const own = await insertOrder(ctx, 'ord_own_order', 'ord_customer');
    const store = new Map([[other.id, other], [own.id, own]]);
    const ids = [other.id, own.id].sort((a, b) => Number(a) - Number(b));
    const node = await ctx.hosted.nodeEndpoint('orders-demo', { handle: ordersGuard(store) });
    const resolver = await ctx.hosted.nodeEndpoint('orders-demo');
    try {
      const aal1 = await fresh(ctx, 'ord_customer', first);
      await attempt(ctx, 'L26.aal1.node', async (check) => {
        const principal = (await resolver.get(aal1.accessToken)).body?.principal;
        check.assert('customer and staff held; staff withheld at aal1; no unscoped key', { roles: ['customer', 'staff'], activeRoles: ['customer'], mfaPending: true, permissions: ['orders:read:own'] },
          { roles: [...(principal?.access?.roles ?? [])].sort(), activeRoles: principal?.access?.activeRoles, mfaPending: principal?.access?.mfaPending, permissions: principal?.access?.permissions });
        const i = await node.get(aal1.accessToken, `/orders/${other.id}`);
        check.assert('(i) another customer\'s order: 403 forbidden, staff withheld', { status: 403, error: 'forbidden', withheld: ['staff'] }, { status: i.status, error: i.body?.error, withheld: i.body?.withheld });
        const ii = await node.get(aal1.accessToken, `/orders/${own.id}`);
        check.assert('(ii) own order: 200 via orders:read:own and ownership', { status: 200, id: own.id }, { status: ii.status, id: ii.body?.id });
      });
      await attempt(ctx, 'L26.aal1.rls', async (check) => {
        check.assert('(i) another customer\'s order: zero rows', [], await visibleOrders(ctx, aal1.accessToken, [other.id]));
        check.assert('(ii) own order: the row', [own.id], await visibleOrders(ctx, aal1.accessToken, [own.id]));
        check.assert('both requested: only the own row', [own.id], await visibleOrders(ctx, aal1.accessToken, ids));
      });

      const aal2 = await ctx.actors.aal2('ord_customer');
      await attempt(ctx, 'L26.aal2.node', async (check) => {
        check.assert('session at aal2', 'aal2', aal2.claims?.aal);
        const i = await node.get(aal2.accessToken, `/orders/${other.id}`);
        check.assert('(i) another customer\'s order: 200 via active staff', { status: 200, id: other.id }, { status: i.status, id: i.body?.id });
        const ii = await node.get(aal2.accessToken, `/orders/${own.id}`);
        check.assert('(ii) own order: 200', { status: 200, id: own.id }, { status: ii.status, id: ii.body?.id });
      });
      await attempt(ctx, 'L26.aal2.rls', async (check) => {
        check.assert('(i) another customer\'s order: the row', [other.id], await visibleOrders(ctx, aal2.accessToken, [other.id]));
        check.assert('(ii) own order: the row', [own.id], await visibleOrders(ctx, aal2.accessToken, [own.id]));
      });
      await attempt(ctx, 'L26.absent_and_anon', async (check) => {
        const absent = await node.get(aal2.accessToken, '/orders/0');
        check.assert('an absent order: 404 on the Node path', 404, absent.status);
        const anonNode = await node.get(null, `/orders/${own.id}`);
        check.assert('no token on the Node path: 401', { status: 401, error: 'no_token' }, { status: anonNode.status, error: anonNode.body?.error });
        const anon = await ctx.hosted.rest.select(null, 'app', 'orders', 'select=id&limit=1');
        check.assert('anon on the direct path: refused', 'failure:401', `${anon.kind}:${anon.status}`);
      });
    } finally {
      await node.close();
      await resolver.close();
    }
  },
}];
