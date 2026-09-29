-- Hosted L26 fixture: one consumer table whose Row Level Security uses the
-- design's own/any guard (design 4.2 and 4.3), on the fixed client
-- `orders-demo`. The operator applies this file to the isolated verification
-- project after the kit's migrations and examples/rls-consumer/policies.sql;
-- the harness only checks it (T.orders_consumer) and never creates or alters
-- it. It holds no data: each run inserts two rows titled with its run marker
-- and deletes them again when `cleanup_sql` is authorized.
--
--   (i)  another customer's order   (ii) an order the caller owns
--
-- A user holding `customer` and MFA-required `staff` at `aal1` reads (ii)
-- only; at `aal2` the active `staff` role grants `orders:read:any` and both
-- rows are visible. The same guard runs on the Node path in the harness.

create schema if not exists app;

create table app.orders (
  id bigint generated always as identity primary key,
  owner_id uuid not null,
  title text not null
);

alter table app.orders enable row level security;
-- The table owner would otherwise bypass its own policy.
alter table app.orders force row level security;

create policy orders_select on app.orders for select to authenticated using (
  auth_kit.has_permission('orders-demo', 'orders:read:any')
  or (auth_kit.has_permission('orders-demo', 'orders:read:own') and owner_id = auth.uid())
);

-- Reads only for signed-in users; `anon` gets nothing. Rows are written by
-- the harness through the Management API, not over PostgREST.
grant usage on schema app to authenticated;
grant select on app.orders to authenticated;
