-- Row Level Security for one consumer table, using the kit's public helpers.
--
-- The kit supplies `auth_kit.has_permission(client_id, key)`, `auth_kit.has_role`
-- and `auth_kit.has_aal2()`. You own this table and these policies. Replace
-- 'rls-demo' with your client id and keep the keys in step with your model file.
--
-- What this path checks, and what it does not:
--   * The helpers read the caller's memberships live, so a membership revoke
--     or a model change takes effect on the next query.
--   * A held role that requires MFA counts only when the JWT's `aal` is `aal2`.
--   * PostgREST verifies the token's signature and expiry. Nothing here asks
--     Supabase Auth whether the session still exists, so a signed-out or
--     banned user's unexpired token keeps working until it expires. Keep only
--     data on this path that such a user may still see for up to one token
--     lifetime; route anything more sensitive through a Node endpoint that
--     calls `resolveSession`.
--   * Ownership (`owner_id = auth.uid()`) is this table's own rule, not the kit's.
--
-- The schema `app` must be listed in the project's exposed schemas for the
-- browser to reach it over PostgREST. Never expose `auth_kit_private`.

create schema if not exists app;

create table app.notes (
  id bigint generated always as identity primary key,
  owner_id uuid not null default auth.uid(),
  title text not null,
  body text not null default ''
);

alter table app.notes enable row level security;
-- The table owner would otherwise bypass its own policies.
alter table app.notes force row level security;

create policy notes_select on app.notes for select to authenticated using (
  auth_kit.has_permission('rls-demo', 'notes:read:any')
  or (auth_kit.has_permission('rls-demo', 'notes:read:own') and owner_id = auth.uid())
);

create policy notes_insert on app.notes for insert to authenticated with check (
  auth_kit.has_permission('rls-demo', 'notes:write:any')
  or (auth_kit.has_permission('rls-demo', 'notes:write:own') and owner_id = auth.uid())
);

create policy notes_update on app.notes for update to authenticated using (
  auth_kit.has_permission('rls-demo', 'notes:write:any')
  or (auth_kit.has_permission('rls-demo', 'notes:write:own') and owner_id = auth.uid())
) with check (
  auth_kit.has_permission('rls-demo', 'notes:write:any')
  or (auth_kit.has_permission('rls-demo', 'notes:write:own') and owner_id = auth.uid())
);

create policy notes_delete on app.notes for delete to authenticated using (
  auth_kit.has_permission('rls-demo', 'notes:write:any')
  or (auth_kit.has_permission('rls-demo', 'notes:write:own') and owner_id = auth.uid())
);

-- `anon` gets nothing: no grant, and every policy is `to authenticated`.
grant usage on schema app to authenticated;
grant select, insert, update, delete on app.notes to authenticated;
