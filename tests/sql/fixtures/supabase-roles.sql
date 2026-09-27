-- Test fixture, cluster level: the database roles a hosted Supabase project
-- provides, created in the harness's own throwaway cluster only. Never part of
-- a production migration. Run as the cluster superuser (supabase_admin, the
-- name hosted Supabase also uses for its superuser).
--
-- Differences from hosted Supabase that matter here:
-- - `postgres` is the migration role and, as on hosted projects, is not a
--   superuser; it has BYPASSRLS and may create schemas in the test database.
-- - `authenticator` stands in for PostgREST's login role: tests connect as it
--   and switch to anon / authenticated / service_role with
--   set_config('role', ...), exactly as PostgREST does per request.
-- - Role passwords, JWT secrets, PostgREST, GoTrue and their extra roles
--   (supabase_auth_admin, dashboard_user, ...) do not exist here.

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then
    create role anon nologin noinherit;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then
    create role authenticated nologin noinherit;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'service_role') then
    create role service_role nologin noinherit bypassrls;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticator') then
    create role authenticator login noinherit;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'postgres') then
    create role postgres login createrole bypassrls;
  end if;
end
$$;

grant anon, authenticated, service_role to authenticator;
grant anon, authenticated, service_role to postgres;
