-- Test fixture, database level: the slice of Supabase's `auth` schema that the
-- migrations read, created as the cluster superuser in the harness's template
-- database only. Never part of a production migration.
--
-- - auth.uid(), auth.role() and auth.jwt() read the request.jwt.claims setting
--   the same way Supabase's published definitions do (including the legacy
--   request.jwt.claim.* settings), so impersonation is real role switching
--   plus real claims, not a shortcut.
-- - auth.users is reduced to the columns the migrations read (id,
--   email_confirmed_at) plus email and is_anonymous for readability. Hosted
--   auth.users is owned by supabase_auth_admin and has many more columns; the
--   migration role only needs SELECT on it, which is all this fixture grants.
-- - No GoTrue: users are inserted directly by the harness.

create schema auth;
grant usage on schema auth to anon, authenticated, service_role, postgres;

create table auth.users (
  id uuid primary key,
  email text,
  email_confirmed_at timestamptz,
  is_anonymous boolean not null default false,
  created_at timestamptz not null default now()
);
grant select on auth.users to postgres;

create function auth.uid() returns uuid
language sql stable
as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim.sub', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'sub')
  )::uuid
$$;

create function auth.role() returns text
language sql stable
as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim.role', true), ''),
    (nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'role')
  )::text
$$;

create function auth.jwt() returns jsonb
language sql stable
as $$
  select coalesce(
    nullif(current_setting('request.jwt.claim', true), ''),
    nullif(current_setting('request.jwt.claims', true), '')
  )::jsonb
$$;

grant execute on function auth.uid(), auth.role(), auth.jwt() to anon, authenticated, service_role, postgres;
