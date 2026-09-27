-- dwarpal auth kit: SQL authority for contract 0.5.
--
-- Two schemas. `auth_kit` is the only one a project may add to its exposed
-- API schemas: it holds security-invoker wrappers, the RLS helpers, `profiles`
-- and the `public_clients` view. `auth_kit_private` holds every table and every
-- security-definer implementation (fixed empty search_path) and is never
-- exposed. Implementations read the actor from `auth.uid()` and
-- `auth.jwt() ->> 'aal'`, never from arguments. Every grant is explicit and the
-- file ends by asserting the complete grant table through
-- `auth_kit_private.grant_violations()`, which operators can re-run.
--
-- Targets hosted Supabase (PostgreSQL 15 or later, UTF8): runs once as the
-- project's migration role and relies on `auth.users`, `auth.uid()`,
-- `auth.jwt()` and the anon, authenticated and service_role roles. Apply the
-- whole file in one transaction; a failure anywhere leaves nothing behind.
--
-- Error convention: a kit refusal raises SQLSTATE DW001 with the refusal code
-- as the message (and, for model refusals, JSON in DETAIL). Any other SQLSTATE
-- is a database failure and must be treated as unavailable, never as success.

-- 0. Preconditions -----------------------------------------------------------

do $pre$
begin
  if pg_catalog.current_setting('server_encoding') <> 'UTF8' then
    raise exception 'dwarpal: the database encoding must be UTF8';
  end if;
  if pg_catalog.current_setting('server_version_num')::integer < 150000 then
    raise exception 'dwarpal: PostgreSQL 15 or later is required';
  end if;
  if pg_catalog.to_regnamespace('auth_kit') is not null
     or pg_catalog.to_regnamespace('auth_kit_private') is not null then
    raise exception 'dwarpal: auth_kit is already installed; this migration runs once';
  end if;
  if pg_catalog.to_regclass('auth.users') is null
     or pg_catalog.to_regprocedure('auth.uid()') is null
     or pg_catalog.to_regprocedure('auth.jwt()') is null then
    raise exception 'dwarpal: the Supabase auth schema (auth.users, auth.uid(), auth.jwt()) is required';
  end if;
  if (select pg_catalog.count(*) from pg_catalog.pg_roles
       where rolname in ('anon', 'authenticated', 'service_role')) <> 3 then
    raise exception 'dwarpal: the roles anon, authenticated and service_role are required';
  end if;
end
$pre$;

-- 1. Schemas and default privileges -----------------------------------------

create schema auth_kit;
create schema auth_kit_private;
comment on schema auth_kit is 'dwarpal auth kit: exposed wrappers, RLS helpers, profiles, public_clients.';
comment on schema auth_kit_private is 'dwarpal auth kit: tables and security-definer implementations. Never expose over the API.';

revoke all on schema auth_kit from public;
revoke all on schema auth_kit_private from public;

-- Per-schema default revocations cannot remove PostgreSQL's built-in PUBLIC
-- EXECUTE on new functions; they are kept as declared intent, and the explicit
-- revocations in section 8 plus the assertion in section 9 are the real fence.
alter default privileges in schema auth_kit revoke all on tables from public, anon, authenticated;
alter default privileges in schema auth_kit revoke all on sequences from public, anon, authenticated;
alter default privileges in schema auth_kit revoke execute on functions from public, anon, authenticated;
alter default privileges in schema auth_kit_private revoke all on tables from public, anon, authenticated;
alter default privileges in schema auth_kit_private revoke all on sequences from public, anon, authenticated;
alter default privileges in schema auth_kit_private revoke execute on functions from public, anon, authenticated;

-- 2. Tables -------------------------------------------------------------------

create table auth_kit_private.migrations (
  version text primary key,
  name text not null,
  applied_at timestamptz not null default pg_catalog.now()
);

create table auth_kit_private.clients (
  client_id text primary key,
  display_name text not null,
  signup_policy text not null check (signup_policy in ('open', 'closed')),
  -- registered -> live on the first successful bootstrap_manager; never back.
  state text not null default 'registered' check (state in ('registered', 'live')),
  created_at timestamptz not null default pg_catalog.now()
);

create table auth_kit_private.roles (
  client_id text not null references auth_kit_private.clients (client_id) on delete restrict,
  role_key text not null,
  description text not null default '',
  self_assignable boolean not null default false,
  manages_members boolean not null default false,
  mfa_required boolean not null default false,
  primary key (client_id, role_key),
  -- Public join grants self-assignable roles, so such a role must never manage members.
  constraint roles_self_assignable_not_manager check (not (self_assignable and manages_members))
);

create table auth_kit_private.permissions (
  client_id text not null references auth_kit_private.clients (client_id) on delete restrict,
  permission_key text not null,
  description text not null default '',
  primary key (client_id, permission_key)
);

-- Composite keys keep a mapping inside one client; restrict keeps a mapped
-- permission or a mapped role from disappearing underneath the mapping.
create table auth_kit_private.role_permissions (
  client_id text not null,
  role_key text not null,
  permission_key text not null,
  primary key (client_id, role_key, permission_key),
  foreign key (client_id, role_key) references auth_kit_private.roles (client_id, role_key) on delete restrict,
  foreign key (client_id, permission_key) references auth_kit_private.permissions (client_id, permission_key) on delete restrict
);

create table auth_kit_private.memberships (
  user_id uuid not null,
  client_id text not null,
  role_key text not null,
  granted_at timestamptz not null default pg_catalog.now(),
  granted_by uuid,
  granted_via text not null check (granted_via in ('join', 'manager', 'operator')),
  primary key (user_id, client_id, role_key),
  -- A held role cannot be deleted; revoke first.
  foreign key (client_id, role_key) references auth_kit_private.roles (client_id, role_key) on delete restrict,
  constraint memberships_granted_by_manager check ((granted_via = 'manager') = (granted_by is not null))
);

-- One row per public enrollment: the durable fact that the initial grant
-- happened. No function updates or deletes it, so a manager's revoke sticks.
create table auth_kit_private.enrollments (
  user_id uuid not null,
  client_id text not null references auth_kit_private.clients (client_id) on delete restrict,
  enrolled_at timestamptz not null default pg_catalog.now(),
  granted_roles text[] not null,
  primary key (user_id, client_id)
);

create table auth_kit_private.membership_events (
  id bigint generated always as identity primary key,
  request_id uuid unique,
  payload_hash text check (payload_hash ~ '^[0-9a-f]{64}$'),
  result text not null,
  action text not null check (action in ('join', 'grant', 'revoke', 'bootstrap', 'revoke_manager', 'mfa_reset')),
  user_id uuid not null,
  client_id text,
  role_key text,
  actor_user_id uuid,
  actor_kind text not null check (actor_kind in ('user', 'operator')),
  at timestamptz not null default pg_catalog.now(),
  -- mfa_reset is project-wide: the only event without a client or role.
  constraint membership_events_scope check ((action = 'mfa_reset') = (client_id is null) and (action = 'mfa_reset') = (role_key is null)),
  constraint membership_events_request check ((action = 'join') = (request_id is null) and (request_id is null) = (payload_hash is null)),
  constraint membership_events_actor check ((actor_kind = 'user') = (actor_user_id is not null))
);

create table auth_kit_private.model_events (
  id bigint generated always as identity primary key,
  request_id uuid not null unique,
  model_hash text not null check (model_hash ~ '^[0-9a-f]{64}$'),
  client_id text not null,
  diff jsonb not null,
  actor_kind text not null default 'operator' check (actor_kind = 'operator'),
  at timestamptz not null default pg_catalog.now()
);

-- One row per request-bearing command, mutating or not. state, factors_seen,
-- run_token, started_at and user_id serve mfa_reset only: its row is reserved
-- as pending before any Auth call, and user_id carries the reset's target to
-- the audit event because the fingerprint only hashes it.
create table auth_kit_private.request_log (
  request_id uuid primary key,
  client_id text,
  operation text not null check (operation in
    ('grant_membership', 'revoke_membership', 'bootstrap_manager', 'revoke_manager', 'apply_model', 'mfa_reset')),
  actor_id text not null check (actor_id <> ''),
  payload_hash text not null check (payload_hash ~ '^[0-9a-f]{64}$'),
  state text not null check (state in ('pending', 'completed')),
  result jsonb,
  factors_seen uuid[],
  run_token uuid,
  started_at timestamptz,
  at timestamptz not null,
  user_id uuid,
  constraint request_log_scope check ((operation = 'mfa_reset') = (client_id is null)),
  constraint request_log_result check ((state = 'completed') = (result is not null)),
  constraint request_log_mfa_fields check (
    case when operation = 'mfa_reset'
      then run_token is not null and started_at is not null and user_id is not null
      else state = 'completed' and run_token is null and started_at is null and user_id is null and factors_seen is null
    end)
);

create table auth_kit.profiles (
  user_id uuid primary key,
  display_name text,
  contact_email text,
  contact_phone text,
  updated_at timestamptz not null default pg_catalog.now()
);

alter table auth_kit.profiles enable row level security;

create policy profiles_select_own on auth_kit.profiles
  for select to authenticated using (user_id = (select auth.uid()));
create policy profiles_insert_own on auth_kit.profiles
  for insert to authenticated with check (user_id = (select auth.uid()));
create policy profiles_update_own on auth_kit.profiles
  for update to authenticated using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));

create view auth_kit.public_clients as
  select client_id, display_name from auth_kit_private.clients;

-- 3. Internal helpers (security invoker; they run as the definer when called
--    from an implementation) -------------------------------------------------

create function auth_kit_private.refuse(p_code text, p_detail jsonb default null)
returns void
language plpgsql
set search_path = ''
as $$
begin
  if p_detail is null then
    raise exception using errcode = 'DW001', message = p_code;
  end if;
  raise exception using errcode = 'DW001', message = p_code, detail = p_detail::text;
end
$$;

-- Sort key for UTF-16 code-unit order, the order core uses for canonical JSON
-- keys. Text comparison (UTF-8 byte order) disagrees with it when U+E000..U+FFFF
-- meets a supplementary character, so keys are compared as big-endian UTF-16.
create function auth_kit_private.utf16_key(p_value text)
returns bytea
language sql
immutable strict parallel safe
set search_path = ''
as $$
  select coalesce(decode(string_agg(
           case when c.cp < 65536 then lpad(to_hex(c.cp), 4, '0')
                else lpad(to_hex(55296 + ((c.cp - 65536) >> 10)), 4, '0')
                  || lpad(to_hex(56320 + ((c.cp - 65536) & 1023)), 4, '0')
           end, '' order by c.ord), 'hex'), '\x'::bytea)
    from (select ascii(t.ch) as cp, t.ord
            from string_to_table(p_value, null) with ordinality as t(ch, ord)) as c
$$;

-- Length in UTF-16 code units, the unit of core's description bound.
create function auth_kit_private.utf16_length(p_value text)
returns integer
language sql
immutable strict parallel safe
set search_path = ''
as $$
  select char_length(p_value) * 2
         - char_length(regexp_replace(p_value, '[\U00010000-\U0010FFFF]', '', 'g'))
$$;

create function auth_kit_private.too_long(p_value text, p_limit integer)
returns boolean
language sql
immutable strict parallel safe
set search_path = ''
as $$
  -- char_length never exceeds the UTF-16 length, so long text is refused
  -- without scanning it character by character.
  select case when char_length(p_value) > p_limit then true
              else auth_kit_private.utf16_length(p_value) > p_limit end
$$;

-- True when the decimal p_decimal reads back (round to nearest, ties to even)
-- as exactly the double p_double; false when it overflows the double range.
create function auth_kit_private.decimal_reads_as(p_decimal numeric, p_double double precision)
returns boolean
language plpgsql
immutable strict
set search_path = ''
as $$
begin
  return p_decimal::text::double precision = p_double;
exception when numeric_value_out_of_range then
  return false;
end
$$;

-- ECMAScript Number::toString of the double nearest to p_value, as
-- JSON.stringify writes it. PostgreSQL's own shortest float output is not
-- usable: it excludes the rounding interval's bounds, so at an exact tie it
-- prints more digits than JavaScript. The double is expanded exactly from its
-- IEEE-754 bits, and the shortest decimal that reads back as the same double
-- is chosen, closest first, then even, as the ECMAScript algorithm requires.
create function auth_kit_private.js_number_text(p_value numeric)
returns text
language plpgsql
immutable strict
set search_path = ''
as $$
declare
  v_float double precision;
  v_abs double precision;
  v_bits bigint;
  v_biased integer;
  v_exp2 integer;
  v_exact numeric;
  v_e integer;
  v_precision integer;
  v_unit numeric;
  v_lo numeric;
  v_lo_ok boolean;
  v_hi_ok boolean;
  v_s numeric;
  v_sign text := '';
  v_digits text;
  v_point integer;
  v_count integer;
  v_exp integer;
begin
  begin
    v_float := p_value::double precision;
  exception when numeric_value_out_of_range then
    -- JSON.parse rounds a magnitude below the smallest subnormal to zero; a
    -- magnitude above the largest double has no finite JSON meaning.
    if abs(p_value) < 1 then
      return '0';
    end if;
    raise;
  end;
  if v_float = 0 then
    return '0';
  end if;
  if v_float < 0 then
    v_sign := '-';
  end if;
  v_abs := abs(v_float);
  v_bits := ('x' || encode(float8send(v_abs), 'hex'))::bit(64)::bigint;
  v_biased := (v_bits >> 52)::integer;
  v_exact := (v_bits & 4503599627370495)::numeric;
  if v_biased = 0 then
    v_exp2 := -1074;
  else
    v_exact := v_exact + 4503599627370496;
    v_exp2 := v_biased - 1075;
  end if;
  -- Numeric multiplication is exact, so this is the double's exact value.
  for i in 1 .. abs(v_exp2) loop
    v_exact := v_exact * case when v_exp2 > 0 then 2::numeric else 0.5 end;
  end loop;
  v_e := floor(log(10::numeric, v_exact))::integer;
  while ('1e' || v_e)::numeric > v_exact loop
    v_e := v_e - 1;
  end loop;
  while ('1e' || (v_e + 1))::numeric <= v_exact loop
    v_e := v_e + 1;
  end loop;
  -- The value is in [10^v_e, 10^(v_e+1)). At each precision the closest valid
  -- candidate is one of the two grid points around it.
  -- A plpgsql integer FOR variable exists only inside its loop, so the
  -- precision that ends the search is counted explicitly.
  v_precision := 0;
  while v_s is null and v_precision < 17 loop
    v_precision := v_precision + 1;
    v_unit := ('1e' || (v_e + 1 - v_precision))::numeric;
    v_lo := div(v_exact, v_unit);
    if v_lo * v_unit = v_exact then
      v_s := v_lo;
      continue;
    end if;
    v_lo_ok := auth_kit_private.decimal_reads_as(v_lo * v_unit, v_abs);
    v_hi_ok := auth_kit_private.decimal_reads_as((v_lo + 1) * v_unit, v_abs);
    if v_lo_ok and v_hi_ok then
      if v_exact - v_lo * v_unit < (v_lo + 1) * v_unit - v_exact then
        v_s := v_lo;
      elsif v_exact - v_lo * v_unit > (v_lo + 1) * v_unit - v_exact then
        v_s := v_lo + 1;
      else
        v_s := case when mod(v_lo, 2) = 0 then v_lo else v_lo + 1 end;
      end if;
    elsif v_lo_ok then
      v_s := v_lo;
    elsif v_hi_ok then
      v_s := v_lo + 1;
    end if;
  end loop;
  if v_s is null then
    raise exception using errcode = '22023', message = 'canonical_json: unsupported number';
  end if;
  -- The value is 0.<v_digits> * 10^v_point.
  v_digits := v_s::text;
  v_point := char_length(v_digits) + v_e + 1 - v_precision;
  v_digits := rtrim(v_digits, '0');
  v_count := char_length(v_digits);
  if v_count <= v_point and v_point <= 21 then
    return v_sign || v_digits || repeat('0', v_point - v_count);
  elsif 0 < v_point and v_point <= 21 then
    return v_sign || left(v_digits, v_point) || '.' || substr(v_digits, v_point + 1);
  elsif -6 < v_point and v_point <= 0 then
    return v_sign || '0.' || repeat('0', -v_point) || v_digits;
  end if;
  v_exp := v_point - 1;
  return v_sign || left(v_digits, 1)
    || case when v_count > 1 then '.' || substr(v_digits, 2) else '' end
    || 'e' || case when v_exp >= 0 then '+' else '-' end || abs(v_exp)::text;
end
$$;

-- Canonical JSON shared with packages/core canonicalJson: keys sorted by
-- UTF-16 code unit, arrays in order, JSON.stringify escaping and numbers, no
-- whitespace, nesting limited to the same depth.
create function auth_kit_private.canonical_json(p_value jsonb, p_depth integer default 0)
returns text
language plpgsql
immutable
set search_path = ''
as $$
declare
  v_kind text;
  v_out text;
begin
  if p_value is null then
    raise exception using errcode = '22023', message = 'canonical_json: a value is required';
  end if;
  if p_depth > 64 then
    raise exception using errcode = '22023', message = 'canonical_json: value is nested too deeply';
  end if;
  v_kind := jsonb_typeof(p_value);
  if v_kind = 'object' then
    select '{' || coalesce(string_agg(to_json(e.key)::text || ':' || auth_kit_private.canonical_json(e.value, p_depth + 1),
                                      ',' order by auth_kit_private.utf16_key(e.key)), '') || '}'
      into v_out
      from jsonb_each(p_value) as e;
    return v_out;
  elsif v_kind = 'array' then
    select '[' || coalesce(string_agg(auth_kit_private.canonical_json(a.value, p_depth + 1), ',' order by a.ord), '') || ']'
      into v_out
      from jsonb_array_elements(p_value) with ordinality as a(value, ord);
    return v_out;
  elsif v_kind = 'string' then
    return to_json(p_value #>> '{}')::text;
  elsif v_kind = 'number' then
    v_out := auth_kit_private.js_number_text((p_value #>> '{}')::numeric);
    -- string_agg drops nulls, so a null here would silently delete a member.
    if v_out is null then
      raise exception using errcode = '22023', message = 'canonical_json: number could not be encoded';
    end if;
    return v_out;
  elsif v_kind = 'boolean' then
    return p_value::text;
  end if;
  return 'null';
end
$$;

create function auth_kit_private.sha256_hex(p_text text)
returns text
language sql
immutable strict parallel safe
set search_path = ''
as $$
  select encode(sha256(convert_to(p_text, 'UTF8')), 'hex')
$$;

-- sha256 of canonical {operation, client_id, actor_id, payload}; the same bytes
-- as core requestFingerprint. client_id is null only for project-wide mfa_reset.
create function auth_kit_private.request_fingerprint(p_operation text, p_client_id text, p_actor_id text, p_payload jsonb)
returns text
language sql
immutable
set search_path = ''
as $$
  select auth_kit_private.sha256_hex(auth_kit_private.canonical_json(jsonb_build_object(
    'operation', p_operation, 'client_id', p_client_id, 'actor_id', p_actor_id, 'payload', p_payload)))
$$;

create function auth_kit_private.iso_utc(p_at timestamptz)
returns text
language sql
immutable strict parallel safe
set search_path = ''
as $$
  select to_char(p_at at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
$$;

-- Serialises every write for one scope. Authority and state are read after the
-- lock, and only READ COMMITTED gives those reads a snapshot taken after the
-- wait; under REPEATABLE READ or SERIALIZABLE a check could see the state from
-- before a concurrent revoke, so such transactions are refused.
create function auth_kit_private.lock_scope(p_scope text)
returns void
language plpgsql
set search_path = ''
as $$
begin
  if current_setting('transaction_isolation') <> 'read committed' then
    raise exception using errcode = '0A000', message = 'auth_kit writes require READ COMMITTED isolation';
  end if;
  perform pg_advisory_xact_lock(hashtext(p_scope));
end
$$;

create function auth_kit_private.lock_client(p_client_id text)
returns void
language sql
set search_path = ''
as $$
  select auth_kit_private.lock_scope('auth_kit:' || p_client_id)
$$;

-- Returns the stored result for a request id, null when the id is unused, or
-- raises request_conflict. The id lock (two-key space, taken after the scope
-- lock) makes two first uses of one id under different scopes serialise, so
-- the second sees the first's row instead of a primary-key violation.
create function auth_kit_private.stored_result(p_request_id uuid, p_payload_hash text)
returns jsonb
language plpgsql
set search_path = ''
as $$
declare
  v_row record;
begin
  perform pg_advisory_xact_lock(hashtext('auth_kit:request_id'), hashtext(p_request_id::text));
  select payload_hash, state, result into v_row
    from auth_kit_private.request_log where request_id = p_request_id;
  if not found then
    return null;
  end if;
  if v_row.payload_hash <> p_payload_hash or v_row.state <> 'completed' then
    perform auth_kit_private.refuse('request_conflict');
  end if;
  return v_row.result;
end
$$;

create function auth_kit_private.record_request(p_request_id uuid, p_client_id text, p_operation text,
                                                p_actor_id text, p_payload_hash text, p_result jsonb)
returns jsonb
language sql
set search_path = ''
as $$
  insert into auth_kit_private.request_log (request_id, client_id, operation, actor_id, payload_hash, state, result, at)
  values (p_request_id, p_client_id, p_operation, p_actor_id, p_payload_hash, 'completed', p_result, clock_timestamp())
  returning result
$$;

-- A role is active when it needs no MFA or the session is aal2 (design 4.4).
create function auth_kit_private.role_active(p_mfa_required boolean)
returns boolean
language sql
stable
set search_path = ''
as $$
  select not p_mfa_required or coalesce(auth.jwt() ->> 'aal', 'aal1') = 'aal2'
$$;

-- Manager authority: one active manages_members role authorises; held but all withheld ->
-- mfa_required; none held -> forbidden.
create function auth_kit_private.require_manager(p_client_id text, p_user_id uuid)
returns void
language plpgsql
set search_path = ''
as $$
declare
  v_active boolean;
  v_held bigint;
begin
  select bool_or(auth_kit_private.role_active(r.mfa_required)), count(*)
    into v_active, v_held
    from auth_kit_private.memberships m
    join auth_kit_private.roles r on r.client_id = m.client_id and r.role_key = m.role_key
   where m.user_id = p_user_id and m.client_id = p_client_id and r.manages_members;
  if v_held = 0 then
    perform auth_kit_private.refuse('forbidden');
  elsif not v_active then
    perform auth_kit_private.refuse('mfa_required');
  end if;
end
$$;

create function auth_kit_private.confirmed_user(p_user_id uuid)
returns void
language plpgsql
set search_path = ''
as $$
declare
  v_confirmed timestamptz;
begin
  select u.email_confirmed_at into v_confirmed from auth.users u where u.id = p_user_id;
  if not found then
    perform auth_kit_private.refuse('unknown_user');
  elsif v_confirmed is null then
    perform auth_kit_private.refuse('email_unverified');
  end if;
end
$$;

-- 4. Model validation, canonical form and change planning --------------------

create function auth_kit_private.unknown_field_issues(p_object jsonb, p_prefix text, p_allowed text[])
returns jsonb
language sql
immutable
set search_path = ''
as $$
  select coalesce(jsonb_agg(jsonb_build_object(
           'path', case when p_prefix = '' then '#' else p_prefix || '.#' end || (s.ord - 1),
           'rule', 'unknown_field') order by s.ord) filter (where not (s.k = any (p_allowed))), '[]'::jsonb)
    from (select k, row_number() over (order by auth_kit_private.utf16_key(k)) as ord
            from jsonb_object_keys(p_object) as k) as s
$$;

-- The issue list core validateModel reports, in the same order and with the
-- same positional paths (caller keys never appear in a path). Keys are always
-- representable here: jsonb cannot hold NUL or an unpaired surrogate.
create function auth_kit_private.model_issues(p_model jsonb)
returns jsonb
language plpgsql
immutable
set search_path = ''
as $$
declare
  v_issues jsonb := '[]'::jsonb;
  v_permissions jsonb;
  v_declared jsonb;
  v_roles jsonb;
  v_role record;
  v_path text;
  v_before integer;
  v_parsed integer := 0;
  v_manager boolean := false;
  v_list jsonb;
  v_flag text;
begin
  if p_model is null or jsonb_typeof(p_model) <> 'object' then
    return jsonb_build_array(jsonb_build_object('path', '$', 'rule', 'not_object'));
  end if;
  v_issues := v_issues || auth_kit_private.unknown_field_issues(p_model, '', array['client', 'roles', 'permissions']);

  if not (p_model ? 'client') then
    v_issues := v_issues || '[{"path": "client", "rule": "required"}]'::jsonb;
  elsif jsonb_typeof(p_model -> 'client') <> 'string' then
    v_issues := v_issues || '[{"path": "client", "rule": "invalid_key"}]'::jsonb;
  end if;

  v_permissions := p_model -> 'permissions';
  if v_permissions is null then
    v_issues := v_issues || '[{"path": "permissions", "rule": "required"}]'::jsonb;
  elsif jsonb_typeof(v_permissions) <> 'object' then
    v_issues := v_issues || '[{"path": "permissions", "rule": "not_object"}]'::jsonb;
  elsif (select count(*) from jsonb_object_keys(v_permissions)) > 2048 then
    v_issues := v_issues || '[{"path": "permissions", "rule": "too_many"}]'::jsonb;
  else
    v_issues := v_issues || coalesce((
      select jsonb_agg(jsonb_build_object('path', 'permissions.#' || (s.ord - 1),
                                          'rule', case when jsonb_typeof(s.value) <> 'string' then 'type' else 'too_long' end)
                       order by s.ord)
        from (select e.key, e.value, row_number() over (order by auth_kit_private.utf16_key(e.key)) as ord
                from jsonb_each(v_permissions) as e) as s
       where case when jsonb_typeof(s.value) <> 'string' then true
                  else auth_kit_private.too_long(s.value #>> '{}', 1024) end), '[]'::jsonb);
    -- Only well-formed declarations count as declared, as in core.
    v_declared := coalesce((
      select jsonb_object_agg(e.key, true)
        from jsonb_each(v_permissions) as e
       where jsonb_typeof(e.value) = 'string' and not auth_kit_private.too_long(e.value #>> '{}', 1024)), '{}'::jsonb);
  end if;

  v_roles := p_model -> 'roles';
  if v_roles is null then
    v_issues := v_issues || '[{"path": "roles", "rule": "required"}]'::jsonb;
  elsif jsonb_typeof(v_roles) <> 'object' then
    v_issues := v_issues || '[{"path": "roles", "rule": "not_object"}]'::jsonb;
  elsif (select count(*) from jsonb_object_keys(v_roles)) > 256 then
    v_issues := v_issues || '[{"path": "roles", "rule": "too_many"}]'::jsonb;
  else
    for v_role in
      select e.key, e.value, row_number() over (order by auth_kit_private.utf16_key(e.key)) - 1 as pos
        from jsonb_each(v_roles) as e
       order by auth_kit_private.utf16_key(e.key)
    loop
      v_path := 'roles.#' || v_role.pos;
      if jsonb_typeof(v_role.value) <> 'object' then
        v_issues := v_issues || jsonb_build_array(jsonb_build_object('path', v_path, 'rule', 'not_object'));
        continue;
      end if;
      v_before := jsonb_array_length(v_issues);
      v_issues := v_issues || auth_kit_private.unknown_field_issues(v_role.value, v_path,
        array['description', 'permissions', 'self_assignable', 'manages_members', 'mfa_required']);
      foreach v_flag in array array['self_assignable', 'manages_members', 'mfa_required'] loop
        -- Booleans only: "true", 1 or null must never acquire a meaning.
        if v_role.value ? v_flag and jsonb_typeof(v_role.value -> v_flag) <> 'boolean' then
          v_issues := v_issues || jsonb_build_array(jsonb_build_object('path', v_path || '.' || v_flag, 'rule', 'type'));
        end if;
      end loop;
      if v_role.value -> 'self_assignable' = 'true'::jsonb and v_role.value -> 'manages_members' = 'true'::jsonb then
        v_issues := v_issues || jsonb_build_array(jsonb_build_object('path', v_path, 'rule', 'self_assignable_manager'));
      end if;
      if v_role.value ? 'description' then
        if jsonb_typeof(v_role.value -> 'description') <> 'string' then
          v_issues := v_issues || jsonb_build_array(jsonb_build_object('path', v_path || '.description', 'rule', 'type'));
        elsif auth_kit_private.too_long(v_role.value ->> 'description', 1024) then
          v_issues := v_issues || jsonb_build_array(jsonb_build_object('path', v_path || '.description', 'rule', 'too_long'));
        end if;
      end if;
      if v_role.value ? 'permissions' then
        v_list := v_role.value -> 'permissions';
        if jsonb_typeof(v_list) <> 'array' then
          v_issues := v_issues || jsonb_build_array(jsonb_build_object('path', v_path || '.permissions', 'rule', 'type'));
        else
          -- A typo must not silently create a permission: every mapped key is declared.
          v_issues := v_issues || coalesce((
            select jsonb_agg(jsonb_build_object('path', v_path || '.permissions[' || (s.ord - 1) || ']', 'rule', s.rule) order by s.ord)
              from (select a.ord,
                           case when jsonb_typeof(a.item) <> 'string' then 'invalid_key'
                                when row_number() over (partition by a.item order by a.ord) > 1 then 'duplicate'
                                when v_declared is not null and not (v_declared ? (a.item #>> '{}')) then 'undeclared_permission'
                           end as rule
                      from jsonb_array_elements(v_list) with ordinality as a(item, ord)) as s
             where s.rule is not null), '[]'::jsonb);
        end if;
      end if;
      if jsonb_array_length(v_issues) = v_before then
        v_parsed := v_parsed + 1;
        v_manager := v_manager or coalesce(v_role.value -> 'manages_members' = 'true'::jsonb, false);
      end if;
    end loop;
    -- Judged only when every role parsed, so an invalid manager role is not
    -- also reported as a missing one.
    if v_parsed = (select count(*) from jsonb_object_keys(v_roles)) and not v_manager then
      v_issues := v_issues || '[{"path": "roles", "rule": "no_manager_role"}]'::jsonb;
    end if;
  end if;
  return v_issues;
end
$$;

-- Canonical form of a valid model: defaults filled, permission lists sorted and
-- de-duplicated. canonical_json of this value is the byte string the model hash covers.
create function auth_kit_private.normalize_model(p_model jsonb)
returns jsonb
language sql
immutable
set search_path = ''
as $$
  select jsonb_build_object(
    'client', p_model -> 'client',
    'permissions', p_model -> 'permissions',
    'roles', coalesce((
      select jsonb_object_agg(r.key, jsonb_build_object(
               'description', coalesce(r.value -> 'description', '""'::jsonb),
               'manages_members', coalesce(r.value -> 'manages_members', 'false'::jsonb),
               'mfa_required', coalesce(r.value -> 'mfa_required', 'false'::jsonb),
               'self_assignable', coalesce(r.value -> 'self_assignable', 'false'::jsonb),
               'permissions', coalesce((
                 select jsonb_agg(to_jsonb(d.k) order by auth_kit_private.utf16_key(d.k))
                   from (select distinct p.k
                           from jsonb_array_elements_text(coalesce(r.value -> 'permissions', '[]'::jsonb)) as p(k)) as d),
                 '[]'::jsonb)))
        from jsonb_each(p_model -> 'roles') as r), '{}'::jsonb))
$$;

-- The applied model of a client in canonical form, or null when none is applied.
create function auth_kit_private.current_model(p_client_id text)
returns jsonb
language sql
stable
set search_path = ''
as $$
  select case
    when not exists (select 1 from auth_kit_private.roles where client_id = p_client_id)
     and not exists (select 1 from auth_kit_private.permissions where client_id = p_client_id)
    then null
    else jsonb_build_object(
      'client', to_jsonb(p_client_id),
      'permissions', coalesce((
        select jsonb_object_agg(p.permission_key, p.description)
          from auth_kit_private.permissions p where p.client_id = p_client_id), '{}'::jsonb),
      'roles', coalesce((
        select jsonb_object_agg(r.role_key, jsonb_build_object(
                 'description', r.description,
                 'manages_members', r.manages_members,
                 'mfa_required', r.mfa_required,
                 'self_assignable', r.self_assignable,
                 'permissions', coalesce((
                   select jsonb_agg(rp.permission_key order by auth_kit_private.utf16_key(rp.permission_key))
                     from auth_kit_private.role_permissions rp
                    where rp.client_id = r.client_id and rp.role_key = r.role_key), '[]'::jsonb)))
          from auth_kit_private.roles r where r.client_id = p_client_id), '{}'::jsonb))
  end
$$;

-- Position of a key in JavaScript property order, which core's diff follows:
-- array-index keys first in numeric order, then the rest in insertion (here
-- UTF-16) order.
create function auth_kit_private.js_index(p_key text)
returns bigint
language sql
immutable strict parallel safe
set search_path = ''
as $$
  select case when p_key ~ '^(0|[1-9][0-9]{0,9})$' and p_key::bigint <= 4294967294 then p_key::bigint end
$$;

-- The annotated diff and refusals core planModelChange computes for the same
-- current model, holders and client state. Holders and state are read by the
-- caller's transaction after the client lock.
create function auth_kit_private.plan_model_change(p_client_id text, p_next jsonb, p_state text)
returns jsonb
language plpgsql
stable
set search_path = ''
as $$
declare
  v_current jsonb := auth_kit_private.current_model(p_client_id);
  v_before_permissions jsonb := coalesce(v_current -> 'permissions', '{}'::jsonb);
  v_before_roles jsonb := coalesce(v_current -> 'roles', '{}'::jsonb);
  v_next_permissions jsonb := p_next -> 'permissions';
  v_next_roles jsonb := p_next -> 'roles';
  v_holders jsonb;
  v_diff jsonb := '[]'::jsonb;
  v_refusals jsonb := '[]'::jsonb;
  v_key text;
  v_prior jsonb;
  v_after jsonb;
  v_count integer;
  v_flag text;
  v_permission text;
begin
  select coalesce(jsonb_object_agg(h.role_key, h.ids), '{}'::jsonb) into v_holders
    from (select m.role_key, jsonb_agg(m.user_id::text order by m.user_id::text collate "C") as ids
            from auth_kit_private.memberships m
           where m.client_id = p_client_id
           group by m.role_key) as h;

  for v_key in select k from jsonb_object_keys(v_before_permissions) as k
                order by auth_kit_private.js_index(k) nulls last, auth_kit_private.utf16_key(k) loop
    if not (v_next_permissions ? v_key) then
      v_diff := v_diff || jsonb_build_array(jsonb_build_object('kind', 'permission_removed', 'permission', v_key));
    elsif v_before_permissions -> v_key <> v_next_permissions -> v_key then
      v_diff := v_diff || jsonb_build_array(jsonb_build_object('kind', 'permission_description_changed', 'permission', v_key));
    end if;
  end loop;
  for v_key in select k from jsonb_object_keys(v_next_permissions) as k
                order by auth_kit_private.js_index(k) nulls last, auth_kit_private.utf16_key(k) loop
    if not (v_before_permissions ? v_key) then
      v_diff := v_diff || jsonb_build_array(jsonb_build_object('kind', 'permission_added', 'permission', v_key));
    end if;
  end loop;

  for v_key in select k from jsonb_object_keys(v_before_roles) as k
                order by auth_kit_private.js_index(k) nulls last, auth_kit_private.utf16_key(k) loop
    if not (v_next_roles ? v_key) then
      v_diff := v_diff || jsonb_build_array(jsonb_build_object('kind', 'role_removed', 'role', v_key));
      if v_holders ? v_key then
        v_refusals := v_refusals || jsonb_build_array(jsonb_build_object('rule', 'role_held', 'role', v_key, 'holders', v_holders -> v_key));
      end if;
    end if;
  end loop;

  for v_key in select k from jsonb_object_keys(v_next_roles) as k
                order by auth_kit_private.js_index(k) nulls last, auth_kit_private.utf16_key(k) loop
    v_after := v_next_roles -> v_key;
    v_prior := v_before_roles -> v_key;
    v_count := coalesce(jsonb_array_length(v_holders -> v_key), 0);
    if v_prior is null then
      if v_after -> 'self_assignable' = 'true'::jsonb then
        v_diff := v_diff || jsonb_build_array(jsonb_build_object('kind', 'role_added', 'role', v_key, 'reach', 'future_joiners'));
      else
        v_diff := v_diff || jsonb_build_array(jsonb_build_object('kind', 'role_added', 'role', v_key));
      end if;
      for v_permission in select p from jsonb_array_elements_text(v_after -> 'permissions') with ordinality as a(p, ord) order by a.ord loop
        v_diff := v_diff || jsonb_build_array(jsonb_build_object('kind', 'mapping_added', 'role', v_key, 'permission', v_permission,
                                                                  'reach', jsonb_build_object('holders', 0)));
      end loop;
      continue;
    end if;
    foreach v_flag in array array['self_assignable', 'manages_members', 'mfa_required'] loop
      if v_prior -> v_flag <> v_after -> v_flag then
        -- Enrollment happens once per user, so a self_assignable change
        -- reaches only users who have not joined yet.
        v_diff := v_diff || jsonb_build_array(jsonb_build_object(
          'kind', 'role_flag_changed', 'role', v_key, 'flag', v_flag, 'from', v_prior -> v_flag, 'to', v_after -> v_flag,
          'reach', case when v_flag = 'self_assignable' then '"future_joiners"'::jsonb
                        else jsonb_build_object('holders', v_count) end));
        -- Promotion is operator-only through bootstrap_manager (I13): a model
        -- change must not promote everyone who already holds the role.
        if v_flag = 'manages_members' and v_after -> v_flag = 'true'::jsonb and v_count > 0 then
          v_refusals := v_refusals || jsonb_build_array(jsonb_build_object('rule', 'promotes_holders', 'role', v_key, 'holders', v_holders -> v_key));
        end if;
      end if;
    end loop;
    if v_prior -> 'description' <> v_after -> 'description' then
      v_diff := v_diff || jsonb_build_array(jsonb_build_object('kind', 'role_description_changed', 'role', v_key));
    end if;
    for v_permission in select p from jsonb_array_elements_text(v_prior -> 'permissions') with ordinality as a(p, ord) order by a.ord loop
      if not ((v_after -> 'permissions') ? v_permission) then
        v_diff := v_diff || jsonb_build_array(jsonb_build_object('kind', 'mapping_removed', 'role', v_key, 'permission', v_permission,
                                                                  'reach', jsonb_build_object('holders', v_count)));
      end if;
    end loop;
    for v_permission in select p from jsonb_array_elements_text(v_after -> 'permissions') with ordinality as a(p, ord) order by a.ord loop
      if not ((v_prior -> 'permissions') ? v_permission) then
        v_diff := v_diff || jsonb_build_array(jsonb_build_object('kind', 'mapping_added', 'role', v_key, 'permission', v_permission,
                                                                  'reach', jsonb_build_object('holders', v_count)));
      end if;
    end loop;
  end loop;

  -- A live client keeps at least one assigned manager (I5).
  if p_state = 'live' and not exists (
       select 1 from jsonb_object_keys(v_next_roles) as k
        where v_next_roles -> k -> 'manages_members' = 'true'::jsonb
          and v_before_roles -> k -> 'manages_members' = 'true'::jsonb
          and v_holders ? k) then
    v_refusals := v_refusals || '[{"rule": "no_manager_would_remain"}]'::jsonb;
  end if;

  return jsonb_build_object('changed', jsonb_array_length(v_diff) > 0, 'diff', v_diff, 'refusals', v_refusals);
end
$$;

-- 5. Implementations (security definer, empty search_path) ------------------

create function auth_kit_private.ensure_profile_impl()
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid();
  v_profile jsonb;
begin
  if v_uid is null then
    perform auth_kit_private.refuse('forbidden');
  end if;
  insert into auth_kit.profiles (user_id) values (v_uid) on conflict (user_id) do nothing;
  select jsonb_build_object('user_id', p.user_id, 'display_name', p.display_name, 'contact_email', p.contact_email,
                            'contact_phone', p.contact_phone, 'updated_at', auth_kit_private.iso_utc(p.updated_at))
    into v_profile
    from auth_kit.profiles p where p.user_id = v_uid;
  return v_profile;
end
$$;

create function auth_kit_private.join_client_impl(p_client_id text)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid();
  v_confirmed timestamptz;
  v_policy text;
  v_enrolled_at timestamptz;
  v_roles text[];
  v_granted text[];
begin
  if p_client_id is null then
    perform auth_kit_private.refuse('invalid_argument');
  end if;
  if v_uid is null then
    perform auth_kit_private.refuse('forbidden');
  end if;
  perform auth_kit_private.lock_client(p_client_id);
  -- The JWT's email claims are not trusted; confirmation comes from auth.users.
  select u.email_confirmed_at into v_confirmed from auth.users u where u.id = v_uid;
  if v_confirmed is null then
    return jsonb_build_object('result', 'email_unverified');
  end if;
  select c.signup_policy into v_policy from auth_kit_private.clients c where c.client_id = p_client_id;
  if not found then
    return jsonb_build_object('result', 'unknown_client');
  end if;
  -- Enrollment is once per user and client (I12): an existing row ends the
  -- join whatever memberships exist now, so a manager's revoke stays durable.
  select e.enrolled_at into v_enrolled_at
    from auth_kit_private.enrollments e where e.user_id = v_uid and e.client_id = p_client_id;
  if found then
    return jsonb_build_object('result', 'already_enrolled', 'enrolled_at', auth_kit_private.iso_utc(v_enrolled_at));
  end if;
  if v_policy = 'closed' then
    return jsonb_build_object('result', 'closed');
  end if;
  select array_agg(r.role_key order by auth_kit_private.utf16_key(r.role_key)) into v_roles
    from auth_kit_private.roles r where r.client_id = p_client_id and r.self_assignable;
  if v_roles is null then
    -- Nothing is written, so the join stays retryable once a role exists.
    return jsonb_build_object('result', 'no_default_role');
  end if;
  -- A role a manager granted before the first join is not granted twice.
  select coalesce(array_agg(k order by auth_kit_private.utf16_key(k)), '{}'::text[]) into v_granted
    from unnest(v_roles) as k
   where not exists (select 1 from auth_kit_private.memberships m
                      where m.user_id = v_uid and m.client_id = p_client_id and m.role_key = k);
  insert into auth_kit_private.enrollments (user_id, client_id, enrolled_at, granted_roles)
  values (v_uid, p_client_id, now(), v_granted)
  returning enrolled_at into v_enrolled_at;
  insert into auth_kit_private.memberships (user_id, client_id, role_key, granted_at, granted_by, granted_via)
  select v_uid, p_client_id, k, now(), null, 'join' from unnest(v_granted) as k;
  insert into auth_kit_private.membership_events (request_id, payload_hash, result, action, user_id, client_id, role_key, actor_user_id, actor_kind)
  select null, null, 'enrolled', 'join', v_uid, p_client_id, k, v_uid, 'user' from unnest(v_granted) as k;
  return jsonb_build_object('result', 'enrolled', 'enrolled_at', auth_kit_private.iso_utc(v_enrolled_at),
                            'granted_roles', to_jsonb(v_granted));
end
$$;

-- Memberships of the caller for one client, with each role's flags and keys,
-- plus the active-role view computed by the same rule as core (no lock).
create function auth_kit_private.effective_access_impl(p_client_id text)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_uid uuid := auth.uid();
  v_enrolled_at timestamptz;
  v_rows jsonb;
begin
  if p_client_id is null then
    perform auth_kit_private.refuse('invalid_argument');
  end if;
  if v_uid is null then
    perform auth_kit_private.refuse('forbidden');
  end if;
  select e.enrolled_at into v_enrolled_at
    from auth_kit_private.enrollments e where e.user_id = v_uid and e.client_id = p_client_id;
  select coalesce(jsonb_agg(jsonb_build_object(
           'role_key', m.role_key,
           'flags', jsonb_build_object('self_assignable', r.self_assignable, 'manages_members', r.manages_members,
                                       'mfa_required', r.mfa_required),
           'granted_at', auth_kit_private.iso_utc(m.granted_at),
           'granted_via', m.granted_via,
           'permissions', coalesce((
             select jsonb_agg(rp.permission_key order by auth_kit_private.utf16_key(rp.permission_key))
               from auth_kit_private.role_permissions rp
              where rp.client_id = m.client_id and rp.role_key = m.role_key), '[]'::jsonb),
           'active', auth_kit_private.role_active(r.mfa_required))
         order by auth_kit_private.utf16_key(m.role_key)), '[]'::jsonb)
    into v_rows
    from auth_kit_private.memberships m
    join auth_kit_private.roles r on r.client_id = m.client_id and r.role_key = m.role_key
   where m.user_id = v_uid and m.client_id = p_client_id;
  return jsonb_build_object(
    'client_id', p_client_id,
    'enrolled_at', auth_kit_private.iso_utc(v_enrolled_at),
    'memberships', coalesce((select jsonb_agg(x - 'active' order by a.ord)
                               from jsonb_array_elements(v_rows) with ordinality as a(x, ord)), '[]'::jsonb),
    'active_roles', coalesce((select jsonb_agg(x -> 'role_key' order by a.ord)
                                from jsonb_array_elements(v_rows) with ordinality as a(x, ord)
                               where (x ->> 'active')::boolean), '[]'::jsonb),
    'permissions', coalesce((select jsonb_agg(to_jsonb(d.k) order by auth_kit_private.utf16_key(d.k))
                               from (select distinct p.k
                                       from jsonb_array_elements(v_rows) as x,
                                            jsonb_array_elements_text(x -> 'permissions') as p(k)
                                      where (x ->> 'active')::boolean) as d), '[]'::jsonb),
    'mfa_pending', exists (select 1 from jsonb_array_elements(v_rows) as x where not (x ->> 'active')::boolean));
end
$$;

create function auth_kit_private.grant_membership_impl(p_user_id uuid, p_client_id text, p_role_key text, p_request_id uuid)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_actor uuid := auth.uid();
  v_hash text;
  v_result jsonb;
  v_manages boolean;
  v_inserted boolean;
begin
  if p_user_id is null or p_client_id is null or p_role_key is null or p_request_id is null then
    perform auth_kit_private.refuse('invalid_argument');
  end if;
  if v_actor is null then
    perform auth_kit_private.refuse('forbidden');
  end if;
  perform auth_kit_private.lock_client(p_client_id);
  v_hash := auth_kit_private.request_fingerprint('grant_membership', p_client_id, v_actor::text,
              jsonb_build_object('user_id', p_user_id, 'role_key', p_role_key));
  v_result := auth_kit_private.stored_result(p_request_id, v_hash);
  if v_result is not null then
    return v_result;
  end if;
  -- Authority is checked after the lock, so a concurrent revoke is seen.
  perform auth_kit_private.require_manager(p_client_id, v_actor);
  select r.manages_members into v_manages
    from auth_kit_private.roles r where r.client_id = p_client_id and r.role_key = p_role_key;
  if not found then
    perform auth_kit_private.refuse('unknown_role');
  elsif v_manages then
    -- Managers never create managers (I4).
    perform auth_kit_private.refuse('forbidden');
  end if;
  perform auth_kit_private.confirmed_user(p_user_id);
  if p_user_id = v_actor then
    perform auth_kit_private.refuse('forbidden');
  end if;
  insert into auth_kit_private.memberships (user_id, client_id, role_key, granted_at, granted_by, granted_via)
  values (p_user_id, p_client_id, p_role_key, now(), v_actor, 'manager')
  on conflict (user_id, client_id, role_key) do nothing;
  v_inserted := found;
  v_result := jsonb_build_object('result', case when v_inserted then 'granted' else 'already_member' end,
                                 'user_id', p_user_id, 'client_id', p_client_id, 'role_key', p_role_key);
  if v_inserted then
    insert into auth_kit_private.membership_events (request_id, payload_hash, result, action, user_id, client_id, role_key, actor_user_id, actor_kind)
    values (p_request_id, v_hash, 'granted', 'grant', p_user_id, p_client_id, p_role_key, v_actor, 'user');
  end if;
  return auth_kit_private.record_request(p_request_id, p_client_id, 'grant_membership', v_actor::text, v_hash, v_result);
end
$$;

create function auth_kit_private.revoke_membership_impl(p_user_id uuid, p_client_id text, p_role_key text, p_request_id uuid)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_actor uuid := auth.uid();
  v_hash text;
  v_result jsonb;
  v_manages boolean;
  v_deleted boolean;
begin
  if p_user_id is null or p_client_id is null or p_role_key is null or p_request_id is null then
    perform auth_kit_private.refuse('invalid_argument');
  end if;
  if v_actor is null then
    perform auth_kit_private.refuse('forbidden');
  end if;
  perform auth_kit_private.lock_client(p_client_id);
  v_hash := auth_kit_private.request_fingerprint('revoke_membership', p_client_id, v_actor::text,
              jsonb_build_object('user_id', p_user_id, 'role_key', p_role_key));
  v_result := auth_kit_private.stored_result(p_request_id, v_hash);
  if v_result is not null then
    return v_result;
  end if;
  perform auth_kit_private.require_manager(p_client_id, v_actor);
  select r.manages_members into v_manages
    from auth_kit_private.roles r where r.client_id = p_client_id and r.role_key = p_role_key;
  if not found then
    perform auth_kit_private.refuse('unknown_role');
  elsif v_manages then
    -- Removal from a manager role is operator-only (revoke_manager, I4).
    perform auth_kit_private.refuse('forbidden');
  end if;
  delete from auth_kit_private.memberships m
   where m.user_id = p_user_id and m.client_id = p_client_id and m.role_key = p_role_key;
  v_deleted := found;
  v_result := jsonb_build_object('result', case when v_deleted then 'revoked' else 'not_member' end,
                                 'user_id', p_user_id, 'client_id', p_client_id, 'role_key', p_role_key);
  if v_deleted then
    insert into auth_kit_private.membership_events (request_id, payload_hash, result, action, user_id, client_id, role_key, actor_user_id, actor_kind)
    values (p_request_id, v_hash, 'revoked', 'revoke', p_user_id, p_client_id, p_role_key, v_actor, 'user');
  end if;
  return auth_kit_private.record_request(p_request_id, p_client_id, 'revoke_membership', v_actor::text, v_hash, v_result);
end
$$;

create function auth_kit_private.register_client_impl(p_client_id text, p_display_name text, p_signup_policy text)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_state text;
  v_outcome text;
begin
  if p_client_id is null or p_display_name is null or p_signup_policy is null
     or p_signup_policy not in ('open', 'closed') then
    perform auth_kit_private.refuse('invalid_argument');
  end if;
  perform auth_kit_private.lock_client(p_client_id);
  insert into auth_kit_private.clients (client_id, display_name, signup_policy)
  values (p_client_id, p_display_name, p_signup_policy)
  on conflict (client_id) do nothing;
  if found then
    v_outcome := 'registered';
  else
    -- A repeat is an update of name or policy; the lifecycle state is never
    -- touched, so a live client stays live.
    update auth_kit_private.clients c
       set display_name = p_display_name, signup_policy = p_signup_policy
     where c.client_id = p_client_id
       and (c.display_name <> p_display_name or c.signup_policy <> p_signup_policy);
    v_outcome := case when found then 'updated' else 'unchanged' end;
  end if;
  select c.state into v_state from auth_kit_private.clients c where c.client_id = p_client_id;
  return jsonb_build_object('result', v_outcome, 'client_id', p_client_id, 'state', v_state);
end
$$;

create function auth_kit_private.apply_model_impl(p_client_id text, p_model jsonb, p_request_id uuid, p_dry_run boolean)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_issues jsonb;
  v_model jsonb;
  v_model_hash text;
  v_hash text;
  v_result jsonb;
  v_state text;
  v_plan jsonb;
begin
  if p_client_id is null or p_model is null or p_dry_run is null or (not p_dry_run and p_request_id is null) then
    perform auth_kit_private.refuse('invalid_argument');
  end if;
  perform auth_kit_private.lock_client(p_client_id);
  v_issues := auth_kit_private.model_issues(p_model);
  if jsonb_array_length(v_issues) = 0 and p_model ->> 'client' <> p_client_id then
    v_issues := '[{"path": "client", "rule": "client_mismatch"}]'::jsonb;
  end if;
  if jsonb_array_length(v_issues) > 0 then
    perform auth_kit_private.refuse('model_invalid', jsonb_build_object('issues',
      (select jsonb_agg(i.value order by i.ord) from jsonb_array_elements(v_issues) with ordinality as i(value, ord) where i.ord <= 50)));
  end if;
  v_model := auth_kit_private.normalize_model(p_model);
  v_model_hash := auth_kit_private.sha256_hex(auth_kit_private.canonical_json(v_model));
  if not p_dry_run then
    -- The payload is the canonical model hash: the same file is the same request.
    v_hash := auth_kit_private.request_fingerprint('apply_model', p_client_id, 'operator', to_jsonb(v_model_hash));
    v_result := auth_kit_private.stored_result(p_request_id, v_hash);
    if v_result is not null then
      return v_result;
    end if;
  end if;
  select c.state into v_state from auth_kit_private.clients c where c.client_id = p_client_id;
  if not found then
    perform auth_kit_private.refuse('unknown_client');
  end if;
  v_plan := auth_kit_private.plan_model_change(p_client_id, v_model, v_state);
  if p_dry_run then
    return jsonb_build_object('result', 'dry_run', 'model_hash', v_model_hash, 'changed', v_plan -> 'changed',
                              'diff', v_plan -> 'diff', 'refusals', v_plan -> 'refusals');
  end if;
  if jsonb_array_length(v_plan -> 'refusals') > 0 then
    perform auth_kit_private.refuse('model_refused', jsonb_build_object('refusals', v_plan -> 'refusals'));
  end if;
  if not (v_plan ->> 'changed')::boolean then
    v_result := jsonb_build_object('result', 'unchanged', 'model_hash', v_model_hash, 'diff', '[]'::jsonb);
  else
    -- Order keeps every foreign key satisfied inside the one transaction:
    -- add and update first, unmap, then delete what the model no longer has.
    insert into auth_kit_private.permissions (client_id, permission_key, description)
    select p_client_id, e.key, e.value #>> '{}' from jsonb_each(v_model -> 'permissions') as e
    on conflict (client_id, permission_key) do update set description = excluded.description
     where auth_kit_private.permissions.description <> excluded.description;
    insert into auth_kit_private.roles (client_id, role_key, description, self_assignable, manages_members, mfa_required)
    select p_client_id, e.key, e.value ->> 'description', (e.value ->> 'self_assignable')::boolean,
           (e.value ->> 'manages_members')::boolean, (e.value ->> 'mfa_required')::boolean
      from jsonb_each(v_model -> 'roles') as e
    on conflict (client_id, role_key) do update
       set description = excluded.description, self_assignable = excluded.self_assignable,
           manages_members = excluded.manages_members, mfa_required = excluded.mfa_required
     where (auth_kit_private.roles.description, auth_kit_private.roles.self_assignable,
            auth_kit_private.roles.manages_members, auth_kit_private.roles.mfa_required)
           is distinct from (excluded.description, excluded.self_assignable, excluded.manages_members, excluded.mfa_required);
    delete from auth_kit_private.role_permissions rp
     where rp.client_id = p_client_id
       and not coalesce((v_model -> 'roles' -> rp.role_key -> 'permissions') ? rp.permission_key, false);
    insert into auth_kit_private.role_permissions (client_id, role_key, permission_key)
    select p_client_id, e.key, p.k
      from jsonb_each(v_model -> 'roles') as e, jsonb_array_elements_text(e.value -> 'permissions') as p(k)
    on conflict do nothing;
    delete from auth_kit_private.roles r
     where r.client_id = p_client_id and not ((v_model -> 'roles') ? r.role_key);
    delete from auth_kit_private.permissions p
     where p.client_id = p_client_id and not ((v_model -> 'permissions') ? p.permission_key);
    insert into auth_kit_private.model_events (request_id, model_hash, client_id, diff, actor_kind)
    values (p_request_id, v_model_hash, p_client_id, v_plan -> 'diff', 'operator');
    v_result := jsonb_build_object('result', 'applied', 'model_hash', v_model_hash, 'diff', v_plan -> 'diff');
  end if;
  -- Written for the no-op too, so the same id with another model conflicts.
  return auth_kit_private.record_request(p_request_id, p_client_id, 'apply_model', 'operator', v_hash, v_result);
end
$$;

create function auth_kit_private.export_model_impl(p_client_id text)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_model jsonb;
  v_text text;
begin
  if p_client_id is null then
    perform auth_kit_private.refuse('invalid_argument');
  end if;
  if not exists (select 1 from auth_kit_private.clients c where c.client_id = p_client_id) then
    perform auth_kit_private.refuse('unknown_client');
  end if;
  -- The file-format text itself, not jsonb: jsonb would reorder the keys.
  -- model_json is null while no model is applied.
  v_model := auth_kit_private.current_model(p_client_id);
  if v_model is not null then
    v_text := auth_kit_private.canonical_json(v_model);
  end if;
  return jsonb_build_object(
    'client_id', p_client_id,
    'model_json', v_text,
    'model_hash', auth_kit_private.sha256_hex(v_text),
    'last_applied_hash', (select e.model_hash from auth_kit_private.model_events e
                           where e.client_id = p_client_id order by e.id desc limit 1));
end
$$;

create function auth_kit_private.bootstrap_manager_impl(p_user_id uuid, p_client_id text, p_role_key text, p_request_id uuid)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_hash text;
  v_result jsonb;
  v_manages boolean;
  v_inserted boolean;
begin
  if p_user_id is null or p_client_id is null or p_role_key is null or p_request_id is null then
    perform auth_kit_private.refuse('invalid_argument');
  end if;
  perform auth_kit_private.lock_client(p_client_id);
  v_hash := auth_kit_private.request_fingerprint('bootstrap_manager', p_client_id, 'operator',
              jsonb_build_object('user_id', p_user_id, 'role_key', p_role_key));
  v_result := auth_kit_private.stored_result(p_request_id, v_hash);
  if v_result is not null then
    return v_result;
  end if;
  if not exists (select 1 from auth_kit_private.clients c where c.client_id = p_client_id) then
    perform auth_kit_private.refuse('unknown_client');
  end if;
  select r.manages_members into v_manages
    from auth_kit_private.roles r where r.client_id = p_client_id and r.role_key = p_role_key;
  if not found then
    perform auth_kit_private.refuse('unknown_role');
  elsif not v_manages then
    perform auth_kit_private.refuse('not_manager_role');
  end if;
  perform auth_kit_private.confirmed_user(p_user_id);
  insert into auth_kit_private.memberships (user_id, client_id, role_key, granted_at, granted_by, granted_via)
  values (p_user_id, p_client_id, p_role_key, now(), null, 'operator')
  on conflict (user_id, client_id, role_key) do nothing;
  v_inserted := found;
  if v_inserted then
    update auth_kit_private.clients c set state = 'live' where c.client_id = p_client_id and c.state = 'registered';
    insert into auth_kit_private.membership_events (request_id, payload_hash, result, action, user_id, client_id, role_key, actor_user_id, actor_kind)
    values (p_request_id, v_hash, 'granted', 'bootstrap', p_user_id, p_client_id, p_role_key, null, 'operator');
  end if;
  v_result := jsonb_build_object('result', case when v_inserted then 'granted' else 'already_member' end,
                                 'user_id', p_user_id, 'client_id', p_client_id, 'role_key', p_role_key);
  return auth_kit_private.record_request(p_request_id, p_client_id, 'bootstrap_manager', 'operator', v_hash, v_result);
end
$$;

create function auth_kit_private.revoke_manager_impl(p_user_id uuid, p_client_id text, p_role_key text, p_request_id uuid)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_hash text;
  v_result jsonb;
  v_manages boolean;
begin
  if p_user_id is null or p_client_id is null or p_role_key is null or p_request_id is null then
    perform auth_kit_private.refuse('invalid_argument');
  end if;
  perform auth_kit_private.lock_client(p_client_id);
  v_hash := auth_kit_private.request_fingerprint('revoke_manager', p_client_id, 'operator',
              jsonb_build_object('user_id', p_user_id, 'role_key', p_role_key));
  v_result := auth_kit_private.stored_result(p_request_id, v_hash);
  if v_result is not null then
    return v_result;
  end if;
  if not exists (select 1 from auth_kit_private.clients c where c.client_id = p_client_id) then
    perform auth_kit_private.refuse('unknown_client');
  end if;
  select r.manages_members into v_manages
    from auth_kit_private.roles r where r.client_id = p_client_id and r.role_key = p_role_key;
  if not found then
    perform auth_kit_private.refuse('unknown_role');
  elsif not v_manages then
    perform auth_kit_private.refuse('not_manager_role');
  end if;
  if not exists (select 1 from auth_kit_private.memberships m
                  where m.user_id = p_user_id and m.client_id = p_client_id and m.role_key = p_role_key) then
    v_result := jsonb_build_object('result', 'not_member', 'user_id', p_user_id, 'client_id', p_client_id, 'role_key', p_role_key);
  else
    -- A client never drops to zero assigned managers (I5).
    if not exists (select 1 from auth_kit_private.memberships m
                     join auth_kit_private.roles r on r.client_id = m.client_id and r.role_key = m.role_key
                    where m.client_id = p_client_id and r.manages_members
                      and not (m.user_id = p_user_id and m.role_key = p_role_key)) then
      perform auth_kit_private.refuse('last_manager');
    end if;
    delete from auth_kit_private.memberships m
     where m.user_id = p_user_id and m.client_id = p_client_id and m.role_key = p_role_key;
    insert into auth_kit_private.membership_events (request_id, payload_hash, result, action, user_id, client_id, role_key, actor_user_id, actor_kind)
    values (p_request_id, v_hash, 'revoked', 'revoke_manager', p_user_id, p_client_id, p_role_key, null, 'operator');
    v_result := jsonb_build_object('result', 'revoked', 'user_id', p_user_id, 'client_id', p_client_id, 'role_key', p_role_key);
  end if;
  return auth_kit_private.record_request(p_request_id, p_client_id, 'revoke_manager', 'operator', v_hash, v_result);
end
$$;

-- mfa_reset is reserve-then-act under one claim (design 4.7). Claim times use
-- clock_timestamp() taken after the locks: now() is the transaction start and
-- could predate the moment the runner sent begin, which the runner's own
-- 100-second deadline assumes it never does.
create function auth_kit_private.lock_mfa_reset(p_request_id uuid)
returns void
language sql
set search_path = ''
as $$
  select auth_kit_private.lock_scope('auth_kit:mfa_reset');
  select pg_advisory_xact_lock(hashtext('auth_kit:request_id'), hashtext(p_request_id::text));
$$;

create function auth_kit_private.mfa_reset_begin_impl(p_user_id uuid, p_request_id uuid)
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_hash text;
  v_row auth_kit_private.request_log%rowtype;
  v_now timestamptz;
  v_token uuid;
begin
  if p_user_id is null or p_request_id is null then
    perform auth_kit_private.refuse('invalid_argument');
  end if;
  perform auth_kit_private.lock_mfa_reset(p_request_id);
  -- Neither the factor list nor the token enters the fingerprint.
  v_hash := auth_kit_private.request_fingerprint('mfa_reset', null, 'operator', jsonb_build_object('user_id', p_user_id));
  select * into v_row from auth_kit_private.request_log r where r.request_id = p_request_id;
  v_now := clock_timestamp();
  if not found then
    v_token := gen_random_uuid();
    insert into auth_kit_private.request_log (request_id, client_id, operation, actor_id, payload_hash, state,
                                              result, factors_seen, run_token, started_at, at, user_id)
    values (p_request_id, null, 'mfa_reset', 'operator', v_hash, 'pending', null, null, v_token, v_now, v_now, p_user_id);
    return jsonb_build_object('outcome', 'proceed', 'run_token', v_token, 'factors_seen', null);
  end if;
  if v_row.payload_hash <> v_hash then
    perform auth_kit_private.refuse('request_conflict');
  end if;
  if v_row.state = 'completed' then
    return jsonb_build_object('outcome', 'completed', 'result', v_row.result);
  end if;
  if v_row.started_at < v_now - interval '120 seconds' then
    -- Takeover is one atomic claim: a fresh token and a fresh lease in the same
    -- statement, so the next caller sees a live lease.
    v_token := gen_random_uuid();
    update auth_kit_private.request_log r set run_token = v_token, started_at = v_now
     where r.request_id = p_request_id;
    return jsonb_build_object('outcome', 'resume', 'run_token', v_token, 'factors_seen', to_jsonb(v_row.factors_seen));
  end if;
  perform auth_kit_private.refuse('request_in_progress');
  return null;
end
$$;

create function auth_kit_private.mfa_reset_note_impl(p_request_id uuid, p_run_token uuid, p_factor_ids uuid[])
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_row auth_kit_private.request_log%rowtype;
  v_seen uuid[];
begin
  if p_request_id is null or p_run_token is null or p_factor_ids is null or array_position(p_factor_ids, null) is not null then
    perform auth_kit_private.refuse('invalid_argument');
  end if;
  perform auth_kit_private.lock_mfa_reset(p_request_id);
  select * into v_row from auth_kit_private.request_log r where r.request_id = p_request_id;
  if not found or v_row.operation <> 'mfa_reset' then
    perform auth_kit_private.refuse('request_conflict');
  end if;
  -- The token is checked before the state: a superseded
  -- runner learns only that it was superseded, even after completion.
  if v_row.run_token <> p_run_token then
    perform auth_kit_private.refuse('run_superseded');
  end if;
  if v_row.state = 'completed' then
    perform auth_kit_private.refuse('request_conflict');
  end if;
  v_seen := v_row.factors_seen;
  if v_seen is null then
    -- Recorded once: a resumed run keeps the original list.
    v_seen := array(select distinct f from unnest(p_factor_ids) as f order by f);
    update auth_kit_private.request_log r set factors_seen = v_seen where r.request_id = p_request_id;
  end if;
  return jsonb_build_object('factors_seen', to_jsonb(v_seen));
end
$$;

create function auth_kit_private.mfa_reset_finish_impl(p_request_id uuid, p_run_token uuid, p_factors_deleted uuid[])
returns jsonb
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  v_row auth_kit_private.request_log%rowtype;
  v_deleted uuid[];
  v_result jsonb;
begin
  if p_request_id is null or p_run_token is null or p_factors_deleted is null
     or array_position(p_factors_deleted, null) is not null then
    perform auth_kit_private.refuse('invalid_argument');
  end if;
  perform auth_kit_private.lock_mfa_reset(p_request_id);
  select * into v_row from auth_kit_private.request_log r where r.request_id = p_request_id;
  if not found or v_row.operation <> 'mfa_reset' then
    perform auth_kit_private.refuse('request_conflict');
  end if;
  if v_row.run_token <> p_run_token then
    perform auth_kit_private.refuse('run_superseded');
  end if;
  if v_row.state = 'completed' then
    -- The claim holder's own retry.
    return v_row.result;
  end if;
  if v_row.factors_seen is null then
    -- The audit never claims a factor list that was not recorded before deletion.
    perform auth_kit_private.refuse('request_conflict');
  end if;
  v_deleted := array(select distinct f from unnest(p_factors_deleted) as f order by f);
  if not (v_deleted <@ v_row.factors_seen) then
    -- Only recorded factors may have been deleted.
    perform auth_kit_private.refuse('invalid_argument');
  end if;
  v_result := jsonb_build_object(
    'result', case when cardinality(v_row.factors_seen) = 0 then 'no_factors' else 'reset' end,
    'factors_seen', to_jsonb(v_row.factors_seen),
    'factors_deleted', to_jsonb(v_deleted));
  update auth_kit_private.request_log r set state = 'completed', result = v_result, at = clock_timestamp()
   where r.request_id = p_request_id;
  insert into auth_kit_private.membership_events (request_id, payload_hash, result, action, user_id, client_id, role_key, actor_user_id, actor_kind)
  values (p_request_id, v_row.payload_hash, v_result ->> 'result', 'mfa_reset', v_row.user_id, null, null, null, 'operator');
  return v_result;
end
$$;

-- RLS helper implementations: false for anything absent, never an error.
create function auth_kit_private.has_permission_impl(p_client_id text, p_permission_key text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
      from auth_kit_private.memberships m
      join auth_kit_private.roles r on r.client_id = m.client_id and r.role_key = m.role_key
      join auth_kit_private.role_permissions rp on rp.client_id = m.client_id and rp.role_key = m.role_key
     where m.user_id = auth.uid() and m.client_id = p_client_id and rp.permission_key = p_permission_key
       and auth_kit_private.role_active(r.mfa_required))
$$;

create function auth_kit_private.has_role_impl(p_client_id text, p_role_key text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
      from auth_kit_private.memberships m
      join auth_kit_private.roles r on r.client_id = m.client_id and r.role_key = m.role_key
     where m.user_id = auth.uid() and m.client_id = p_client_id and m.role_key = p_role_key
       and auth_kit_private.role_active(r.mfa_required))
$$;

create function auth_kit_private.profiles_touch()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at := now();
  return new;
end
$$;

create trigger profiles_touch before update on auth_kit.profiles
  for each row execute function auth_kit_private.profiles_touch();

-- 6. Exposed wrappers (security invoker). Argument types are the shape check
--    at the API boundary; the implementation validates values authoritatively
--    because authenticated may also call it directly from SQL. ------------

create function auth_kit.ensure_profile()
returns jsonb language sql volatile security invoker set search_path = ''
as $$ select auth_kit_private.ensure_profile_impl() $$;

create function auth_kit.join_client(client_id text)
returns jsonb language sql volatile security invoker set search_path = ''
as $$ select auth_kit_private.join_client_impl($1) $$;

create function auth_kit.effective_access(client_id text)
returns jsonb language sql stable security invoker set search_path = ''
as $$ select auth_kit_private.effective_access_impl($1) $$;

create function auth_kit.grant_membership(user_id uuid, client_id text, role_key text, request_id uuid)
returns jsonb language sql volatile security invoker set search_path = ''
as $$ select auth_kit_private.grant_membership_impl($1, $2, $3, $4) $$;

create function auth_kit.revoke_membership(user_id uuid, client_id text, role_key text, request_id uuid)
returns jsonb language sql volatile security invoker set search_path = ''
as $$ select auth_kit_private.revoke_membership_impl($1, $2, $3, $4) $$;

create function auth_kit.register_client(client_id text, display_name text, signup_policy text)
returns jsonb language sql volatile security invoker set search_path = ''
as $$ select auth_kit_private.register_client_impl($1, $2, $3) $$;

create function auth_kit.apply_model(client_id text, model jsonb, request_id uuid default null, dry_run boolean default false)
returns jsonb language sql volatile security invoker set search_path = ''
as $$ select auth_kit_private.apply_model_impl($1, $2, $3, $4) $$;

create function auth_kit.export_model(client_id text)
returns jsonb language sql stable security invoker set search_path = ''
as $$ select auth_kit_private.export_model_impl($1) $$;

create function auth_kit.bootstrap_manager(user_id uuid, client_id text, role_key text, request_id uuid)
returns jsonb language sql volatile security invoker set search_path = ''
as $$ select auth_kit_private.bootstrap_manager_impl($1, $2, $3, $4) $$;

create function auth_kit.revoke_manager(user_id uuid, client_id text, role_key text, request_id uuid)
returns jsonb language sql volatile security invoker set search_path = ''
as $$ select auth_kit_private.revoke_manager_impl($1, $2, $3, $4) $$;

create function auth_kit.mfa_reset_begin(user_id uuid, request_id uuid)
returns jsonb language sql volatile security invoker set search_path = ''
as $$ select auth_kit_private.mfa_reset_begin_impl($1, $2) $$;

create function auth_kit.mfa_reset_note(request_id uuid, run_token uuid, factor_ids uuid[])
returns jsonb language sql volatile security invoker set search_path = ''
as $$ select auth_kit_private.mfa_reset_note_impl($1, $2, $3) $$;

create function auth_kit.mfa_reset_finish(request_id uuid, run_token uuid, factors_deleted uuid[])
returns jsonb language sql volatile security invoker set search_path = ''
as $$ select auth_kit_private.mfa_reset_finish_impl($1, $2, $3) $$;

-- RLS helpers. plpgsql, not a one-line sql body: a sql body is parsed as the
-- caller before its CASE runs, so anon (no USAGE on auth_kit_private) would
-- get "permission denied" instead of false. Here the private schema is
-- reached only when a user id is present.
create function auth_kit.has_permission(client_id text, permission_key text)
returns boolean language plpgsql stable security invoker set search_path = ''
as $$
begin
  if auth.uid() is null then
    return false;
  end if;
  return auth_kit_private.has_permission_impl(client_id, permission_key);
end
$$;

create function auth_kit.has_role(client_id text, role_key text)
returns boolean language plpgsql stable security invoker set search_path = ''
as $$
begin
  if auth.uid() is null then
    return false;
  end if;
  return auth_kit_private.has_role_impl(client_id, role_key);
end
$$;

create function auth_kit.has_aal2()
returns boolean language sql stable security invoker set search_path = ''
as $$ select coalesce(auth.jwt() ->> 'aal', 'aal1') = 'aal2' $$;

-- 7. Grant assertion (also run by doctor) ------------------------------------

-- Every row where an actual privilege or property differs from the grant table
-- (design 4.6). Empty means the installation matches.
create function auth_kit_private.grant_violations()
returns table (object text, grantee text, privilege text, expected boolean, actual boolean)
language sql
stable
set search_path = ''
as $$
  with grantees(role) as (values ('anon'), ('authenticated'), ('service_role'), ('public')),
  expected_functions(schema_name, name, kind) as (values
    ('auth_kit', 'ensure_profile', 'user'), ('auth_kit', 'join_client', 'user'),
    ('auth_kit', 'effective_access', 'user'), ('auth_kit', 'grant_membership', 'user'),
    ('auth_kit', 'revoke_membership', 'user'),
    ('auth_kit', 'register_client', 'operator'), ('auth_kit', 'apply_model', 'operator'),
    ('auth_kit', 'export_model', 'operator'), ('auth_kit', 'bootstrap_manager', 'operator'),
    ('auth_kit', 'revoke_manager', 'operator'), ('auth_kit', 'mfa_reset_begin', 'operator'),
    ('auth_kit', 'mfa_reset_note', 'operator'), ('auth_kit', 'mfa_reset_finish', 'operator'),
    ('auth_kit', 'has_permission', 'helper'), ('auth_kit', 'has_role', 'helper'), ('auth_kit', 'has_aal2', 'helper'),
    ('auth_kit_private', 'ensure_profile_impl', 'user_impl'), ('auth_kit_private', 'join_client_impl', 'user_impl'),
    ('auth_kit_private', 'effective_access_impl', 'user_impl'), ('auth_kit_private', 'grant_membership_impl', 'user_impl'),
    ('auth_kit_private', 'revoke_membership_impl', 'user_impl'),
    ('auth_kit_private', 'has_permission_impl', 'user_impl'), ('auth_kit_private', 'has_role_impl', 'user_impl'),
    ('auth_kit_private', 'register_client_impl', 'operator_impl'), ('auth_kit_private', 'apply_model_impl', 'operator_impl'),
    ('auth_kit_private', 'export_model_impl', 'operator_impl'), ('auth_kit_private', 'bootstrap_manager_impl', 'operator_impl'),
    ('auth_kit_private', 'revoke_manager_impl', 'operator_impl'), ('auth_kit_private', 'mfa_reset_begin_impl', 'operator_impl'),
    ('auth_kit_private', 'mfa_reset_note_impl', 'operator_impl'), ('auth_kit_private', 'mfa_reset_finish_impl', 'operator_impl'),
    ('auth_kit_private', 'grant_violations', 'internal')),
  functions as (
    select p.oid, n.nspname as schema_name, p.proname as name, p.oid::regprocedure::text as signature,
           p.prosecdef, p.proconfig, p.proowner = n.nspowner as owned,
           coalesce(e.kind, case when n.nspname = 'auth_kit_private' then 'internal' else 'unexpected' end) as kind
      from pg_proc p
      join pg_namespace n on n.oid = p.pronamespace
      left join expected_functions e on e.schema_name = n.nspname and e.name = p.proname
     where n.nspname in ('auth_kit', 'auth_kit_private')),
  relations as (
    select c.oid, n.nspname as schema_name, c.relname as name, c.relkind, c.relrowsecurity,
           n.nspname || '.' || c.relname as label
      from pg_class c join pg_namespace n on n.oid = c.relnamespace
     where n.nspname in ('auth_kit', 'auth_kit_private') and c.relkind in ('r', 'p', 'v', 'm', 'f', 'S')),
  table_privileges(privilege) as (values ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')),
  profile_columns(name, can_select, can_insert, can_update) as (values
    ('user_id', true, true, false), ('display_name', true, true, true), ('contact_email', true, true, true),
    ('contact_phone', true, true, true), ('updated_at', true, false, false)),
  checks as (
    -- Function inventory: every expected function exists.
    select e.schema_name || '.' || e.name as object, '-' as grantee, 'EXISTS' as privilege, true as expected,
           exists (select 1 from functions f where f.schema_name = e.schema_name and f.name = e.name) as actual
      from expected_functions e
    union all
    select f.signature, g.role, 'EXECUTE',
           case f.kind
             when 'user' then g.role in ('authenticated', 'service_role')
             when 'operator' then g.role = 'service_role'
             when 'helper' then g.role in ('anon', 'authenticated', 'service_role')
             when 'user_impl' then g.role in ('authenticated', 'service_role')
             when 'operator_impl' then g.role = 'service_role'
             when 'internal' then g.role = 'service_role'
             else false
           end,
           has_function_privilege(g.role, f.oid, 'EXECUTE')
      from functions f cross join grantees g
    union all
    -- Exposed functions are invokers; implementations are definers.
    select f.signature, '-', 'SECURITY DEFINER', f.kind in ('user_impl', 'operator_impl'), f.prosecdef
      from functions f
    union all
    select f.signature, '-', 'SEARCH_PATH EMPTY', true, coalesce('search_path=""' = any (f.proconfig), false)
      from functions f
    union all
    select f.signature, '-', 'OWNED BY SCHEMA OWNER', true, f.owned
      from functions f
    union all
    select f.signature, '-', 'EXPECTED', false, true
      from functions f where f.kind = 'unexpected'
    union all
    select s.schema_name, g.role, 'USAGE',
           case s.schema_name when 'auth_kit' then g.role <> 'public'
                              else g.role in ('authenticated', 'service_role') end,
           has_schema_privilege(g.role, s.schema_name, 'USAGE')
      from (values ('auth_kit'), ('auth_kit_private')) as s(schema_name) cross join grantees g
    union all
    select s.schema_name, g.role, 'CREATE', false, has_schema_privilege(g.role, s.schema_name, 'CREATE')
      from (values ('auth_kit'), ('auth_kit_private')) as s(schema_name) cross join grantees g
    union all
    select r.label, g.role, t.privilege,
           case
             when g.role = 'service_role' then r.label in ('auth_kit.profiles', 'auth_kit.public_clients') or r.schema_name = 'auth_kit_private'
             when r.label = 'auth_kit.public_clients' then g.role = 'authenticated' and t.privilege = 'SELECT'
             else false
           end,
           has_table_privilege(g.role, r.oid, t.privilege)
      from relations r cross join grantees g cross join table_privileges t
     where r.relkind <> 'S'
    union all
    select r.label, g.role, s.privilege, g.role = 'service_role' and r.schema_name = 'auth_kit_private',
           has_sequence_privilege(g.role, r.oid, s.privilege)
      from relations r cross join grantees g cross join (values ('USAGE'), ('SELECT'), ('UPDATE')) as s(privilege)
     where r.relkind = 'S'
    union all
    select r.label, '-', 'EXPECTED', false, true
      from relations r
     where r.schema_name = 'auth_kit' and r.name not in ('profiles', 'public_clients')
    union all
    -- profiles: own-row access for authenticated is column grants plus RLS.
    select 'auth_kit.profiles.' || c.name, g.role, p.privilege,
           case when g.role = 'service_role' then true
                when g.role = 'authenticated' then
                  case p.privilege when 'SELECT' then c.can_select when 'INSERT' then c.can_insert
                                   when 'UPDATE' then c.can_update else false end
                else false end,
           has_column_privilege(g.role, 'auth_kit.profiles'::regclass, c.name, p.privilege)
      from profile_columns c cross join grantees g
      cross join (values ('SELECT'), ('INSERT'), ('UPDATE'), ('REFERENCES')) as p(privilege)
    union all
    select 'auth_kit.profiles', '-', 'ROW LEVEL SECURITY', true, r.relrowsecurity
      from relations r where r.label = 'auth_kit.profiles'
    union all
    -- Default privileges in the two schemas never grant to anon, authenticated or PUBLIC.
    select 'default privileges in ' || n.nspname, coalesce(g.rolname, 'public'), a.privilege_type, false, true
      from pg_default_acl d
      join pg_namespace n on n.oid = d.defaclnamespace
      cross join lateral aclexplode(d.defaclacl) as a
      left join pg_roles g on g.oid = a.grantee
     where n.nspname in ('auth_kit', 'auth_kit_private')
       and (a.grantee = 0 or g.rolname in ('anon', 'authenticated')))
  select object, grantee, privilege, expected, actual from checks where expected is distinct from actual
$$;

-- 8. Grants ---------------------------------------------------------------------

grant usage on schema auth_kit to anon, authenticated, service_role;
grant usage on schema auth_kit_private to authenticated, service_role;

revoke all on all tables in schema auth_kit_private from public, anon, authenticated;
revoke all on all sequences in schema auth_kit_private from public, anon, authenticated;
grant all on all tables in schema auth_kit_private to service_role;
grant all on all sequences in schema auth_kit_private to service_role;

revoke all on auth_kit.profiles from public, anon, authenticated;
grant select (user_id, display_name, contact_email, contact_phone, updated_at) on auth_kit.profiles to authenticated;
grant insert (user_id, display_name, contact_email, contact_phone) on auth_kit.profiles to authenticated;
grant update (display_name, contact_email, contact_phone) on auth_kit.profiles to authenticated;
grant all on auth_kit.profiles to service_role;

revoke all on auth_kit.public_clients from public, anon, authenticated;
grant select on auth_kit.public_clients to authenticated;
grant all on auth_kit.public_clients to service_role;

revoke execute on all functions in schema auth_kit from public, anon, authenticated, service_role;
revoke execute on all functions in schema auth_kit_private from public, anon, authenticated, service_role;

grant execute on function
  auth_kit.ensure_profile(), auth_kit.join_client(text), auth_kit.effective_access(text),
  auth_kit.grant_membership(uuid, text, text, uuid), auth_kit.revoke_membership(uuid, text, text, uuid)
  to authenticated, service_role;

grant execute on function
  auth_kit.register_client(text, text, text), auth_kit.apply_model(text, jsonb, uuid, boolean),
  auth_kit.export_model(text), auth_kit.bootstrap_manager(uuid, text, text, uuid),
  auth_kit.revoke_manager(uuid, text, text, uuid), auth_kit.mfa_reset_begin(uuid, uuid),
  auth_kit.mfa_reset_note(uuid, uuid, uuid[]), auth_kit.mfa_reset_finish(uuid, uuid, uuid[])
  to service_role;

grant execute on function
  auth_kit.has_permission(text, text), auth_kit.has_role(text, text), auth_kit.has_aal2()
  to anon, authenticated, service_role;

grant execute on function
  auth_kit_private.ensure_profile_impl(), auth_kit_private.join_client_impl(text),
  auth_kit_private.effective_access_impl(text), auth_kit_private.grant_membership_impl(uuid, text, text, uuid),
  auth_kit_private.revoke_membership_impl(uuid, text, text, uuid),
  auth_kit_private.has_permission_impl(text, text), auth_kit_private.has_role_impl(text, text)
  to authenticated;

grant execute on all functions in schema auth_kit_private to service_role;

-- 9. Identity and assertion ------------------------------------------------------

revoke execute on all functions in schema auth_kit from public;
revoke execute on all functions in schema auth_kit_private from public;

insert into auth_kit_private.migrations (version, name) values ('20260927000000', 'dwarpal_auth_kit');

do $assert$
declare
  v_report text;
begin
  select string_agg(format('%s [%s] %s expected=%s actual=%s', v.object, v.grantee, v.privilege, v.expected, v.actual), '; ')
    into v_report
    from auth_kit_private.grant_violations() as v;
  if v_report is not null then
    raise exception 'dwarpal: grant assertion failed: %', v_report;
  end if;
end
$assert$;
