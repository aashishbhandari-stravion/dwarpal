-- Test fixture: fault injection for rollback gates. Installed by individual
-- tests into their own throwaway database, never into the template and never
-- by a production migration. A statement fails when the session setting
-- dwarpal_test.fail_on names the table it writes, so a test can make a real
-- write inside an implementation fail at a chosen step and then prove that
-- nothing of the call survived.

create schema dwarpal_test;

create function dwarpal_test.fault() returns trigger
language plpgsql
as $$
begin
  if current_setting('dwarpal_test.fail_on', true) = tg_table_name then
    raise exception using errcode = 'DT001', message = 'injected fault on ' || tg_table_name || ' ' || lower(tg_op);
  end if;
  return null;
end
$$;

create trigger dwarpal_test_fault after insert or update or delete on auth_kit_private.clients
  for each row execute function dwarpal_test.fault();
create trigger dwarpal_test_fault after insert or update or delete on auth_kit_private.roles
  for each row execute function dwarpal_test.fault();
create trigger dwarpal_test_fault after insert or update or delete on auth_kit_private.permissions
  for each row execute function dwarpal_test.fault();
create trigger dwarpal_test_fault after insert or update or delete on auth_kit_private.role_permissions
  for each row execute function dwarpal_test.fault();
create trigger dwarpal_test_fault after insert or update or delete on auth_kit_private.memberships
  for each row execute function dwarpal_test.fault();
create trigger dwarpal_test_fault after insert or update or delete on auth_kit_private.enrollments
  for each row execute function dwarpal_test.fault();
create trigger dwarpal_test_fault after insert or update or delete on auth_kit_private.membership_events
  for each row execute function dwarpal_test.fault();
create trigger dwarpal_test_fault after insert or update or delete on auth_kit_private.model_events
  for each row execute function dwarpal_test.fault();
create trigger dwarpal_test_fault after insert or update or delete on auth_kit_private.request_log
  for each row execute function dwarpal_test.fault();
