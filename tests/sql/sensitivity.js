#!/usr/bin/env node
// Sensitivity check for the SQL gates (engineering rule V5): each critical
// guard is removed from a disposable copy of the migration, and the gate that
// claims to detect that defect must then fail. The repository itself is never
// modified; every copy lives in a fresh temporary directory that is deleted
// afterwards. An unmutated copy runs first and must pass.
//
//   DWARPAL_PG_BIN=<bin dir> node tests/sql/sensitivity.js [--work-dir <dir>] [--only <id>] [--report <file>]
//
// Exit status 0 only when the baseline passes and every mutation is detected
// by its named test. A mutation whose anchor text is missing is a harness
// failure, never a pass.

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..', '..');
const MIGRATION = 'supabase/migrations/20260927000000_dwarpal_auth_kit.sql';

// Each mutation: the guard it removes, exact text edits (each anchor must
// occur exactly once) in the migration or in `file`, the case files to run
// and test-name prefixes that must fail.
const MUTATIONS = [
  {
    id: 'retry-fingerprint', guard: 'a reused request id with a changed payload is request_conflict',
    edits: [["  if v_row.payload_hash <> p_payload_hash or v_row.state <> 'completed' then", "  if v_row.state <> 'completed' then"]],
    tests: ['requests'], expect: ['L30 grant_membership, mutating first call'],
  },
  {
    id: 'request-id-lock', guard: 'first uses of one id under different scope locks serialise on the id',
    edits: [["  perform pg_advisory_xact_lock(hashtext('auth_kit:request_id'), hashtext(p_request_id::text));\n  select payload_hash", '  select payload_hash']],
    tests: ['requests'], expect: ['concurrent first use of one id under two different client locks'],
  },
  {
    id: 'noop-request-log', guard: 'a no-op first call still binds its request id',
    edits: [["  return auth_kit_private.record_request(p_request_id, p_client_id, 'grant_membership', v_actor::text, v_hash, v_result);",
      "  if not v_inserted then\n    return v_result;\n  end if;\n  return auth_kit_private.record_request(p_request_id, p_client_id, 'grant_membership', v_actor::text, v_hash, v_result);"]],
    tests: ['requests'], expect: ['L30 grant_membership, no-op first call'],
  },
  {
    id: 'authority-before-lock', guard: 'manager authority is read after the client lock',
    edits: [
      ["  perform auth_kit_private.lock_client(p_client_id);\n  v_hash := auth_kit_private.request_fingerprint('grant_membership'",
        "  perform auth_kit_private.require_manager(p_client_id, v_actor);\n  perform auth_kit_private.lock_client(p_client_id);\n  v_hash := auth_kit_private.request_fingerprint('grant_membership'"],
      ['  -- Authority is checked after the lock, so a concurrent revoke is seen.\n  perform auth_kit_private.require_manager(p_client_id, v_actor);\n', ''],
    ],
    tests: ['locking'], expect: ['a manager revoked while its grant waits on the lock'],
  },
  {
    id: 'isolation-guard', guard: 'writes refuse snapshots older than the lock wait',
    edits: [["  if current_setting('transaction_isolation') <> 'read committed' then", '  if false then']],
    tests: ['locking'], expect: ['writes refuse REPEATABLE READ and SERIALIZABLE'],
  },
  {
    id: 'mfa-token-before-state', guard: 'mfa_reset_note checks the token before the row state',
    edits: [["  if v_row.run_token <> p_run_token then\n    perform auth_kit_private.refuse('run_superseded');\n  end if;\n  if v_row.state = 'completed' then\n    perform auth_kit_private.refuse('request_conflict');\n  end if;",
      "  if v_row.state = 'completed' then\n    perform auth_kit_private.refuse('request_conflict');\n  end if;\n  if v_row.run_token <> p_run_token then\n    perform auth_kit_private.refuse('run_superseded');\n  end if;"]],
    tests: ['mfa'], expect: ['L35(h)'],
  },
  {
    id: 'mfa-atomic-takeover', guard: 'a takeover replaces the token and lease in one statement',
    edits: [["    v_token := gen_random_uuid();\n    update auth_kit_private.request_log r set run_token = v_token, started_at = v_now\n     where r.request_id = p_request_id;\n",
      '    v_token := v_row.run_token;\n']],
    tests: ['mfa'], expect: ['L35(g)'],
  },
  {
    id: 'mfa-finish-fence', guard: 'mfa_reset_finish refuses a superseded token',
    edits: [["  if v_row.run_token <> p_run_token then\n    perform auth_kit_private.refuse('run_superseded');\n  end if;\n  if v_row.state = 'completed' then\n    -- The claim holder's own retry.",
      "  if v_row.state = 'completed' then\n    -- The claim holder's own retry."]],
    tests: ['mfa'], expect: ['L35(h)'],
  },
  {
    id: 'mfa-claim-clock', guard: 'the claim time is taken after the locks',
    edits: [['  v_now := clock_timestamp();\n  if not found then\n    v_token := gen_random_uuid();', '  v_now := now();\n  if not found then\n    v_token := gen_random_uuid();']],
    tests: ['mfa'], expect: ['the claim time is taken after the locks'],
  },
  {
    id: 'helper-sql-body', guard: 'has_permission answers false for anon without touching the private schema',
    edits: [[`create function auth_kit.has_permission(client_id text, permission_key text)
returns boolean language plpgsql stable security invoker set search_path = ''
as $$
begin
  if auth.uid() is null then
    return false;
  end if;
  return auth_kit_private.has_permission_impl(client_id, permission_key);
end
$$;`, `create function auth_kit.has_permission(client_id text, permission_key text)
returns boolean language sql stable security invoker set search_path = ''
as $$ select case when auth.uid() is null then false else auth_kit_private.has_permission_impl($1, $2) end $$;`]],
    tests: ['access'], expect: ['a consumer RLS policy over the helpers'],
  },
  {
    id: 'widened-grant', guard: 'authenticated executes only the user and helper implementations',
    edits: [
      ['-- 9. Identity and assertion', 'grant execute on function auth_kit_private.apply_model_impl(text, jsonb, uuid, boolean) to authenticated;\n-- 9. Identity and assertion'],
      ["  if v_report is not null then\n    raise exception 'dwarpal: grant assertion failed: %', v_report;\n  end if;", '  null;'],
    ],
    tests: ['access', 'migration'], expect: ['executed privileges on every function', 'one migration file'],
  },
  {
    id: 'public-execute', guard: 'PUBLIC keeps no EXECUTE on private functions',
    edits: [
      ['revoke execute on all functions in schema auth_kit_private from public, anon, authenticated, service_role;\n', ''],
      ['revoke execute on all functions in schema auth_kit_private from public;\n', ''],
      ["  if v_report is not null then\n    raise exception 'dwarpal: grant assertion failed: %', v_report;\n  end if;", '  null;'],
    ],
    tests: ['access'], expect: ['executed privileges on every function'],
  },
  {
    id: 'enrollment-once', guard: 'an existing enrollment ends the join, so revokes are durable',
    edits: [["  if found then\n    return jsonb_build_object('result', 'already_enrolled'", "  if false then\n    return jsonb_build_object('result', 'already_enrolled'"]],
    tests: ['enrollment'], expect: ['retry and sign-in after a manager revoke'],
  },
  {
    id: 'join-email-check', guard: 'join reads email confirmation from auth.users',
    edits: [["  if v_confirmed is null then\n    return jsonb_build_object('result', 'email_unverified');", "  if false then\n    return jsonb_build_object('result', 'email_unverified');"]],
    tests: ['enrollment'], expect: ['outcomes that write nothing'],
  },
  {
    id: 'mfa-withheld-role', guard: 'an MFA-required role is inactive below aal2',
    edits: [["  select not p_mfa_required or coalesce(auth.jwt() ->> 'aal', 'aal1') = 'aal2'", '  select true']],
    tests: ['membership', 'access'], expect: ['manager authority', 'effective_access and the helpers agree'],
  },
  {
    id: 'manager-grants-manager', guard: 'managers cannot grant manager roles',
    edits: [["  elsif v_manages then\n    -- Managers never create managers (I4).\n    perform auth_kit_private.refuse('forbidden');", "  elsif v_manages then\n    -- Managers never create managers (I4).\n    null;"]],
    tests: ['membership'], expect: ['target rules'],
  },
  {
    id: 'last-manager', guard: 'revoke_manager never removes the last manager membership',
    edits: [["      perform auth_kit_private.refuse('last_manager');", '      null;']],
    tests: ['membership'], expect: ['revoke_manager: never the last manager'],
  },
  {
    id: 'promotion', guard: 'a model change cannot promote existing holders',
    edits: [["        if v_flag = 'manages_members' and v_after -> v_flag = 'true'::jsonb and v_count > 0 then", '        if false then']],
    tests: ['model'], expect: ['strict promotion'],
  },
  {
    id: 'live-manager', guard: 'a live client keeps an assigned manager',
    edits: [["  if p_state = 'live' and not exists (", '  if false and not exists (']],
    tests: ['model'], expect: ['a live client keeps an assigned manager'],
  },
  {
    id: 'held-role', guard: 'removing a held role is refused with its holders',
    edits: [["      if v_holders ? v_key then\n        v_refusals := v_refusals || jsonb_build_array(jsonb_build_object('rule', 'role_held'",
      "      if false then\n        v_refusals := v_refusals || jsonb_build_array(jsonb_build_object('rule', 'role_held'"]],
    tests: ['model'], expect: ['held role deletion is refused'],
  },
  {
    id: 'client-scope', guard: 'helpers read only the named client',
    edits: [['     where m.user_id = auth.uid() and m.client_digest = auth_kit_private.key_digest(p_client_id) and m.client_id = p_client_id\n       and rp.permission_digest',
      '     where m.user_id = auth.uid()\n       and rp.permission_digest']],
    tests: ['access'], expect: ['no cross-client leakage'],
  },
  {
    id: 'exact-reference', guard: 'a membership must name its role by exact text, not only by digest',
    edits: [['create trigger exact_key_reference after insert or update of client_id, role_key on auth_kit_private.memberships\n  for each row execute function auth_kit_private.exact_key_reference();\n', '']],
    tests: ['opaque-keys'], expect: ['with a deliberately colliding digest'],
  },
  {
    id: 'exact-lookup', guard: 'has_role compares the role key text, not only its digest',
    edits: [['       and m.role_digest = auth_kit_private.key_digest(p_role_key) and m.role_key = p_role_key', '       and m.role_digest = auth_kit_private.key_digest(p_role_key)']],
    tests: ['opaque-keys'], expect: ['with a deliberately colliding digest'],
  },
  {
    id: 'column-audit', guard: 'the audit checks column privileges on every kit relation',
    edits: [["     where r.relkind <> 'S' and a.attnum > 0 and not a.attisdropped),", "     where r.relkind <> 'S' and a.attnum > 0 and not a.attisdropped and r.label = 'auth_kit.profiles'),"]],
    tests: ['access-audit'], expect: ['column-only grants on kit relations', "the migration's final assertion aborts the installation on a private column-only grant"],
  },
  {
    id: 'policy-expression-audit', guard: 'the audit compares each own-row policy expression',
    edits: [['                      and p.roles = array[\'authenticated\'] and p.qual is not distinct from e.qual', "                      and p.roles = array['authenticated']"]],
    tests: ['access-audit'], expect: ['profile policy drift is reported', "the migration's final assertion aborts the installation on a changed profile policy"],
  },
  {
    id: 'extra-policy-audit', guard: 'the audit reports policies it did not install',
    edits: [['     where not exists (select 1 from expected_policies e where e.relation = p.relation and e.name = p.name)', '     where false']],
    tests: ['access-audit'], expect: ['profile policy drift is reported', "the migration's final assertion aborts the installation on an added profile policy"],
  },
  {
    id: 'noop-bootstrap-live', guard: 'a bootstrap that finds the membership present still makes the client live',
    edits: [["  update auth_kit_private.clients c set state = 'live'\n   where", "  update auth_kit_private.clients c set state = 'live'\n   where v_inserted and"]],
    tests: ['membership'], expect: ['bootstrap that finds an existing manager membership'],
  },
  {
    id: 'teardown-status', guard: 'a teardown failure makes the runner exit nonzero', file: 'tests/sql/run.js',
    edits: [['  if (harnessError || report.failures.length > 0) return 1;', '  if (harnessError) return 1;']],
    tests: ['teardown'], expect: ['a passing run whose pg_ctl stop fails'],
  },
  {
    id: 'utf16-order', guard: 'canonical keys sort by UTF-16 code unit',
    edits: [["                                      ',' order by auth_kit_private.utf16_key(e.key)), '') || '}'", "                                      ',' order by e.key collate \"C\"), '') || '}'"]],
    tests: ['canonical'], expect: ['canonical JSON: fixed vectors match core'],
  },
];

function parseArgs(argv) {
  const out = { workDir: process.env.DWARPAL_SQL_WORK_DIR ?? os.tmpdir(), only: null, report: null };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--work-dir') out.workDir = path.resolve(argv[(i += 1)]);
    else if (arg === '--only') out.only = argv[(i += 1)];
    else if (arg === '--report') out.report = path.resolve(argv[(i += 1)]);
    else throw new Error(`unknown argument ${arg}`);
  }
  return out;
}

function copyTree(target) {
  for (const entry of ['package.json', 'packages', 'supabase', 'tests/sql']) {
    fs.cpSync(path.join(repoRoot, entry), path.join(target, entry), { recursive: true });
  }
}

function applyEdits(file, edits) {
  let text = fs.readFileSync(file, 'utf8');
  for (const [find, replace] of edits) {
    const count = text.split(find).length - 1;
    if (count !== 1) throw new Error(`mutation anchor found ${count} times: ${JSON.stringify(find.slice(0, 80))}`);
    text = text.replace(find, () => replace);
  }
  fs.writeFileSync(file, text);
}

function runGates(copy, tests, workDir) {
  const files = tests.map((t) => path.join(copy, 'tests', 'sql', 'cases', `${t}.test.js`));
  const result = spawnSync(process.execPath, [path.join(copy, 'tests', 'sql', 'run.js'), '--work-dir', workDir, '--timeout', '600', ...files], {
    cwd: copy, encoding: 'utf8', timeout: 900_000, env: process.env, maxBuffer: 64 * 1024 * 1024,
  });
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  const failed = [...new Set([...output.matchAll(/^✖ (.+?) \(\d+(?:\.\d+)?ms\)$/gm)].map((m) => m[1]))];
  const passed = [...output.matchAll(/^✔ (.+?) \(\d+(?:\.\d+)?ms\)$/gm)].length;
  return { status: result.status, signal: result.signal, failed, passed, output };
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  if (!process.env.DWARPAL_PG_BIN) throw new Error('Set DWARPAL_PG_BIN; see tests/sql/README.md.');
  fs.mkdirSync(options.workDir, { recursive: true });
  const selected = options.only ? MUTATIONS.filter((m) => m.id === options.only) : MUTATIONS;
  if (selected.length === 0) throw new Error(`no mutation ${options.only}`);
  const report = { migration: MIGRATION, baseline: null, mutations: [] };
  const withCopy = (fn) => {
    const copy = fs.mkdtempSync(path.join(options.workDir, 'mut-'));
    try {
      copyTree(copy);
      return fn(copy);
    } finally {
      fs.rmSync(copy, { recursive: true, force: true });
    }
  };
  const allTests = [...new Set(selected.flatMap((m) => m.tests))].sort();
  const baseline = withCopy((copy) => runGates(copy, allTests, options.workDir));
  report.baseline = { tests: allTests, status: baseline.status, passed: baseline.passed, failed: baseline.failed };
  console.log(`[sensitivity] baseline ${allTests.join(', ')}: exit ${baseline.status}, ${baseline.passed} passed, ${baseline.failed.length} failed`);
  let ok = baseline.status === 0 && baseline.failed.length === 0;
  for (const mutation of selected) {
    const outcome = withCopy((copy) => {
      applyEdits(path.join(copy, mutation.file ?? MIGRATION), mutation.edits);
      return runGates(copy, mutation.tests, options.workDir);
    });
    const missing = mutation.expect.filter((prefix) => !outcome.failed.some((name) => name.startsWith(prefix)));
    const detected = outcome.status !== 0 && missing.length === 0;
    ok &&= detected;
    report.mutations.push({ id: mutation.id, guard: mutation.guard, file: mutation.file ?? MIGRATION, tests: mutation.tests, expect: mutation.expect, status: outcome.status, failed: outcome.failed, missing, detected });
    console.log(`[sensitivity] ${detected ? 'detected' : 'NOT DETECTED'} ${mutation.id}: exit ${outcome.status}; failing: ${outcome.failed.join(' | ') || 'none'}`);
  }
  if (options.report) fs.writeFileSync(options.report, `${JSON.stringify(report, null, 2)}\n`);
  console.log(`[sensitivity] ${ok ? 'all mutations detected' : 'FAILED'}`);
  process.exitCode = ok ? 0 : 1;
}

try {
  main();
} catch (error) {
  console.error(`[sensitivity] harness failure: ${error.message}`);
  process.exitCode = 1;
}
