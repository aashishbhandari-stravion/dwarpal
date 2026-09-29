// The hosted verification inventory: every actor the harness provisions and
// every case it reports, with the access path it exercises, the credentials
// it needs, the classes of external action it must be authorized for, and
// the procedure that produces it. Design references are to the frozen
// design packet (sections 4.1, 4.2, 5.1, 5.14, 8, and the L25-L35 table).
//
// The inventory is data. A case that is not listed here cannot be reported,
// and a listed case that no procedure reports is not_run, never passed.

// Classes of external action the target's authorization must name before a
// procedure may run (see README, "Authorization").
export const ACTION_CLASSES = Object.freeze({
  connect: 'read-only calls to the target: signing keys, settings, Management API reads, PostgREST reads',
  create_users: 'create, ban and delete disposable users through the Auth admin API (no e-mail is sent)',
  mutations: 'kit writes (register, apply-model, bootstrap, grant, revoke, join, mfa-reset), consumer rows, sign-in and sign-out of disposable users',
  totp: 'enrol, challenge, verify and delete TOTP factors of disposable users',
  catalog_mutation: 'temporary catalog changes that are reverted in the same run: widened grants (L33), a fault trigger (L27)',
  cleanup_sql: 'Management API deletes of rows this harness created',
  send_email: 'real SMTP deliveries to the authorized recipients',
  interactive_sign_in: 'a human Google sign-in with the authorized test identity',
});

// Inputs a case may need. Secrets come from the environment only.
export const CAPABILITIES = Object.freeze({
  publishable_key: 'SUPABASE_PUBLISHABLE_KEY',
  secret_key: 'SUPABASE_SECRET_KEY',
  management_token: 'SUPABASE_ACCESS_TOKEN (Management API personal access token)',
  smtp_recipient: 'identities.smtpRecipients in the target descriptor',
  google_identity: 'identities.google in the target descriptor',
  interactive: '--interactive on a terminal',
});

// Clients the harness creates, per run: `<prefix>` is a fresh run prefix.
export const CLIENTS = Object.freeze({
  A: 'the example model (a copy of examples/creditone/auth-model.json under a run client id); matrix states S0, S1, S2',
  B: 'a second client with the same model: other-client actors and L31',
  D: 'L34 model: role `lead` manages members without MFA, role `chief` manages members with MFA',
  E: 'L27 enrollment client: self-assignable `member`, later a second self-assignable role',
  F: 'L29 registered client with no holders; L30 apply_model',
  G: 'L32 bootstrap target, registered only until the confirmed --user-id run',
  RLS: 'the fixed client `rls-demo` of examples/rls-consumer (its policies name it); shared across runs',
});

export const ACTORS = Object.freeze([
  { id: 'anon', kind: 'publishable key only, no user token' },
  { id: 'service', kind: 'secret key (service_role); the operator client and CLI' },
  { id: 'member_a', kind: 'confirmed user, joined A (customer), aal1' },
  { id: 'staff_a', kind: 'customer (join) and staff (manager grant) of A, TOTP factor; used at aal1 (MFA-pending) and aal2 (active staff)' },
  { id: 'manager_a', kind: 'admin of A (bootstrap), TOTP factor; aal2 active manager and aal1 withheld manager' },
  { id: 'manager_a2', kind: 'second admin of A (L30 revoke_manager, cross-manager request id), TOTP factor' },
  { id: 'manager_b', kind: 'admin of B (manager of another client), TOTP factor, aal2' },
  { id: 'member_b', kind: 'customer of B only (member of another client)' },
  { id: 'cross_ab', kind: 'admin of A and customer of B (L31)' },
  { id: 'l34_u1', kind: 'D: holds lead and chief' },
  { id: 'l34_u2', kind: 'D: holds chief only, TOTP factor' },
  { id: 'l34_u3', kind: 'D: holds lead only' },
  { id: 'l34_none', kind: 'D: holds no manager role (member only)' },
  { id: 'e_manager', kind: 'E: manager (non-MFA manager role)' },
  { id: 'e_user1', kind: 'E: first join, retry, revoke, re-grant' },
  { id: 'e_user2', kind: 'E: two concurrent first joins' },
  { id: 'e_user3', kind: 'E: join with an injected failure after the enrollment insert' },
  { id: 'e_user4', kind: 'E: joins after the model adds a self-assignable role' },
  { id: 'rls_member', kind: 'rls-demo member with own notes' },
  { id: 'rls_staff', kind: 'rls-demo member and staff (MFA), TOTP factor; aal1 and aal2' },
  { id: 'rls_manager', kind: 'rls-demo manager (MFA), TOTP factor, aal2' },
  { id: 'rls_other', kind: 'member of B only, queries rls-demo notes' },
  { id: 'revoke_signout', kind: 'rls-demo member; signs out while holding an unexpired token (L25)' },
  { id: 'revoke_ban', kind: 'rls-demo member; banned while holding an unexpired token (L25)' },
  { id: 'revoke_member', kind: 'rls-demo member; membership revoked by a manager while holding a token (5.14)' },
  { id: 'lookup_confirmed', kind: 'confirmed user found by --email (L32)' },
  { id: 'lookup_unconfirmed', kind: 'unconfirmed user (L32)' },
  { id: 'probe_user', kind: 'disposable doctor --probe user with a generated password (L33)' },
  { id: 'mfa_u', kind: 'L35 user U with one verified TOTP factor' },
  { id: 'mfa_u2', kind: 'L35 user U2 with one verified TOTP factor' },
  { id: 'smtp_user', kind: 'signs up with an authorized real mailbox; confirmation arrives by SMTP' },
  { id: 'google_user', kind: 'the authorized Google test identity, signed in interactively' },
  { id: 'routing_user', kind: 'confirmed user with no membership: the authenticated caller of the routing checks' },
  { id: 'f_admin', kind: 'F: the held manager role (L29 live client)' },
  { id: 'f_staff', kind: 'F: holds staff (L29 promotion refusal)' },
  { id: 'r_steward1', kind: 'R: manager (L30)' },
  { id: 'r_steward2', kind: 'R: second manager (L30 cross-manager id)' },
  { id: 'r_target', kind: 'R: grant and revoke target (L30)' },
  { id: 'r_other', kind: 'R: second target for conflicting payloads (L30)' },
  { id: 'r_target2', kind: 'R: bootstrap and revoke_manager target (L30)' },
  { id: 'r_joiner', kind: 'R: joins twice (L30 natural keys)' },
  { id: 'dup_one', kind: 'L32: address reused with different case to attempt a duplicate' },
  { id: 'lookup_email', kind: 'L32: unique confirmed --email match' },
  { id: 'l34_t1', kind: 'D: grant target of U1' },
  { id: 'l34_t2', kind: 'D: grant target of U2' },
  { id: 'l34_t3', kind: 'D: grant target of U3 and of the non-manager' },
  { id: 'totp_user', kind: 'D: chief (MFA role); TOTP enrol, challenge, verify and self-unenrol' },
]);

const BASE = { needs: ['publishable_key', 'secret_key'], authorize: ['connect'] };
const WRITE = { needs: ['publishable_key', 'secret_key'], authorize: ['connect', 'create_users', 'mutations'] };
const MGMT = { needs: ['publishable_key', 'secret_key', 'management_token'] };

function entry(fields) {
  return Object.freeze({ required: true, ...fields, needs: Object.freeze([...fields.needs]), authorize: Object.freeze([...fields.authorize]) });
}

function group(procedure, defaults, list) {
  return list.map(([id, lld, paths, title, extra = {}]) => entry({ procedure, lld, id, paths, title, ...defaults, ...extra }));
}

const MATRIX_ACTORS = ['anon', 'member_a', 'staff_a@aal1', 'staff_a@aal2', 'manager_a@aal1', 'manager_a@aal2', 'manager_b', 'member_b', 'service'];
const MATRIX_STATES = [
  ['S0', 'registered, no model applied'],
  ['S1', 'the example model applied'],
  ['S2', 'a changed model applied (one key added to staff, one customer key unmapped and removed)'],
];

const matrix = MATRIX_STATES.flatMap(([state, label]) => MATRIX_ACTORS.map((actor) => entry({
  procedure: 'matrix', lld: '5.1', id: `M.${state}.${actor}`, paths: ['postgrest'],
  title: `${label}: ${actor} effective_access, helpers, profiles, public_clients, private tables`,
  needs: WRITE.needs, authorize: [...WRITE.authorize, ...(actor.includes('@aal2') ? ['totp'] : [])],
})));

export const CASES = Object.freeze([
  // Target prerequisites: checked before anything else; a failure blocks the cases that depend on it.
  ...group('target', BASE, [
    ['T.identity', 'setup', ['local'], 'descriptor, environment URL and key kinds agree; authorization current', { authorize: [] }],
    ['T.signing_keys', 'D5', ['auth'], 'JWKS publishes asymmetric keys only'],
    ['T.auth_settings', '10', ['management'], 'TOTP enabled, e-mail confirmation required, token lifetime recorded, redirect allow-list holds the harness callback', { needs: MGMT.needs }],
    ['T.management', 'D1', ['management'], 'Management API token accepted; SQL probe channel round-trips; session role may impersonate anon, authenticated and service_role', { needs: MGMT.needs }],
    ['T.schema', '4.2', ['management'], 'installed migration versions equal the repository files; grant assertion empty', { needs: MGMT.needs }],
    ['T.exposed_schemas', 'R4', ['management'], 'exposed schemas include auth_kit and app and never auth_kit_private', { needs: MGMT.needs }],
    ['T.rls_consumer', 'F4', ['management'], 'examples/rls-consumer installed: app.notes, forced RLS, four policies', { needs: MGMT.needs }],
  ]),

  // HTTP routing versus SQL EXECUTE (R4, L28, 5.1).
  ...group('routing', { needs: WRITE.needs, authorize: WRITE.authorize }, [
    ['L28.http.private_rpc.anon', 'L28', ['postgrest'], 'every auth_kit_private function over HTTP with the private profile: PGRST106 for anon'],
    ['L28.http.private_rpc.authenticated', 'L28', ['postgrest'], 'the same for an authenticated member'],
    ['L28.http.private_rpc.service', 'L28', ['postgrest'], 'the same for the service role: routing is independent of role'],
    ['L28.http.private_table.anon', '5.1', ['postgrest'], 'every auth_kit_private table over HTTP: PGRST106 for anon'],
    ['L28.http.private_table.authenticated', '5.1', ['postgrest'], 'the same for an authenticated member'],
    ['L28.http.impl_in_exposed_profile', 'L28', ['postgrest'], 'has_permission_impl under the auth_kit profile: not found, for anon and authenticated'],
  ]),
  ...group('routing', { needs: MGMT.needs, authorize: ['connect'] }, [
    ['L28.sql.execute.anon', 'L28', ['sql'], 'SQL impersonation as anon: permission denied on every private function; catalog agrees'],
    ['L28.sql.execute.authenticated', 'L28', ['sql'], 'as authenticated: exactly the five user and two helper implementations execute; catalog agrees'],
    ['L28.sql.execute.service_role', 'L28', ['sql'], 'as service_role: every function executes; catalog agrees'],
    ['L28.sql.wrappers', '4.2', ['sql'], 'exposed wrapper EXECUTE per role equals the grant table (catalog and impersonation)'],
    ['L28.sql.private_tables', '4.2', ['sql'], 'direct SELECT on every private table: denied for anon and authenticated'],
    ['L28.sql.public_execute', 'L28', ['sql'], 'PUBLIC holds EXECUTE on no function in either schema'],
  ]),

  // The real consumer RLS policy (L28 policy results) on rls-demo.
  ...group('policy', { needs: WRITE.needs, authorize: [...WRITE.authorize, 'totp'] }, [
    ['L28.policy.anon', 'L28', ['postgrest'], 'anon: helpers false without error; notes refused'],
    ['L28.policy.member', 'L28', ['postgrest'], 'member: own notes only; member keys true'],
    ['L28.policy.other_client', 'L28', ['postgrest'], 'member of another client: helpers false, zero notes'],
    ['L28.policy.staff_aal1', 'L28', ['postgrest'], 'MFA-pending staff: staff-only key false, member key true, own notes only'],
    ['L28.policy.staff_aal2', 'L28', ['postgrest'], 'staff at aal2: every run note'],
    ['L28.policy.manager_aal2', 'L28', ['postgrest'], 'manager at aal2: helpers true, every run note'],
    ['L28.policy.unknown_key', 'L28', ['postgrest'], 'unknown key: false for every actor'],
  ]),

  // The actor matrix across three model states (5.1, 8).
  ...matrix,
  ...group('matrix', { ...WRITE, authorize: [...WRITE.authorize, 'totp'] }, [
    ['M.forged_metadata', '5.1', ['postgrest', 'node'], 'user_metadata and app_metadata claiming a role grant nothing'],
    ['M.forged_jwt', '5.1', ['postgrest', 'node'], 'a token signed by a foreign key: PostgREST 401, Node invalid_token'],
    ['M.wrong_client', '5.1', ['postgrest'], 'A member asking for B: empty access, helpers false; A manager writing on B: forbidden'],
    ['M.manager_promotes_manager', 'D17', ['postgrest'], 'a manager granting a manages_members role is refused, nothing written'],
    ['M.self_target', '4.2', ['postgrest'], 'a manager granting to self is refused, nothing written'],
    ['M.operator_wrappers_as_user', '4.2', ['postgrest'], 'operator wrappers over HTTP as anon and authenticated: permission denied'],
  ]),

  // L25 and the direct-path revocation guarantees (5.14, D20).
  ...group('revocation', { ...WRITE }, [
    ['L25.signout.node', 'L25', ['node'], 'signed-out token on the Node path: 401 invalid_token on the very next request'],
    ['L25.signout.postgrest_live', 'L25', ['postgrest'], 'the same token on the direct RLS path: rows still returned before expiry'],
    ['L25.signout.postgrest_expired', 'L25', ['postgrest'], 'the same token after expiry: 401'],
    ['L25.ban.node', 'L25', ['node'], 'banned user\'s token on the Node path: 401 invalid_token'],
    ['L25.ban.postgrest_live', 'L25', ['postgrest'], 'banned user\'s token on the direct path: rows until expiry'],
    ['L25.ban.postgrest_expired', 'L25', ['postgrest'], 'banned user\'s token after expiry: 401'],
    ['L25.side_by_side', 'L25', ['node', 'postgrest'], 'both outcomes recorded side by side with the token lifetime and clock offset'],
    ['L25.membership_revoke_direct', '5.14', ['postgrest'], 'membership revoke is immediate on the direct path with the same token'],
  ]),

  // L27 enrollment matrix on client E.
  ...group('enrollment', { ...WRITE }, [
    ['L27.first', 'L27', ['postgrest', 'sql'], 'first join: enrolled, one enrollment row, one join event per self-assignable role'],
    ['L27.retry', 'L27', ['postgrest', 'sql'], 'retry: already_enrolled, nothing written'],
    ['L27.revoke_then_signin', 'L27', ['postgrest', 'sql'], 'after a manager revoke and a new sign-in: already_enrolled, membership stays absent'],
    ['L27.concurrent', 'L27', ['postgrest', 'sql'], 'two concurrent first joins: one enrollment row, one event per role in total'],
    ['L27.injected_failure', 'L27', ['postgrest', 'sql'], 'a join failing after the enrollment insert leaves no row; the next join enrolls', { needs: MGMT.needs, authorize: [...WRITE.authorize, 'catalog_mutation'] }],
    ['L27.new_role_future_only', 'L27', ['postgrest', 'sql'], 'a new self-assignable role: enrolled users unchanged, the next new user gets both'],
    ['L27.regrant', 'L27', ['postgrest', 'sql'], 'manager re-grant restores the revoked role with a manager event'],
  ].map((row) => [...row.slice(0, 4), { needs: MGMT.needs, ...(row[4] ?? {}) }])),

  // L29 model refusals and apply_model concurrency.
  ...group('model', { needs: MGMT.needs, authorize: WRITE.authorize }, [
    ['L29.live.no_manager_refused', 'L29', ['postgrest', 'sql'], 'live client: model removing manages_members from the only held manager role is refused with holders, nothing written'],
    ['L29.live.promotion_refused', 'L29', ['postgrest', 'sql'], 'live client: model setting manages_members on a held role is refused with holders, nothing written'],
    ['L29.registered.accepted', 'L29', ['postgrest', 'sql'], 'the same two models accepted on a registered client with no holders'],
    ['L29.concurrent_apply', '8', ['postgrest', 'sql'], 'two concurrent applies of one model with different ids: one applied, one unchanged, one model event'],
  ]),

  // L30 request-bearing commands.
  ...group('requests', { needs: MGMT.needs, authorize: [...WRITE.authorize, 'totp'] }, [
    ...['grant_membership', 'revoke_membership', 'bootstrap_manager', 'revoke_manager', 'apply_model'].flatMap((cmd) => [
      [`L30.${cmd}.mutating`, 'L30', ['postgrest', 'sql'], `${cmd}: mutating first call, then same-id same payload (stored result) and different payload (request_conflict), counting rows`],
      [`L30.${cmd}.noop`, 'L30', ['postgrest', 'sql'], `${cmd}: no-op first call writes request_log only; same retries`],
    ]),
    ['L30.cross_manager_id', 'L30', ['postgrest', 'sql'], 'a manager reusing another manager\'s request id: request_conflict, nothing written'],
    ['L30.natural_keys', 'L30', ['postgrest', 'sql'], 'join_client and register_client write no request_log row and are idempotent on their natural keys'],
  ]),

  // L31 client scope on the Node path.
  ...group('scope', { needs: WRITE.needs, authorize: WRITE.authorize }, [
    ['L31.scoped_principal', 'L31', ['node'], 'server configured for B: memberships and access are B\'s only'],
    ['L31.no_other_client_call', 'L31', ['node'], 'no outbound call made while resolving mentions A'],
  ]),

  // L32 bootstrap-manager lookups (CLI and library against the real Admin API).
  ...group('bootstrap', { needs: WRITE.needs, authorize: WRITE.authorize }, [
    ['L32.email_zero_matches', 'L32', ['cli'], '--email with no confirmed match in a complete listing: unknown_user, nothing written'],
    ['L32.email_two_matches', 'L32', ['cli'], 'two confirmed matches: Supabase Auth keeps e-mail addresses unique, so this state cannot be created on a hosted project; attempted and recorded, disposition required', { required: false }],
    ['L32.lookup_incomplete', 'L32', ['auth'], 'listing with page size 1 and cap 2 over three or more users: lookup_incomplete, nothing written, --user-id named'],
    ['L32.user_id_unconfirmed', 'L32', ['cli'], '--user-id of an unconfirmed user: email_unverified, nothing written'],
    ['L32.user_id_confirmed', 'L32', ['cli', 'sql'], '--user-id of a confirmed user: granted, client state live'],
    ['L32.email_unique_match', 'L32', ['cli'], '--email with exactly one confirmed match: granted'],
  ].map((row) => [...row.slice(0, 4), { needs: MGMT.needs, ...(row[4] ?? {}) }])),

  // L33 doctor modes (D1 amendment A).
  ...group('doctor', { needs: WRITE.needs, authorize: WRITE.authorize }, [
    ['L33.secret_only_incomplete', 'L33', ['cli'], 'secret key only: privileged catalog checks not_run, overall incomplete (exit 5); public signing-key check runs'],
    ['L33.catalog_ok', 'L33', ['cli', 'management'], 'with the Management token: catalog inspects grants, schema, exposed schemas, redirects; ok', { needs: MGMT.needs }],
    ['L33.probe_mode', 'L33', ['cli', 'postgrest'], '--probe with a disposable user: anon and authenticated outcomes in a separate probe mode', { needs: MGMT.needs }],
    ['L33.catalog_detects_widening', 'L33', ['cli', 'management'], 'a deliberately widened grant is reported by catalog mode', { needs: MGMT.needs, authorize: [...WRITE.authorize, 'catalog_mutation'] }],
    ['L33.probe_detects_widening', 'L33', ['cli', 'postgrest'], 'a probe-observable widened grant is reported by probe mode', { needs: MGMT.needs, authorize: [...WRITE.authorize, 'catalog_mutation'] }],
    ['L33.widening_reverted', 'L33', ['management'], 'every widened grant is revoked and the grant assertion is empty again', { needs: MGMT.needs, authorize: [...WRITE.authorize, 'catalog_mutation'] }],
  ]),

  // L34 two manager roles on client D.
  ...group('managers', { needs: MGMT.needs, authorize: [...WRITE.authorize, 'totp'] }, [
    ['L34.u1', 'L34', ['postgrest', 'node'], 'U1 (lead + chief) at aal1: granted via lead; has_role lead true, chief false; explain shows chief withheld'],
    ['L34.u2_aal1', 'L34', ['postgrest', 'sql'], 'U2 (chief) at aal1: mfa_required, nothing written'],
    ['L34.u3', 'L34', ['postgrest'], 'U3 (lead) at aal1: granted'],
    ['L34.u2_aal2', 'L34', ['postgrest'], 'U2 at aal2: granted'],
    ['L34.no_manager', 'L34', ['postgrest', 'sql'], 'a user with no manager role: forbidden, nothing written'],
  ]),

  // L35 hosted cases (a)-(d); (e)-(i) have unit and fault-injection evidence from earlier lanes.
  ...group('mfa_reset', { needs: MGMT.needs, authorize: [...WRITE.authorize, 'totp'] }, [
    ['L35.a', 'L35', ['auth', 'sql'], 'run to completion: pending row before listFactors, then completed with [F], one event with client_id null'],
    ['L35.b', 'L35', ['auth', 'sql'], 'retry after success: stored result, no admin API call, nothing written'],
    ['L35.c', 'L35', ['auth', 'sql'], 'another user with the same id: request_conflict before any admin call, U2 untouched'],
    ['L35.d', 'L35', ['auth', 'sql'], 'two concurrent runs: one proceeds, the other request_in_progress before any admin call'],
  ]),

  // Providers.
  ...group('providers', { needs: WRITE.needs, authorize: [...WRITE.authorize, 'totp'] }, [
    ['P.totp.enrol_challenge', '10', ['auth', 'node'], 'TOTP enrol, challenge and verify reach aal2; resolveSession reports aal2 and the MFA role active'],
    ['P.totp.unenrol_self', '4.1', ['auth'], 'a user at aal2 removes their own factor'],
  ]),
  ...group('smtp', { needs: [...WRITE.needs, 'smtp_recipient', 'interactive'], authorize: [...WRITE.authorize, 'send_email'] }, [
    ['P.smtp.confirmation_delivered', '8', ['smtp', 'auth'], 'sign-up sends a confirmation through the configured SMTP; the operator receives it and its link verifies'],
    ['P.smtp.custom_sender', '10', ['smtp', 'management'], 'custom SMTP is configured on the project and the received message came from the authorized sending domain', { needs: [...MGMT.needs, 'smtp_recipient', 'interactive'] }],
  ]),
  ...group('google', { needs: [...WRITE.needs, 'google_identity', 'interactive'], authorize: [...WRITE.authorize, 'interactive_sign_in'] }, [
    ['P.google.sign_in', '8', ['browser', 'auth', 'node'], 'one interactive Google sign-in (PKCE) with the authorized test identity; resolveSession reports provider google and the verified address'],
  ]),

  // Cleanup and residue: part of the verdict.
  ...group('cleanup', { needs: WRITE.needs, authorize: ['connect', 'create_users'] }, [
    ['C.users_deleted', 'setup', ['auth'], 'every user in the residue ledger is deleted, or reported'],
    ['C.catalog_restored', 'setup', ['management'], 'no widened grant or fault trigger remains; grant assertion empty', { needs: MGMT.needs }],
    ['C.rows_reported', 'setup', ['management'], 'remaining rows of this run (notes, kit rows of run clients) counted and reported', { needs: MGMT.needs }],
  ]),
]);

/** Cases whose non-hosted evidence comes from earlier lanes and are not rerun here. */
export const EARLIER_LANE_EVIDENCE = Object.freeze([
  { lld: 'L35', cases: '(e)-(i)', evidence: 'mocked admin API and fake clock (tests/server/mfa-reset.test.js) and SQL claim gates (tests/server/sql/mfa-reset.test.js, tests/sql/cases)', rerun: 'only when a concrete gap requires it' },
  { lld: 'L26', cases: 'all', evidence: 'unit and SQL (tests/core, tests/examples/sql)', rerun: 'not in the hosted brief; see README open questions' },
]);

/** Checks the inventory's own integrity; returns a list of problems. */
export function inventoryProblems(cases = CASES) {
  const problems = [];
  const ids = new Set();
  const actorIds = new Set(ACTORS.map((a) => a.id));
  for (const c of cases) {
    if (ids.has(c.id)) problems.push(`duplicate case ${c.id}`);
    ids.add(c.id);
    for (const n of c.needs) if (!Object.hasOwn(CAPABILITIES, n)) problems.push(`${c.id}: unknown capability ${n}`);
    for (const a of c.authorize) if (!Object.hasOwn(ACTION_CLASSES, a)) problems.push(`${c.id}: unknown action class ${a}`);
    if (typeof c.procedure !== 'string' || c.procedure === '') problems.push(`${c.id}: no procedure`);
  }
  for (const actor of MATRIX_ACTORS) if (!actorIds.has(actor.split('@')[0])) problems.push(`matrix actor ${actor} not in ACTORS`);
  return problems;
}

export function casesFor(procedure) {
  return CASES.filter((c) => c.procedure === procedure);
}

export { MATRIX_ACTORS, MATRIX_STATES };
