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
  doctor_config: 'doctor.configFile in the target descriptor: a valid consumer config for this project (doctor --config; required for complete D1 catalog proof)',
  interactive: '--interactive on a terminal',
  chromium: 'the Chromium build playwright-core expects, installed locally (the hosted Playwright suite)',
});

// Clients the harness creates, per run: `<prefix>` is a fresh run prefix.
export const CLIENTS = Object.freeze({
  A: 'the example model (a copy of examples/creditone/auth-model.json under a run client id); matrix states S0, S1, S2',
  B: 'a second client with the same model: other-client actors and L31',
  D: 'L34 model: role `lead` manages members without MFA, role `chief` manages members with MFA',
  E: 'L27 enrollment client: self-assignable `member`, later a second self-assignable role',
  F: 'L29 registered client with no holders; L30 apply_model',
  G: 'L32 bootstrap target, registered only until the confirmed --user-id run',
  PW: 'browser flows: open client with a non-MFA manager role, an MFA-required staff role and a self-assignable member',
  PWC: 'browser flows: the same model, invite-only (closed signup)',
  PWN: 'browser flows: registered with no model (no self-assignable role)',
  RLS: 'the fixed client `rls-demo` of examples/rls-consumer (its policies name it); shared across runs',
  ORD: 'the fixed client `orders-demo` of the L26 fixture tests/hosted/fixtures/orders-consumer (its policy names it); shared across runs',
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
  { id: 'lookup_email', kind: 'L32: unique confirmed --email match' },
  { id: 'l34_t1', kind: 'D: grant target of U1' },
  { id: 'l34_t2', kind: 'D: grant target of U2' },
  { id: 'l34_t3', kind: 'D: grant target of U3 and of the non-manager' },
  { id: 'totp_user', kind: 'D: chief (MFA role); TOTP enrol, challenge, verify and self-unenrol' },
  { id: 'ord_manager', kind: 'orders-demo manager (MFA), TOTP factor, aal2; grants staff (L26)' },
  { id: 'ord_customer', kind: 'orders-demo customer (join) and staff (manager grant), TOTP factor; aal1 and aal2 (L26)' },
  { id: 'ord_other', kind: 'orders-demo customer who owns the other order (L26)' },
  { id: 'pw_manager', kind: 'PW keeper (bootstrap, no MFA): grants and revokes for the browser flows' },
  { id: 'pw_member', kind: 'PW member: browser sign-in, return path, failures and sign-out' },
  { id: 'pw_closed', kind: 'signs in on the invite-only client PWC in the browser: no_access' },
  { id: 'pw_nodefault', kind: 'signs in on PWN (no model) in the browser: setup_pending' },
  { id: 'pw_revoked', kind: 'PW member whose membership a manager revokes; browser shows no_access' },
  { id: 'pw_mfa', kind: 'PW member and staff (MFA): browser TOTP enrolment, then a challenge' },
  { id: 'pw_verify', kind: 'unconfirmed user from an admin-generated signup link, confirmed in the browser' },
  { id: 'pw_recover', kind: 'confirmed user who resets the password from an admin-generated recovery link in the browser' },
  { id: 'pw_nobody', kind: 'an address with no user: the browser sign-in failure is neutral' },
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
    ['T.orders_consumer', 'L26', ['management'], 'the L26 fixture installed: app.orders, forced RLS, the own/any orders_select policy on orders-demo, SELECT only for authenticated, nothing for anon', { needs: MGMT.needs }],
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

  // L26 own/any order guard on the Node path and the RLS path, at aal1 and aal2 (4.3, S4, S4b).
  ...group('orders', { needs: MGMT.needs, authorize: [...WRITE.authorize, 'totp'] }, [
    ['L26.aal1.node', 'L26', ['node'], 'customer + MFA-pending staff at aal1, Node guard: another customer\'s order 403 forbidden with staff withheld; own order 200'],
    ['L26.aal1.rls', 'L26', ['postgrest'], 'the same token through the orders RLS policy: another customer\'s order zero rows; own order the row'],
    ['L26.aal2.node', 'L26', ['node'], 'after aal2, Node guard: both orders 200'],
    ['L26.aal2.rls', 'L26', ['postgrest'], 'after aal2, RLS policy: both orders visible'],
    ['L26.absent_and_anon', 'L26', ['node', 'postgrest'], 'an absent order is 404 and no token is 401 on the Node path; anon is refused on the direct path'],
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
    ['L32.lookup_incomplete', 'L32', ['auth'], 'listing with page size 1 and cap 2 over three or more users: lookup_incomplete, nothing written, --user-id named'],
    ['L32.user_id_unconfirmed', 'L32', ['cli'], '--user-id of an unconfirmed user: email_unverified, nothing written'],
    ['L32.user_id_confirmed', 'L32', ['cli', 'sql'], '--user-id of a confirmed user: granted, client state live'],
    ['L32.email_unique_match', 'L32', ['cli'], '--email with exactly one confirmed match: granted'],
  ].map((row) => [...row.slice(0, 4), { needs: MGMT.needs, ...(row[4] ?? {}) }])),

  // L33 doctor modes (D1 amendment A).
  ...group('doctor', { needs: WRITE.needs, authorize: WRITE.authorize }, [
    ['L33.secret_only_incomplete', 'L33', ['cli'], 'secret key only: privileged catalog checks not_run, overall incomplete (exit 5); public signing-key check runs'],
    ['L33.catalog_ok', 'L33', ['cli', 'management'], 'with the Management token and the consumer config: grants, schema, memberships, exposed schemas, redirect allow-list and client registration all ran and passed', { needs: [...MGMT.needs, 'doctor_config'] }],
    ['L33.probe_mode', 'L33', ['cli', 'postgrest'], '--probe with a disposable user: anon and authenticated outcomes in a separate probe mode', { needs: MGMT.needs }],
    ['L33.catalog_detects_widening', 'L33', ['cli', 'management'], 'a deliberately widened grant is reported by complete catalog mode', { needs: [...MGMT.needs, 'doctor_config'], authorize: [...WRITE.authorize, 'catalog_mutation'] }],
    ['L33.probe_detects_widening', 'L33', ['cli', 'postgrest'], 'a probe-observable widened grant is reported by probe mode', { needs: MGMT.needs, authorize: [...WRITE.authorize, 'catalog_mutation'] }],
    ['L33.widening_reverted', 'L33', ['management'], 'every widened grant is revoked; the grant assertion is empty and complete catalog mode is ok again', { needs: [...MGMT.needs, 'doctor_config'], authorize: [...WRITE.authorize, 'catalog_mutation'] }],
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

  // The hosted Playwright suite: the browser kit in Chromium against the target (design 8).
  ...group('browser', { needs: [...WRITE.needs, 'chromium'], authorize: [...WRITE.authorize, 'totp'] }, [
    ['PW.sign_in_redirect', '7', ['browser', 'auth', 'postgrest'], 'browser sign-in joins once; an external return path falls back to the default, an allowed one is kept'],
    ['PW.sign_in_failures', '7', ['browser', 'auth'], 'wrong password and unknown address: the same invalid_credentials; no session stored'],
    ['PW.enrollment_states', 'L27', ['browser', 'postgrest'], 'invite-only client: no_access; client without a self-assignable role: setup_pending with a retry'],
    ['PW.revoked_no_access', 'L27', ['browser', 'postgrest'], 'after a manager revoke, a new browser sign-in shows no_access and re-grants nothing'],
    ['PW.mfa', '10', ['browser', 'auth'], 'MFA role withheld at aal1; TOTP enrolment in the browser reaches aal2; the next sign-in is challenged and passes'],
    ['PW.verify_link', '7', ['browser', 'auth'], 'a signup link: stripped from the address bar, not consumed by loading, confirmed by one click; reopened it is expired_link'],
    ['PW.recovery', '7', ['browser', 'auth'], 'a recovery link: reset pending (a second tab stays confined), new password set, old refused, new accepted'],
    ['PW.sign_out', '5.12', ['browser', 'auth', 'node'], 'browser sign-out clears every kit key and the Node path refuses the signed-out token on the next request'],
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
    ['C.rows_reported', 'setup', ['management'], 'remaining rows of this run counted and reported: notes and orders by run marker whatever the ledger holds, kit rows of run clients; an unknown count fails', { needs: MGMT.needs }],
  ]),
]);

/** Cases whose non-hosted evidence comes from earlier lanes and are not rerun here. */
export const EARLIER_LANE_EVIDENCE = Object.freeze([
  { lld: 'L35', cases: '(e)-(i)', evidence: 'mocked admin API and fake clock (tests/server/mfa-reset.test.js) and SQL claim gates (tests/server/sql/mfa-reset.test.js, tests/sql/cases)', rerun: 'only when a concrete gap requires it' },
  // The owner's L32 disposition (2026-09-29): two confirmed users with one address is not a valid hosted Supabase state,
  // so it is neither created nor counted here; the refusal stays a defensive unit/CLI test with an injected listing.
  { lld: 'L32', cases: 'ambiguous_user (two confirmed matches)', evidence: 'injected duplicate admin listing (tests/cli/cli.test.js, tests/server/operator.test.js)', rerun: 'never on a hosted project; unit/CLI evidence, not hosted proof' },
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
