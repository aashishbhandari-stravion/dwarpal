// Expected outcomes stated from the design, independently of the code under
// test: the grant table of design 4.2 and the evaluation rule of 4.3. The
// harness compares hosted observations with these; it never derives an
// expectation from the migration's own assertion or from packages/core.

export const USER_WRAPPERS = Object.freeze(['ensure_profile', 'join_client', 'effective_access', 'grant_membership', 'revoke_membership']);
export const OPERATOR_WRAPPERS = Object.freeze(['register_client', 'apply_model', 'export_model', 'bootstrap_manager', 'revoke_manager',
  'mfa_reset_begin', 'mfa_reset_note', 'mfa_reset_finish']);
export const HELPER_WRAPPERS = Object.freeze(['has_permission', 'has_role', 'has_aal2']);
export const USER_IMPLS = Object.freeze(USER_WRAPPERS.map((n) => `${n}_impl`));
// has_aal2 has no private implementation (4.2).
export const HELPER_IMPLS = Object.freeze(['has_permission_impl', 'has_role_impl']);
export const ROLES = Object.freeze(['anon', 'authenticated', 'service_role']);

/** Design 4.2 grant table: may `role` EXECUTE `schema.name`? */
export function expectedExecute(schema, name, role) {
  if (role === 'service_role') return true;
  if (schema === 'auth_kit') {
    if (HELPER_WRAPPERS.includes(name)) return true;
    return role === 'authenticated' && USER_WRAPPERS.includes(name);
  }
  if (schema === 'auth_kit_private') return role === 'authenticated' && (USER_IMPLS.includes(name) || HELPER_IMPLS.includes(name));
  return false;
}

/** Every wrapper the exposed schema must contain. */
export const EXPOSED_FUNCTIONS = Object.freeze([...USER_WRAPPERS, ...OPERATOR_WRAPPERS, ...HELPER_WRAPPERS]);

/**
 * Design 4.3: a role is active when it needs no MFA or the session is aal2;
 * permissions are the union over active roles.
 * @param {{ roles: Record<string, { mfa_required?: boolean, manages_members?: boolean, permissions: string[] }> } | null} model
 * @param {string[]} held role keys the user holds
 * @param {'aal1' | 'aal2'} aal
 */
export function expectedAccess(model, held, aal) {
  const roles = model?.roles ?? {};
  const present = held.filter((r) => Object.hasOwn(roles, r)).sort();
  const active = present.filter((r) => roles[r].mfa_required !== true || aal === 'aal2');
  const permissions = [...new Set(active.flatMap((r) => roles[r].permissions))].sort();
  return { roles: present, activeRoles: active, permissions, mfaPending: active.length < present.length };
}

/** Code-unit order, the order the kit sorts keys in. */
export function sortKeys(list) {
  return [...list].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
}
