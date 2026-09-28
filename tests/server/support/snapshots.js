// Builds effective_access answers in the migration's wire shape (snake_case,
// UTF-16 code-unit order, active roles decided by the token's aal) for the
// scripted PostgREST handler in unit tests. The PostgreSQL-backed tests use
// the real function instead.

function compare(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * @param {string} clientId
 * @param {{ role: string, mfa?: boolean, manages?: boolean, selfAssignable?: boolean, permissions: string[], via?: string }[]} roles
 * @param {'aal1' | 'aal2'} aal
 */
export function accessSnapshot(clientId, roles, aal = 'aal1', { enrolledAt = '2026-01-01T00:00:00.000000Z' } = {}) {
  const rows = [...roles].sort((a, b) => compare(a.role, b.role)).map((r) => ({
    role_key: r.role,
    flags: { self_assignable: r.selfAssignable ?? false, manages_members: r.manages ?? false, mfa_required: r.mfa ?? false },
    granted_at: '2026-01-02T00:00:00.000000Z',
    granted_via: r.via ?? 'manager',
    permissions: [...r.permissions].sort(compare),
    active: !(r.mfa ?? false) || aal === 'aal2',
  }));
  const active = rows.filter((r) => r.active);
  return {
    client_id: clientId,
    enrolled_at: enrolledAt,
    memberships: rows.map(({ active: _, ...rest }) => rest),
    active_roles: active.map((r) => r.role_key),
    permissions: [...new Set(active.flatMap((r) => r.permissions))].sort(compare),
    mfa_pending: active.length < rows.length,
  };
}
