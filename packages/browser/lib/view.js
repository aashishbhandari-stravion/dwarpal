// Builds the frozen view the controller publishes. Every field has one fixed
// default, so a view never carries a stale value from the previous one. The
// principal is shown only in states where the last pass produced it.

const PRINCIPAL_STATES = new Set(['signed_in', 'no_access', 'mfa_enrol']);
const WITHHELD_STATES = new Set(['signed_in', 'mfa_enrol']);

/**
 * @param {object} fields the state-specific fields
 * @param {{ principal: object | null, resendAt: number | null }} page
 */
export function composeView(fields, { principal, resendAt }) {
  const shown = PRINCIPAL_STATES.has(fields.state) ? principal : null;
  const withheld = shown && WITHHELD_STATES.has(fields.state)
    ? shown.access.roles.filter((role) => !shown.access.activeRoles.includes(role))
    : [];
  return Object.freeze({
    screen: fields.screen ?? null,
    state: fields.state,
    error: fields.error ?? null,
    setupReason: fields.setupReason ?? null,
    link: fields.link === true,
    recoveryPending: fields.recoveryPending === true,
    mfa: fields.mfa ? Object.freeze({ ...fields.mfa, enrolment: fields.mfa.enrolment ? Object.freeze({ ...fields.mfa.enrolment }) : null }) : null,
    principal: shown,
    withheldRoles: Object.freeze(withheld),
    next: fields.next ?? null,
    resendAvailableAt: resendAt,
    signOut: fields.signOut ? Object.freeze({ ...fields.signOut }) : null,
    canRetry: typeof fields.retry === 'function',
  });
}
