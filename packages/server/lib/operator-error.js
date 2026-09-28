// Closed outcome set of the operator surface (design 4.1 error list plus the
// SQL refusal codes the operator wrappers raise). The consumer AuthError set
// is narrower and is never widened: operator-only codes live here. Messages
// are fixed per code and `details` carries only structural paths, rule
// names, counts, UUIDs and fixed tags, never peer text, keys, emails or model
// values.
//
// No message claims that nothing changed: a failure after a write was sent
// cannot know whether it committed. Such a failure is `outcome_unknown` and
// carries `details.recovery`, one of RECOVERY, naming the safe way to converge.

export const OPERATOR_ERROR_CODES = Object.freeze([
  // shared with the consumer set
  'config_invalid',
  'model_invalid',
  'request_conflict',
  'email_unverified',
  'unavailable',
  // SQL refusals of the operator wrappers
  'invalid_argument',
  'unknown_client',
  'unknown_role',
  'unknown_user',
  'not_manager_role',
  'last_manager',
  'model_refused',
  // bootstrap-manager lookup
  'ambiguous_user',
  'lookup_incomplete',
  // mfa-reset claim
  'request_in_progress',
  'run_superseded',
  'lease_expired',
  // transport and prerequisites
  'outcome_unknown',
  'prerequisite_missing',
  'migration_failed',
  'no_model',
]);

export const RECOVERY = Object.freeze([
  // the same request id returns the stored result or finishes the claimed run
  'rerun_same_request_id',
  // register-client is an upsert by client id: the same arguments converge
  'rerun_same_arguments',
  // an invitation may have been sent; a rerun invites only an unlisted address
  'rerun_lookup_before_invite',
  // migrate reads the installed versions first and applies only what is missing
  'rerun_migrate',
]);

const MESSAGES = Object.freeze({
  config_invalid: 'The operator configuration is invalid.',
  model_invalid: 'The permission model is invalid.',
  request_conflict: 'The request id was already used with a different payload.',
  email_unverified: 'The user has not confirmed their e-mail address.',
  unavailable: 'Supabase could not be reached or answered abnormally.',
  invalid_argument: 'The database refused an argument.',
  unknown_client: 'No client with this id is registered.',
  unknown_role: 'The client has no role with this key.',
  unknown_user: 'No confirmed user matches.',
  not_manager_role: 'The role does not manage members.',
  last_manager: 'The client would be left without a manager.',
  model_refused: 'The model change was refused.',
  ambiguous_user: 'More than one confirmed user matches; use --user-id.',
  lookup_incomplete: 'The user listing could not be read completely; use --user-id.',
  request_in_progress: 'Another run with this request id holds the claim; rerun with the same id after it ends.',
  run_superseded: 'This run was taken over after its lease expired and the database refused its record; rerun with the same id to see the outcome.',
  lease_expired: 'This run stopped before an admin call because its claim could have expired; rerun with the same id.',
  outcome_unknown: 'A write was sent but its outcome is unknown; it may have been applied.',
  prerequisite_missing: 'A required credential or input is missing.',
  migration_failed: 'The migration did not complete: the database refused a file, or a check before or after the files failed.',
  no_model: 'The client has no applied model.',
});

const CODE_SET = new Set(OPERATOR_ERROR_CODES);
const RECOVERY_SET = new Set(RECOVERY);

export class OperatorError extends Error {
  /**
   * @param {string} code one of OPERATOR_ERROR_CODES
   * @param {Record<string, unknown>} [details] bounded, already-sanitized fields
   */
  constructor(code, details) {
    if (!CODE_SET.has(code)) throw new TypeError('OperatorError code must be one of OPERATOR_ERROR_CODES.');
    const recovery = details?.recovery;
    if (code === 'outcome_unknown' ? !RECOVERY_SET.has(recovery) : recovery !== undefined && !RECOVERY_SET.has(recovery)) {
      throw new TypeError('OperatorError recovery must be one of RECOVERY, and outcome_unknown needs one.');
    }
    super(MESSAGES[code]);
    Object.defineProperties(this, {
      name: { value: 'OperatorError', enumerable: false },
      code: { value: code, enumerable: true },
      details: { value: Object.freeze(details ?? {}), enumerable: true },
    });
  }

  toJSON() {
    return { name: this.name, code: this.code, message: this.message, details: this.details };
  }
}

export function isOperatorError(value) {
  return value instanceof OperatorError;
}

/** The error a write step raises when its answer was lost or unreadable. */
export function outcomeUnknown(stage, reason, recovery) {
  return new OperatorError('outcome_unknown', { stage, reason, recovery });
}
