// Operator MFA reset: reserve, then act, under one claim (design 4.1, G1/G4).
//
//   begin ─▶ completed: the stored result; no Auth call at all
//         ─▶ proceed / resume (run token)
//               ─▶ [no recorded list] check deadline, listFactors, note (records once)
//               ─▶ for each recorded factor: check deadline, deleteFactor (not-found = deleted)
//               ─▶ finish with the token and the deleted list
//
// The claim is bound in SQL before Auth is touched, so a replay, a changed
// target or a concurrent run is refused there (request_conflict /
// request_in_progress) with zero admin calls. Every admin call has its own
// abort deadline (admin.js), and before each one the runner requires its
// claim to be younger than 100 s (the 120 s lease minus the 20 s call
// timeout), measured on its own monotonic clock from just before it sent
// begin; begin's claim time is taken later, after the database locks, so the
// runner's age never understates the lease's. Past the deadline the runner
// stops with lease_expired and the row stays pending with its recorded list.
// A superseded runner's note and finish are refused by SQL (run_superseded)
// and surface as that error, never as a stored success.

import { UUID_PATTERN } from '../../core/shape.js';
import { OperatorError } from './operator-error.js';

export const CLAIM_DEADLINE_MS = 100_000;
const RESULTS = new Set(['reset', 'no_factors']);

function isUuidList(value) {
  return Array.isArray(value) && value.length <= 1000 && value.every((id) => typeof id === 'string' && UUID_PATTERN.test(id));
}

function malformed(stage) {
  return new OperatorError('unavailable', { stage, reason: 'malformed' });
}

function readStoredResult(stage, value) {
  const keys = ['result', 'factors_seen', 'factors_deleted'];
  if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).length !== keys.length
      || !keys.every((key) => Object.hasOwn(value, key)) || !RESULTS.has(value.result)
      || !isUuidList(value.factors_seen) || !isUuidList(value.factors_deleted)) {
    throw malformed(stage);
  }
  return Object.freeze({
    result: value.result,
    factorsSeen: Object.freeze(value.factors_seen.map((id) => id.toLowerCase())),
    factorsDeleted: Object.freeze(value.factors_deleted.map((id) => id.toLowerCase())),
  });
}

function readBegin(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw malformed('mfa_reset_begin');
  if (value.outcome === 'completed' && Object.keys(value).length === 2 && Object.hasOwn(value, 'result')) {
    return { outcome: 'completed', result: readStoredResult('mfa_reset_begin', value.result) };
  }
  const keys = ['outcome', 'run_token', 'factors_seen'];
  const ok = (value.outcome === 'proceed' || value.outcome === 'resume') && Object.keys(value).length === keys.length
    && keys.every((key) => Object.hasOwn(value, key)) && typeof value.run_token === 'string' && UUID_PATTERN.test(value.run_token)
    && (value.factors_seen === null || isUuidList(value.factors_seen))
    && !(value.outcome === 'proceed' && value.factors_seen !== null);
  if (!ok) throw malformed('mfa_reset_begin');
  return {
    outcome: value.outcome,
    token: value.run_token,
    recorded: value.factors_seen === null ? null : value.factors_seen.map((id) => id.toLowerCase()),
  };
}

/**
 * @param {{ userId: string, requestId: string }} input lower-case UUIDs
 * @param {{ rpcWrite: (fn: string, args: object) => Promise<unknown>,
 *           admin: { listFactors(userId: string): Promise<string[]>, deleteFactor(userId: string, id: string): Promise<'deleted' | 'not_found'> },
 *           monotonicNow: () => number, deadlineMs?: number }} deps
 */
export async function runMfaReset({ userId, requestId }, deps) {
  const deadlineMs = deps.deadlineMs ?? CLAIM_DEADLINE_MS;
  const sentAt = deps.monotonicNow();
  const beforeAdminCall = (stage) => {
    const age = deps.monotonicNow() - sentAt;
    if (!(age < deadlineMs)) throw new OperatorError('lease_expired', { stage, claimAgeMs: Math.floor(age) });
  };

  const begin = readBegin(await deps.rpcWrite('mfa_reset_begin', { user_id: userId, request_id: requestId }));
  if (begin.outcome === 'completed') {
    return Object.freeze({ outcome: 'completed', replayed: true, ...begin.result });
  }

  let recorded = begin.recorded;
  if (recorded === null) {
    beforeAdminCall('list_factors');
    const listed = await deps.admin.listFactors(userId);
    const noted = await deps.rpcWrite('mfa_reset_note', { request_id: requestId, run_token: begin.token, factor_ids: listed });
    if (noted === null || typeof noted !== 'object' || Object.keys(noted).length !== 1 || !isUuidList(noted.factors_seen)) {
      throw malformed('mfa_reset_note');
    }
    // The recorded list is authoritative: a resumed row keeps its original list.
    recorded = noted.factors_seen.map((id) => id.toLowerCase());
  }

  const deleted = [];
  for (const factorId of recorded) {
    beforeAdminCall('delete_factor');
    await deps.admin.deleteFactor(userId, factorId);
    deleted.push(factorId);
  }

  const finished = readStoredResult('mfa_reset_finish',
    await deps.rpcWrite('mfa_reset_finish', { request_id: requestId, run_token: begin.token, factors_deleted: deleted }));
  const sorted = [...recorded].sort();
  if (finished.factorsSeen.length !== sorted.length || finished.factorsSeen.some((id, index) => id !== sorted[index])) {
    throw new OperatorError('unavailable', { stage: 'mfa_reset_finish', reason: 'inconsistent_result' });
  }
  return Object.freeze({ outcome: begin.outcome, replayed: false, ...finished });
}
