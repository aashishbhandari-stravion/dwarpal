// Case statuses and the rules that turn case records into a run verdict.
//
//   passed   executed against the authorized hosted target in `run` mode;
//            every assertion held and each one has an evidence reference
//   failed   executed and an assertion did not hold, the platform contradicted
//            the design, or the harness broke after hosted effects began
//   blocked  could not execute: an input, authorization, capability or an
//            earlier setup step is missing, or an outcome became unknown
//   not_run  not attempted in this run (not selected, or waiting for a
//            recorded disposition)
//
// Fail closed: a case with no record is not_run; a pass without hosted
// provenance is not_run (`not_hosted`); a pass without assertions or evidence
// is failed (`invalid_pass_record`). The run is `passed` only when every
// required case passed.

export const STATUSES = Object.freeze(['passed', 'failed', 'blocked', 'not_run']);
const STATUS_SET = new Set(STATUSES);
const REASON = /^[a-z][a-z0-9_]{0,63}$/;

export class Blocked extends Error {
  /** @param {string} reason fixed tag */
  constructor(reason, details = {}) {
    super(`blocked: ${reason}`);
    this.name = 'Blocked';
    this.reason = reason;
    this.details = details;
  }
}

/** Collects the assertions of one case; `verdict()` gives passed only if all held. */
export class CaseCheck {
  constructor(id) {
    this.id = id;
    this.assertions = [];
  }

  /**
   * @param {string} name what was asserted
   * @param {unknown} expected
   * @param {unknown} observed
   * @param {boolean} [ok] defaults to deep equality of expected and observed
   * @param {string | null} [evidence] reference to the evidence line
   */
  assert(name, expected, observed, ok = deepEqual(expected, observed), evidence = null) {
    this.assertions.push({ name, expected, observed, ok: ok === true, evidence });
    return ok === true;
  }

  get ok() {
    return this.assertions.length > 0 && this.assertions.every((a) => a.ok);
  }
}

export function deepEqual(a, b) {
  if (Object.is(a, b)) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== 'object') return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const ka = Object.keys(a);
  const kb = Object.keys(b);
  if (ka.length !== kb.length) return false;
  return ka.every((k) => Object.hasOwn(b, k) && deepEqual(a[k], b[k]));
}

/**
 * Normalises one emitted record. Anything malformed becomes a failed record:
 * a harness defect must never read as a pass or silently disappear.
 */
export function normaliseRecord(record, { hosted }) {
  const id = record?.id;
  if (typeof id !== 'string' || id === '') throw new TypeError('case record needs an id');
  if (!hosted) {
    // A rehearsal or any run without hosted provenance proves nothing about
    // the hosted target, whatever it observed; its own outcome is kept apart.
    const inner = normaliseRecord(record, { hosted: true });
    return { id, status: 'not_run', reason: 'not_hosted', hosted: false, assertions: inner.assertions, rehearsal: { status: inner.status, reason: inner.reason ?? null } };
  }
  if (!STATUS_SET.has(record.status)) return { id, status: 'failed', reason: 'invalid_status', hosted, assertions: [] };
  const reason = record.reason ?? null;
  if (reason !== null && !REASON.test(reason)) return { id, status: 'failed', reason: 'invalid_reason', hosted, assertions: [] };
  const assertions = Array.isArray(record.assertions) ? record.assertions : [];
  if (record.status === 'passed') {
    if (assertions.length === 0 || !assertions.every((a) => a.ok === true && typeof a.evidence === 'string' && a.evidence !== '')) {
      return { id, status: 'failed', reason: 'invalid_pass_record', hosted, assertions };
    }
  }
  if ((record.status === 'failed' || record.status === 'blocked' || record.status === 'not_run') && reason === null) {
    return { id, status: record.status, reason: record.status === 'failed' ? 'assertion_failed' : 'unspecified', hosted, assertions };
  }
  return { id, status: record.status, reason, hosted, assertions, ...(record.note ? { note: String(record.note) } : {}) };
}

/**
 * @param {{ id: string, required: boolean }[]} inventory
 * @param {Map<string, object>} records normalised, keyed by id
 */
export function summarise(inventory, records) {
  const counts = { passed: 0, failed: 0, blocked: 0, not_run: 0 };
  const cases = [];
  const unknown = [...records.keys()].filter((id) => !inventory.some((c) => c.id === id));
  for (const entry of inventory) {
    const record = records.get(entry.id) ?? { id: entry.id, status: 'not_run', reason: 'no_record', hosted: false, assertions: [] };
    counts[record.status] += 1;
    cases.push({ id: entry.id, required: entry.required, status: record.status, reason: record.reason ?? null });
  }
  const required = cases.filter((c) => c.required);
  let verdict;
  if (unknown.length > 0 || required.some((c) => c.status === 'failed')) verdict = 'failed';
  else if (required.length > 0 && required.every((c) => c.status === 'passed')) verdict = 'passed';
  else verdict = 'incomplete';
  return { verdict, counts, requiredCount: required.length, unknownRecords: unknown, cases };
}
