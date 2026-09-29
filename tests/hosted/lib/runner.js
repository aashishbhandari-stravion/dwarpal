// Runs the case procedures in a fixed order and turns what they report into
// normalised case records. Fail closed at every step:
//
// - Before any procedure runs, each case is gated on its capabilities and
//   authorized action classes; a missing one is `blocked` with the reason,
//   an unselected case `not_run`.
// - Target prerequisites (T.*) run first; a procedure whose prerequisites did
//   not pass has its cases blocked with `target_<check>`.
// - A procedure that throws Blocked blocks every case it had not reported;
//   any other error fails them (`harness_error` or `hosted_<stage>`), with
//   the sanitised error in the evidence.
// - A case its procedure never reported is failed (`not_reported`): a
//   silent gap cannot read as a pass or a skip.

import { CASES } from './inventory.js';
import { Blocked, CaseCheck, normaliseRecord, summarise } from './status.js';
import { HostedError } from './hosted.js';

class RecordedCheck extends CaseCheck {
  constructor(id, evidence, procedure) {
    super(id);
    this.evidence = evidence;
    this.procedure = procedure;
  }

  assert(name, expected, observed, ok) {
    const held = ok === undefined ? undefined : ok === true;
    const probe = new CaseCheck(this.id);
    probe.assert(name, expected, observed, held);
    const verdict = probe.assertions[0].ok;
    const ref = this.evidence.observe(this.procedure, `${this.id}: ${name}`, { expected, observed, ok: verdict });
    return super.assert(name, expected, observed, verdict, ref);
  }
}

export function errorTag(error) {
  if (error instanceof HostedError) return `hosted_${error.stage}`.slice(0, 64);
  if (error?.name === 'OperatorError' && typeof error.code === 'string') return `operator_${error.code}`.slice(0, 64);
  return 'harness_error';
}

/**
 * @param {{ procedures: { id: string, group: string, requiresTargets?: string[], run: (ctx: object) => Promise<void> }[],
 *           ctx: object, selection: Set<string> | null, capabilities: Record<string, boolean>, actions: Set<string>,
 *           hosted: boolean, evidence: import('./evidence.js').Evidence, cases?: typeof CASES }} options
 */
export async function runProcedures({ procedures, ctx, selection, capabilities, actions, hosted, evidence, cases = CASES }) {
  const records = new Map();
  const byId = new Map(cases.map((c) => [c.id, c]));
  const record = (raw) => {
    if (!byId.has(raw.id)) throw new Error(`unknown case ${raw.id}`);
    if (records.has(raw.id)) throw new Error(`case ${raw.id} reported twice`);
    const normalised = normaliseRecord(raw, { hosted });
    records.set(raw.id, normalised);
    evidence.append('cases.jsonl', normalised);
  };

  // Target prerequisites and cleanup are never deselected: the first gate
  // everything else, the second must always account for residue.
  if (selection !== null) selection = new Set([...selection, ...cases.filter((c) => c.procedure === 'target' || c.procedure === 'cleanup').map((c) => c.id)]);

  // Static gating.
  for (const c of cases) {
    if (selection !== null && !selection.has(c.id)) record({ id: c.id, status: 'not_run', reason: 'not_selected' });
    else if (c.needs.some((n) => capabilities[n] !== true)) record({ id: c.id, status: 'blocked', reason: `missing_${c.needs.find((n) => capabilities[n] !== true)}` });
    else if (c.authorize.some((a) => !actions.has(a))) record({ id: c.id, status: 'blocked', reason: `not_authorized_${c.authorize.find((a) => !actions.has(a))}` });
  }

  const groupsLeft = new Map();
  for (const p of procedures) groupsLeft.set(p.group, (groupsLeft.get(p.group) ?? 0) + 1);
  const failedGroups = new Map();

  for (const procedure of procedures) {
    const groupCases = cases.filter((c) => c.procedure === procedure.group);
    const open = () => groupCases.filter((c) => !records.has(c.id));
    const unmet = (procedure.requiresTargets ?? []).find((t) => records.get(t)?.status !== 'passed' && records.get(t)?.rehearsal?.status !== 'passed');
    let skipped = false;
    if (failedGroups.has(procedure.group)) {
      skipped = true;
    } else if (unmet !== undefined) {
      for (const c of open()) record({ id: c.id, status: 'blocked', reason: `target_${unmet.replace(/\./g, '_').toLowerCase()}` });
      skipped = true;
    } else if (open().length > 0 || procedure.always === true) {
      const scoped = {
        ...ctx,
        procedure: procedure.id,
        wants: (id) => {
          if (!byId.has(id) || byId.get(id).procedure !== procedure.group) throw new Error(`${procedure.id} cannot report ${id}`);
          return !records.has(id);
        },
        check: (id) => new RecordedCheck(id, evidence, procedure.id),
        finish: (check) => record({ id: check.id, status: check.ok ? 'passed' : 'failed', reason: check.ok ? null : 'assertion_failed', assertions: check.assertions }),
        block: (id, reason) => record({ id, status: 'blocked', reason }),
        fail: (id, reason, note) => record({ id, status: 'failed', reason, note }),
        notRun: (id, reason, note) => record({ id, status: 'not_run', reason, note }),
        observe: (what, value) => evidence.observe(procedure.id, what, value),
      };
      try {
        await procedure.run(scoped);
      } catch (error) {
        const blocked = error instanceof Blocked;
        const reason = blocked ? error.reason : errorTag(error);
        evidence.observe(procedure.id, 'procedure_error', {
          name: error?.name ?? 'Error', reason, stage: error?.stage ?? error?.details?.stage ?? null, status: error?.status ?? null,
          code: error?.code ?? null, cause: error?.details?.reason ?? null, message: String(error?.message ?? '').slice(0, 500),
        });
        failedGroups.set(procedure.group, { blocked, reason });
        for (const c of open()) record({ id: c.id, status: blocked ? 'blocked' : 'failed', reason });
      }
    }
    groupsLeft.set(procedure.group, groupsLeft.get(procedure.group) - 1);
    if (groupsLeft.get(procedure.group) === 0 && !skipped) {
      for (const c of open()) record({ id: c.id, status: 'failed', reason: 'not_reported' });
    }
  }
  for (const c of cases) if (!records.has(c.id)) record({ id: c.id, status: 'failed', reason: 'not_reported' });
  return { records, summary: summarise(cases, records) };
}
