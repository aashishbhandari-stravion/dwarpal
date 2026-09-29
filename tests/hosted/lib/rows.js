// Consumer rows this harness writes on the target: notes (L25, L28 policy;
// inserted over PostgREST by their owner) and orders (L26; inserted by
// Management SQL). Every row's title starts with the run marker
// `hv<run> `, so a row whose insert committed but whose answer was lost is
// still found. Cleanup never assumes: it looks the run's rows up by marker,
// deletes them only with `cleanup_sql`, counts again, and marks a ledger
// entry removed only when that count is a known zero. An unreadable count is
// reported as unknown, never as zero.

import { textLiteral } from './sqlprobe.js';

export const ROW_TABLES = Object.freeze({ notes: 'app.notes', orders: 'app.orders' });

export function runMarker(runId) {
  return `hv${runId} `;
}

export function rowTitle(runId, alias) {
  return `${runMarker(runId)}${alias}`;
}

function matches(runId) {
  const marker = runMarker(runId);
  return `pg_catalog.left(title, ${marker.length}) = ${textLiteral(marker)}`;
}

/** The statements cleanup sends, exported so tests can answer them exactly. */
export const rowSql = Object.freeze({
  ids: (kind, runId) => `select coalesce(jsonb_agg(id order by id), '[]'::jsonb)::text as result from ${ROW_TABLES[kind]} where ${matches(runId)}`,
  remove: (kind, runId) => `delete from ${ROW_TABLES[kind]} where ${matches(runId)}`,
  count: (kind, runId) => `select pg_catalog.count(*)::text as result from ${ROW_TABLES[kind]} where ${matches(runId)}`,
});

/**
 * Finds, optionally deletes, and recounts this run's rows of one kind, and
 * settles the ledger entries of that kind.
 * @returns {Promise<{ kind: string, intents: number, knownIds: number, foundByMarker: number | null, recoveredByMarker: number | null,
 *                     deleted: boolean, remaining: number | null, reason: string | null }>}
 */
export async function settleRows(ctx, kind) {
  const entries = ctx.ledger.outstanding().filter((e) => e.kind === kind);
  const out = { kind, intents: entries.length, knownIds: 0, foundByMarker: null, recoveredByMarker: null, deleted: false, remaining: null, reason: null };
  if (entries.length === 0) {
    out.remaining = 0;
    return out;
  }
  const known = entries.filter((e) => Number.isInteger(e.rowId)).map((e) => e.rowId);
  out.knownIds = known.length;
  let found = null;
  try {
    const ids = await ctx.hosted.management.read(rowSql.ids(kind, ctx.runId));
    if (Array.isArray(ids) && ids.every(Number.isInteger)) found = ids;
  } catch {
    found = null;
  }
  if (found !== null) {
    out.foundByMarker = found.length;
    out.recoveredByMarker = found.filter((id) => !known.includes(id)).length;
    if (found.length > 0 && ctx.actions.has('cleanup_sql')) {
      try {
        await ctx.hosted.management.exec(rowSql.remove(kind, ctx.runId));
        out.deleted = true;
      } catch {
        out.reason = 'delete_failed';
      }
    }
    if (found.length === 0 || out.deleted || out.reason !== null) {
      try {
        out.remaining = Number(await ctx.hosted.management.read(rowSql.count(kind, ctx.runId)));
        if (!Number.isInteger(out.remaining)) out.remaining = null;
      } catch {
        out.remaining = null;
      }
    } else {
      out.remaining = found.length;
    }
  }
  if (out.remaining === 0) {
    for (const e of entries) ctx.ledger.removed(kind, e.key, { rowId: e.rowId ?? null, byMarker: true });
    return out;
  }
  out.reason ??= out.remaining === null ? 'unverified' : ctx.actions.has('cleanup_sql') ? 'rows_remain' : 'cleanup_sql_not_authorized';
  for (const e of entries) ctx.ledger.residue(kind, e.key, out.reason);
  return out;
}
