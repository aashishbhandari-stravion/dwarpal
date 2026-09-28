// In-memory mirror of the three mfa_reset_* functions (migration section 6,
// design 4.2 table) for fast unit tests of the runner: fingerprint over the
// user only, 120 s lease, atomic takeover with a fresh token, token checked
// before state, one event per completed request. The PostgreSQL-backed
// suite runs the same scenarios against the real functions; where the two
// could differ, the real one is authoritative.

import { randomUUID } from 'node:crypto';
import { jsonResponse } from './fake-supabase.js';

function refuse(code) {
  return jsonResponse(400, { code: 'DW001', message: code, details: null, hint: null });
}

export function createMemoryMfa({ now = () => Date.now() } = {}) {
  const rows = new Map();
  const events = [];
  const state = { rows, events, now, calls: [] };

  state.handle = async ({ fn, args, actor }) => {
    state.calls.push(fn);
    if (actor.role !== 'service_role') return jsonResponse(403, { code: '42501', message: 'permission denied' });
    if (fn === 'mfa_reset_begin') {
      const row = rows.get(args.request_id);
      const t = state.now();
      if (!row) {
        const token = randomUUID();
        rows.set(args.request_id, { userId: args.user_id, state: 'pending', factorsSeen: null, token, startedAt: t, result: null });
        return jsonResponse(200, { outcome: 'proceed', run_token: token, factors_seen: null });
      }
      if (row.userId !== args.user_id) return refuse('request_conflict');
      if (row.state === 'completed') return jsonResponse(200, { outcome: 'completed', result: row.result });
      if (row.startedAt < t - 120_000) {
        row.token = randomUUID();
        row.startedAt = t;
        return jsonResponse(200, { outcome: 'resume', run_token: row.token, factors_seen: row.factorsSeen });
      }
      return refuse('request_in_progress');
    }
    if (fn === 'mfa_reset_note') {
      const row = rows.get(args.request_id);
      if (!row) return refuse('request_conflict');
      if (row.token !== args.run_token) return refuse('run_superseded');
      if (row.state === 'completed') return refuse('request_conflict');
      if (row.factorsSeen === null) row.factorsSeen = [...new Set(args.factor_ids)].sort();
      return jsonResponse(200, { factors_seen: row.factorsSeen });
    }
    if (fn === 'mfa_reset_finish') {
      const row = rows.get(args.request_id);
      if (!row) return refuse('request_conflict');
      if (row.token !== args.run_token) return refuse('run_superseded');
      if (row.state === 'completed') return jsonResponse(200, row.result);
      if (row.factorsSeen === null) return refuse('request_conflict');
      const deleted = [...new Set(args.factors_deleted)].sort();
      if (!deleted.every((id) => row.factorsSeen.includes(id))) return refuse('invalid_argument');
      row.result = { result: row.factorsSeen.length === 0 ? 'no_factors' : 'reset', factors_seen: row.factorsSeen, factors_deleted: deleted };
      row.state = 'completed';
      events.push({ requestId: args.request_id, token: row.token });
      return jsonResponse(200, row.result);
    }
    return jsonResponse(404, { code: 'PGRST202', message: 'unknown function' });
  };

  /** Moves the claim's start back, as the SQL gates do for lease expiry. */
  state.expire = (requestId, ms = 121_000) => {
    rows.get(requestId).startedAt -= ms;
  };

  return state;
}
