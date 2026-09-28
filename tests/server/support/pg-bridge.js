// Routes the fixture's PostgREST RPC and Management API answers into the
// real migration on the SQL harness's throwaway PostgreSQL cluster (run
// these suites through tests/sql/run.js). RPCs call the exposed auth_kit
// wrappers as the real database role with the request's JWT claims, the way
// PostgREST does; Management API queries run as the non-superuser `postgres`
// migration role. PostgreSQL's answers (values, SQLSTATEs, DETAIL) reach the
// library unchanged in PostgREST's error shape. PostgREST routing, schema
// exposure and JWT validation themselves are the fixture's, not hosted.

import { lit, jsonLit, arrayLit, PgError } from '../../sql/harness/db.js';
import { jsonResponse } from './fake-supabase.js';

// Exposed wrappers and their parameters (migration section 6).
const SIGNATURES = {
  ensure_profile: [],
  join_client: [['client_id', 'text']],
  effective_access: [['client_id', 'text']],
  grant_membership: [['user_id', 'uuid'], ['client_id', 'text'], ['role_key', 'text'], ['request_id', 'uuid']],
  revoke_membership: [['user_id', 'uuid'], ['client_id', 'text'], ['role_key', 'text'], ['request_id', 'uuid']],
  register_client: [['client_id', 'text'], ['display_name', 'text'], ['signup_policy', 'text']],
  apply_model: [['client_id', 'text'], ['model', 'jsonb'], ['request_id', 'uuid'], ['dry_run', 'boolean']],
  export_model: [['client_id', 'text']],
  bootstrap_manager: [['user_id', 'uuid'], ['client_id', 'text'], ['role_key', 'text'], ['request_id', 'uuid']],
  revoke_manager: [['user_id', 'uuid'], ['client_id', 'text'], ['role_key', 'text'], ['request_id', 'uuid']],
  mfa_reset_begin: [['user_id', 'uuid'], ['request_id', 'uuid']],
  mfa_reset_note: [['request_id', 'uuid'], ['run_token', 'uuid'], ['factor_ids', 'uuid[]']],
  mfa_reset_finish: [['request_id', 'uuid'], ['run_token', 'uuid'], ['factors_deleted', 'uuid[]']],
  has_permission: [['client_id', 'text'], ['permission_key', 'text']],
  has_role: [['client_id', 'text'], ['role_key', 'text']],
  has_aal2: [],
};

function sqlValue(value, type) {
  if (value === null || value === undefined) return `null::${type}`;
  if (type === 'jsonb') return jsonLit(JSON.stringify(value));
  if (type === 'uuid[]') {
    if (!Array.isArray(value)) throw new TypeError('array expected');
    return arrayLit(value, 'uuid');
  }
  if (type === 'boolean') {
    if (typeof value !== 'boolean') throw new TypeError('boolean expected');
    return lit(value);
  }
  if (typeof value !== 'string') throw new TypeError('string expected');
  return `${lit(value)}::${type}`;
}

function pgErrorResponse(error, actor) {
  const body = { code: error.code, message: error.message, details: error.detail ?? null, hint: error.hint ?? null };
  if (error.code === '42501') return jsonResponse(actor.role === 'anon' ? 401 : 403, body);
  if (error.code === 'DW001' || /^(22|23|P0)/.test(error.code)) return jsonResponse(400, body);
  return jsonResponse(500, body);
}

/** PostgREST-shaped RPC handler over TestDatabase `db`. */
export function pgRpc(db) {
  return async ({ fn, args, actor }) => {
    const signature = SIGNATURES[fn];
    if (!signature) return jsonResponse(404, { code: 'PGRST202', message: 'Could not find the function', details: null, hint: null });
    const known = new Map(signature);
    if (Object.keys(args).some((name) => !known.has(name))) {
      return jsonResponse(404, { code: 'PGRST202', message: 'Could not find the function with these parameters', details: null, hint: null });
    }
    let list;
    try {
      list = Object.entries(args).map(([name, value]) => `${name} => ${sqlValue(value, known.get(name))}`).join(', ');
    } catch {
      return jsonResponse(400, { code: '22P02', message: 'invalid input syntax', details: null, hint: null });
    }
    try {
      const value = await db.as({ role: actor.role, claims: actor.claims }, `select auth_kit.${fn}(${list})`);
      return jsonResponse(200, value);
    } catch (error) {
      if (error instanceof PgError) return pgErrorResponse(error, actor);
      throw error;
    }
  };
}

/** Management API database/query handler over TestDatabase `db`, as the migration role. */
export function pgManagement(db) {
  let connection = null;
  const handler = async (sql) => {
    connection ??= await db.connection('postgres');
    handler.queries.push(sql);
    try {
      const results = await connection.query(sql, { timeoutMs: 120_000 });
      const last = results.at(-1);
      return jsonResponse(201, last?.rows ?? []);
    } catch (error) {
      if (connection.txStatus !== 'I') await connection.query('rollback').catch(() => {});
      if (error instanceof PgError) return jsonResponse(400, { message: `Failed to run sql query: ERROR: ${error.code}: ${error.message}` });
      throw error;
    }
  };
  handler.queries = [];
  return handler;
}

/** Creates the same confirmed (or not) user in the fixture's Auth and in auth.users. */
export async function addUser(fake, db, { confirmed = true, email, password } = {}) {
  const id = fake.addUser({ confirmed, ...(email ? { email } : {}) });
  if (password) fake.users.get(id).password = password;
  await db.createUser({ id, email: fake.users.get(id).email, confirmed });
  return id;
}
