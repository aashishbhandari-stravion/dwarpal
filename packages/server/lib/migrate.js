// `migrate` over the Management API (design 9 step 2). Each numbered file
// runs as one explicit transaction and records its version in
// auth_kit_private.migrations; the installed versions are read first, so a
// rerun after a lost answer applies only what is missing instead of failing
// on the migration's own "already installed" guard. A partial or
// out-of-order installation is refused rather than guessed at. After the
// files, the grant assertion is re-run and must be empty.

import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { OperatorError } from './operator-error.js';
import { jsonResult } from './management.js';

const FILE_PATTERN = /^(\d{14})_([a-z0-9_]+)\.sql$/;
const MIGRATION_TIMEOUT_MS = 120_000;

/** The repository's migration directory; absent from a package that does not ship SQL. */
export const DEFAULT_MIGRATIONS_DIR = fileURLToPath(new URL('../../../supabase/migrations/', import.meta.url));

/**
 * @returns {{ version: string, name: string, file: string, sql: string, sha256: string }[]}
 */
export function readMigrations(dir) {
  let names;
  try {
    names = fs.readdirSync(dir);
  } catch {
    throw new OperatorError('prerequisite_missing', { stage: 'migration_files', reason: 'directory_unreadable' });
  }
  const files = names.filter((name) => FILE_PATTERN.test(name)).sort();
  if (files.length === 0) throw new OperatorError('prerequisite_missing', { stage: 'migration_files', reason: 'no_migration_files' });
  return files.map((name) => {
    const [, version, base] = FILE_PATTERN.exec(name);
    let bytes;
    try {
      bytes = fs.readFileSync(path.join(dir, name));
    } catch {
      throw new OperatorError('prerequisite_missing', { stage: 'migration_files', reason: 'file_unreadable' });
    }
    return { version, name: base, file: name, sql: bytes.toString('utf8'), sha256: createHash('sha256').update(bytes).digest('hex') };
  });
}

const STATE_SQL = `select jsonb_build_object(
  'kit', pg_catalog.to_regnamespace('auth_kit') is not null,
  'private', pg_catalog.to_regnamespace('auth_kit_private') is not null,
  'ledger', pg_catalog.to_regclass('auth_kit_private.migrations') is not null)::text as result`;
const VERSIONS_SQL = `select coalesce(jsonb_agg(version order by version), '[]'::jsonb)::text as result
  from auth_kit_private.migrations`;
const VIOLATIONS_SQL = `select pg_catalog.count(*)::text as result from auth_kit_private.grant_violations()`;

/** Installed migration versions, or null when the kit is not installed at all. */
export async function installedVersions(management) {
  const state = jsonResult('migration_state', await management.query(STATE_SQL, { stage: 'migration_state' }));
  if (!state.kit && !state.private && !state.ledger) return null;
  if (!state.ledger) throw new OperatorError('migration_failed', { stage: 'migration_state', reason: 'partial_install' });
  const versions = jsonResult('migration_state', await management.query(VERSIONS_SQL, { stage: 'migration_state' }));
  if (!Array.isArray(versions) || !versions.every((v) => typeof v === 'string')) {
    throw new OperatorError('unavailable', { stage: 'migration_state', reason: 'malformed' });
  }
  return versions;
}

/**
 * @returns {Promise<{ applied: { version: string, sha256: string }[], alreadyInstalled: string[], unknownInstalled: string[] }>}
 */
export async function migrate(management, migrations) {
  const installed = (await installedVersions(management)) ?? [];
  const known = new Set(migrations.map((m) => m.version));
  const pending = migrations.filter((m) => !installed.includes(m.version));
  // A pending file older than an installed one would run against a schema
  // it was not written for.
  const newestInstalled = installed.filter((v) => known.has(v)).sort().at(-1);
  if (pending.length > 0 && newestInstalled !== undefined && pending[0].version < newestInstalled) {
    throw new OperatorError('migration_failed', { stage: 'migration_state', reason: 'out_of_order' });
  }
  const applied = [];
  for (const migration of pending) {
    await management.query(`begin;\n${migration.sql}\n;\ncommit;`, { stage: `migration_${migration.version}`, write: true, callTimeoutMs: MIGRATION_TIMEOUT_MS });
    const now = await installedVersions(management);
    if (now === null || !now.includes(migration.version)) {
      throw new OperatorError('migration_failed', { stage: `migration_${migration.version}`, reason: 'version_not_recorded' });
    }
    applied.push({ version: migration.version, sha256: migration.sha256 });
  }
  const violations = Number(jsonResult('grant_assertion', await management.query(VIOLATIONS_SQL, { stage: 'grant_assertion' })));
  if (violations !== 0) throw new OperatorError('migration_failed', { stage: 'grant_assertion', reason: 'grant_violations', count: violations });
  return {
    applied,
    alreadyInstalled: installed.filter((v) => known.has(v)),
    unknownInstalled: installed.filter((v) => !known.has(v)),
  };
}
