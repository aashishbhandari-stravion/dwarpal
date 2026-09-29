// Preloaded (`node --import`) into an installed `auth-kit` run by
// scripts/check-package.mjs. It replaces `fetch` with an in-process stand-in for
// the one Management API endpoint `migrate` uses, so the installed CLI can read
// its packed SQL files and "apply" them without any network access. Any other
// URL fails as a network error. The stand-in accepts a migration only when the
// request body is byte-for-byte `begin;\n<file>\n;\ncommit;` for a file in
// FAKE_MANAGEMENT_DIR (the repository's own copy), and logs every request.
//
// Environment: FAKE_MANAGEMENT_LOG (file to append JSON lines to),
// FAKE_MANAGEMENT_DIR (reference migration directory), FAKE_MANAGEMENT_INSTALLED
// (optional JSON list of versions already installed).

import { appendFileSync, readFileSync, readdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';

const logFile = process.env.FAKE_MANAGEMENT_LOG;
const dir = process.env.FAKE_MANAGEMENT_DIR;
const reference = new Map(readdirSync(dir).filter((n) => n.endsWith('.sql')).map((name) => {
  const sql = readFileSync(join(dir, name), 'utf8');
  return [`begin;\n${sql}\n;\ncommit;`, name.slice(0, 14)];
}));
let installed = process.env.FAKE_MANAGEMENT_INSTALLED ? JSON.parse(process.env.FAKE_MANAGEMENT_INSTALLED) : null;

const log = (entry) => appendFileSync(logFile, `${JSON.stringify(entry)}\n`);
const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

globalThis.fetch = async (url, init = {}) => {
  const target = String(url);
  if (!/^https:\/\/api\.supabase\.com\/v1\/projects\/[a-z0-9]+\/database\/query$/.test(target) || init.method !== 'POST') {
    log({ kind: 'refused', url: target });
    throw new TypeError('network access is not available in this check');
  }
  const query = JSON.parse(init.body).query;
  // A migration file itself mentions the catalog it checks, so recognise it first and exactly.
  if (reference.has(query)) {
    const version = reference.get(query);
    log({ kind: 'migration', version, sha256: createHash('sha256').update(query).digest('hex') });
    installed = [...(installed ?? []), version];
    return json(200, []);
  }
  if (query.includes("to_regnamespace('auth_kit')")) {
    log({ kind: 'state' });
    const present = installed !== null;
    return json(200, [{ result: JSON.stringify({ kit: present, private: present, ledger: present }) }]);
  }
  if (query.includes('jsonb_agg(version')) {
    log({ kind: 'versions' });
    return json(200, [{ result: JSON.stringify(installed ?? []) }]);
  }
  if (query.includes('auth_kit_private.grant_violations()')) {
    log({ kind: 'grant_assertion' });
    return json(200, [{ result: '0' }]);
  }
  log({ kind: 'unexpected_sql', sha256: createHash('sha256').update(query).digest('hex') });
  return json(400, { message: 'unexpected statement' });
};
