// The kit is generic: consumer-specific role keys, permission keys, brands and
// adapters exist only under examples/ (and in the design's prose). This scans
// the kit's shipped source and SQL for them.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../..', import.meta.url));
const SHIPPED = ['packages/core', 'packages/server', 'packages/browser', 'supabase/migrations'];
// Names and keys of the example deployments, and adapter-style vocabulary.
const CONSUMER_SPECIFIC = [
  /creditone/i,
  /example-?studio/i,
  /\b(?:orders|leads|contacts|documents):(?:read|create|update|cancel|reopen|grant|upload|download|review|assign|convert)/,
  /\b(?:leadsAdapter|ordersAdapter|customerLink|orderLink)\b/i,
];

async function files(dir) {
  const out = [];
  for (const entry of await readdir(join(root, dir), { recursive: true, withFileTypes: true })) {
    if (!entry.isFile() || entry.parentPath.includes('/dist')) continue;
    out.push(join(entry.parentPath, entry.name));
  }
  return out;
}

test('no consumer-specific name, key or adapter in the kit\'s shipped source or SQL', async () => {
  let scanned = 0;
  for (const dir of SHIPPED) {
    for (const file of await files(dir)) {
      const text = await readFile(file, 'utf8');
      scanned += 1;
      for (const pattern of CONSUMER_SPECIFIC) assert.ok(!pattern.test(text), `${file.slice(root.length)} matches ${pattern}`);
    }
  }
  assert.ok(scanned > 40, `scanned ${scanned} files`);
});

test('the kit stores no customer or record links of its own', async () => {
  const sql = await readFile(join(root, 'supabase/migrations', (await readdir(join(root, 'supabase/migrations'))).sort()[0]), 'utf8');
  const tables = [...sql.matchAll(/create table (?:if not exists )?([a-z_.]+)/g)].map((m) => m[1]);
  assert.ok(tables.length > 5);
  for (const table of tables) assert.ok(!/order|lead|customer|record|link/.test(table.split('.').pop()), `kit table ${table} looks consumer-specific`);
});
