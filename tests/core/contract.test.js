import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import * as core from '@briqvent/dwarpal';
import * as testing from '@briqvent/dwarpal/testing';

const root = fileURLToPath(new URL('../../', import.meta.url));

export const CORE_EXPORTS = [
  'AAL_LEVELS', 'AUTH_CONTRACT_VERSION', 'AUTH_ERROR_CODES', 'AuthError', 'CLIENT_STATES', 'GRANTED_VIA',
  'PROVIDERS', 'ROLE_FLAGS', 'ROUTE_NAMES', 'can', 'canAll', 'canAny', 'canonicalJson', 'canonicalModelJson',
  'createPrincipal', 'explain', 'isAuthError', 'modelHash', 'planModelChange', 'requestFingerprint',
  'requireMfa', 'requirePermission', 'requireRole', 'resolveReturnPath', 'sha256Hex', 'validateClientConfig',
  'validateModel',
];
export const TESTING_EXPORTS = [
  'FIXTURE_CLIENT_ID', 'FIXTURE_MODEL', 'FIXTURE_OTHER_CLIENT_ID', 'FIXTURE_USER_IDS', 'fixturePrincipal', 'fixturePrincipals',
];

async function sourceFiles(dir) {
  const out = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...await sourceFiles(path));
    else out.push(path);
  }
  return out;
}

test('contract string is 0.5', () => {
  assert.equal(core.AUTH_CONTRACT_VERSION, '0.5');
});

test('entry points export exactly the implemented surface', () => {
  assert.deepEqual(Object.keys(core).sort(), CORE_EXPORTS);
  assert.deepEqual(Object.keys(testing).sort(), TESTING_EXPORTS);
});

test('core source is pure: no Node, network, storage or process access', async () => {
  const forbidden = [/from ['"]node:/, /\brequire\(/, /\bimport\(\s*['"](?!\.)/, /\bfetch\(/, /\bprocess\./, /\bXMLHttpRequest\b/, /\blocalStorage\b/, /\bsessionStorage\b/, /\bDate\.now\(/, /\bMath\.random\(/];
  for (const file of await sourceFiles(join(root, 'packages/core'))) {
    const text = await readFile(file, 'utf8');
    for (const pattern of forbidden) assert.ok(!pattern.test(text), `${relative(root, file)} matches ${pattern}`);
    for (const match of text.matchAll(/from ['"]([^'"]+)['"]/g)) {
      assert.ok(match[1].startsWith('.'), `${relative(root, file)} imports ${match[1]}`);
    }
  }
});

test('core carries no example-client names or keys', async () => {
  const words = [/creditone/i, /\borders:/, /\bleads:/, /\bdocuments:/, /\bcontacts:/, /\bmembers:manage\b/, /['"](admin|staff|customer)['"]/];
  for (const file of await sourceFiles(join(root, 'packages/core'))) {
    const text = await readFile(file, 'utf8');
    for (const pattern of words) assert.ok(!pattern.test(text), `${relative(root, file)} matches ${pattern}`);
  }
});
