// Runs the real auth-kit executable as a child process against the fixture
// served over loopback HTTP, and checks that no credential or e-mail marker
// reaches its output.

import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { SECRET_KEY, PUBLISHABLE_KEY, MANAGEMENT_TOKEN, PROJECT_REF } from '../server/support/fake-supabase.js';

const here = path.dirname(fileURLToPath(import.meta.url));
export const BIN = path.resolve(here, '../../packages/server/cli/auth-kit.js');

export const PROBE_PASSWORD = 'probe-password-MARKER-7e1';
const MARKERS = ['SECRETMARKER', 'MANAGEMENTMARKER', 'MARKER-7e1', 'SMTPSECRETMARKER', 'GOOGLESECRETMARKER'];

export function baseEnv(fake, { management = true, extra = {} } = {}) {
  const env = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    SUPABASE_URL: fake.origin,
    SUPABASE_SECRET_KEY: SECRET_KEY,
    SUPABASE_PUBLISHABLE_KEY: PUBLISHABLE_KEY,
    AUTH_KIT_PROBE_PASSWORD: PROBE_PASSWORD,
    ...extra,
  };
  if (management) Object.assign(env, { SUPABASE_ACCESS_TOKEN: MANAGEMENT_TOKEN, SUPABASE_PROJECT_REF: PROJECT_REF, SUPABASE_MANAGEMENT_API_URL: fake.origin });
  return env;
}

/**
 * @returns {Promise<{ code: number, stdout: string, stderr: string, json: any }>}
 */
export function runCli(args, { env, cwd, forbidden = [] } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [BIN, ...args], { env, cwd, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    const timer = setTimeout(() => child.kill('SIGKILL'), 60_000);
    child.on('error', reject);
    child.on('close', (code) => {
      clearTimeout(timer);
      for (const marker of [...MARKERS, ...forbidden]) {
        assert.ok(!stdout.includes(marker) && !stderr.includes(marker), `output leaked ${marker}:\n${stdout}\n${stderr}`);
      }
      let json;
      try {
        json = JSON.parse(stdout);
      } catch {
        json = undefined;
      }
      resolve({ code, stdout, stderr, json });
    });
  });
}
