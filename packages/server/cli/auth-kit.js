#!/usr/bin/env node
// auth-kit executable. All behavior is in main.js; this file only binds it
// to the process.

import { main } from './main.js';

const [major] = process.versions.node.split('.').map(Number);
if (major < 22) {
  process.stderr.write('auth-kit: Node.js 22 or later is required.\n');
  process.exitCode = 2;
} else {
  process.exitCode = await main(process.argv.slice(2), { env: process.env, stdout: process.stdout, stderr: process.stderr });
}
