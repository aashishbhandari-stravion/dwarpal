#!/usr/bin/env node
// Starts the protected consumer on a loopback port.
//
//   SUPABASE_URL=... SUPABASE_PUBLISHABLE_KEY=... CLIENT_ID=protected-demo \
//   DATA_FILE=./records.sqlite PORT=8787 node server.js
//
// The server holds only the publishable key; it never sees a secret key.

import { createServer } from 'node:http';
import { AUTH_CONTRACT_VERSION, createAuthServer } from '@briqvent/dwarpal/server';
import { createApp } from './app.js';
import { createStore } from './store.js';

if (AUTH_CONTRACT_VERSION !== '0.5') throw new Error('this example was written for contract 0.5');

const need = (name) => {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
};

const auth = createAuthServer({
  supabaseUrl: need('SUPABASE_URL'),
  publishableKey: need('SUPABASE_PUBLISHABLE_KEY'),
  clientId: need('CLIENT_ID'),
});
const store = createStore(process.env.DATA_FILE ?? './records.sqlite');
const server = createServer(createApp({ auth, store }));
server.listen(Number(process.env.PORT ?? 8787), '127.0.0.1', () => {
  console.log(`protected consumer listening on http://127.0.0.1:${server.address().port}`);
});
process.on('SIGTERM', () => server.close(() => store.close()));
