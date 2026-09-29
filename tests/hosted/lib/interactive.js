// Operator interaction for the cases a human must complete: pasting a
// received confirmation link, naming the sender's domain, and a Google
// sign-in in a browser. Prompts go to stderr; answers are read from the
// terminal and never written anywhere. Without a terminal the cases are
// blocked, never guessed.

import http from 'node:http';
import readline from 'node:readline';
import { Blocked } from './status.js';

export function createPrompter({ input = process.stdin, output = process.stderr, enabled = false } = {}) {
  return {
    enabled: enabled && input.isTTY === true,
    say(text) {
      output.write(`[hosted] ${text}\n`);
    },
    async ask(question, { timeoutMs = 15 * 60_000 } = {}) {
      if (!this.enabled) throw new Blocked('interactive_unavailable');
      const rl = readline.createInterface({ input, output, terminal: true });
      try {
        return await new Promise((resolve, reject) => {
          const timer = setTimeout(() => reject(new Blocked('interactive_timeout')), timeoutMs);
          rl.question(`[hosted] ${question} `, (answer) => {
            clearTimeout(timer);
            resolve(answer.trim());
          });
        });
      } finally {
        rl.close();
      }
    },
  };
}

/**
 * Waits for one OAuth redirect to http://localhost:<port><path>. Listens on
 * both loopback addresses because browsers resolve localhost either way.
 * @returns {Promise<URLSearchParams>}
 */
export function awaitCallback(port, path, { timeoutMs = 10 * 60_000 } = {}) {
  const servers = [];
  const done = new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Blocked('callback_timeout')), timeoutMs);
    const handler = (req, res) => {
      const url = new URL(req.url, `http://localhost:${port}`);
      if (url.pathname !== path) {
        res.writeHead(404).end();
        return;
      }
      res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' });
      res.end('Sign-in received by the hosted harness. You can close this tab.\n');
      clearTimeout(timer);
      resolve(url.searchParams);
    };
    for (const host of ['127.0.0.1', '::1']) {
      const server = http.createServer(handler);
      server.on('error', () => {});
      server.listen(port, host);
      servers.push(server);
    }
  });
  return done.finally(() => {
    for (const s of servers) s.close();
  });
}
