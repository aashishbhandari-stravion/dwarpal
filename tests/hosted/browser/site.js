// The consumer page the hosted Playwright suite drives: the browser kit's
// prebuilt bundle (packages/browser/dist, the asset the package ships) served
// from a loopback origin, one site per client, with a CSP that lets the page
// reach only the project it is configured for. The page exposes the
// controller so a flow can act and read its view; nothing else is added.

import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const RETURN_PATHS = Object.freeze(['/app', '/app/orders']);
export const DEFAULT_RETURN = '/app';
export const ASSETS_DIR = fileURLToPath(new URL('../../../packages/browser/dist/', import.meta.url));

/**
 * @param {{ assetsDir?: string, clientId: string, supabaseUrl: string, publishableKey: string, selfSignup: boolean }} options
 * @returns {Promise<{ origin: string, close: () => Promise<void> }>}
 */
export function startSite({ assetsDir = ASSETS_DIR, clientId, supabaseUrl, publishableKey, selfSignup }) {
  let origin = null;
  const server = createServer((req, res) => {
    serve(req, res).catch(() => {
      if (!res.headersSent) res.writeHead(500);
      res.end();
    });
  });
  const send = (res, type, body) => {
    res.writeHead(200, {
      'content-type': type,
      'cache-control': 'no-store',
      'content-security-policy': `default-src 'none'; script-src 'self'; style-src 'self'; connect-src ${supabaseUrl}; img-src 'self' data:; base-uri 'none'; form-action 'self'`,
      'referrer-policy': 'no-referrer',
    });
    res.end(body);
  };
  async function serve(req, res) {
    const url = new URL(req.url, origin);
    if (url.pathname === '/bundle.js') return send(res, 'text/javascript', await readFile(join(assetsDir, 'dwarpal-browser.js')));
    if (url.pathname === '/bundle.css') return send(res, 'text/css', await readFile(join(assetsDir, 'dwarpal-browser.css')));
    if (url.pathname === '/config.js') {
      return send(res, 'text/javascript', `export default ${JSON.stringify({
        clientId, supabaseUrl, publishableKey, origin, allowedReturnPaths: RETURN_PATHS, defaultReturnPath: DEFAULT_RETURN,
        providers: { email: true, google: false }, selfSignup,
      })};`);
    }
    if (url.pathname === '/boot.js') {
      return send(res, 'text/javascript', [
        "import { createAuthController, mountAuthScreens } from '/bundle.js';",
        "import config from '/config.js';",
        'const controller = createAuthController({ config, autoNavigate: false });',
        "mountAuthScreens(document.getElementById('auth'), controller);",
        'window.__controller = controller;',
        'window.__view = () => controller.getView();',
        'window.__ready = controller.start();',
      ].join('\n'));
    }
    return send(res, 'text/html', '<!doctype html><title>Hosted check</title><link rel="stylesheet" href="/bundle.css"><script type="module" src="/boot.js"></script><main id="auth"></main>');
  }
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      origin = `http://127.0.0.1:${server.address().port}`;
      resolve({
        origin,
        close: () => new Promise((done) => {
          server.closeAllConnections();
          server.close(() => done());
        }),
      });
    });
  });
}
