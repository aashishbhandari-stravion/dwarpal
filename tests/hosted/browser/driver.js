// Chromium for the browser flows (playwright-core, the repository's own
// development dependency). Each tab is a fresh browser context, so storage
// never leaks from one flow to the next. Every request the browser makes is
// checked against `admits(origin)` before it leaves: anything else is
// aborted and logged as blocked. Service workers are blocked.

/**
 * @param {{ chromium: import('playwright-core').BrowserType, sites: Record<string, { origin: string }>,
 *           admits: (origin: string) => boolean, onRequest: (entry: { method: string, url: string, status: number, blocked?: boolean }) => void,
 *           timeoutMs?: number }} options
 */
export async function createBrowser({ chromium, sites, admits, onRequest, timeoutMs = 30_000 }) {
  const browser = await chromium.launch();
  const contexts = new Set();

  async function tab(siteKey) {
    const site = sites[siteKey];
    if (!site) throw new Error(`unknown site ${siteKey}`);
    const context = await browser.newContext({ serviceWorkers: 'block' });
    context.setDefaultTimeout(timeoutMs);
    contexts.add(context);
    const errors = [];
    await context.route('**/*', async (route) => {
      const request = route.request();
      const url = request.url();
      let origin = null;
      try {
        origin = new URL(url).origin;
      } catch {
        origin = null;
      }
      if (origin === null || !admits(origin)) {
        onRequest({ method: request.method(), url: origin ?? 'about:blank', status: 0, blocked: true });
        return route.abort('blockedbyclient');
      }
      return route.continue();
    });
    context.on('requestfinished', async (request) => {
      const response = await request.response().catch(() => null);
      onRequest({ method: request.method(), url: request.url(), status: response?.status() ?? 0 });
    });
    context.on('requestfailed', (request) => {
      if (request.failure()?.errorText !== 'net::ERR_BLOCKED_BY_CLIENT') onRequest({ method: request.method(), url: request.url(), status: 0 });
    });
    context.on('page', (page) => page.on('pageerror', (error) => errors.push(String(error?.message ?? error).slice(0, 200))));
    return {
      async open(path) {
        const page = await context.newPage();
        await page.goto(`${site.origin}${path}`);
        await page.evaluate(() => window.__ready);
        return page;
      },
      errors: () => [...errors],
      async close() {
        contexts.delete(context);
        await context.close();
      },
    };
  }

  const keys = (page) => page.evaluate(() => [...Object.keys(localStorage), ...Object.keys(sessionStorage)].filter((key) => key.startsWith('dwarpal:')).sort());

  return {
    tab,
    view: (page) => page.evaluate(() => window.__view()),
    act: (page, method, input) => page.evaluate(({ method, input }) => window.__controller[method](input), { method, input }),
    kitKeys: keys,
    sessionKeys: async (page) => (await keys(page)).filter((key) => /:auth$/.test(key)),
    /** The browser session's access token, read from the kit's own storage key. */
    accessToken: (page) => page.evaluate(() => {
      const key = Object.keys(localStorage).find((k) => k.startsWith('dwarpal:') && k.endsWith(':auth'));
      try {
        return key ? JSON.parse(localStorage.getItem(key))?.access_token ?? null : null;
      } catch {
        return null;
      }
    }),
    async close() {
      for (const context of contexts) await context.close().catch(() => {});
      await browser.close();
    },
  };
}
