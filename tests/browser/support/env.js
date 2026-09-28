// SYNTHETIC TEST SUPPORT. A page environment for the controller outside a
// browser: an address bar with history.replaceState, Web Storage areas that
// can be shared between "tabs" or made to fail, and a navigation recorder.

import { createAuthController } from '../../../packages/browser/index.js';
import { ORIGIN, PUBLISHABLE_KEY, createScriptedSupabase } from './scripted-supabase.js';

export const SITE = 'https://site.example.test';
export const CLIENT_ID = 'studio';

export function baseConfig(overrides = {}) {
  return {
    clientId: CLIENT_ID,
    supabaseUrl: ORIGIN,
    publishableKey: PUBLISHABLE_KEY,
    origin: SITE,
    allowedReturnPaths: ['/app', '/app/orders'],
    defaultReturnPath: '/app',
    providers: { email: true, google: true },
    selfSignup: true,
    ...overrides,
  };
}

export class FakeStorage {
  #map = new Map();
  failSet = false;
  failRemove = false;

  get length() {
    return this.#map.size;
  }

  key(i) {
    return [...this.#map.keys()][i] ?? null;
  }

  getItem(key) {
    return this.#map.has(key) ? this.#map.get(key) : null;
  }

  setItem(key, value) {
    if (this.failSet && !key.endsWith('probe')) throw new DOMException('quota', 'QuotaExceededError');
    this.#map.set(key, String(value));
  }

  removeItem(key) {
    if (this.failRemove && !key.endsWith('probe')) throw new DOMException('denied', 'SecurityError');
    this.#map.delete(key);
  }

  keys() {
    return [...this.#map.keys()];
  }

  entries() {
    return [...this.#map.entries()];
  }
}

/** One browser tab. Tabs of one browser share `localStorage`, never `sessionStorage`. */
export function createTab(href, { localStorage = new FakeStorage(), sessionStorage = new FakeStorage() } = {}) {
  const tab = {
    href,
    replaced: [],
    navigations: [],
    localStorage,
    sessionStorage,
  };
  tab.env = {
    location: {
      get href() {
        return tab.href;
      },
    },
    history: {
      state: null,
      replaceState(_state, _title, url) {
        tab.href = new URL(url, tab.href).toString();
        tab.replaced.push(tab.href);
      },
    },
    localStorage,
    sessionStorage,
    navigate(url) {
      tab.navigations.push(url);
    },
  };
  return tab;
}

/** A fixture, a first tab at `path` and a started controller over the real supabase-js. */
export async function setup(path = '/account/sign-in', { fixture = createScriptedSupabase(), config = baseConfig(), tab, start = true, options = {} } = {}) {
  const page = tab ?? createTab(`${SITE}${path}`);
  const controller = openController(page, fixture, config, options);
  if (start) await controller.start();
  return { fixture, tab: page, controller, config };
}

export function openController(tab, fixture, config = baseConfig(), options = {}) {
  return createAuthController({
    config,
    env: tab.env,
    fetch: fixture.fetch,
    autoRefreshToken: false,
    requestTimeoutMs: 2000,
    ...options,
  });
}

/** A second page load (or tab) over the same browser storage. */
export function reopen(previous, path, { newTab = false } = {}) {
  return createTab(`${SITE}${path}`, {
    localStorage: previous.localStorage,
    sessionStorage: newTab ? new FakeStorage() : previous.sessionStorage,
  });
}

export const MODEL_ROLES = Object.freeze({
  member: { selfAssignable: true, permissions: ['orders:read:own'] },
  staff: { mfaRequired: true, permissions: ['orders:read:any'] },
  owner: { managesMembers: true, mfaRequired: true, permissions: ['members:manage'] },
});

/** A confirmed user signed in with a password through the controller. */
export async function signedIn(options = {}) {
  const fixture = options.fixture ?? createScriptedSupabase();
  if (!options.skipClient) fixture.seedClient({ clientId: CLIENT_ID, roles: MODEL_ROLES });
  const email = options.email ?? 'member@example.test';
  const userId = fixture.userIdOf(email) ?? fixture.seedUser({ email });
  const context = await setup(options.path ?? '/account/sign-in', { fixture, options: options.controller });
  await context.controller.signIn({ email, password: 'correct horse battery' });
  return { ...context, email, userId };
}
