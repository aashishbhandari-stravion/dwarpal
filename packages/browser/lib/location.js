// Reads the current page address once, at start: which kit route it is, the
// requested return path, and any link or callback parameters. Secrets in the
// address (a PKCE code, an e-mail token hash, a provider error text, or tokens
// in a fragment) are removed from the address bar and history immediately and
// held in memory only; nothing is verified or exchanged by reading them.

import { resolveReturnPath } from '../../core/redirect.js';

const SECRET_PARAMS = ['code', 'token_hash', 'type', 'error', 'error_code', 'error_description', 'sb_flow_id'];
const LINK_TYPES = new Set(['email', 'recovery']);
const MAX_PARAM_LENGTH = 4096;

/**
 * @param {{ location: { href: string }, history: { state?: unknown, replaceState(state: unknown, title: string, url: string): void } }} env
 * @param {import('../../core/index.js').ValidatedClientConfig} config
 */
export function readLocation(env, config) {
  const url = new URL(env.location.href);
  const params = url.searchParams;
  const route = routeFor(url.pathname, config.routes);
  const nextValues = params.getAll('next');
  // A repeated `next` is ambiguous; the default is used instead of a guess.
  const next = nextValues.length === 1 ? resolveReturnPath(nextValues[0], config) : null;

  const hasLink = params.has('token_hash');
  const tokenHash = single(params, 'token_hash');
  const type = single(params, 'type');
  const code = single(params, 'code');
  const hasProviderError = params.has('error') || params.has('error_code') || params.has('error_description');
  const hash = new URLSearchParams(url.hash.startsWith('#') ? url.hash.slice(1) : '');
  const fragmentSecret = ['access_token', 'refresh_token', 'provider_token', 'error', 'error_description'].some((k) => hash.has(k));

  const present = SECRET_PARAMS.some((name) => params.has(name)) || fragmentSecret;
  if (present) {
    for (const name of SECRET_PARAMS) params.delete(name);
    if (fragmentSecret) url.hash = '';
    stripAddress(env, url);
  }

  return {
    route,
    next,
    stripped: present,
    // A link whose token or type is missing, repeated or unknown is kept as
    // an unusable link so the page can say so instead of ignoring it.
    link: hasLink ? { tokenHash, type: LINK_TYPES.has(type) ? type : null } : null,
    callback: route === 'callback' ? { code, providerError: hasProviderError || fragmentSecret } : null,
  };
}

/** The route name whose configured path equals `pathname` exactly, or null. */
export function routeFor(pathname, routes) {
  for (const [name, path] of Object.entries(routes)) {
    if (name !== 'prefix' && path === pathname) return name;
  }
  return null;
}

function single(params, name) {
  const values = params.getAll(name);
  if (values.length !== 1) return null;
  const value = values[0];
  return value.length > 0 && value.length <= MAX_PARAM_LENGTH ? value : null;
}

function stripAddress(env, url) {
  try {
    env.history.replaceState(env.history.state ?? null, '', `${url.pathname}${url.search}${url.hash}`);
  } catch {
    // A failed replaceState leaves the address as it was; the values are
    // still only used from memory, and nothing else depends on the strip.
  }
}
