// Client configuration validation. The config reaches the browser, so it must
// hold only public values; a secret key placed here is refused before it can
// be bundled.

import { AuthError } from './errors.js';
import { isSafeConfiguredPath } from './redirect.js';
import {
  isPlainObject,
  isOpaqueKey,
  isDenseArray,
  own,
  sortedKeys,
  memberPath,
  extraKeyPositions,
  deepFreeze,
} from './shape.js';

export const ROUTE_NAMES = Object.freeze(['signIn', 'signUp', 'verify', 'callback', 'forgot', 'reset', 'mfa', 'signOut']);

const DEFAULT_PREFIX = '/account';
const DEFAULT_ROUTES = Object.freeze({
  signIn: 'sign-in',
  signUp: 'sign-up',
  verify: 'verify',
  callback: 'callback',
  forgot: 'forgot',
  reset: 'reset',
  mfa: 'mfa',
  signOut: 'sign-out',
});
const CONFIG_FIELDS = [
  'clientId', 'supabaseUrl', 'publishableKey', 'routes', 'origin', 'allowedReturnPaths',
  'defaultReturnPath', 'providers', 'session', 'brand', 'copy', 'selfSignup',
];
const FIELD_PATTERN = /^[A-Za-z][A-Za-z0-9]{0,31}$/;
const COPY_KEY_PATTERN = /^[A-Za-z][A-Za-z0-9.]{0,63}$/;
const ROUTE_SEGMENT_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;
const HEX_COLOR_PATTERN = /^#(?:[0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$/;
const FONT_STACK_PATTERN = /^[A-Za-z0-9 ,'"_-]{1,256}$/;
const PUBLISHABLE_PREFIX = 'sb_publishable_';
const KEY_BODY_PATTERN = /^[A-Za-z0-9_.-]{1,2048}$/;
const MAX_RETURN_PATHS = 256;
const MAX_COPY_ENTRIES = 512;

/**
 * @param {unknown} config
 * @returns {import('./index.js').ValidatedClientConfig}
 */
export function validateClientConfig(config) {
  const issues = [];
  const add = (path, rule) => issues.push({ path, rule });
  if (!isPlainObject(config)) {
    add('$', 'not_object');
    throw new AuthError('config_invalid', { issues });
  }
  for (const position of extraKeyPositions(config, CONFIG_FIELDS)) add(memberPath('', position), 'unknown_field');

  if (!isOpaqueKey(config.clientId)) add('clientId', ruleFor(config.clientId, 'invalid_key'));
  const supabaseUrl = readOrigin(config.supabaseUrl, 'supabaseUrl', add);
  const origin = readOrigin(config.origin, 'origin', add);
  checkPublishableKey(config.publishableKey, add);
  const routes = readRoutes(config.routes, add);

  const allowed = config.allowedReturnPaths;
  if (!isDenseArray(allowed) || allowed.length === 0 || allowed.length > MAX_RETURN_PATHS) {
    add('allowedReturnPaths', ruleFor(allowed, 'type'));
  } else {
    allowed.forEach((path, index) => {
      if (!isSafeConfiguredPath(path)) add(`allowedReturnPaths[${index}]`, 'unsafe_path');
      else if (allowed.indexOf(path) !== index) add(`allowedReturnPaths[${index}]`, 'duplicate');
    });
  }
  if (!isSafeConfiguredPath(config.defaultReturnPath)) add('defaultReturnPath', ruleFor(config.defaultReturnPath, 'unsafe_path'));

  const providers = config.providers;
  if (!isPlainObject(providers)) add('providers', ruleFor(providers, 'not_object'));
  else {
    for (const position of extraKeyPositions(providers, ['email', 'google'])) add(memberPath('providers', position), 'unknown_field');
    for (const key of ['email', 'google']) {
      if (typeof providers[key] !== 'boolean') add(`providers.${key}`, ruleFor(providers[key], 'type'));
    }
    if (providers.email === false && providers.google === false) add('providers', 'no_provider');
  }

  const session = readSession(config.session, add);
  const brand = readBrand(config.brand, add);
  const copy = readCopy(config.copy, add);
  if (typeof config.selfSignup !== 'boolean') add('selfSignup', ruleFor(config.selfSignup, 'type'));

  if (issues.length > 0) throw new AuthError('config_invalid', { issues });
  return deepFreeze({
    clientId: config.clientId,
    supabaseUrl,
    publishableKey: config.publishableKey,
    routes,
    origin,
    allowedReturnPaths: [...allowed],
    defaultReturnPath: config.defaultReturnPath,
    providers: { email: providers.email, google: providers.google },
    session,
    brand,
    copy,
    selfSignup: config.selfSignup,
  });
}

function ruleFor(value, rule) {
  return value === undefined ? 'required' : rule;
}

// https origins only; plain http is accepted for loopback hosts so a local
// emulator can be configured. No path, query, fragment or credentials.
function readOrigin(value, path, add) {
  if (typeof value !== 'string' || value.length > 2048) {
    add(path, ruleFor(value, 'type'));
    return null;
  }
  let url;
  try {
    url = new URL(value);
  } catch {
    add(path, 'not_url');
    return null;
  }
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  const schemeOk = url.protocol === 'https:' || (url.protocol === 'http:' && loopback);
  const bare = url.username === '' && url.password === '' && url.pathname === '/' && url.search === '' && url.hash === '';
  if (!schemeOk || !bare || (value !== url.origin && value !== `${url.origin}/`)) {
    add(path, 'not_origin');
    return null;
  }
  return url.origin;
}

// Only publishable keys belong in a browser config: the new-style
// `sb_publishable_` key, or a legacy JWT whose role claim is `anon`. A secret
// key or a legacy `service_role` JWT is refused. The value is never echoed.
function checkPublishableKey(value, add) {
  if (typeof value !== 'string' || !KEY_BODY_PATTERN.test(value)) {
    add('publishableKey', ruleFor(value, 'type'));
    return;
  }
  if (value.startsWith(PUBLISHABLE_PREFIX) && value.length > PUBLISHABLE_PREFIX.length) return;
  if (legacyJwtRole(value) === 'anon') return;
  add('publishableKey', 'not_publishable_key');
}

function legacyJwtRole(value) {
  const parts = value.split('.');
  if (parts.length !== 3 || parts.some((part) => part === '')) return null;
  try {
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const payload = JSON.parse(atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, '=')));
    return isPlainObject(payload) && typeof payload.role === 'string' ? payload.role : null;
  } catch {
    return null;
  }
}

function readRoutes(value, add) {
  const input = value === undefined ? {} : value;
  if (!isPlainObject(input)) {
    add('routes', 'not_object');
    return null;
  }
  for (const position of extraKeyPositions(input, ['prefix', ...ROUTE_NAMES])) add(memberPath('routes', position), 'unknown_field');
  const prefix = own(input, 'prefix') === undefined ? DEFAULT_PREFIX : own(input, 'prefix');
  const prefixOk = isSafeConfiguredPath(prefix) && prefix !== '/' && !prefix.endsWith('/');
  if (!prefixOk) add('routes.prefix', 'unsafe_path');
  const out = { prefix };
  const seen = new Set();
  for (const name of ROUTE_NAMES) {
    const segment = own(input, name) === undefined ? DEFAULT_ROUTES[name] : own(input, name);
    // Paths are built only from parts already known to be safe strings: a
    // malformed part (null, an array, an object with its own toString) is
    // reported, never interpolated or otherwise converted.
    if (typeof segment !== 'string' || !ROUTE_SEGMENT_PATTERN.test(segment)) {
      add(`routes.${name}`, 'segment_syntax');
      continue;
    }
    if (seen.has(segment)) add(`routes.${name}`, 'duplicate');
    seen.add(segment);
    if (prefixOk) out[name] = `${prefix}/${segment}`;
  }
  return out;
}

function readSession(value, add) {
  if (value === undefined) return { accessTokenMinutes: 30 };
  if (!isPlainObject(value)) {
    add('session', 'not_object');
    return null;
  }
  for (const position of extraKeyPositions(value, ['accessTokenMinutes'])) add(memberPath('session', position), 'unknown_field');
  const minutes = value.accessTokenMinutes === undefined ? 30 : value.accessTokenMinutes;
  if (!Number.isInteger(minutes) || minutes < 1 || minutes > 1440) add('session.accessTokenMinutes', 'out_of_range');
  return { accessTokenMinutes: minutes };
}

function readBrand(value, add) {
  if (value === undefined) return null;
  if (!isPlainObject(value)) {
    add('brand', 'not_object');
    return null;
  }
  for (const position of extraKeyPositions(value, ['name', 'logoUrl', 'colors', 'fontStack'])) add(memberPath('brand', position), 'unknown_field');
  if (typeof value.name !== 'string' || value.name.length === 0 || value.name.length > 128) add('brand.name', ruleFor(value.name, 'type'));
  if (value.logoUrl !== undefined && !isSafeAsset(value.logoUrl)) add('brand.logoUrl', 'unsafe_url');
  if (value.fontStack !== undefined && (typeof value.fontStack !== 'string' || !FONT_STACK_PATTERN.test(value.fontStack))) {
    add('brand.fontStack', 'type');
  }
  const colors = value.colors === undefined ? {} : value.colors;
  if (!isPlainObject(colors)) add('brand.colors', 'not_object');
  else {
    sortedKeys(colors).forEach((key, position) => {
      const path = memberPath('brand.colors', position);
      if (!FIELD_PATTERN.test(key)) add(path, 'key_syntax');
      else if (typeof colors[key] !== 'string' || !HEX_COLOR_PATTERN.test(colors[key])) add(path, 'not_hex_color');
    });
  }
  const out = { name: value.name, colors: isPlainObject(colors) ? { ...colors } : {} };
  if (value.logoUrl !== undefined) out.logoUrl = value.logoUrl;
  if (value.fontStack !== undefined) out.fontStack = value.fontStack;
  return out;
}

// A logo is a same-site path or an https URL; no scripts, data or credentials.
function isSafeAsset(value) {
  if (typeof value !== 'string') return false;
  if (value.startsWith('/')) return isSafeConfiguredPath(value);
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.username === '' && url.password === '' && value.length <= 2048;
  } catch {
    return false;
  }
}

function readCopy(value, add) {
  if (value === undefined) return {};
  if (!isPlainObject(value)) {
    add('copy', 'not_object');
    return null;
  }
  const keys = sortedKeys(value);
  if (keys.length > MAX_COPY_ENTRIES) {
    add('copy', 'too_many');
    return null;
  }
  keys.forEach((key, position) => {
    const path = memberPath('copy', position);
    if (!COPY_KEY_PATTERN.test(key)) add(path, 'key_syntax');
    else if (typeof value[key] !== 'string' || value[key].length > 2000) add(path, 'type');
  });
  return { ...value };
}
