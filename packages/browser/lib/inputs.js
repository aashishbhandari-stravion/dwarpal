// Pure checks for what the controller accepts from the page and from Auth
// before acting on it: typed credentials and codes, the TOTP enrolment
// answer, the authorize address, and the page environment.

const MAX_EMAIL_LENGTH = 320;
const MAX_PASSWORD_LENGTH = 1024;
const EMAIL_SHAPE = /^[^\s@]+@[^\s@]+$/;
const TOTP_CODE = /^\d{6}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const TOTP_SECRET = /^[A-Z2-7]{16,128}=*$/;
const FLOW_ID = /^[A-Za-z0-9_-]{8,64}$/;

export function validEmail(value) {
  return typeof value === 'string' && value.length <= MAX_EMAIL_LENGTH && EMAIL_SHAPE.test(value);
}

export function validPassword(value) {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_PASSWORD_LENGTH;
}

export function validTotpCode(value) {
  return typeof value === 'string' && TOTP_CODE.test(value);
}

export function isUuid(value) {
  return typeof value === 'string' && UUID.test(value);
}

export function isFlowId(value) {
  return typeof value === 'string' && FLOW_ID.test(value);
}

/** The TOTP enrolment answer, or null when any part is not the expected shape. */
export function readEnrolment(data) {
  if (data === null || typeof data !== 'object' || data.type !== 'totp') return null;
  const { id, totp } = data;
  if (!isUuid(id) || totp === null || typeof totp !== 'object') return null;
  const { qr_code: qrCode, secret, uri } = totp;
  // supabase-js turns Auth's SVG into this data: URL; nothing else is shown.
  if (typeof qrCode !== 'string' || !qrCode.startsWith('data:image/svg+xml') || qrCode.length > 65536) return null;
  if (typeof secret !== 'string' || !TOTP_SECRET.test(secret)) return null;
  if (typeof uri !== 'string' || !uri.startsWith('otpauth://totp/') || uri.length > 2048) return null;
  return { factorId: id, qrCode, secret, uri };
}

/**
 * Only Auth's own authorize endpoint on the configured project is ever
 * navigated to. skip_http_redirect asks Auth to answer with JSON instead of
 * redirecting; the kit navigates itself, so the parameter is removed.
 */
export function readAuthorizeUrl(value, supabaseUrl) {
  if (typeof value !== 'string') return null;
  let url;
  try {
    url = new URL(value);
  } catch {
    return null;
  }
  if (url.origin !== supabaseUrl || url.pathname !== '/auth/v1/authorize') return null;
  url.searchParams.delete('skip_http_redirect');
  return url.toString();
}

export function defaultEnv() {
  const w = globalThis.window;
  if (!w) throw new TypeError('createAuthController: no window; pass env.');
  return {
    location: w.location,
    history: w.history,
    localStorage: safeGet(() => w.localStorage),
    sessionStorage: safeGet(() => w.sessionStorage),
    navigate: (url) => w.location.assign(url),
  };
}

// Reading window.localStorage itself can throw when storage is disabled.
function safeGet(read) {
  try {
    return read();
  } catch {
    return null;
  }
}
