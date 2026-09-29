// RFC 6238 TOTP (HMAC-SHA1, 30-second steps, 6 digits), the parameters
// Supabase Auth uses for TOTP factors. The harness computes codes for its
// own disposable factors; secrets and codes stay in memory and are
// registered with the redactor by the caller.

import { createHmac } from 'node:crypto';

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Decode(text) {
  const clean = text.replace(/=+$/, '').replace(/\s+/g, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of clean) {
    const index = BASE32.indexOf(ch);
    if (index === -1) throw new TypeError('totp: secret is not base32');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** The code for time step `step` (floor(unixSeconds / period)). */
export function hotp(key, step, digits = 6) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const mac = createHmac('sha1', key).update(counter).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const binary = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3];
  return String(binary % 10 ** digits).padStart(digits, '0');
}

export function stepAt(unixSeconds, period = 30) {
  return Math.floor(unixSeconds / period);
}

/** @param {string} secret base32 */
export function totp(secret, unixSeconds, { period = 30, digits = 6 } = {}) {
  return hotp(base32Decode(secret), stepAt(unixSeconds, period), digits);
}
