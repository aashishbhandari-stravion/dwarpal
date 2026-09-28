// Per-instance key material and the small primitives the fixture needs: ES256
// access tokens with a JWKS, RFC 6238 TOTP, password hashes and digests of
// bearer values. node:crypto only; nothing here reaches the network.

import {
  createHash, createHmac, generateKeyPairSync, randomBytes, randomUUID, scryptSync, sign, timingSafeEqual, verify,
} from 'node:crypto';

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{1,4096}\.[A-Za-z0-9_-]{1,8192}\.[A-Za-z0-9_-]{1,512}$/;
// A low scrypt cost: the hashes only keep plain passwords out of memory
// snapshots of a development fixture; they protect nothing at rest.
const SCRYPT = { N: 1024, r: 8, p: 1 };

export function newId() {
  return randomUUID();
}

export function randomToken(bytes = 32) {
  return randomBytes(bytes).toString('base64url');
}

/** Hex digest used to hold bearer values (link tokens, refresh tokens, codes) without the value. */
export function digest(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

export function hashPassword(password) {
  const salt = randomBytes(16);
  return { salt, hash: scryptSync(password, salt, 32, SCRYPT) };
}

export function checkPassword(record, password) {
  if (!record) return false;
  return timingSafeEqual(record.hash, scryptSync(password, record.salt, 32, SCRYPT));
}

/** RFC 7636 S256 challenge of a verifier. */
export function pkceChallenge(verifier) {
  return createHash('sha256').update(verifier, 'utf8').digest('base64url');
}

export function createSigner() {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const kid = randomUUID();
  const jwk = Object.freeze({ ...publicKey.export({ format: 'jwk' }), kid, alg: 'ES256', use: 'sig', key_ops: ['verify'] });
  const header = base64urlJson({ alg: 'ES256', kid, typ: 'JWT' });
  return {
    jwks: () => ({ keys: [{ ...jwk, key_ops: [...jwk.key_ops] }] }),
    sign(payload) {
      const input = `${header}.${base64urlJson(payload)}`;
      const signature = sign('sha256', Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' });
      return `${input}.${signature.toString('base64url')}`;
    },
    /** The payload when the token is well formed and signed by this instance's key; otherwise null. Expiry is the caller's. */
    verify(token) {
      if (typeof token !== 'string' || !TOKEN_PATTERN.test(token)) return null;
      const [head, body, signature] = token.split('.');
      const parsedHeader = parseJsonSegment(head);
      if (!parsedHeader || parsedHeader.alg !== 'ES256' || parsedHeader.kid !== kid) return null;
      const ok = verify('sha256', Buffer.from(`${head}.${body}`), { key: publicKey, dsaEncoding: 'ieee-p1363' },
        Buffer.from(signature, 'base64url'));
      if (!ok) return null;
      const payload = parseJsonSegment(body);
      return payload && typeof payload === 'object' && !Array.isArray(payload) ? payload : null;
    },
  };
}

function base64urlJson(value) {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function parseJsonSegment(segment) {
  try {
    return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

export function newTotpSecret() {
  return base32Encode(randomBytes(20));
}

/** RFC 6238 code (SHA-1, 30 s steps, 6 digits) for the step containing `atMs`. */
export function totpCode(secret, atMs, stepOffset = 0) {
  const counter = Math.floor(atMs / 30_000) + stepOffset;
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac('sha1', base32Decode(secret)).update(message).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const binary = mac.readUInt32BE(offset) & 0x7fffffff;
  return String(binary % 1_000_000).padStart(6, '0');
}

/** Accepts the current step and one step either side, as TOTP verifiers commonly do. */
export function totpMatches(secret, atMs, code) {
  if (typeof code !== 'string' || !/^\d{6}$/.test(code)) return false;
  return [-1, 0, 1].some((offset) => timingSafeEqual(Buffer.from(totpCode(secret, atMs, offset)), Buffer.from(code)));
}

function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
  return out;
}

function base32Decode(text) {
  let bits = 0;
  let value = 0;
  const out = [];
  for (const char of text) {
    const index = BASE32.indexOf(char);
    if (index === -1) throw new TypeError('invalid base32 secret');
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}
