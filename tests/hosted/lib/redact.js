// Evidence sanitation. Every value that reaches an evidence file passes
// through `sanitize`; every finished file is then scanned by `scan`, and a hit
// fails the run. Two layers on purpose: sanitation can miss a value that
// arrives in an unexpected shape, and the scan catches it before anyone reads
// the file.
//
//   secrets   exact values (keys, tokens, passwords, TOTP secrets, refresh
//             tokens) registered as they appear; replaced by [secret:<label>]
//   aliases   identifiers that are not secret but personal or unstable (test
//             e-mail addresses, user and factor ids); replaced by <alias>
//   patterns  shapes that must never be kept even when unregistered: JWTs,
//             Supabase keys, Management tokens, otpauth URIs, e-mail
//             addresses, long hex runs (token hashes). Remaining UUIDs get a
//             stable per-run alias so evidence can still be correlated.

const PATTERNS = [
  [/eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*/g, '[jwt]'],
  [/sb_secret_[A-Za-z0-9_-]+/g, '[sb_secret]'],
  [/sb_publishable_[A-Za-z0-9_-]+/g, '[sb_publishable]'],
  [/sbp_[A-Za-z0-9]{8,}/g, '[management_token]'],
  [/otpauth:\/\/[^\s"']+/g, '[otpauth]'],
  [/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, '[email]'],
  [/\b[0-9a-f]{40,}\b/gi, '[hex]'],
];
const UUID = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;
// Shapes the scan refuses outright (a subset of PATTERNS that sanitation always removes).
const LEAK_PATTERNS = [
  ['jwt', /eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*/],
  ['sb_secret', /sb_secret_[A-Za-z0-9_-]+/],
  ['management_token', /sbp_[A-Za-z0-9]{8,}/],
  ['otpauth', /otpauth:\/\//],
  ['email', /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/],
];
const MIN_SECRET = 6;

export class Redactor {
  constructor() {
    this.secrets = new Map();
    this.aliases = new Map();
    this.uuidAliases = new Map();
  }

  /** Registers a secret value; short values are refused because they would match by accident. */
  secret(value, label) {
    if (typeof value !== 'string' || value === '') return;
    if (value.length < MIN_SECRET) throw new Error(`secret ${label} is too short to redact safely`);
    this.secrets.set(value, label);
  }

  alias(value, alias) {
    if (typeof value !== 'string' || value === '') return;
    this.aliases.set(value, alias);
    if (UUID.test(value)) this.aliases.set(value.toLowerCase(), alias);
    UUID.lastIndex = 0;
  }

  sanitizeText(text) {
    let out = text;
    const bySize = (a, b) => b[0].length - a[0].length;
    for (const [value, label] of [...this.secrets].sort(bySize)) out = out.split(value).join(`[secret:${label}]`);
    for (const [value, alias] of [...this.aliases].sort(bySize)) out = out.split(value).join(`<${alias}>`);
    for (const [pattern, replacement] of PATTERNS) out = out.replace(pattern, replacement);
    out = out.replace(UUID, (id) => {
      const key = id.toLowerCase();
      if (!this.uuidAliases.has(key)) this.uuidAliases.set(key, `uuid-${this.uuidAliases.size + 1}`);
      return this.uuidAliases.get(key);
    });
    return out;
  }

  /** Deep copy with every string sanitised (keys too). */
  sanitize(value, depth = 0) {
    if (depth > 32) return '[depth]';
    if (typeof value === 'string') return this.sanitizeText(value);
    if (value === null || typeof value !== 'object') return value;
    if (Array.isArray(value)) return value.map((v) => this.sanitize(v, depth + 1));
    const out = {};
    for (const [k, v] of Object.entries(value)) out[this.sanitizeText(k)] = this.sanitize(v, depth + 1);
    return out;
  }

  /**
   * Leak scan of finished evidence text: registered secrets and refused shapes.
   * @returns {{ kind: string, label: string }[]} hits (never the matched text)
   */
  scan(text) {
    const hits = [];
    for (const [value, label] of this.secrets) if (text.includes(value)) hits.push({ kind: 'secret', label });
    for (const [label, pattern] of LEAK_PATTERNS) if (pattern.test(text)) hits.push({ kind: 'pattern', label });
    return hits;
  }
}
