// The hosted target: a private, secret-free descriptor file plus credentials
// from the environment (or an owner-only env file outside every Git tree).
// Nothing here makes a network call. `authorize` is the only way to obtain
// the origins the network gate may open, and it refuses unless the
// descriptor records an explicit, current authorization for an isolated,
// disposable project and the invocation confirms the same project ref.
//
// Descriptor (schema dwarpal-hosted-target/1):
//   {
//     "schema": "dwarpal-hosted-target/1",
//     "project": { "ref": "<ref>", "url": "https://<ref>.supabase.co" },
//     "authorization": {
//       "record": "<private record id>",       // where the owner authorized this target
//       "isolated": true, "disposable": true, "noProductionData": true,
//       "expiresAt": "<ISO time>",
//       "actions": ["connect", "create_users", ...]   // inventory.ACTION_CLASSES
//     },
//     "identities": {
//       "emailTemplate": "<local>+{tag}@<authorized domain>",   // disposable users, created confirmed, no mail sent
//       "smtpRecipients": ["<local>+{tag}@<domain>"],           // real mailbox for send_email ({tag} gives a fresh address per run)
//       "smtpSenderDomain": "<domain>",                           // the authorized sending domain
//       "google": { "email": "<address>" }                      // the authorized Google test identity
//     },
//     "callbackPort": 54329,                                    // the allow-listed http://localhost:<port>/hosted/callback
//     "limits": { "signInsPerFiveMinutes": 25, "maxTokenLifetimeSeconds": 3600 },
//     "doctor": { "configFile": "<absolute path of the consumer config for doctor --config>" }
//   }
//
// The doctor config is required for complete D1 catalog proof (L33): without
// a valid config for this project, doctor runs no redirect allow-list or
// client-registration check, so the catalog-proof cases are blocked.

import fs from 'node:fs';
import path from 'node:path';
import { parseEnv } from 'node:util';
import { ACTION_CLASSES } from './inventory.js';
import { validateClientConfig } from '../../../packages/core/index.js';
import { chromiumAvailable } from './chromium.js';
import { readCredentialFile } from './paths.js';

export const SCHEMA = 'dwarpal-hosted-target/1';
export const MANAGEMENT_ORIGIN = 'https://api.supabase.com';
const REF = /^[a-z0-9]{20}$/;
const TEMPLATE = /^[A-Za-z0-9._%-]+\+\{tag\}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;
const EMAIL = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;
const RECORD = /^[A-Za-z0-9._:-]{3,128}$/;
const DOMAIN = /^[a-z0-9.-]+\.[a-z]{2,}$/;
const ENV_NAMES = ['SUPABASE_URL', 'SUPABASE_PUBLISHABLE_KEY', 'SUPABASE_SECRET_KEY', 'SUPABASE_ACCESS_TOKEN'];

export class TargetError extends Error {
  constructor(problems) {
    super(`target refused: ${problems.join(', ')}`);
    this.name = 'TargetError';
    this.problems = problems;
  }
}

/** Reads and validates the descriptor; never includes file text in errors. */
export function readDescriptor(file) {
  let value;
  try {
    value = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    throw new TargetError(['descriptor_unreadable']);
  }
  const problems = descriptorProblems(value);
  if (problems.length > 0) throw new TargetError(problems);
  return value;
}

export function descriptorProblems(d) {
  const p = [];
  if (d === null || typeof d !== 'object' || Array.isArray(d)) return ['descriptor_not_object'];
  if (d.schema !== SCHEMA) p.push('schema');
  const ref = d.project?.ref;
  if (typeof ref !== 'string' || !REF.test(ref)) p.push('project_ref');
  else if (d.project.url !== `https://${ref}.supabase.co`) p.push('project_url_not_ref_url');
  const a = d.authorization;
  if (a === null || typeof a !== 'object') {
    p.push('authorization_missing');
  } else {
    if (typeof a.record !== 'string' || !RECORD.test(a.record)) p.push('authorization_record');
    for (const flag of ['isolated', 'disposable', 'noProductionData']) if (a[flag] !== true) p.push(`authorization_${flag}`);
    if (typeof a.expiresAt !== 'string' || Number.isNaN(Date.parse(a.expiresAt))) p.push('authorization_expiry');
    if (!Array.isArray(a.actions) || a.actions.some((x) => !Object.hasOwn(ACTION_CLASSES, x))) p.push('authorization_actions');
  }
  const ids = d.identities ?? {};
  if (ids.emailTemplate !== undefined && (typeof ids.emailTemplate !== 'string' || !TEMPLATE.test(ids.emailTemplate))) p.push('email_template');
  if (ids.smtpRecipients !== undefined && (!Array.isArray(ids.smtpRecipients) || !ids.smtpRecipients.every((e) => typeof e === 'string' && (EMAIL.test(e) || TEMPLATE.test(e))))) p.push('smtp_recipients');
  if (ids.smtpSenderDomain !== undefined && (typeof ids.smtpSenderDomain !== 'string' || !DOMAIN.test(ids.smtpSenderDomain))) p.push('smtp_sender_domain');
  if (d.doctor?.configFile !== undefined && (typeof d.doctor.configFile !== 'string' || !path.isAbsolute(d.doctor.configFile))) p.push('doctor_config_file');
  if (d.limits !== undefined) {
    const { signInsPerFiveMinutes: s, maxTokenLifetimeSeconds: t } = d.limits ?? {};
    if (s !== undefined && !(Number.isInteger(s) && s >= 1 && s <= 1000)) p.push('limit_sign_ins');
    if (t !== undefined && !(Number.isInteger(t) && t >= 60 && t <= 86_400)) p.push('limit_token_lifetime');
  }
  if (ids.google !== undefined && (typeof ids.google?.email !== 'string' || !EMAIL.test(ids.google.email))) p.push('google_identity');
  if (d.callbackPort !== undefined && !(Number.isInteger(d.callbackPort) && d.callbackPort >= 1024 && d.callbackPort <= 65535)) p.push('callback_port');
  return p;
}

/**
 * Credentials: the process environment first, then an owner-only env file
 * outside every Git working tree. Only the four known names are read.
 */
export function readCredentials(env, envPath) {
  const out = {};
  for (const name of ENV_NAMES) if (typeof env[name] === 'string' && env[name] !== '') out[name] = env[name];
  if (envPath !== undefined) {
    const read = readCredentialFile(envPath);
    if (read.problem) throw new TargetError([`env_file_${read.problem}`]);
    const parsed = parseEnv(read.text);
    for (const name of ENV_NAMES) if (!Object.hasOwn(out, name) && typeof parsed[name] === 'string' && parsed[name] !== '') out[name] = parsed[name];
  }
  return out;
}

/**
 * The consumer config doctor --config reads: valid for core's
 * validateClientConfig and naming this project's URL. Local only.
 * @returns {{ file: string, config: object } | { problem: string }}
 */
export function readDoctorConfig(descriptor) {
  const file = descriptor?.doctor?.configFile;
  if (typeof file !== 'string' || !path.isAbsolute(file)) return { problem: 'doctor_config_missing' };
  let raw;
  try {
    raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return { problem: 'doctor_config_unreadable' };
  }
  let config;
  try {
    config = validateClientConfig(raw);
  } catch {
    return { problem: 'doctor_config_invalid' };
  }
  if (config.supabaseUrl !== descriptor.project?.url) return { problem: 'doctor_config_other_project' };
  return { file, config };
}

function keyKind(value, prefix) {
  if (typeof value !== 'string') return null;
  if (value.startsWith(prefix)) return 'new';
  const parts = value.split('.');
  if (parts.length !== 3) return null;
  try {
    return JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')).role ?? null;
  } catch {
    return null;
  }
}

/** Which inventory capabilities the inputs provide. */
export function capabilities(descriptor, creds, { interactive = false, chromium = chromiumAvailable() } = {}) {
  const pub = keyKind(creds.SUPABASE_PUBLISHABLE_KEY, 'sb_publishable_');
  const sec = keyKind(creds.SUPABASE_SECRET_KEY, 'sb_secret_');
  return {
    publishable_key: pub === 'new' || pub === 'anon',
    secret_key: sec === 'new' || sec === 'service_role',
    management_token: typeof creds.SUPABASE_ACCESS_TOKEN === 'string' && /^[A-Za-z0-9_.-]{8,4096}$/.test(creds.SUPABASE_ACCESS_TOKEN),
    smtp_recipient: Array.isArray(descriptor?.identities?.smtpRecipients) && descriptor.identities.smtpRecipients.length > 0,
    google_identity: typeof descriptor?.identities?.google?.email === 'string',
    doctor_config: descriptor !== null && descriptor !== undefined && readDoctorConfig(descriptor).config !== undefined,
    interactive: interactive === true,
    chromium: chromium === true,
  };
}

/**
 * The gate. Returns the authorized action classes and the origins the
 * network layer may open, or throws TargetError with every problem found.
 * @param {{ descriptor: object, creds: object, confirmRef: string | undefined, now?: number }} input
 */
export function authorize({ descriptor, creds, confirmRef, now = Date.now() }) {
  const problems = descriptorProblems(descriptor);
  if (problems.length > 0) throw new TargetError(problems);
  const { ref, url } = descriptor.project;
  if (confirmRef !== ref) problems.push('confirm_ref_mismatch');
  if (creds.SUPABASE_URL !== url) problems.push('env_url_mismatch');
  if (Date.parse(descriptor.authorization.expiresAt) <= now) problems.push('authorization_expired');
  const caps = capabilities(descriptor, creds);
  if (!caps.publishable_key) problems.push('publishable_key_missing_or_wrong_kind');
  if (!caps.secret_key) problems.push('secret_key_missing_or_wrong_kind');
  if (creds.SUPABASE_PUBLISHABLE_KEY && creds.SUPABASE_PUBLISHABLE_KEY === creds.SUPABASE_SECRET_KEY) problems.push('keys_identical');
  if (!descriptor.authorization.actions.includes('connect')) problems.push('connect_not_authorized');
  if (problems.length > 0) throw new TargetError(problems);
  const actions = new Set(descriptor.authorization.actions);
  const origins = [url];
  if (caps.management_token) origins.push(MANAGEMENT_ORIGIN);
  return Object.freeze({ ref, url, record: descriptor.authorization.record, actions, origins });
}
