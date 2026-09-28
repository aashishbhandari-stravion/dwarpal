// auth-kit: the operator CLI, a thin wrapper over createOperatorClient
// (design 4.1, 9; manual 5). Credentials come from the environment (or an
// --env-path file outside the repository), never from arguments. The option
// is not called --env-file because Node itself consumes that flag anywhere
// on its command line, before this program runs.
//
// Output: stdout carries one JSON document per run (the result, or
// `{ "error": code, ... }`), except export-model, whose stdout is the
// canonical model file text. stderr carries short fixed-text notes. Every
// line passes through a redactor holding the credential values and any
// e-mail argument, so none of them can be printed even by mistake.
//
// Exit status (closed set):
//   0  done                     3  unavailable (nothing changed by the failed step)
//   1  refused / not completed  4  outcome unknown: rerun with the same request id
//   2  usage or input error     5  prerequisite missing, or doctor incomplete
//   70 internal error

import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { parseEnv } from 'node:util';
import { createOperatorClient, isOperatorError } from '../operator.js';
import { parseOptions, required, UsageError } from './args.js';
import { INIT_FILES } from './templates.js';

export const EXIT = Object.freeze({ ok: 0, refused: 1, usage: 2, unavailable: 3, outcomeUnknown: 4, incomplete: 5, internal: 70 });

const MAX_FILE_BYTES = 4 * 1024 * 1024;
const SECRET_ENV = ['SUPABASE_SECRET_KEY', 'SUPABASE_ACCESS_TOKEN', 'AUTH_KIT_PROBE_PASSWORD'];

const USAGE = `usage: auth-kit <command> [options]

commands:
  init [--dir <dir>]
  migrate [--migrations-dir <dir>]
  doctor [--config <file>] [--model <file>] [--client <id>] [--probe --probe-email <email>]
         [--origin <url>] [--migrations-dir <dir>]
  register-client --client <id> --name <display name> --signup open|closed
  apply-model [--model <file>] [--client <id>] [--dry-run] [--request-id <uuid>]
  export-model --client <id>
  bootstrap-manager --client <id> --role <role> (--user-id <uuid> | --email <address> [--invite])
                    [--request-id <uuid>]
  revoke-manager --client <id> --role <role> --user-id <uuid> [--request-id <uuid>]
  mfa-reset --user-id <uuid> [--request-id <uuid>]

every command also takes --env-path <file> (a dotenv file) and --help.

environment: SUPABASE_URL, SUPABASE_SECRET_KEY; for migrate and doctor's catalog
checks SUPABASE_ACCESS_TOKEN (Management API) and, for a custom domain,
SUPABASE_PROJECT_REF; for doctor --probe SUPABASE_PUBLISHABLE_KEY and
AUTH_KIT_PROBE_PASSWORD.
`;

const COMMON = { 'env-path': 'value', help: 'flag' };
const SPECS = {
  init: { dir: 'value' },
  migrate: { 'migrations-dir': 'value' },
  doctor: { config: 'value', model: 'value', client: 'value', probe: 'flag', 'probe-email': 'value', origin: 'value', 'migrations-dir': 'value' },
  'register-client': { client: 'value', name: 'value', signup: 'value' },
  'apply-model': { model: 'value', client: 'value', 'dry-run': 'flag', 'request-id': 'value' },
  'export-model': { client: 'value' },
  'bootstrap-manager': { client: 'value', role: 'value', 'user-id': 'value', email: 'value', invite: 'flag', 'request-id': 'value' },
  'revoke-manager': { client: 'value', role: 'value', 'user-id': 'value', 'request-id': 'value' },
  'mfa-reset': { 'user-id': 'value', 'request-id': 'value' },
};

// Fixed hints printed after an error, keyed by code.
const HINTS = {
  lookup_incomplete: 'find the user id in the Supabase dashboard and rerun with --user-id.',
  ambiguous_user: 'rerun with --user-id.',
  outcome_unknown: 'rerun the same command with the same --request-id; a completed request returns its stored result.',
  request_in_progress: 'rerun with the same --request-id after the other run ends (the claim lasts 120 seconds).',
  lease_expired: 'rerun with the same --request-id; the run resumes with the recorded factor list.',
  run_superseded: 'rerun with the same --request-id to see the outcome.',
  prerequisite_missing: 'see `auth-kit --help` for the required environment.',
};

function exitFor(code) {
  if (code === 'config_invalid' || code === 'invalid_argument') return EXIT.usage;
  if (code === 'unavailable') return EXIT.unavailable;
  if (code === 'outcome_unknown') return EXIT.outcomeUnknown;
  if (code === 'prerequisite_missing') return EXIT.incomplete;
  return EXIT.refused;
}

function createOutput(io, secrets) {
  const values = secrets.filter((s) => typeof s === 'string' && s.length >= 3).sort((a, b) => b.length - a.length);
  const redact = (text) => values.reduce((out, secret) => out.split(secret).join('[redacted]'), text);
  return {
    json: (value) => io.stdout.write(`${redact(JSON.stringify(value, null, 2))}\n`),
    raw: (text) => io.stdout.write(redact(text)),
    note: (text) => io.stderr.write(`auth-kit: ${redact(text)}\n`),
  };
}

function readEnv(base, file) {
  const env = { ...base };
  if (file === undefined) return env;
  let text;
  try {
    text = readSmallFile(file);
  } catch {
    throw new UsageError('the --env-path file could not be read');
  }
  // Values already in the environment win, as with Node's own env files.
  for (const [key, value] of Object.entries(parseEnv(text))) if (!Object.hasOwn(env, key)) env[key] = value;
  return env;
}

function readSmallFile(file) {
  const stat = fs.statSync(file);
  if (!stat.isFile() || stat.size > MAX_FILE_BYTES) throw new Error('not a small regular file');
  return fs.readFileSync(file, 'utf8');
}

function readJsonFile(file, what) {
  let text;
  try {
    text = readSmallFile(file);
  } catch {
    throw new UsageError(`the ${what} file could not be read`);
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new UsageError(`the ${what} file is not JSON`);
  }
}

function envValue(env, name) {
  const value = env[name];
  return typeof value === 'string' && value !== '' ? value : null;
}

function operatorFor(env, deps, out) {
  const supabaseUrl = envValue(env, 'SUPABASE_URL');
  const secretKey = envValue(env, 'SUPABASE_SECRET_KEY');
  if (supabaseUrl === null || secretKey === null) {
    throw Object.assign(new UsageError('SUPABASE_URL and SUPABASE_SECRET_KEY must be set'), { exit: EXIT.incomplete });
  }
  return createOperatorClient({
    supabaseUrl,
    secretKey,
    publishableKey: envValue(env, 'SUPABASE_PUBLISHABLE_KEY'),
    management: {
      token: envValue(env, 'SUPABASE_ACCESS_TOKEN'),
      projectRef: envValue(env, 'SUPABASE_PROJECT_REF'),
      url: envValue(env, 'SUPABASE_MANAGEMENT_API_URL') ?? undefined,
    },
    fetch: deps.fetch,
    timers: deps.timers,
    monotonicNow: deps.monotonicNow,
    onWarning: (code) => out.note(`warning: ${code === 'legacy_service_role_key' ? 'a legacy service_role key is in use; prefer a secret key' : code}`),
  });
}

function requestIdFor(options, out) {
  if (Object.hasOwn(options, 'request-id')) return options['request-id'];
  const id = randomUUID();
  out.note(`request id ${id} (reuse it with --request-id to retry this command)`);
  return id;
}

const COMMANDS = {
  async init(options, ctx) {
    const dir = path.resolve(ctx.cwd, options.dir ?? '.');
    const results = [];
    for (const [name, content] of Object.entries(INIT_FILES)) {
      try {
        fs.writeFileSync(path.join(dir, name), content, { flag: 'wx', mode: 0o644 });
        results.push({ file: name, result: 'written' });
      } catch (error) {
        if (error?.code !== 'EEXIST') throw new UsageError('the target directory is not writable');
        results.push({ file: name, result: 'exists_unchanged' });
      }
    }
    ctx.out.json({ result: 'initialized', files: results });
    return EXIT.ok;
  },

  async migrate(options, ctx) {
    const operator = operatorFor(ctx.env, ctx.deps, ctx.out);
    try {
      const report = await operator.migrate(options['migrations-dir'] ? { migrationsDir: path.resolve(ctx.cwd, options['migrations-dir']) } : {});
      ctx.out.json({ result: report.applied.length > 0 ? 'migrated' : 'up_to_date', ...report });
      return EXIT.ok;
    } catch (error) {
      if (isOperatorError(error) && error.code === 'prerequisite_missing') {
        ctx.out.note('no Management API access: open the project\'s SQL editor, paste each file of supabase/migrations in name order and run it, then run `auth-kit doctor`.');
      }
      throw error;
    }
  },

  async doctor(options, ctx) {
    const operator = operatorFor(ctx.env, ctx.deps, ctx.out);
    const config = options.config === undefined ? null : readJsonFile(path.resolve(ctx.cwd, options.config), 'config');
    const model = options.model === undefined ? null : readJsonFile(path.resolve(ctx.cwd, options.model), 'model');
    let probe = null;
    if (options.probe) {
      const email = options['probe-email'];
      const password = envValue(ctx.env, 'AUTH_KIT_PROBE_PASSWORD');
      if (typeof email !== 'string') throw new UsageError('--probe needs --probe-email');
      if (password === null) throw Object.assign(new UsageError('--probe needs AUTH_KIT_PROBE_PASSWORD in the environment'), { exit: EXIT.incomplete });
      probe = { email, password };
    } else if (options['probe-email'] !== undefined) {
      throw new UsageError('--probe-email needs --probe');
    }
    const report = await operator.doctor({
      clientId: options.client ?? null,
      config,
      model,
      probe,
      hostOrigin: options.origin ?? null,
      ...(options['migrations-dir'] ? { migrationsDir: path.resolve(ctx.cwd, options['migrations-dir']) } : {}),
    });
    ctx.out.json(report);
    if (!report.probeRan) ctx.out.note('no actor probe ran (use --probe --probe-email <disposable user>).');
    return report.status === 'ok' ? EXIT.ok : report.status === 'fail' ? EXIT.refused : EXIT.incomplete;
  },

  async 'register-client'(options, ctx) {
    const operator = operatorFor(ctx.env, ctx.deps, ctx.out);
    const result = await operator.registerClient({ clientId: required(options, 'client'), displayName: required(options, 'name'), signupPolicy: required(options, 'signup') });
    ctx.out.json(result);
    return EXIT.ok;
  },

  async 'apply-model'(options, ctx) {
    const operator = operatorFor(ctx.env, ctx.deps, ctx.out);
    const model = readJsonFile(path.resolve(ctx.cwd, options.model ?? 'auth-model.json'), 'model');
    if (options.client !== undefined && (model === null || typeof model !== 'object' || model.client !== options.client)) {
      throw new UsageError('--client does not match the model file');
    }
    const dryRun = options['dry-run'] === true;
    const requestId = dryRun ? null : requestIdFor(options, ctx.out);
    const result = await operator.applyModel(model, { dryRun, requestId });
    ctx.out.json(result);
    if (!result.hashMatchesFile) {
      ctx.out.note('the database hashed this model differently from the file; run doctor and report this.');
      return EXIT.refused;
    }
    return EXIT.ok;
  },

  async 'export-model'(options, ctx) {
    const operator = operatorFor(ctx.env, ctx.deps, ctx.out);
    const result = await operator.exportModel(required(options, 'client'));
    if (result.modelJson === null) {
      ctx.out.note('the client has no applied model.');
      return EXIT.refused;
    }
    // The canonical file text itself, byte for byte.
    ctx.out.raw(`${result.modelJson}\n`);
    if (result.modelHash !== result.lastAppliedHash) ctx.out.note('the model was changed outside apply-model; commit this export before the next apply.');
    return EXIT.ok;
  },

  async 'bootstrap-manager'(options, ctx) {
    const operator = operatorFor(ctx.env, ctx.deps, ctx.out);
    const hasId = Object.hasOwn(options, 'user-id');
    const hasEmail = Object.hasOwn(options, 'email');
    if (hasId === hasEmail) throw new UsageError('give exactly one of --user-id and --email');
    if (options.invite && !hasEmail) throw new UsageError('--invite needs --email');
    const clientId = required(options, 'client');
    const roleKey = required(options, 'role');
    const requestId = requestIdFor(options, ctx.out);
    const result = await operator.bootstrapManager({
      clientId,
      roleKey,
      requestId,
      ...(hasId ? { userId: options['user-id'] } : { email: options.email, invite: options.invite === true }),
    });
    if (result.result === 'setup_pending') {
      ctx.out.json({ result: 'setup_pending', userId: result.userId });
      ctx.out.note(`invitation sent; once the user has accepted it, rerun bootstrap-manager with --user-id ${result.userId}.`);
      return EXIT.refused;
    }
    ctx.out.json(result);
    return EXIT.ok;
  },

  async 'revoke-manager'(options, ctx) {
    const operator = operatorFor(ctx.env, ctx.deps, ctx.out);
    const result = await operator.revokeManager({
      clientId: required(options, 'client'),
      roleKey: required(options, 'role'),
      userId: required(options, 'user-id'),
      requestId: requestIdFor(options, ctx.out),
    });
    ctx.out.json(result);
    return EXIT.ok;
  },

  async 'mfa-reset'(options, ctx) {
    const operator = operatorFor(ctx.env, ctx.deps, ctx.out);
    const userId = required(options, 'user-id');
    const requestId = requestIdFor(options, ctx.out);
    const result = await operator.mfaReset({ userId, requestId });
    ctx.out.json(result);
    return EXIT.ok;
  },
};

/**
 * @param {string[]} argv
 * @param {{ env: Record<string, string | undefined>, stdout: { write(s: string): unknown }, stderr: { write(s: string): unknown },
 *           cwd?: string, fetch?: typeof fetch, timers?: object, monotonicNow?: () => number }} io
 * @returns {Promise<number>} exit status
 */
export async function main(argv, io) {
  const command = argv[0];
  let out = createOutput(io, SECRET_ENV.map((name) => io.env[name]));
  if (command === undefined || command === '--help' || command === 'help') {
    io.stdout.write(USAGE);
    return command === undefined ? EXIT.usage : EXIT.ok;
  }
  if (!Object.hasOwn(SPECS, command)) {
    out.note('unknown command; see auth-kit --help.');
    return EXIT.usage;
  }
  try {
    const options = parseOptions(argv.slice(1), { ...COMMON, ...SPECS[command] });
    if (options.help) {
      io.stdout.write(USAGE);
      return EXIT.ok;
    }
    const env = readEnv(io.env, options['env-path'] === undefined ? undefined : path.resolve(io.cwd ?? process.cwd(), options['env-path']));
    out = createOutput(io, [...SECRET_ENV.map((name) => env[name]), options.email, options['probe-email']]);
    const ctx = { env, out, cwd: io.cwd ?? process.cwd(), deps: { fetch: io.fetch, timers: io.timers, monotonicNow: io.monotonicNow } };
    return await COMMANDS[command](options, ctx);
  } catch (error) {
    if (error instanceof UsageError) {
      out.json({ error: 'usage', message: error.message });
      out.note(error.message);
      return error.exit ?? EXIT.usage;
    }
    if (isOperatorError(error)) {
      out.json({ error: error.code, message: error.message, details: error.details });
      out.note(`${error.code}: ${error.message}`);
      if (Object.hasOwn(HINTS, error.code)) out.note(HINTS[error.code]);
      return exitFor(error.code);
    }
    // Unexpected: say so without the error's text, which could carry input.
    out.json({ error: 'internal' });
    out.note('internal error.');
    return EXIT.internal;
  }
}
