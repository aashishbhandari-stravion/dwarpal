// Strict argument parsing for auth-kit. Each command declares its options;
// an unknown, repeated or value-less option is a usage error, never a guess.
// `--name=value` passes any value, including an empty string or one that
// starts with `--`; `--name value` refuses a value that looks like an option.

export class UsageError extends Error {
  constructor(message) {
    super(message);
    this.name = 'UsageError';
  }
}

/**
 * @param {string[]} argv arguments after the command name
 * @param {Record<string, 'flag' | 'value'>} spec
 * @returns {Record<string, string | true>}
 */
export function parseOptions(argv, spec) {
  const out = Object.create(null);
  for (let i = 0; i < argv.length; i += 1) {
    const token = argv[i];
    if (!token.startsWith('--')) throw new UsageError('unexpected positional argument');
    const eq = token.indexOf('=');
    const name = eq === -1 ? token.slice(2) : token.slice(2, eq);
    if (!Object.hasOwn(spec, name)) throw new UsageError(`unknown option --${name.replace(/[^a-z0-9-]/g, '?').slice(0, 40)}`);
    if (Object.hasOwn(out, name)) throw new UsageError(`--${name} given more than once`);
    if (spec[name] === 'flag') {
      if (eq !== -1) throw new UsageError(`--${name} takes no value`);
      out[name] = true;
      continue;
    }
    if (eq !== -1) {
      out[name] = token.slice(eq + 1);
      continue;
    }
    const value = argv[i + 1];
    if (value === undefined || value.startsWith('--')) throw new UsageError(`--${name} needs a value`);
    out[name] = value;
    i += 1;
  }
  return out;
}

export function required(options, name) {
  if (!Object.hasOwn(options, name)) throw new UsageError(`--${name} is required`);
  return options[name];
}
