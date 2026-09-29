// Sanitised raw evidence for one run, in a fresh private directory:
//
//   run.json          source and target identity, authorization reference, options
//   calls.jsonl       every outbound request: method, sanitised path, status, duration
//   observations.jsonl  what each procedure observed, line by line
//   cases.jsonl       one record per case, assertions pointing at observation lines
//   summary.json      the verdict (status.summarise)
//   manifest.json     SHA-256 and size of every file above, written last
//
// Every line is sanitised on write. `finalize` scans every file for leaks
// before writing the manifest; a hit quarantines the file (renamed, left out
// of the manifest) and the run fails.

import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { evidenceLocationProblem, canonicalPath } from './paths.js';

export class EvidenceError extends Error {
  constructor(reason) {
    super(`evidence: ${reason}`);
    this.name = 'EvidenceError';
    this.reason = reason;
  }
}

export function sha256File(file) {
  return createHash('sha256').update(fs.readFileSync(file)).digest('hex');
}

export class Evidence {
  /**
   * @param {string} dir must not exist yet
   * @param {import('./redact.js').Redactor} redactor
   */
  constructor(dir, redactor, { root } = {}) {
    const problem = evidenceLocationProblem(dir, root);
    if (problem) throw new EvidenceError(problem);
    const expected = canonicalPath(dir);
    try {
      fs.mkdirSync(path.dirname(expected), { recursive: true, mode: 0o700 });
      fs.mkdirSync(expected, { mode: 0o700 });
    } catch (error) {
      throw new EvidenceError(error?.code === 'EEXIST' ? 'directory_exists' : 'directory_unwritable');
    }
    // The directory is written only where it was checked to be: a link
    // swapped in on the way while it was created is caught here.
    const real = fs.realpathSync.native(dir);
    if (real !== expected || evidenceLocationProblem(real, root) !== null) {
      try { fs.rmdirSync(expected); } catch { /* reported below */ }
      throw new EvidenceError('location_changed');
    }
    this.dir = real;
    this.redactor = redactor;
    this.lines = new Map();
    this.finalized = false;
  }

  file(name) {
    return path.join(this.dir, name);
  }

  /** Appends one sanitised JSON line; returns its reference `<file>#<line>`. */
  append(name, value) {
    if (this.finalized) throw new EvidenceError('finalized');
    const text = JSON.stringify(this.redactor.sanitize(value));
    fs.appendFileSync(this.file(name), `${text}\n`, { mode: 0o600 });
    const line = (this.lines.get(name) ?? 0) + 1;
    this.lines.set(name, line);
    return `${name}#${line}`;
  }

  /** Records an observation and returns its reference for assertions. */
  observe(procedure, what, value) {
    return this.append('observations.jsonl', { at: new Date().toISOString(), procedure, what, value });
  }

  writeJson(name, value) {
    if (this.finalized) throw new EvidenceError('finalized');
    fs.writeFileSync(this.file(name), `${JSON.stringify(this.redactor.sanitize(value), null, 2)}\n`, { mode: 0o600, flag: 'wx' });
  }

  /**
   * Leak scan and manifest. `extraFiles` (for example the residue ledger) are
   * scanned and hashed too.
   * @returns {{ leaks: { file: string, hits: object[] }[], manifest: object }}
   */
  finalize(extraFiles = []) {
    this.finalized = true;
    const leaks = [];
    const files = [];
    const names = fs.readdirSync(this.dir).filter((name) => name !== 'manifest.json').sort();
    const targets = [...names.map((name) => this.file(name)), ...extraFiles.filter((f) => fs.existsSync(f))];
    for (const file of targets) {
      if (!fs.statSync(file).isFile()) continue;
      const hits = this.redactor.scan(fs.readFileSync(file, 'utf8'));
      if (hits.length > 0) {
        const quarantined = `${file}.quarantine`;
        fs.renameSync(file, quarantined);
        leaks.push({ file: path.relative(this.dir, file), hits });
        continue;
      }
      files.push({ file: path.relative(this.dir, file), bytes: fs.statSync(file).size, sha256: sha256File(file) });
    }
    const manifest = { leakScan: leaks.length === 0 ? 'clean' : 'leaks_quarantined', leaks, files };
    fs.writeFileSync(this.file('manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
    return { leaks, manifest };
  }
}
