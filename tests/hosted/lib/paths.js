// Where private files may live. Credentials must be outside every Git
// working tree; evidence and state must never be trackable by the public
// repository (outside it, or inside an ignored path such as internal/scratch).

import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

export const PUBLIC_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

/**
 * The Git working tree that contains `dir` (by Git's own discovery, so a
 * stray empty `.git` directory does not count), or null. When Git cannot be
 * run, any enclosing `.git` entry counts: the answer errs towards "inside".
 */
export function workingTreeOf(dir) {
  const env = { ...Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('GIT_'))), LC_ALL: 'C' };
  const result = spawnSync('git', ['-C', path.resolve(dir), 'rev-parse', '--show-toplevel'], { encoding: 'utf8', env });
  if (result.error === undefined && result.status === 0) return result.stdout.trim();
  if (result.error === undefined && /not a git repository/.test(result.stderr)) return null;
  let current = path.resolve(dir);
  for (;;) {
    if (fs.existsSync(path.join(current, '.git'))) return current;
    const parent = path.dirname(current);
    if (parent === current) return null;
    current = parent;
  }
}

function inside(child, parent) {
  const rel = path.relative(parent, child);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

/** True when `target` (existing or not) is ignored by the public repository. */
export function ignoredByPublic(target, root = PUBLIC_ROOT) {
  const rel = path.relative(root, path.resolve(target));
  const result = spawnSync('git', ['-C', root, 'check-ignore', '-q', '--no-index', rel], { stdio: 'ignore' });
  return result.status === 0;
}

/**
 * Evidence and state directories: outside the public working tree, or
 * inside it only where the public repository ignores them.
 * @returns {string | null} a problem tag, or null when allowed
 */
export function evidenceLocationProblem(target, root = PUBLIC_ROOT) {
  const abs = path.resolve(target);
  if (!inside(abs, root)) return null;
  return ignoredByPublic(abs, root) ? null : 'inside_public_tree';
}

/**
 * Credential files: a regular file outside every Git working tree, readable
 * by its owner only.
 * @returns {string | null} a problem tag, or null when allowed
 */
export function credentialFileProblem(file) {
  let stat;
  try {
    stat = fs.statSync(file);
  } catch {
    return 'unreadable';
  }
  if (!stat.isFile()) return 'not_a_file';
  if (workingTreeOf(path.dirname(file)) !== null) return 'inside_git_tree';
  if ((stat.mode & 0o077) !== 0) return 'group_or_world_accessible';
  return null;
}
