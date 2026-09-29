// Where private files may live. Credentials must be outside every Git
// working tree; evidence and state must never be trackable by the public
// repository (outside it, or inside an ignored path such as internal/scratch).
// Every decision is made on the resolved location: existing components are
// canonicalised (symlinks followed), a symlinked credential file, a dangling
// symlink on the way to an evidence directory and a hard-linked credential
// file are refused, so no link can carry a secret or evidence into a tree.

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

export class PathError extends Error {
  constructor(reason) {
    super(`path: ${reason}`);
    this.name = 'PathError';
    this.reason = reason;
  }
}

/**
 * `target` with every existing component resolved (symlinks followed) and
 * the missing trailing components appended. A missing component that is a
 * (dangling) symlink, or an unreadable one, throws PathError: creating
 * through it could land anywhere.
 */
export function canonicalPath(target) {
  let current = path.resolve(target);
  const rest = [];
  for (;;) {
    try {
      const real = fs.realpathSync.native(current);
      return rest.length === 0 ? real : path.join(real, ...rest.reverse());
    } catch (error) {
      if (error?.code !== 'ENOENT') throw new PathError('unresolvable_path');
      let link = false;
      try {
        link = fs.lstatSync(current).isSymbolicLink();
      } catch (inner) {
        if (inner?.code !== 'ENOENT' && inner?.code !== 'ENOTDIR') throw new PathError('unresolvable_path');
      }
      if (link) throw new PathError('dangling_symlink');
      const parent = path.dirname(current);
      if (parent === current) throw new PathError('unresolvable_path');
      rest.push(path.basename(current));
      current = parent;
    }
  }
}

/** True when `target` (existing or not) is ignored by the public repository. */
export function ignoredByPublic(target, root = PUBLIC_ROOT) {
  const rel = path.relative(root, path.resolve(target));
  const result = spawnSync('git', ['-C', root, 'check-ignore', '-q', '--no-index', rel], { stdio: 'ignore' });
  return result.status === 0;
}

/**
 * Evidence and state directories: resolved, outside the public working tree,
 * or inside it only where the public repository ignores them.
 * @returns {string | null} a problem tag, or null when allowed
 */
export function evidenceLocationProblem(target, root = PUBLIC_ROOT) {
  let abs;
  let realRoot;
  try {
    abs = canonicalPath(target);
    realRoot = canonicalPath(root);
  } catch (error) {
    if (error instanceof PathError) return error.reason;
    throw error;
  }
  if (!inside(abs, realRoot)) return null;
  return ignoredByPublic(abs, realRoot) ? null : 'inside_public_tree';
}

function statProblem(stat, file) {
  if (!stat.isFile()) return 'not_a_file';
  if (stat.nlink !== 1) return 'hard_linked';
  let dir;
  try {
    dir = fs.realpathSync.native(path.dirname(path.resolve(file)));
  } catch {
    return 'unreadable';
  }
  if (workingTreeOf(dir) !== null) return 'inside_git_tree';
  if ((stat.mode & 0o077) !== 0) return 'group_or_world_accessible';
  return null;
}

/**
 * Credential files: a regular, singly linked file (not a symlink) whose
 * resolved directory is outside every Git working tree, readable by its
 * owner only.
 * @returns {string | null} a problem tag, or null when allowed
 */
export function credentialFileProblem(file) {
  let stat;
  try {
    stat = fs.lstatSync(file);
  } catch {
    return 'unreadable';
  }
  if (stat.isSymbolicLink()) return 'symlink';
  return statProblem(stat, file);
}

/**
 * Reads a credential file through one descriptor opened without following a
 * final symlink, and checks that same file, so it cannot be swapped between
 * the check and the read.
 * @returns {{ problem: string } | { text: string }}
 */
export function readCredentialFile(file) {
  const early = credentialFileProblem(file);
  if (early) return { problem: early };
  let fd;
  try {
    fd = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  } catch (error) {
    return { problem: error?.code === 'ELOOP' ? 'symlink' : 'unreadable' };
  }
  try {
    const problem = statProblem(fs.fstatSync(fd), file);
    return problem ? { problem } : { text: fs.readFileSync(fd, 'utf8') };
  } finally {
    fs.closeSync(fd);
  }
}
