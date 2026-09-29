// Residue ledger: a write-ahead record of everything the harness creates on
// the target. The intent line is flushed to disk before the creating call is
// sent, so a crash, a lost answer or a killed process still leaves a record
// that `run.js cleanup` can act on. Lines hold kinds, aliases, ids and fixed
// statement names only: no e-mail address (it is regenerated from the run id
// and the descriptor's template), password, token or key.
//
//   intent    about to create <kind> <key>
//   created   the target confirmed it (with the id when there is one)
//   removed   cleanup confirmed it is gone (or was never created)
//   residue   cleanup could not remove it; the reason is kept

import fs from 'node:fs';
import path from 'node:path';

export const LEDGER_KINDS = Object.freeze(['user', 'client', 'notes', 'grant_widening', 'fault_trigger']);
const KIND_SET = new Set(LEDGER_KINDS);
const KEY = /^[A-Za-z0-9_.:@-]{1,128}$/;

export class Ledger {
  constructor(file) {
    this.file = path.resolve(file);
    fs.mkdirSync(path.dirname(this.file), { recursive: true, mode: 0o700 });
  }

  write(op, kind, key, data = {}) {
    if (!KIND_SET.has(kind) || !KEY.test(key)) throw new TypeError(`ledger: bad ${kind} ${key}`);
    const line = `${JSON.stringify({ at: new Date().toISOString(), op, kind, key, ...data })}\n`;
    const fd = fs.openSync(this.file, 'a', 0o600);
    try {
      fs.writeSync(fd, line);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
  }

  intent(kind, key, data) {
    this.write('intent', kind, key, data);
  }

  created(kind, key, data) {
    this.write('created', kind, key, data);
  }

  removed(kind, key, data) {
    this.write('removed', kind, key, data);
  }

  residue(kind, key, reason) {
    this.write('residue', kind, key, { reason });
  }

  /** Every entry whose latest state is not `removed`, with its known id. */
  outstanding() {
    let text;
    try {
      text = fs.readFileSync(this.file, 'utf8');
    } catch (error) {
      if (error?.code === 'ENOENT') return [];
      throw error;
    }
    const state = new Map();
    for (const line of text.split('\n')) {
      if (line.trim() === '') continue;
      let entry;
      try {
        entry = JSON.parse(line);
      } catch {
        // A torn last line from a crash: the entry before it still stands.
        continue;
      }
      const id = `${entry.kind}:${entry.key}`;
      const prev = state.get(id) ?? {};
      state.set(id, { ...prev, ...entry, id: entry.id ?? prev.id ?? null });
    }
    return [...state.values()].filter((e) => e.op !== 'removed');
  }
}
