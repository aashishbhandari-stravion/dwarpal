// The consumer's own data: records, the identity-to-record links this
// application audits itself, and the link events. The kit never stores any of
// this (manual rule 6). Node's built-in SQLite (`node:sqlite`, Node 22.13+ or
// 24) keeps the example dependency-free.
//
// Every failure of the file, a lock or the schema becomes StoreUnavailableError.
// The application answers 503 for it and never guesses an answer: an
// unreadable link table must not turn "own" access into "any" or "none".

import { DatabaseSync } from 'node:sqlite';

export class StoreUnavailableError extends Error {
  constructor() {
    super('the consumer data store is unavailable');
    this.name = 'StoreUnavailableError';
  }
}

const SCHEMA = `
create table if not exists records (
  id text primary key,
  title text not null,
  -- Historical contact data. It is never a lookup key for access: a verified
  -- sign-in email that equals it grants nothing without a link row (manual rule 6).
  contact_email text
) strict;
create table if not exists record_links (
  record_id text not null references records(id),
  user_id text not null,
  linked_by text not null,
  linked_at text not null,
  primary key (record_id, user_id)
) strict;
create table if not exists link_events (
  id integer primary key,
  record_id text not null,
  user_id text not null,
  action text not null check (action in ('link', 'unlink')),
  actor_id text not null,
  at text not null
) strict;
`;

/**
 * @param {string} file Database path (or ':memory:').
 * @param {{ busyTimeoutMs?: number, now?: () => Date }} [options]
 */
export function createStore(file, { busyTimeoutMs = 2000, now = () => new Date() } = {}) {
  let db;
  try {
    db = new DatabaseSync(file);
    db.exec(`pragma busy_timeout = ${Math.trunc(busyTimeoutMs)}; pragma foreign_keys = on; pragma journal_mode = wal;`);
    db.exec(SCHEMA);
  } catch {
    try { db?.close(); } catch { /* already unusable */ }
    throw new StoreUnavailableError();
  }

  // Runs `work` and maps any failure to StoreUnavailableError.
  function guarded(work) {
    try {
      return work();
    } catch {
      throw new StoreUnavailableError();
    }
  }

  // One writer transaction; a lock that outlasts the busy timeout fails the
  // whole call and leaves nothing behind.
  function writing(work) {
    return guarded(() => {
      db.exec('begin immediate');
      try {
        const result = work();
        db.exec('commit');
        return result;
      } catch (error) {
        db.exec('rollback');
        throw error;
      }
    });
  }

  const insertRecord = db.prepare('insert or ignore into records (id, title, contact_email) values (?, ?, ?)');
  const selectRecord = db.prepare('select id, title from records where id = ?');
  const selectAll = db.prepare('select id, title from records order by id');
  const selectOwn = db.prepare('select r.id, r.title from records r join record_links l on l.record_id = r.id where l.user_id = ? order by r.id');
  const selectLink = db.prepare('select 1 as linked from record_links where record_id = ? and user_id = ?');
  const insertLink = db.prepare('insert or ignore into record_links (record_id, user_id, linked_by, linked_at) values (?, ?, ?, ?)');
  const deleteLink = db.prepare('delete from record_links where record_id = ? and user_id = ?');
  const insertEvent = db.prepare('insert into link_events (record_id, user_id, action, actor_id, at) values (?, ?, ?, ?, ?)');
  const selectEvents = db.prepare('select record_id, user_id, action, actor_id from link_events order by id');

  return Object.freeze({
    /** Seeds a record; an existing id is left unchanged. */
    createRecord: ({ id, title, contactEmail = null }) => guarded(() => { insertRecord.run(id, title, contactEmail); }),
    getRecord: (id) => guarded(() => selectRecord.get(id) ?? null),
    listAll: () => guarded(() => selectAll.all()),
    listLinked: (userId) => guarded(() => selectOwn.all(userId)),
    isLinked: (recordId, userId) => guarded(() => selectLink.get(recordId, userId) !== undefined),
    /**
     * Idempotent: a repeat writes neither a second link nor a second event.
     * @returns {'linked' | 'already_linked' | 'unknown_record'}
     */
    link: (recordId, userId, actorId) => writing(() => {
      if (selectRecord.get(recordId) === undefined) return 'unknown_record';
      const at = now().toISOString();
      if (insertLink.run(recordId, userId, actorId, at).changes === 0) return 'already_linked';
      insertEvent.run(recordId, userId, 'link', actorId, at);
      return 'linked';
    }),
    /** @returns {'unlinked' | 'not_linked'} */
    unlink: (recordId, userId, actorId) => writing(() => {
      if (deleteLink.run(recordId, userId).changes === 0) return 'not_linked';
      insertEvent.run(recordId, userId, 'unlink', actorId, now().toISOString());
      return 'unlinked';
    }),
    events: () => guarded(() => selectEvents.all().map((row) => ({ ...row }))),
    close: () => { try { db.close(); } catch { /* already closed */ } },
  });
}
