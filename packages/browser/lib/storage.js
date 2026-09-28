// Browser storage owned by the kit. Every key the kit or supabase-js writes
// for one client starts with the same prefix, so sign-out can find and remove
// all of them without knowing supabase-js's internal key names:
//
//   dwarpal:<client>:auth                  session (localStorage, via supabase-js)
//   dwarpal:<client>:auth-user             split user record, if supabase-js writes one
//   dwarpal:<client>:auth-...code-verifier PKCE verifiers (sessionStorage, via supabase-js)
//   dwarpal:<client>:flow                  the tab's pending flow and its return path (sessionStorage)
//   dwarpal:<client>:recovery              the recovery_pending marker (localStorage)
//
// The client id is URI-encoded so one client's prefix can never be a prefix
// of another client's keys (`:` never appears in an encoded id).
//
// PKCE verifiers live in sessionStorage, which is private to one tab, so two
// tabs that start Google sign-in at the same time keep separate verifiers.
// The session lives in localStorage (design D11) and is shared by all tabs,
// and so is the recovery marker: a second tab must not escape a pending reset.

const ROOT = 'dwarpal:';
const VERIFIER_SUFFIX = '-code-verifier';
const FLOW_KINDS = new Set(['password', 'signup', 'oauth', 'recovery']);
const FLOW_ID_PATTERN = /^[A-Za-z0-9_-]{8,64}$/;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_NEXT_LENGTH = 2048;

// Flow records expire so a callback or link that arrives long after its start
// is treated as stale. Google's round trip is short; an e-mail may wait.
const FLOW_TTL_MS = Object.freeze({
  oauth: 10 * 60 * 1000,
  password: 30 * 60 * 1000,
  signup: 24 * 60 * 60 * 1000,
  recovery: 60 * 60 * 1000,
});

export function storagePrefix(clientId) {
  return `${ROOT}${encodeURIComponent(clientId)}:`;
}

/**
 * @param {{ clientId: string, localStorage?: Storage | null, sessionStorage?: Storage | null }} options
 */
export function createKitStorage({ clientId, localStorage, sessionStorage }) {
  const prefix = storagePrefix(clientId);
  const local = usableArea(localStorage);
  const tab = usableArea(sessionStorage);
  const authKey = `${prefix}auth`;
  const flowKey = `${prefix}flow`;
  const recoveryKey = `${prefix}recovery`;

  // The adapter supabase-js uses for everything under `authKey`. Values are
  // the strings supabase-js serializes; they pass through untouched.
  const authAdapter = Object.freeze({
    getItem: (key) => areaFor(key).getItem(key),
    setItem: (key, value) => areaFor(key).setItem(key, value),
    removeItem: (key) => areaFor(key).removeItem(key),
  });

  function areaFor(key) {
    if (typeof key !== 'string' || !key.startsWith(authKey)) throw new TypeError('kit storage: foreign key');
    return key.endsWith(VERIFIER_SUFFIX) ? tab : local;
  }

  return Object.freeze({
    prefix,
    authKey,
    authAdapter,
    persistent: local.persistent,

    hasSession() {
      return readRaw(local, authKey) !== null;
    },

    /** @param {{ kind: string, id?: string | null, next: string, at: number }} record */
    writeFlow(record) {
      tab.setItem(flowKey, JSON.stringify({ v: 1, kind: record.kind, id: record.id ?? null, next: record.next, at: record.at }));
    },

    /**
     * The tab's pending flow, or null when absent, malformed or outside its
     * lifetime. A timestamp in the future (the clock moved back) is stale too.
     */
    readFlow(nowMs) {
      const value = parseJson(readRaw(tab, flowKey));
      if (!isRecord(value) || value.v !== 1 || !FLOW_KINDS.has(value.kind)) return null;
      if (value.kind === 'oauth' ? !FLOW_ID_PATTERN.test(value.id) : value.id !== null) return null;
      if (typeof value.next !== 'string' || value.next.length > MAX_NEXT_LENGTH) return null;
      if (!Number.isFinite(value.at)) return null;
      const age = nowMs - value.at;
      if (age < 0 || age > FLOW_TTL_MS[value.kind]) return null;
      return { kind: value.kind, id: value.id, next: value.next, at: value.at };
    },

    clearFlow() {
      tab.removeItem(flowKey);
    },

    /** Removes this tab's PKCE verifiers without touching the session. */
    clearVerifiers() {
      for (const key of keysWithPrefix(tab, authKey)) {
        if (key.endsWith(VERIFIER_SUFFIX)) tab.removeItem(key);
      }
      tab.removeItem(`${authKey}-flows${VERIFIER_SUFFIX}`);
    },

    /**
     * The recovery marker. Anything present but unreadable counts as pending:
     * the marker only ever narrows what a session may do, so a damaged one
     * must not release it.
     * @returns {{ phase: 'verifying' | 'pending', userId: string | null } | null}
     */
    readRecovery() {
      const raw = readRaw(local, recoveryKey);
      if (raw === null) return null;
      const value = parseJson(raw);
      if (isRecord(value) && value.v === 1 && (value.phase === 'verifying' || value.phase === 'pending')
          && (value.userId === null || (typeof value.userId === 'string' && UUID_PATTERN.test(value.userId)))) {
        return { phase: value.phase, userId: value.userId };
      }
      return { phase: 'pending', userId: null };
    },

    readRecoveryRaw() {
      return readRaw(local, recoveryKey);
    },

    /** Puts back a raw marker value read earlier (or removes it when it was absent). */
    restoreRecoveryRaw(raw) {
      if (raw === null) local.removeItem(recoveryKey);
      else local.setItem(recoveryKey, raw);
    },

    writeRecovery(phase, userId) {
      local.setItem(recoveryKey, JSON.stringify({ v: 1, phase, userId }));
    },

    clearRecovery() {
      local.removeItem(recoveryKey);
    },

    /**
     * Removes every key under this client's prefix from both areas, then
     * checks that none is left. Each removal is attempted even when an
     * earlier one throws; the result says whether the areas are now clean.
     */
    wipe() {
      let clean = true;
      for (const area of [local, tab]) {
        let keys;
        try {
          keys = keysWithPrefix(area, prefix);
        } catch {
          clean = false;
          continue;
        }
        for (const key of keys) {
          try {
            area.removeItem(key);
          } catch {
            clean = false;
          }
        }
        try {
          if (keysWithPrefix(area, prefix).length > 0) clean = false;
        } catch {
          clean = false;
        }
      }
      return clean;
    },
  });
}

function readRaw(area, key) {
  const value = area.getItem(key);
  return typeof value === 'string' ? value : null;
}

function parseJson(raw) {
  if (raw === null) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return undefined;
  }
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function keysWithPrefix(area, prefix) {
  const keys = [];
  for (let i = 0; i < area.length; i += 1) {
    const key = area.key(i);
    if (typeof key === 'string' && key.startsWith(prefix)) keys.push(key);
  }
  return keys;
}

// Web Storage can be missing or throw on access (disabled cookies, some
// private modes). Such an area is replaced by a per-page memory area: the
// kit keeps working for the page's lifetime and simply does not persist.
function usableArea(area) {
  try {
    if (area && typeof area.getItem === 'function') {
      const probe = `${ROOT}probe`;
      area.setItem(probe, '1');
      area.removeItem(probe);
      return wrapArea(area, true);
    }
  } catch {
    // fall through to memory
  }
  return wrapArea(memoryArea(), false);
}

function wrapArea(area, persistent) {
  return {
    persistent,
    get length() {
      return area.length;
    },
    key: (i) => area.key(i),
    getItem: (key) => area.getItem(key),
    setItem: (key, value) => area.setItem(key, value),
    removeItem: (key) => area.removeItem(key),
  };
}

function memoryArea() {
  const map = new Map();
  return {
    get length() {
      return map.size;
    },
    key: (i) => [...map.keys()][i] ?? null,
    getItem: (key) => (map.has(key) ? map.get(key) : null),
    setItem: (key, value) => void map.set(key, String(value)),
    removeItem: (key) => void map.delete(key),
  };
}
