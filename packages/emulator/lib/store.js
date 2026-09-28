// In-memory state of one fixture instance and its in-process controls.
// Everything is synthetic. Passwords are held as scrypt hashes and every
// bearer value (link token hash, refresh token, OAuth code) only as a digest,
// so no snapshot, log or error can reveal one.
//
// State changes happen synchronously inside one request handler, after all
// awaits (body read, fingerprint hashing). Node runs one handler section at a
// time, which gives the per-client serialisation the SQL advisory lock gives.

import { validateModel, CLIENT_STATES } from '../../core/index.js';
import { isOpaqueKey, isPlainObject } from '../../core/shape.js';
import { checkPassword, digest, hashPassword, newId, newTotpSecret, randomToken, totpCode } from './crypto.js';

export const OPERATIONS = Object.freeze([
  'signup', 'verify_email', 'password_sign_in', 'recovery_request', 'verify_recovery', 'update_password',
  'oauth_exchange', 'mfa_enroll', 'mfa_verify', 'global_sign_out', 'ensure_profile', 'effective_access',
  'join_client', 'grant_membership', 'revoke_membership',
]);
export const FAULT_MODES = Object.freeze(['http_503', 'transport_loss', 'lost_after_commit', 'failed_before_commit']);
const READ_ONLY_OPERATIONS = new Set(['effective_access']);
const SIGNUP_POLICIES = new Set(['open', 'closed']);
const LINK_TYPES = new Set(['email', 'recovery']);
const EMAIL_PATTERN = /^[^\s@"<>()[\]\\,;:]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)+$/;
const MAX_EMAIL_CHARS = 254;
export const MIN_PASSWORD_CHARS = 6;
export const MAX_PASSWORD_BYTES = 72;

/** ISO-8601 UTC with microseconds, the format `auth_kit_private.iso_utc` returns. */
export function isoMicro(ms) {
  return new Date(Math.floor(ms)).toISOString().replace('Z', '000Z');
}

export function normalizeEmail(value) {
  if (typeof value !== 'string') return null;
  const email = value.trim().toLowerCase();
  return email.length <= MAX_EMAIL_CHARS && EMAIL_PATTERN.test(email) ? email : null;
}

/** null when acceptable, otherwise the Auth error code for the password. */
export function passwordProblem(password) {
  if (typeof password !== 'string' || password.length < MIN_PASSWORD_CHARS) return 'weak_password';
  if (Buffer.byteLength(password, 'utf8') > MAX_PASSWORD_BYTES) return 'validation_failed';
  return null;
}

export function createState({ now, accessTokenTtlSeconds, linkTtlSeconds }) {
  return {
    clock: { now },
    accessTokenTtlSeconds,
    linkTtlMs: linkTtlSeconds * 1000,
    flowTtlMs: 300_000,
    challengeTtlMs: 300_000,
    users: new Map(),
    usersByEmail: new Map(),
    sessions: new Map(),
    refreshTokens: new Map(),
    links: new Map(),
    flows: new Map(),
    challenges: new Map(),
    profiles: new Map(),
    clients: new Map(),
    requestLog: new Map(),
    counters: { mailsSent: 0, linksIssued: 0, linksUsed: 0 },
    requests: new Map(),
    faults: new Map(),
    oauthAccount: null,
  };
}

export function nowMs(state) {
  return Math.floor(state.clock.now);
}

export function createUser(state, { email, password, confirmed, provider = 'email', metadata = {} }) {
  const at = nowMs(state);
  const user = {
    id: newId(),
    email,
    password: password === null ? null : hashPassword(password),
    confirmedAt: confirmed ? at : null,
    createdAt: at,
    updatedAt: at,
    lastSignInAt: null,
    providers: new Map([[provider, newId()]]),
    metadata,
    factors: new Map(),
    currentLinks: { email: null, recovery: null },
  };
  state.users.set(user.id, user);
  state.usersByEmail.set(email, user.id);
  return user;
}

export function userByEmail(state, email) {
  const id = state.usersByEmail.get(email);
  return id === undefined ? null : state.users.get(id);
}

export function passwordMatches(user, password) {
  return user.password !== null && typeof password === 'string' && checkPassword(user.password, password);
}

export function addFactor(state, user, { friendlyName, verified }) {
  const at = nowMs(state);
  const factor = {
    id: newId(), friendlyName, secret: newTotpSecret(), status: verified ? 'verified' : 'unverified',
    createdAt: at, updatedAt: at,
  };
  user.factors.set(factor.id, factor);
  return factor;
}

/** A new mail supersedes the previous link of its type: that link stops working. */
export function supersedeLink(state, user, type) {
  const current = user.currentLinks[type];
  if (current !== null) state.links.delete(current);
  user.currentLinks[type] = null;
}

export function recordMail(state, user, type) {
  supersedeLink(state, user, type);
  state.counters.mailsSent += 1;
}

/** Consumes a link; returns its user or null (unknown, superseded, used or expired). */
export function consumeLink(state, tokenHash, type) {
  if (typeof tokenHash !== 'string' || tokenHash.length === 0 || tokenHash.length > 256) return null;
  const key = digest(tokenHash);
  const link = state.links.get(key);
  if (!link || link.type !== type) return null;
  state.links.delete(key);
  const user = state.users.get(link.userId);
  if (user && user.currentLinks[type] === key) user.currentLinks[type] = null;
  if (link.expiresAt <= nowMs(state) || !user) return null;
  state.counters.linksUsed += 1;
  return user;
}

export function membershipsOf(client, userId) {
  let held = client.memberships.get(userId);
  if (!held) {
    held = new Map();
    client.memberships.set(userId, held);
  }
  return held;
}

export function countRequest(state, name) {
  state.requests.set(name, (state.requests.get(name) ?? 0) + 1);
}

/** Removes and returns the pending fault for an operation, if any (faults are one-shot). */
export function takeFault(state, operation) {
  const mode = state.faults.get(operation);
  if (mode === undefined) return null;
  state.faults.delete(operation);
  return mode;
}

// Controls ---------------------------------------------------------------------

function fail(message) {
  throw new TypeError(`auth emulator: ${message}`);
}

function checkFields(input, allowed, name) {
  if (!isPlainObject(input)) fail(`${name} needs an options object.`);
  for (const key of Object.keys(input)) {
    if (!allowed.includes(key)) fail(`${name} does not accept that option.`);
  }
}

export function createControls(state) {
  return Object.freeze({
    seedClient(input) {
      checkFields(input, ['clientId', 'signupPolicy', 'model', 'state', 'managerUserId', 'managerRoleKey', 'displayName'], 'seedClient');
      const { clientId, signupPolicy, model, state: lifecycle = 'registered', managerUserId, managerRoleKey } = input;
      if (!isOpaqueKey(clientId)) fail('seedClient needs an opaque clientId string.');
      if (state.clients.has(clientId)) fail('seedClient: that client is already seeded.');
      if (!SIGNUP_POLICIES.has(signupPolicy)) fail("seedClient: signupPolicy must be 'open' or 'closed'.");
      if (!CLIENT_STATES.includes(lifecycle)) fail("seedClient: state must be 'registered' or 'live'.");
      const displayName = input.displayName ?? clientId;
      if (typeof displayName !== 'string' || displayName.length > 256) fail('seedClient: displayName must be a short string.');
      // A registered client may exist before any model is applied (join then
      // answers no_default_role); a live one always has a model and a manager.
      if (model === null && lifecycle !== 'registered') fail('seedClient: a live client needs a model.');
      const canonical = model === null ? null : validateModel(model, { clientId });
      const client = {
        clientId, displayName, signupPolicy, state: lifecycle,
        roles: new Map(canonical === null ? [] : Object.keys(canonical.roles).map((key) => [key, canonical.roles[key]])),
        memberships: new Map(), enrollments: new Map(), events: [],
      };
      if (lifecycle === 'live') {
        const manager = state.users.get(managerUserId);
        if (!manager) fail('seedClient: a live client must name a previously seeded manager user.');
        if (manager.confirmedAt === null) fail('seedClient: the manager user must be confirmed.');
        const role = typeof managerRoleKey === 'string' ? client.roles.get(managerRoleKey) : undefined;
        if (!role || !role.manages_members) fail('seedClient: managerRoleKey must name a model role with manages_members.');
        const at = nowMs(state);
        membershipsOf(client, manager.id).set(managerRoleKey, { grantedAt: at, grantedBy: null, grantedVia: 'operator' });
        client.events.push({ action: 'bootstrap', result: 'granted', userId: manager.id, roleKey: managerRoleKey,
          actorKind: 'operator', actorUserId: null, requestId: null, at });
      } else if (managerUserId !== undefined || managerRoleKey !== undefined) {
        fail('seedClient: only a live client names a manager.');
      }
      state.clients.set(clientId, client);
      return { clientId };
    },

    seedUser(input) {
      checkFields(input, ['email', 'password', 'confirmed', 'aal'], 'seedUser');
      const email = normalizeEmail(input.email);
      if (email === null) fail('seedUser needs a valid email address.');
      if (state.usersByEmail.has(email)) fail('seedUser: that email is already seeded.');
      if (passwordProblem(input.password) !== null) fail(`seedUser needs a password of ${MIN_PASSWORD_CHARS} to ${MAX_PASSWORD_BYTES} bytes.`);
      const confirmed = input.confirmed ?? true;
      const aal = input.aal ?? 'aal1';
      if (typeof confirmed !== 'boolean') fail('seedUser: confirmed must be a boolean.');
      if (aal !== 'aal1' && aal !== 'aal2') fail("seedUser: aal must be 'aal1' or 'aal2'.");
      const user = createUser(state, { email, password: input.password, confirmed });
      if (aal === 'aal1') return { userId: user.id };
      // aal2 means the user can reach aal2: a verified TOTP factor exists, so a
      // password session starts at aal1 and is raised by challenge/verify.
      const factor = addFactor(state, user, { friendlyName: 'fixture', verified: true });
      return { userId: user.id, factorId: factor.id };
    },

    issueLink(input) {
      checkFields(input, ['type', 'email'], 'issueLink');
      if (!LINK_TYPES.has(input.type)) fail("issueLink: type must be 'email' or 'recovery'.");
      const email = normalizeEmail(input.email);
      const user = email === null ? null : userByEmail(state, email);
      if (!user) fail('issueLink: no seeded or signed-up user has that email.');
      supersedeLink(state, user, input.type);
      // The shape of a Supabase token_hash: 56 lowercase hex characters.
      const tokenHash = Buffer.from(randomToken(28), 'base64url').toString('hex');
      const key = digest(tokenHash);
      state.links.set(key, { userId: user.id, type: input.type, expiresAt: nowMs(state) + state.linkTtlMs });
      user.currentLinks[input.type] = key;
      state.counters.linksIssued += 1;
      return { tokenHash };
    },

    setMembership(input) {
      checkFields(input, ['userId', 'clientId', 'roleKey', 'present'], 'setMembership');
      const user = state.users.get(input.userId);
      if (!user) fail('setMembership: unknown user.');
      const client = state.clients.get(input.clientId);
      if (!client) fail('setMembership: unknown client.');
      if (typeof input.roleKey !== 'string' || !client.roles.has(input.roleKey)) fail('setMembership: unknown role for that client.');
      if (typeof input.present !== 'boolean') fail('setMembership: present must be a boolean.');
      const held = membershipsOf(client, user.id);
      // A fixture edit, like a row changed in the SQL editor: no event, no
      // request log, and the enrollment ledger is never touched.
      if (input.present && !held.has(input.roleKey)) {
        held.set(input.roleKey, { grantedAt: nowMs(state), grantedBy: null, grantedVia: 'operator' });
        return { changed: true };
      }
      if (!input.present && held.has(input.roleKey)) {
        held.delete(input.roleKey);
        return { changed: true };
      }
      return { changed: false };
    },

    setFault(input) {
      checkFields(input, ['operation', 'mode'], 'setFault');
      if (!OPERATIONS.includes(input.operation)) fail('setFault: unsupported operation.');
      if (!FAULT_MODES.includes(input.mode)) fail('setFault: unsupported mode.');
      if (input.mode === 'lost_after_commit' && READ_ONLY_OPERATIONS.has(input.operation)) {
        fail('setFault: lost_after_commit needs a writing operation.');
      }
      state.faults.set(input.operation, input.mode);
    },

    advanceTime(ms) {
      if (typeof ms !== 'number' || !Number.isFinite(ms) || ms < 0) fail('advanceTime needs a finite nonnegative number of milliseconds.');
      state.clock.now += ms;
    },

    // Additions for frozen cases (documented in the package README).

    /** Current TOTP code of a factor at the fixture clock, for MFA flows in tests. */
    totpCode(input) {
      checkFields(input, ['factorId'], 'totpCode');
      for (const user of state.users.values()) {
        const factor = user.factors.get(input.factorId);
        if (factor) return totpCode(factor.secret, nowMs(state));
      }
      fail('totpCode: unknown factor.');
    },

    /**
     * Sets the Auth record's confirmation while sessions stay valid, the state
     * in which join_client answers email_unverified (it reads auth.users, never
     * the token). No session can otherwise exist for an unconfirmed address.
     */
    setEmailConfirmed(input) {
      checkFields(input, ['userId', 'confirmed'], 'setEmailConfirmed');
      const user = state.users.get(input.userId);
      if (!user) fail('setEmailConfirmed: unknown user.');
      if (typeof input.confirmed !== 'boolean') fail('setEmailConfirmed: confirmed must be a boolean.');
      user.confirmedAt = input.confirmed ? (user.confirmedAt ?? nowMs(state)) : null;
    },

    /** The Google account the fake consent screen signs in next; null makes it deny. */
    setOAuthAccount(input) {
      if (input === null) {
        state.oauthAccount = null;
        return;
      }
      checkFields(input, ['email'], 'setOAuthAccount');
      const email = normalizeEmail(input.email);
      if (email === null) fail('setOAuthAccount needs a valid email address.');
      state.oauthAccount = { email };
    },

    snapshot() {
      return snapshot(state);
    },
  });
}

function snapshot(state) {
  const users = [...state.users.values()].map((user) => ({
    userId: user.id,
    email: user.email,
    confirmed: user.confirmedAt !== null,
    providers: [...user.providers.keys()].sort(),
    factors: [...user.factors.values()].map((factor) => ({ factorId: factor.id, status: factor.status })),
  }));
  const clients = [...state.clients.values()].map((client) => {
    const memberships = [];
    for (const [userId, held] of client.memberships) {
      for (const [roleKey, row] of held) {
        memberships.push({ userId, roleKey, grantedVia: row.grantedVia, grantedBy: row.grantedBy });
      }
    }
    const requestLog = [...state.requestLog.entries()]
      .filter(([, row]) => row.clientId === client.clientId)
      .map(([requestId, row]) => ({ requestId, operation: row.operation, actorId: row.actorId, result: row.result.result }));
    return {
      clientId: client.clientId,
      signupPolicy: client.signupPolicy,
      state: client.state,
      roles: [...client.roles.keys()],
      enrollments: [...client.enrollments.entries()].map(([userId, row]) => ({
        userId, enrolledAt: isoMicro(row.enrolledAt), grantedRoles: [...row.grantedRoles],
      })),
      memberships,
      events: client.events.map((event) => ({ ...event, at: isoMicro(event.at) })),
      requestLog,
    };
  });
  const sum = (pick) => clients.reduce((total, client) => total + pick(client), 0);
  return {
    synthetic: true,
    now: isoMicro(nowMs(state)),
    counts: {
      users: users.length,
      confirmedUsers: users.filter((user) => user.confirmed).length,
      profiles: state.profiles.size,
      clients: clients.length,
      enrollments: sum((client) => client.enrollments.length),
      memberships: sum((client) => client.memberships.length),
      membershipEvents: sum((client) => client.events.length),
      requestLog: state.requestLog.size,
      activeSessions: [...state.sessions.values()].filter((session) => !session.revoked).length,
      mailsSent: state.counters.mailsSent,
      linksIssued: state.counters.linksIssued,
      linksUsed: state.counters.linksUsed,
    },
    users,
    profiles: [...state.profiles.keys()].map((userId) => ({ userId })),
    clients,
    httpRequests: Object.fromEntries([...state.requests.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))),
    pendingFaults: [...state.faults.entries()].map(([operation, mode]) => ({ operation, mode })),
  };
}
