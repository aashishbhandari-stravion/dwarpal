// Headless browser controller (design 7): one state machine per page over the
// pinned supabase-js client. It owns the view; every other module returns
// values. Screens, a host page or tests drive it through its actions and read
// the frozen view it emits. The principal it shows is display state only
// (design 5.11): authorization happens in the consumer's server.
//
// This module is the single owner of the page's auth state; its actions share
// that state and one action slot, so they stay in one unit (pure parsing,
// view building and the onboarding pass live in lib/).
//
// Concurrency: one action runs at a time; a second call while one is running
// returns the current view without a request (a double click never sends a
// link, a sign-in or a join twice). Sign-out always runs: it supersedes the
// running action, whose later results are dropped, and it keeps later
// actions out until that action has finished and its possible session write
// has been wiped again.

import { createClient } from '@supabase/supabase-js';
import { validateClientConfig } from '../core/config.js';
import { resolveReturnPath } from '../core/redirect.js';
import { createKitStorage } from './lib/storage.js';
import { readLocation } from './lib/location.js';
import { authCall, authFailure, readAccessClaims, verifiedTotpFactors } from './lib/answers.js';
import { onboard, failureOutcome } from './lib/onboarding.js';
import { timedFetch } from './lib/fetch.js';
import { authErrorCode, linkRejected } from './lib/codes.js';
import { defaultEnv, isFlowId, isUuid, readAuthorizeUrl, readEnrolment, validEmail, validPassword, validTotpCode } from './lib/inputs.js';
import { composeView } from './lib/view.js';

export const BROWSER_STATES = Object.freeze([
  'idle', 'submitting', 'sent', 'error', 'expired_link', 'already_used',
  'mfa_enrol', 'mfa_challenge', 'setup_pending', 'no_access', 'signed_in', 'offline',
]);

const RESEND_COOLDOWN_MS = 60 * 1000;
const DEFAULT_TIMEOUT_MS = 20 * 1000;
const ALL_FLOWS = ['password', 'signup', 'oauth', 'recovery'];

class Superseded extends Error {}

export function createAuthController(options) {
  return new AuthController(options);
}

class AuthController {
  #config;
  #env;
  #client;
  #storage;
  #now;
  #mfaEnrolOptional;
  #autoNavigate;
  #listeners = new Set();
  #view;
  #epoch = 0;
  #busyEpoch = null;
  #inFlight = null;
  #signingOut = false;
  // Page-lifetime state, all in memory: the address the page was opened at,
  // the link waiting for a click, the last address typed, MFA progress.
  #started = false;
  #route = null;
  #requestedNext = null;
  #link = null;
  #lastEmail = null;
  #resendAt = null;
  #mfa = null;
  #enrolment = null;
  #mfaSkipped = false;
  #principal = null;
  #retry = null;
  // Set when sign-out could not remove the stored session: this page then
  // never resumes it, even though storage still holds it.
  #staleSession = false;

  constructor(options = {}) {
    if (options === null || typeof options !== 'object') throw new TypeError('createAuthController: options must be an object.');
    this.#config = validateClientConfig(options.config);
    this.#env = options.env ?? defaultEnv();
    this.#now = options.now ?? (() => Date.now());
    this.#mfaEnrolOptional = options.mfaEnrolOptional === true;
    this.#autoNavigate = options.autoNavigate !== false;
    const timeoutMs = options.requestTimeoutMs ?? DEFAULT_TIMEOUT_MS;
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 120000) throw new TypeError('createAuthController: requestTimeoutMs out of range.');
    this.#storage = createKitStorage({
      clientId: this.#config.clientId,
      localStorage: this.#env.localStorage,
      sessionStorage: this.#env.sessionStorage,
    });
    const fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.#client = createClient(this.#config.supabaseUrl, this.#config.publishableKey, {
      auth: {
        flowType: 'pkce',
        // The kit reads the address itself: links need a click and a
        // callback must match this tab's own flow record.
        detectSessionInUrl: false,
        persistSession: true,
        autoRefreshToken: options.autoRefreshToken !== false,
        storage: this.#storage.authAdapter,
        storageKey: this.#storage.authKey,
      },
      global: { fetch: timedFetch(fetchImpl, timeoutMs) },
    });
    this.#view = this.#compose({ screen: null, state: 'idle' });
  }

  get config() {
    return this.#config;
  }

  getView() {
    return this.#view;
  }

  /** Display state only; never an authorization decision. */
  getPrincipal() {
    return this.#view.principal;
  }

  subscribe(listener) {
    if (typeof listener !== 'function') throw new TypeError('subscribe: listener must be a function.');
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  dispose() {
    this.#listeners.clear();
    Promise.resolve().then(() => this.#client.auth.stopAutoRefresh()).catch(() => {});
  }

  /**
   * Reads the page address (first call only: its secrets are stripped then)
   * and the stored session, and settles the view. Later calls re-check the
   * session for the same page.
   */
  start() {
    return this.#act(async (epoch) => {
      if (!this.#started) {
        this.#started = true;
        const place = readLocation(this.#env, this.#config);
        this.#route = place.route;
        this.#requestedNext = place.next;
        if (place.link && (place.route === 'verify' || place.route === 'reset')) {
          const expected = place.route === 'verify' ? 'email' : 'recovery';
          const usable = place.link.tokenHash !== null && place.link.type === expected;
          this.#link = { tokenHash: usable ? place.link.tokenHash : null, type: expected, sent: false, consumed: false };
        }
        if (place.route === 'callback') return this.#completeCallback(epoch, place.callback);
      }
      if (this.#link && !this.#link.consumed && !this.#recoveryBlocks()) {
        if (this.#link.tokenHash === null) return this.#show(epoch, { screen: this.#route, state: 'expired_link' });
        return this.#show(epoch, { screen: this.#route, state: 'idle', link: true });
      }
      return this.#settle(epoch, ALL_FLOWS);
    });
  }

  signIn({ email, password } = {}) {
    return this.#act(async (epoch) => {
      if (!this.#config.providers.email) return this.#error(epoch, 'signIn', 'method_disabled');
      if (this.#recoveryBlocks()) return this.#showRecovery(epoch);
      if (!validEmail(email) || !validPassword(password)) return this.#error(epoch, 'signIn', 'invalid_input');
      this.#lastEmail = email;
      this.#startFlow('password', null);
      this.#show(epoch, { screen: 'signIn', state: 'submitting' });
      const result = await authCall(() => this.#client.auth.signInWithPassword({ email, password }));
      this.#check(epoch);
      if (result.failure) return this.#authFailure(epoch, 'signIn', 'signIn', result.failure);
      return this.#settle(epoch, ['password']);
    });
  }

  /** Always ends in the same neutral `sent` for a new or an existing address (L1). */
  signUp({ email, password } = {}) {
    return this.#act(async (epoch) => {
      if (!this.#config.selfSignup || !this.#config.providers.email) return this.#error(epoch, 'signUp', 'method_disabled');
      if (this.#recoveryBlocks()) return this.#showRecovery(epoch);
      if (!validEmail(email) || !validPassword(password)) return this.#error(epoch, 'signUp', 'invalid_input');
      this.#lastEmail = email;
      this.#startFlow('signup', null);
      this.#show(epoch, { screen: 'signUp', state: 'submitting' });
      const result = await authCall(() => this.#client.auth.signUp({
        email, password, options: { emailRedirectTo: this.#routeUrl('verify') },
      }));
      this.#check(epoch);
      if (result.failure) return this.#authFailure(epoch, 'signUp', 'signUp', result.failure);
      this.#resendAt = this.#now() + RESEND_COOLDOWN_MS;
      return this.#show(epoch, { screen: 'signUp', state: 'sent' });
    });
  }

  /** Resends the confirmation e-mail; ignored during the countdown. */
  resendConfirmation({ email } = {}) {
    return this.#act(async (epoch) => {
      const address = email ?? this.#lastEmail;
      const screen = this.#view.screen ?? 'verify';
      if (!validEmail(address)) return this.#error(epoch, screen, 'invalid_input');
      if (this.#resendAt !== null && this.#now() < this.#resendAt) return this.#view;
      this.#lastEmail = address;
      this.#show(epoch, { screen, state: 'submitting' });
      const result = await authCall(() => this.#client.auth.resend({
        type: 'signup', email: address, options: { emailRedirectTo: this.#routeUrl('verify') },
      }));
      this.#check(epoch);
      if (result.failure) return this.#authFailure(epoch, screen, 'signUp', result.failure);
      this.#resendAt = this.#now() + RESEND_COOLDOWN_MS;
      return this.#show(epoch, { screen, state: 'sent' });
    });
  }

  /**
   * Verifies the e-mail or recovery link on the page, only ever on this
   * explicit call (a prefetch or page load verifies nothing; L2).
   */
  confirmLink() {
    return this.#act((epoch) => this.#confirmLinkIn(epoch));
  }

  /** Starts Google sign-in with a fresh PKCE verifier bound to this tab's flow (L3). */
  startGoogle() {
    return this.#act(async (epoch) => {
      if (!this.#config.providers.google) return this.#error(epoch, 'signIn', 'method_disabled');
      if (this.#recoveryBlocks()) return this.#showRecovery(epoch);
      this.#show(epoch, { screen: 'signIn', state: 'submitting' });
      const result = await authCall(() => this.#client.auth.signInWithOAuth({
        provider: 'google',
        options: { redirectTo: this.#routeUrl('callback'), skipBrowserRedirect: true },
      }));
      this.#check(epoch);
      const target = result.failure ? null : readAuthorizeUrl(result.data?.url, this.#config.supabaseUrl);
      const flowId = result.data?.flowId;
      if (target === null || !isFlowId(flowId)) {
        this.#quietly(() => this.#storage.clearVerifiers());
        return this.#error(epoch, 'signIn', 'provider_unavailable');
      }
      if (!this.#startFlow('oauth', flowId)) return this.#error(epoch, 'signIn', 'unavailable');
      this.#env.navigate(target);
      return this.#view;
    });
  }

  requestRecovery({ email } = {}) {
    return this.#act(async (epoch) => {
      if (!this.#config.providers.email) return this.#error(epoch, 'forgot', 'method_disabled');
      if (this.#recoveryBlocks()) return this.#showRecovery(epoch);
      if (!validEmail(email)) return this.#error(epoch, 'forgot', 'invalid_input');
      this.#show(epoch, { screen: 'forgot', state: 'submitting' });
      const result = await authCall(() => this.#client.auth.resetPasswordForEmail(email, { redirectTo: this.#routeUrl('reset') }));
      this.#check(epoch);
      if (result.failure) return this.#authFailure(epoch, 'forgot', 'recovery', result.failure);
      return this.#show(epoch, { screen: 'forgot', state: 'sent' });
    });
  }

  /** Sets the new password in a recovery session; the marker stays until this succeeds (L13). */
  updatePassword({ password } = {}) {
    return this.#act(async (epoch) => {
      if (!this.#recoveryBlocks()) return this.#view;
      if (!validPassword(password)) return this.#error(epoch, 'reset', 'invalid_input', { recoveryPending: true });
      this.#show(epoch, { screen: 'reset', state: 'submitting', recoveryPending: true });
      const result = await authCall(() => this.#client.auth.updateUser({ password }));
      this.#check(epoch);
      if (result.failure) {
        const failure = result.failure;
        if (failure.kind === 'api' && failure.code === 'insufficient_aal') return this.#challengeForRecovery(epoch);
        const ended = failureOutcome(failure).kind === 'session_ended';
        if (ended) return this.#endSession(epoch);
        return this.#authFailure(epoch, 'reset', 'password', failure, { recoveryPending: true });
      }
      try {
        this.#storage.clearRecovery();
      } catch {
        return this.#error(epoch, 'reset', 'unavailable', { recoveryPending: true });
      }
      return this.#settle(epoch, ['recovery']);
    });
  }

  /** Creates the TOTP factor for the enrolment screen; once per page. */
  startMfaEnrol() {
    return this.#act(async (epoch) => {
      if (this.#mfa?.mode !== 'enrol' || this.#enrolment) return this.#view;
      this.#show(epoch, this.#mfaFields('submitting'));
      const result = await authCall(() => this.#client.auth.mfa.enroll({ factorType: 'totp' }));
      this.#check(epoch);
      if (result.failure) return this.#authFailure(epoch, 'mfa', 'mfa', result.failure, this.#mfaExtras());
      const enrolment = readEnrolment(result.data);
      if (!enrolment) return this.#error(epoch, 'mfa', 'unavailable', this.#mfaExtras());
      this.#enrolment = enrolment;
      return this.#show(epoch, this.#mfaFields('mfa_enrol'));
    });
  }

  /** Challenge and verify one TOTP code, then continue with the refreshed aal2 session (L14). */
  verifyMfa({ code } = {}) {
    return this.#act(async (epoch) => {
      const factorId = this.#mfa?.mode === 'enrol' ? this.#enrolment?.factorId : this.#mfa?.factorId;
      if (!factorId) return this.#view;
      if (!validTotpCode(code)) return this.#error(epoch, 'mfa', 'invalid_input', this.#mfaExtras());
      this.#show(epoch, this.#mfaFields('submitting'));
      const challenge = await authCall(() => this.#client.auth.mfa.challenge({ factorId }));
      this.#check(epoch);
      if (challenge.failure) return this.#mfaFailure(epoch, challenge.failure);
      const challengeId = challenge.data?.id;
      if (!isUuid(challengeId)) return this.#error(epoch, 'mfa', 'unavailable', this.#mfaExtras());
      const verified = await authCall(() => this.#client.auth.mfa.verify({ factorId, challengeId, code }));
      this.#check(epoch);
      if (verified.failure) return this.#mfaFailure(epoch, verified.failure);
      if (!(await this.#ensureAal2(epoch))) return this.#error(epoch, 'mfa', 'unavailable', this.#mfaExtras());
      this.#mfa = null;
      this.#enrolment = null;
      return this.#settle(epoch, ALL_FLOWS);
    });
  }

  /** Only when the host marked enrolment optional: withheld roles stay withheld. */
  skipMfaEnrol() {
    return this.#act(async (epoch) => {
      if (!this.#mfaEnrolOptional || this.#mfa?.mode !== 'enrol') return this.#view;
      this.#mfaSkipped = true;
      this.#mfa = null;
      return this.#settle(epoch, ALL_FLOWS);
    });
  }

  /** The explicit retry offered by `setup_pending`, `offline` and `unavailable`; never automatic. */
  retry() {
    return this.#act(async (epoch) => {
      const again = this.#retry;
      if (!again) return this.#view;
      return again(epoch);
    });
  }

  /**
   * Global sign-out. Local session, flow and marker state is cleared whether
   * or not Auth could be reached; the view reports both halves. The result is
   * published only once any action that was running has finished: a session
   * that action saved late is revoked globally too before the final clear, so
   * `revoked` and `skipped` are never claimed while a session may be live.
   */
  async signOut() {
    this.#epoch += 1;
    const epoch = this.#epoch;
    this.#busyEpoch = null;
    this.#signingOut = true;
    try {
      this.#show(epoch, { screen: 'signOut', state: 'submitting' });
      let remote = await this.#revokeStoredSession('skipped');
      let cleared = this.#clearLocal();
      // An action that was running may still save a session when its answer
      // arrives. New actions stay out until it has finished and any session
      // it saved has been revoked and cleared.
      const running = this.#inFlight;
      if (running) {
        await running.catch(() => {});
        if (this.#hasStoredSession()) {
          remote = await this.#revokeStoredSession(remote);
          cleared = this.#clearLocal() && cleared;
        }
      }
      const local = cleared ? 'cleared' : 'failed';
      this.#staleSession = !cleared;
      return this.#show(epoch, { screen: 'signOut', state: 'idle', signOut: { remote, local } });
    } catch (error) {
      if (error instanceof Superseded) return this.#view;
      throw error;
    } finally {
      if (epoch === this.#epoch) this.#signingOut = false;
    }
  }

  // Asks Auth to revoke the stored session everywhere. `previous` is the
  // outcome so far: once any revocation is unconfirmed, the result stays so.
  async #revokeStoredSession(previous) {
    if (!this.#hasStoredSession()) return previous;
    const result = await authCall(() => this.#client.auth.signOut({ scope: 'global' }));
    return result.failure || previous === 'unconfirmed' ? 'unconfirmed' : 'revoked';
  }

  // ---- internals -------------------------------------------------------

  #act(fn) {
    if (this.#busyEpoch !== null || this.#signingOut) return Promise.resolve(this.#view);
    const epoch = this.#epoch;
    this.#busyEpoch = epoch;
    const run = (async () => {
      try {
        return await fn(epoch);
      } catch (error) {
        if (error instanceof Superseded) return this.#view;
        // Anything unexpected (a storage exception, a malformed answer that
        // escaped a check) fails closed: never signed in on an exception.
        this.#retry = null;
        if (epoch === this.#epoch) this.#publish(this.#compose({ screen: this.#view.screen, state: 'error', error: 'unavailable' }));
        return this.#view;
      } finally {
        if (this.#busyEpoch === epoch) this.#busyEpoch = null;
      }
    })();
    this.#inFlight = run;
    run.finally(() => {
      if (this.#inFlight === run) this.#inFlight = null;
    }).catch(() => {});
    return run;
  }

  #check(epoch) {
    if (epoch !== this.#epoch) throw new Superseded();
  }

  async #settle(epoch, flows) {
    const retry = (e) => this.#settle(e, flows);
    if (this.#staleSession) {
      if (flows !== ALL_FLOWS) {
        this.#staleSession = false;
      } else {
        this.#staleSession = !this.#clearLocal();
        return this.#show(epoch, { screen: this.#route, state: 'idle' });
      }
    }
    const outcome = await onboard({
      client: this.#client,
      storage: this.#storage,
      config: this.#config,
      now: this.#now,
      mfaSkipped: this.#mfaSkipped,
    }, () => this.#check(epoch));
    this.#check(epoch);
    const screen = this.#route;
    switch (outcome.kind) {
      case 'no_session':
        this.#principal = null;
        // A marker without a session has nothing left to protect.
        this.#quietly(() => this.#storage.clearRecovery());
        return this.#show(epoch, { screen, state: 'idle' });
      case 'offline':
        return this.#show(epoch, { screen, state: 'offline', retry });
      case 'unavailable':
        return this.#show(epoch, { screen, state: 'error', error: 'unavailable', retry });
      case 'session_ended':
        return this.#endSession(epoch);
      case 'recovery_pending':
        return this.#showRecovery(epoch);
      case 'mfa_challenge':
        this.#mfa = { mode: 'challenge', factorId: outcome.factorId };
        return this.#show(epoch, this.#mfaFields('mfa_challenge'));
      case 'mfa_enrol':
        this.#principal = outcome.principal;
        this.#mfa = { mode: 'enrol', factorId: null };
        return this.#show(epoch, this.#mfaFields('mfa_enrol'));
      case 'setup_pending':
        return this.#show(epoch, { screen, state: 'setup_pending', setupReason: outcome.reason, retry });
      case 'no_access':
        this.#principal = outcome.principal;
        return this.#show(epoch, { screen, state: 'no_access' });
      case 'verify_email':
        return this.#show(epoch, { screen: 'verify', state: 'error', error: 'email_unverified' });
      case 'signed_in': {
        this.#principal = outcome.principal;
        const next = this.#takeNext(flows);
        const view = this.#show(epoch, { screen, state: 'signed_in', next });
        if (this.#autoNavigate && screen !== null && screen !== 'signOut') this.#env.navigate(next);
        return view;
      }
      default:
        return this.#show(epoch, { screen, state: 'error', error: 'unavailable', retry });
    }
  }

  // Runs inside an action slot (confirmLink or its retry).
  async #confirmLinkIn(epoch) {
    const link = this.#link;
    if (!link) return this.#view;
    const screen = link.type === 'email' ? 'verify' : 'reset';
    if (this.#recoveryBlocks()) return this.#showRecovery(epoch);
    if (link.consumed) return this.#show(epoch, { screen, state: 'already_used' });
    if (link.tokenHash === null) return this.#show(epoch, { screen, state: 'expired_link' });

    // The marker is set before the session can exist, so a recovery session
    // is never usable without it, even if the page dies right after Auth
    // answers. It is put back only when Auth certainly issued nothing here.
    const previousMarker = link.type === 'recovery' ? this.#storage.readRecoveryRaw() : null;
    if (link.type === 'recovery') this.#storage.writeRecovery('verifying', null);
    const firstSend = !link.sent;
    link.sent = true;
    this.#show(epoch, { screen, state: 'submitting' });
    let failure = null;
    let data = null;
    let threw = false;
    try {
      const answer = await this.#client.auth.verifyOtp({ token_hash: link.tokenHash, type: link.type });
      if (answer?.error) failure = authFailure(answer.error);
      else data = answer?.data ?? null;
    } catch (error) {
      // A throw can come from saving the session after Auth answered: the
      // marker then stays, and the next pass shows the reset screen.
      threw = true;
      failure = authFailure(error);
    }
    this.#check(epoch);
    if (failure || !data?.session) {
      if (link.type === 'recovery' && !threw) this.#storage.restoreRecoveryRaw(previousMarker);
      return this.#linkFailure(epoch, screen, link, firstSend, failure ?? { kind: 'unavailable' });
    }
    link.consumed = true;
    link.tokenHash = null;
    if (link.type === 'recovery') {
      const userId = isUuid(data.user?.id) ? data.user.id.toLowerCase() : null;
      this.#storage.writeRecovery('pending', userId);
      return this.#showRecovery(epoch);
    }
    return this.#settle(epoch, ['signup']);
  }

  async #completeCallback(epoch, callback) {
    if (this.#recoveryBlocks()) return this.#showRecovery(epoch);
    const record = this.#readFlowQuietly();
    // Only this tab's own, fresh Google flow may be completed, and only with
    // its own verifier: anything else stores nothing (L3, L8).
    if (callback.providerError || callback.code === null || record?.kind !== 'oauth') {
      this.#abandonOAuth();
      return this.#error(epoch, 'callback', 'provider_unavailable');
    }
    this.#show(epoch, { screen: 'callback', state: 'submitting' });
    const result = await authCall(() => this.#client.auth.exchangeCodeForSession(callback.code, { flowId: record.id }));
    this.#check(epoch);
    if (result.failure || !result.data?.session) {
      this.#abandonOAuth();
      return this.#error(epoch, 'callback', 'provider_unavailable');
    }
    return this.#settle(epoch, ['oauth']);
  }

  #abandonOAuth() {
    this.#quietly(() => this.#storage.clearFlow());
    this.#quietly(() => this.#storage.clearVerifiers());
  }

  #linkFailure(epoch, screen, link, firstSend, failure) {
    if (linkRejected(failure)) {
      link.tokenHash = null;
      // Auth refuses a used and an expired token alike. If this page already
      // sent this token once and lost the answer, it was most likely used.
      return this.#show(epoch, { screen, state: firstSend ? 'expired_link' : 'already_used' });
    }
    const retry = (e) => this.#confirmLinkIn(e);
    if (failure.kind === 'offline') return this.#show(epoch, { screen, state: 'offline', link: true, retry });
    const code = failure.kind === 'api' && failure.status === 429 ? 'rate_limited' : 'unavailable';
    return this.#show(epoch, { screen, state: 'error', error: code, link: true, retry });
  }

  #mfaFailure(epoch, failure) {
    if (failure.kind === 'session_missing' || (failure.kind === 'api' && failure.status === 401)) return this.#endSession(epoch);
    return this.#authFailure(epoch, 'mfa', 'mfa', failure, this.#mfaExtras());
  }

  // After verify, supabase-js has saved Auth's new session; its token must
  // carry aal2 before any read, or the server would still withhold roles.
  // One explicit refresh is attempted when it does not.
  async #ensureAal2(epoch) {
    const current = async () => {
      const read = await authCall(() => this.#client.auth.getSession());
      this.#check(epoch);
      try {
        return readAccessClaims(read.data?.session?.access_token).aal;
      } catch {
        return null;
      }
    };
    if ((await current()) === 'aal2') return true;
    const refreshed = await authCall(() => this.#client.auth.refreshSession());
    this.#check(epoch);
    if (refreshed.failure) return false;
    return (await current()) === 'aal2';
  }

  async #challengeForRecovery(epoch) {
    const read = await authCall(() => this.#client.auth.getUser());
    this.#check(epoch);
    let factors = [];
    try {
      factors = read.failure ? [] : verifiedTotpFactors(read.data?.user);
    } catch {
      factors = [];
    }
    if (factors.length === 0) return this.#error(epoch, 'reset', 'unavailable', { recoveryPending: true });
    this.#mfa = { mode: 'challenge', factorId: factors[0] };
    return this.#show(epoch, { ...this.#mfaFields('mfa_challenge'), recoveryPending: true });
  }

  #endSession(epoch) {
    this.#principal = null;
    this.#mfa = null;
    this.#enrolment = null;
    this.#clearLocal();
    return this.#show(epoch, { screen: 'signIn', state: 'error', error: 'session_ended' });
  }

  #clearLocal() {
    this.#principal = null;
    this.#mfa = null;
    this.#enrolment = null;
    this.#mfaSkipped = false;
    this.#link = null;
    this.#retry = null;
    return this.#storage.wipe();
  }

  #hasStoredSession() {
    try {
      return this.#storage.hasSession();
    } catch {
      return true;
    }
  }

  // A pending recovery (marker plus a session) confines the page to the
  // reset screen. An unreadable store counts as pending.
  #recoveryBlocks() {
    try {
      return this.#storage.readRecovery() !== null && this.#storage.hasSession();
    } catch {
      return true;
    }
  }

  #showRecovery(epoch) {
    return this.#show(epoch, { screen: 'reset', state: 'idle', recoveryPending: true });
  }

  #startFlow(kind, id) {
    try {
      this.#storage.writeFlow({ kind, id, next: this.#requestedNext ?? this.#config.defaultReturnPath, at: this.#now() });
      return true;
    } catch {
      return false;
    }
  }

  #readFlowQuietly() {
    try {
      return this.#storage.readFlow(this.#now());
    } catch {
      return null;
    }
  }

  // The stored return path is re-validated on read: storage is as untrusted
  // as the query string it came from.
  #takeNext(flows) {
    const record = this.#readFlowQuietly();
    this.#quietly(() => this.#storage.clearFlow());
    if (record && flows.includes(record.kind)) return resolveReturnPath(record.next, this.#config);
    return this.#requestedNext ?? this.#config.defaultReturnPath;
  }

  #routeUrl(name) {
    return `${this.#config.origin}${this.#config.routes[name]}`;
  }

  #authFailure(epoch, screen, table, failure, extras = {}) {
    if (failure.kind === 'offline') return this.#show(epoch, { screen, state: 'offline', ...extras });
    const code = authErrorCode(table, failure);
    if (code === 'sent') {
      // Neutral outcomes: the same answer whether or not the address exists.
      this.#resendAt = this.#now() + RESEND_COOLDOWN_MS;
      return this.#show(epoch, { screen, state: 'sent', ...extras });
    }
    return this.#error(epoch, screen, code, extras);
  }

  #error(epoch, screen, code, extras = {}) {
    return this.#show(epoch, { screen, state: 'error', error: code, ...extras });
  }

  #mfaExtras() {
    return {
      mfa: this.#mfaView(),
      recoveryPending: this.#view.recoveryPending,
    };
  }

  #mfaFields(state) {
    return { screen: 'mfa', state, ...this.#mfaExtras() };
  }

  #mfaView() {
    if (!this.#mfa) return null;
    const enrolment = this.#mfa.mode === 'enrol' && this.#enrolment
      ? { qrCode: this.#enrolment.qrCode, secret: this.#enrolment.secret, uri: this.#enrolment.uri }
      : null;
    return { mode: this.#mfa.mode, optional: this.#mfa.mode === 'enrol' && this.#mfaEnrolOptional, enrolment };
  }

  #quietly(fn) {
    try {
      fn();
    } catch {
      // cleanup that cannot run leaves the state it found; callers never
      // depend on it for a security decision
    }
  }

  #show(epoch, fields) {
    this.#check(epoch);
    this.#retry = fields.retry ?? null;
    return this.#publish(this.#compose(fields));
  }

  #compose(fields) {
    return composeView(fields, { principal: this.#principal, resendAt: this.#resendAt });
  }

  #publish(view) {
    this.#view = view;
    for (const listener of [...this.#listeners]) {
      try {
        listener(view);
      } catch {
        // a failing listener must not stop the controller or other listeners
      }
    }
    return view;
  }
}
