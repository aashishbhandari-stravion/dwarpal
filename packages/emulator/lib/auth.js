// The Supabase Auth (GoTrue) subset the browser kit calls through
// supabase-js 2.117.2. Errors use the API-version 2024-01-01 body
// `{ code, message }` that auth-js reads for its error codes. Every handler
// is synchronous: it runs as one uninterrupted state change.

import { digest, hashPassword, newId, pkceChallenge, randomToken, totpMatches } from './crypto.js';
import { isLoopbackUrl } from './http.js';
import {
  addFactor, consumeLink, createUser, isoMicro, normalizeEmail, nowMs, passwordMatches, passwordProblem, recordMail,
  userByEmail,
} from './store.js';

const MAX_METADATA_CHARS = 4096;
const MAX_FACTORS = 10;
const VERIFY_TYPES = new Map([['email', 'email'], ['signup', 'email'], ['magiclink', 'email'], ['recovery', 'recovery']]);
const LOGOUT_SCOPES = new Set(['global', 'local', 'others']);
const PKCE_CHALLENGE = /^[A-Za-z0-9_-]{43,128}$/;
const PLACEHOLDER_QR = '<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><title>synthetic fixture factor</title></svg>';

export function authError(status, code, message, extra = {}) {
  return { status, body: { code, message, ...extra } };
}

const ok = (body) => ({ status: 200, body });

function text(value, max) {
  return typeof value === 'string' && value.length > 0 && value.length <= max ? value : null;
}

// Response shapes ---------------------------------------------------------------

function iso(ms) {
  return ms === null ? undefined : isoMicro(ms);
}

function appMetadata(user) {
  const providers = [...user.providers.keys()];
  return { provider: providers[0], providers };
}

function userMetadata(user) {
  return { ...user.metadata, email: user.email, email_verified: user.confirmedAt !== null, phone_verified: false, sub: user.id };
}

export function userJson(user, extra = {}) {
  const identities = [...user.providers.entries()].map(([provider, identityId]) => ({
    identity_id: identityId,
    id: provider === 'email' ? user.id : identityId,
    user_id: user.id,
    identity_data: { email: user.email, email_verified: user.confirmedAt !== null, phone_verified: false, sub: user.id },
    provider,
    last_sign_in_at: iso(user.lastSignInAt ?? user.createdAt),
    created_at: iso(user.createdAt),
    updated_at: iso(user.updatedAt),
    email: user.email,
  }));
  const body = {
    id: user.id,
    aud: 'authenticated',
    role: 'authenticated',
    email: user.email,
    email_confirmed_at: iso(user.confirmedAt),
    phone: '',
    confirmed_at: iso(user.confirmedAt),
    last_sign_in_at: iso(user.lastSignInAt),
    app_metadata: appMetadata(user),
    user_metadata: userMetadata(user),
    identities,
    created_at: iso(user.createdAt),
    updated_at: iso(user.updatedAt),
    is_anonymous: false,
    ...extra,
  };
  if (user.factors.size > 0) {
    body.factors = [...user.factors.values()].map((factor) => ({
      id: factor.id, friendly_name: factor.friendlyName, factor_type: 'totp', status: factor.status,
      created_at: iso(factor.createdAt), updated_at: iso(factor.updatedAt),
    }));
  }
  return JSON.parse(JSON.stringify(body));
}

// The neutral answer to a sign-up for an address that is already confirmed:
// user-shaped, a fresh id, no identities, nothing written (hosted behaviour).
function obfuscatedUser(state, email) {
  const at = isoMicro(nowMs(state));
  return {
    id: newId(), aud: 'authenticated', role: 'authenticated', email, phone: '', confirmation_sent_at: at,
    app_metadata: { provider: 'email', providers: ['email'] },
    user_metadata: {}, identities: [], created_at: at, updated_at: at, is_anonymous: false,
  };
}

// Sessions ----------------------------------------------------------------------

function newSession(state, user, method) {
  const at = nowMs(state);
  const session = { id: newId(), userId: user.id, aal: 'aal1', amr: [{ method, timestamp: Math.floor(at / 1000) }], revoked: false, refresh: null };
  state.sessions.set(session.id, session);
  user.lastSignInAt = at;
  return session;
}

/** Mints a fresh access token and rotates the session's refresh token. */
function sessionBody(ctx, user, session) {
  const { state, signer } = ctx;
  if (session.refresh !== null) {
    const previous = state.refreshTokens.get(session.refresh);
    if (previous) previous.used = true;
  }
  const refreshToken = randomToken(24);
  session.refresh = digest(refreshToken);
  state.refreshTokens.set(session.refresh, { sessionId: session.id, used: false });
  const iat = Math.floor(nowMs(state) / 1000);
  const exp = iat + state.accessTokenTtlSeconds;
  const accessToken = signer.sign({
    aud: 'authenticated', exp, iat, iss: `${ctx.origin}/auth/v1`, sub: user.id, email: user.email, phone: '',
    app_metadata: appMetadata(user), user_metadata: userMetadata(user), role: 'authenticated', aal: session.aal,
    amr: session.amr, session_id: session.id, is_anonymous: false,
  });
  return ok({
    access_token: accessToken, token_type: 'bearer', expires_in: state.accessTokenTtlSeconds, expires_at: exp,
    refresh_token: refreshToken, user: userJson(user),
  });
}

/** Resolves the caller of a user endpoint from its access token and live session. */
function authenticate(ctx) {
  const header = ctx.request.headers.authorization;
  const match = typeof header === 'string' ? /^Bearer ([^\s]{1,16384})$/.exec(header) : null;
  if (!match || match[1] === ctx.publishableKey) {
    return { error: authError(401, 'no_authorization', 'This endpoint requires a valid Bearer token') };
  }
  const claims = ctx.signer.verify(match[1]);
  if (!claims) return { error: authError(403, 'bad_jwt', 'invalid JWT: unable to parse or verify signature') };
  if (typeof claims.exp !== 'number' || claims.exp <= Math.floor(nowMs(ctx.state) / 1000)) {
    return { error: authError(403, 'bad_jwt', 'invalid JWT: token is expired') };
  }
  const session = ctx.state.sessions.get(claims.session_id);
  if (!session || session.revoked || session.userId !== claims.sub) {
    return { error: authError(403, 'session_not_found', 'Session from session_id claim in JWT does not exist') };
  }
  const user = ctx.state.users.get(session.userId);
  if (!user) return { error: authError(404, 'user_not_found', 'User from sub claim in JWT does not exist') };
  return { user, session };
}

function checkPassword(password) {
  const problem = passwordProblem(password);
  if (problem === 'weak_password') {
    return authError(422, 'weak_password', `Password should be at least 6 characters.`, { weak_password: { reasons: ['length'] } });
  }
  if (problem !== null) return authError(422, 'validation_failed', 'Password cannot be longer than 72 characters');
  return null;
}

const invalidEmail = () => authError(400, 'validation_failed', 'Unable to validate email address: invalid format');

// Handlers ----------------------------------------------------------------------

export function signup(ctx) {
  const { state, body } = ctx;
  const email = normalizeEmail(body.email);
  if (email === null) return invalidEmail();
  const passwordError = checkPassword(body.password);
  if (passwordError) return passwordError;
  const data = body.data ?? {};
  if (data === null || typeof data !== 'object' || Array.isArray(data) || JSON.stringify(data).length > MAX_METADATA_CHARS) {
    return authError(400, 'validation_failed', 'User metadata must be a small JSON object');
  }
  const existing = userByEmail(state, email);
  if (existing && existing.confirmedAt !== null) return ok(obfuscatedUser(state, email));
  if (existing) {
    // An unconfirmed address gets the confirmation mail again, as hosted.
    recordMail(state, existing, 'email');
    return ok(userJson(existing, { confirmation_sent_at: isoMicro(nowMs(state)) }));
  }
  const user = createUser(state, { email, password: body.password, confirmed: false, metadata: { ...data } });
  recordMail(state, user, 'email');
  return ok(userJson(user, { confirmation_sent_at: isoMicro(nowMs(state)) }));
}

export function resend(ctx) {
  const { state, body } = ctx;
  if (body.type !== 'signup') return authError(400, 'validation_failed', 'Only signup confirmation resend is emulated');
  const email = normalizeEmail(body.email);
  if (email === null) return invalidEmail();
  const user = userByEmail(state, email);
  if (user && user.confirmedAt === null) recordMail(state, user, 'email');
  return ok({});
}

export function passwordSignIn(ctx) {
  const { state, body } = ctx;
  const email = normalizeEmail(body.email);
  const user = email === null ? null : userByEmail(state, email);
  if (!user || !passwordMatches(user, body.password)) return authError(400, 'invalid_credentials', 'Invalid login credentials');
  if (user.confirmedAt === null) return authError(400, 'email_not_confirmed', 'Email not confirmed');
  return sessionBody(ctx, user, newSession(state, user, 'password'));
}

export function recover(ctx) {
  const { state, body } = ctx;
  const email = normalizeEmail(body.email);
  if (email === null) return invalidEmail();
  const user = userByEmail(state, email);
  // The same answer whether or not the address is known.
  if (user) recordMail(state, user, 'recovery');
  return ok({});
}

export function verifyOperation(body) {
  return body.type === 'recovery' ? 'verify_recovery' : 'verify_email';
}

export function verify(ctx) {
  const { state, body } = ctx;
  const type = VERIFY_TYPES.get(body.type);
  if (type === undefined) return authError(400, 'validation_failed', 'Verify requires a supported type');
  if (typeof body.token_hash !== 'string') return authError(400, 'validation_failed', 'Only token_hash verification is emulated');
  const user = consumeLink(state, body.token_hash, type);
  if (!user) return authError(403, 'otp_expired', 'Email link is invalid or has expired');
  if (user.confirmedAt === null) user.confirmedAt = nowMs(state);
  user.updatedAt = nowMs(state);
  return sessionBody(ctx, user, newSession(state, user, type === 'recovery' ? 'recovery' : 'otp'));
}

export function refresh(ctx) {
  const { state, body } = ctx;
  const token = text(body.refresh_token, 512);
  const entry = token === null ? undefined : state.refreshTokens.get(digest(token));
  const session = entry ? state.sessions.get(entry.sessionId) : undefined;
  if (!entry || !session || session.revoked) {
    return authError(400, 'refresh_token_not_found', 'Invalid Refresh Token: Refresh Token Not Found');
  }
  if (entry.used) return authError(400, 'refresh_token_already_used', 'Invalid Refresh Token: Already Used');
  const user = state.users.get(session.userId);
  if (!user) return authError(400, 'refresh_token_not_found', 'Invalid Refresh Token: Refresh Token Not Found');
  return sessionBody(ctx, user, session);
}

export function exchangeCode(ctx) {
  const { state, body } = ctx;
  const code = text(body.auth_code, 512);
  const verifier = text(body.code_verifier, 256);
  if (code === null || verifier === null) return authError(400, 'validation_failed', 'auth_code and code_verifier are required');
  const key = digest(code);
  const flow = state.flows.get(key);
  if (!flow) return authError(404, 'flow_state_not_found', 'invalid flow state, no valid flow state found');
  if (flow.expiresAt <= nowMs(state)) {
    state.flows.delete(key);
    return authError(400, 'flow_state_expired', 'invalid flow state, flow state has expired');
  }
  // A wrong verifier leaves the flow in place: only its own verifier can use it.
  if (pkceChallenge(verifier) !== flow.challenge) {
    return authError(403, 'bad_code_verifier', 'code challenge does not match previously saved code verifier');
  }
  state.flows.delete(key);
  const user = state.users.get(flow.userId);
  if (!user) return authError(404, 'flow_state_not_found', 'invalid flow state, no valid flow state found');
  return sessionBody(ctx, user, newSession(state, user, 'oauth'));
}

/** The fake Google consent: redirects back with a PKCE-bound code, or with an error when denied. */
export function authorize(ctx) {
  const { state, url } = ctx;
  const query = url.searchParams;
  if (query.get('provider') !== 'google') return authError(400, 'validation_failed', 'Unsupported provider: Provider is not enabled');
  const challenge = query.get('code_challenge');
  const method = String(query.get('code_challenge_method') ?? '').toLowerCase();
  if (challenge === null || !PKCE_CHALLENGE.test(challenge) || method !== 's256') {
    return authError(400, 'validation_failed', 'The development fixture emulates the PKCE flow with S256 only');
  }
  const requested = query.get('redirect_to');
  const target = new URL(requested !== null && isLoopbackUrl(requested) ? requested : ctx.siteUrl);
  if (state.oauthAccount === null) {
    target.searchParams.set('error', 'access_denied');
    target.searchParams.set('error_code', 'provider_consent_denied');
    target.searchParams.set('error_description', 'The synthetic Google consent was denied');
    return { status: 303, location: target.href };
  }
  const { email } = state.oauthAccount;
  let user = userByEmail(state, email);
  if (!user) {
    user = createUser(state, { email, password: null, confirmed: true, provider: 'google' });
  } else {
    // Google vouches for the address: link the identity and confirm it.
    if (!user.providers.has('google')) user.providers.set('google', newId());
    if (user.confirmedAt === null) user.confirmedAt = nowMs(state);
    user.updatedAt = nowMs(state);
  }
  const code = randomToken(24);
  state.flows.set(digest(code), { challenge, userId: user.id, expiresAt: nowMs(state) + state.flowTtlMs });
  target.searchParams.set('code', code);
  return { status: 303, location: target.href };
}

export function getUser(ctx) {
  const auth = authenticate(ctx);
  return auth.error ?? ok(userJson(auth.user));
}

export function updateUser(ctx) {
  const auth = authenticate(ctx);
  if (auth.error) return auth.error;
  const { state, body } = ctx;
  const { user } = auth;
  for (const key of Object.keys(body)) {
    if (!['password', 'data', 'nonce', 'code_challenge', 'code_challenge_method'].includes(key)) {
      return authError(400, 'validation_failed', 'The development fixture updates only the password and user data');
    }
  }
  if (body.data !== undefined) {
    if (body.data === null || typeof body.data !== 'object' || Array.isArray(body.data)
        || JSON.stringify({ ...user.metadata, ...body.data }).length > MAX_METADATA_CHARS) {
      return authError(400, 'validation_failed', 'User metadata must be a small JSON object');
    }
  }
  if (body.password !== undefined) {
    const passwordError = checkPassword(body.password);
    if (passwordError) return passwordError;
    if (passwordMatches(user, body.password)) {
      return authError(422, 'same_password', 'New password should be different from the old password.');
    }
    user.password = hashPassword(body.password);
  }
  if (body.data !== undefined) user.metadata = { ...user.metadata, ...body.data };
  user.updatedAt = nowMs(state);
  return ok(userJson(user));
}

export function logout(ctx) {
  const scope = ctx.url.searchParams.get('scope') ?? 'global';
  if (!LOGOUT_SCOPES.has(scope)) return authError(400, 'validation_failed', 'Unsupported logout scope');
  const auth = authenticate(ctx);
  if (auth.error) return auth.error;
  for (const session of ctx.state.sessions.values()) {
    if (session.userId !== auth.user.id) continue;
    const current = session.id === auth.session.id;
    if (scope === 'global' || (scope === 'local' && current) || (scope === 'others' && !current)) session.revoked = true;
  }
  return { status: 204 };
}

export function enroll(ctx) {
  const auth = authenticate(ctx);
  if (auth.error) return auth.error;
  const { user, session } = auth;
  const { body } = ctx;
  if (body.factor_type !== 'totp') return authError(400, 'validation_failed', 'The development fixture emulates TOTP factors only');
  const friendlyName = body.friendly_name ?? '';
  const issuer = body.issuer ?? 'dwarpal-fixture';
  if (typeof friendlyName !== 'string' || friendlyName.length > 64 || typeof issuer !== 'string' || issuer.length > 64) {
    return authError(400, 'validation_failed', 'friendly_name and issuer must be short strings');
  }
  const factors = [...user.factors.values()];
  if (factors.some((factor) => factor.status === 'verified') && session.aal !== 'aal2') {
    return authError(403, 'insufficient_aal', 'AAL2 required to enroll a new factor');
  }
  if (friendlyName !== '' && factors.some((factor) => factor.friendlyName === friendlyName)) {
    return authError(422, 'mfa_factor_name_conflict', 'A factor with the friendly name already exists');
  }
  if (factors.length >= MAX_FACTORS) return authError(422, 'too_many_enrolled_mfa_factors', 'Maximum number of factors reached');
  const factor = addFactor(ctx.state, user, { friendlyName, verified: false });
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(user.email)}`;
  return ok({
    id: factor.id, type: 'totp', friendly_name: friendlyName,
    totp: {
      qr_code: PLACEHOLDER_QR,
      secret: factor.secret,
      uri: `otpauth://totp/${label}?secret=${factor.secret}&issuer=${encodeURIComponent(issuer)}`,
    },
  });
}

function ownFactor(ctx, user) {
  const factor = user.factors.get(ctx.params.factorId);
  return factor ?? null;
}

export function challenge(ctx) {
  const auth = authenticate(ctx);
  if (auth.error) return auth.error;
  const factor = ownFactor(ctx, auth.user);
  if (!factor) return authError(404, 'mfa_factor_not_found', 'Factor not found');
  const id = newId();
  const expiresAt = nowMs(ctx.state) + ctx.state.challengeTtlMs;
  ctx.state.challenges.set(id, { factorId: factor.id, userId: auth.user.id, expiresAt });
  return ok({ id, type: 'totp', expires_at: Math.floor(expiresAt / 1000) });
}

export function verifyFactor(ctx) {
  const auth = authenticate(ctx);
  if (auth.error) return auth.error;
  const { state, body } = ctx;
  const { user, session } = auth;
  const factor = ownFactor(ctx, user);
  if (!factor) return authError(404, 'mfa_factor_not_found', 'Factor not found');
  const id = typeof body.challenge_id === 'string' ? body.challenge_id : '';
  const found = state.challenges.get(id);
  if (!found || found.factorId !== factor.id || found.userId !== user.id) {
    return authError(422, 'mfa_challenge_expired', 'MFA challenge has expired or was already used');
  }
  if (found.expiresAt <= nowMs(state)) {
    state.challenges.delete(id);
    return authError(422, 'mfa_challenge_expired', 'MFA challenge has expired or was already used');
  }
  if (!totpMatches(factor.secret, nowMs(state), body.code)) {
    return authError(422, 'mfa_verification_failed', 'Invalid TOTP code entered');
  }
  state.challenges.delete(id);
  const at = nowMs(state);
  factor.status = 'verified';
  factor.updatedAt = at;
  session.aal = 'aal2';
  session.amr = [{ method: 'totp', timestamp: Math.floor(at / 1000) }, ...session.amr];
  return sessionBody(ctx, user, session);
}

export function jwks(ctx) {
  return ok(ctx.signer.jwks());
}

export function settings() {
  return ok({
    external: { email: true, google: true, phone: false },
    disable_signup: false, mailer_autoconfirm: false, phone_autoconfirm: false, sms_provider: '',
    saml_enabled: false,
  });
}
