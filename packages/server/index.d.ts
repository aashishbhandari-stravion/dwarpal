// Type declarations for @briqvent/dwarpal/server (Node 22+).

import type { Principal } from '../core/index.js';

export {
  AUTH_CONTRACT_VERSION,
  AUTH_ERROR_CODES,
  AuthError,
  isAuthError,
  can,
  canAll,
  canAny,
  explain,
  requirePermission,
  requireRole,
  requireMfa,
} from '../core/index.js';
export type {
  Principal,
  Identity,
  Membership,
  Access,
  Session,
  AuthErrorCode,
  Explanation,
  RoleKey,
  PermissionKey,
} from '../core/index.js';

export interface AuthServerOptions {
  /** The project URL: an https origin (plain http only for a loopback host). */
  supabaseUrl: string;
  /** The publishable key. A secret or service_role key is refused with config_invalid. */
  publishableKey: string;
  /** Fixed for the server's lifetime; never read from a request. Opaque; '' is a valid id. */
  clientId: string;
  /** Allowed clock skew for exp, nbf and iat, in seconds (0–300, default 5). */
  clockToleranceSeconds?: number;
  /** Per-call deadline for Auth, JWKS and PostgREST calls, in ms (default 10000). */
  requestTimeoutMs?: number;
  fetch?: typeof fetch;
  /** Wall clock in ms used for token time checks (default Date.now). */
  now?: () => number;
}

/** A Fetch API Request, or a Node IncomingMessage (anything with headers). */
export type RequestLike = Request | { readonly headers: Headers | Readonly<Record<string, string | string[] | undefined>> };

export interface MembershipChange<R extends string> {
  readonly result: R;
  readonly userId: string;
  readonly clientId: string;
  readonly roleKey: string;
}

export interface AuthServer {
  readonly clientId: string;
  /**
   * Verifies the bearer token (JWKS signature, issuer, audience, time claims,
   * is_anonymous, session_id, aal), checks the session live with Supabase Auth,
   * and reads this client's access freshly. Resolves to null when the request
   * has no Authorization header. Rejects with AuthError `invalid_token`,
   * `expired` or `unavailable`; never returns an empty or stale principal.
   */
  resolveSession(request: RequestLike): Promise<Principal | null>;
  /**
   * Grants a non-manager role as the manager whose token `request` carries
   * (the same request passed to resolveSession). Reuse `requestId` on retry:
   * after `unavailable` the write may have committed, and the same id returns
   * the stored result. Rejects with `no_token`, `invalid_token`, `forbidden`,
   * `mfa_required`, `request_conflict`, `email_unverified` or `unavailable`;
   * throws TypeError for a malformed argument before any call.
   */
  grantMembership(userId: string, roleKey: string, requestId: string, request: RequestLike): Promise<MembershipChange<'granted' | 'already_member'>>;
  /** As grantMembership, for revoking a non-manager role. */
  revokeMembership(userId: string, roleKey: string, requestId: string, request: RequestLike): Promise<MembershipChange<'revoked' | 'not_member'>>;
}

export declare function createAuthServer(options: AuthServerOptions): AuthServer;
