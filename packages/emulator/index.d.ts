// Development-only, loopback-only fixture of the Supabase Auth subset and the
// auth_kit RPCs used by the dwarpal browser kit. Synthetic fixture evidence,
// never hosted proof.

export type FixtureOperation =
  | 'signup' | 'verify_email' | 'password_sign_in' | 'recovery_request' | 'verify_recovery' | 'update_password'
  | 'oauth_exchange' | 'mfa_enroll' | 'mfa_verify' | 'global_sign_out' | 'ensure_profile' | 'effective_access'
  | 'join_client' | 'grant_membership' | 'revoke_membership';

/** `failed_before_commit` is a fixture addition: a server error after which nothing is written. */
export type FaultMode = 'http_503' | 'transport_loss' | 'lost_after_commit' | 'failed_before_commit';

export interface AuthEmulatorOptions {
  /** Loopback address to bind; default '127.0.0.1'. */
  host?: '127.0.0.1' | '::1';
  /** Port; default 0 (an ephemeral port). */
  port?: number;
  /** Initial fixture clock, epoch milliseconds; default the real time at start. The clock moves only by advanceTime. */
  now?: number;
  /** Access-token lifetime; default 3600. */
  accessTokenTtlSeconds?: number;
  /** Email and recovery link lifetime; default 3600. */
  linkTtlSeconds?: number;
  /** Loopback URL used when an OAuth redirect_to is not a loopback URL; default the fixture origin. */
  siteUrl?: string;
  /** Receives one redacted entry per request: fixed route names and statuses only. */
  log?: (entry: FixtureLogEntry) => void;
}

export interface FixtureLogEntry {
  readonly method: string;
  readonly route: string;
  readonly operation?: FixtureOperation | null;
  readonly status: number;
  readonly fault?: FaultMode | null;
}

export interface SeedClientInput {
  clientId: string;
  signupPolicy: 'open' | 'closed';
  /** A model file validated by core validateModel; null only for a registered client with no model applied yet. */
  model: unknown;
  state?: 'registered' | 'live';
  managerUserId?: string;
  managerRoleKey?: string;
  displayName?: string;
}

export interface SeedUserInput {
  email: string;
  password: string;
  confirmed?: boolean;
  /** 'aal2' seeds a verified TOTP factor, so the user can raise a session to aal2 by challenge and verify. */
  aal?: 'aal1' | 'aal2';
}

export interface FixtureSnapshot {
  readonly synthetic: true;
  readonly now: string;
  readonly counts: {
    users: number; confirmedUsers: number; profiles: number; clients: number; enrollments: number;
    memberships: number; membershipEvents: number; requestLog: number; activeSessions: number;
    mailsSent: number; linksIssued: number; linksUsed: number;
  };
  readonly users: Array<{ userId: string; email: string; confirmed: boolean; providers: string[]; factors: Array<{ factorId: string; status: 'verified' | 'unverified' }> }>;
  readonly profiles: Array<{ userId: string }>;
  readonly clients: Array<{
    clientId: string;
    signupPolicy: 'open' | 'closed';
    state: 'registered' | 'live';
    roles: string[];
    enrollments: Array<{ userId: string; enrolledAt: string; grantedRoles: string[] }>;
    memberships: Array<{ userId: string; roleKey: string; grantedVia: 'join' | 'manager' | 'operator'; grantedBy: string | null }>;
    events: Array<{ action: 'join' | 'grant' | 'revoke' | 'bootstrap'; result: string; userId: string; roleKey: string; actorKind: 'user' | 'operator'; actorUserId: string | null; requestId: string | null; at: string }>;
    requestLog: Array<{ requestId: string; operation: string; actorId: string; result: string }>;
  }>;
  /** Request counts by operation or route name. */
  readonly httpRequests: Record<string, number>;
  readonly pendingFaults: Array<{ operation: FixtureOperation; mode: FaultMode }>;
}

export interface AuthEmulatorControls {
  seedClient(input: SeedClientInput): { clientId: string };
  seedUser(input: SeedUserInput): { userId: string; factorId?: string };
  issueLink(input: { type: 'email' | 'recovery'; email: string }): { tokenHash: string };
  setMembership(input: { userId: string; clientId: string; roleKey: string; present: boolean }): { changed: boolean };
  setFault(input: { operation: FixtureOperation; mode: FaultMode }): void;
  advanceTime(ms: number): void;
  snapshot(): FixtureSnapshot;
  /** Fixture addition: the current TOTP code of a factor at the fixture clock. */
  totpCode(input: { factorId: string }): string;
  /** Fixture addition: clears or restores the Auth record's email confirmation while sessions stay valid (join answers email_unverified). */
  setEmailConfirmed(input: { userId: string; confirmed: boolean }): void;
  /** Fixture addition: the account the synthetic Google consent signs in next; null denies consent. */
  setOAuthAccount(input: { email: string } | null): void;
}

export interface AuthEmulator {
  /** Loopback origin, e.g. http://127.0.0.1:54123 */
  readonly origin: string;
  /** Synthetic sb_publishable_ key; the only apikey the fixture accepts. */
  readonly publishableKey: string;
  readonly controls: AuthEmulatorControls;
  /** Closes this instance's listener and connections; awaitable and idempotent. */
  close(): Promise<void>;
}

export function startAuthEmulator(options?: AuthEmulatorOptions): Promise<AuthEmulator>;
