// Type declarations for the core entry of @briqvent/dwarpal (contract 0.5).

export declare const AUTH_CONTRACT_VERSION: '0.5';

/**
 * Role keys, permission keys and client ids are opaque client-defined strings.
 * Any non-empty string without NUL or an unpaired surrogate is valid; the
 * `resource:action[:scope]` form for permission keys is a recommendation.
 */
export type RoleKey = string;
/** Opaque; see RoleKey. Recommended form `resource:action` or `resource:action:scope`. */
export type PermissionKey = string;
export type Provider = 'email' | 'google';
export type Aal = 'aal1' | 'aal2';
export type GrantedVia = 'join' | 'manager' | 'operator';

export interface RoleFlags {
  selfAssignable: boolean;
  managesMembers: boolean;
  mfaRequired: boolean;
}

export interface Identity {
  userId: string;
  verifiedEmail: string | null;
  providers: Provider[];
}

export interface Membership {
  clientId: string;
  roleKey: RoleKey;
  flags: RoleFlags;
  grantedAt: string;
  grantedVia: GrantedVia;
  /**
   * Permission keys this role grants, from the same effective-access read.
   * Additive optional field within contract 0.5; used only by `explain` and
   * `requirePermission` to name granting and withheld roles, never to grant.
   */
  permissions?: PermissionKey[];
}

export interface Access {
  clientId: string;
  enrolledAt: string | null;
  /** All roles held for the client, active or not. Display only. */
  roles: RoleKey[];
  /** Roles whose MFA requirement the session satisfies. */
  activeRoles: RoleKey[];
  /** Union of permission keys over activeRoles. */
  permissions: PermissionKey[];
  mfaPending: boolean;
}

export interface Session {
  id: string;
  aal: Aal;
  issuedAt: string;
  expiresAt: string;
  checkedAt: string;
}

export interface Principal {
  identity: Identity;
  /** For the configured client only. */
  memberships: Membership[];
  access: Access;
  session: Session;
}

export interface Profile {
  userId: string;
  displayName: string | null;
  contactEmail: string | null;
  contactPhone: string | null;
}

export type AuthErrorCode =
  | 'no_token'
  | 'invalid_token'
  | 'expired'
  | 'email_unverified'
  | 'mfa_required'
  | 'forbidden'
  | 'unavailable'
  | 'provider_unavailable'
  | 'config_invalid'
  | 'model_invalid'
  | 'request_conflict';

export declare const AUTH_ERROR_CODES: readonly AuthErrorCode[];

export interface ValidationIssue {
  /**
   * Structural location only: fixed field names, `[i]` for an array index and
   * `#i` for a caller-chosen key, where i is the key's position among the
   * object's own keys in UTF-16 code-unit order (`roles.#1.permissions[0]`).
   * Caller-chosen keys and values never appear.
   */
  readonly path: string;
  readonly rule: string;
}

export declare class AuthError extends Error {
  constructor(code: AuthErrorCode, options?: { issues?: ValidationIssue[] });
  readonly name: 'AuthError';
  readonly code: AuthErrorCode;
  /** Present for config_invalid and model_invalid; paths and rule names only, never values. */
  readonly issues: readonly ValidationIssue[];
  toJSON(): { name: 'AuthError'; code: AuthErrorCode; message: string; issues?: readonly ValidationIssue[] };
}

export declare function isAuthError(value: unknown): value is AuthError;

// Evaluation

export interface Explanation {
  allowed: boolean;
  via: RoleKey[];
  withheld: { role: RoleKey; reason: 'mfa_required' }[];
}

export declare function can(principal: Principal | null | undefined, key: PermissionKey): boolean;
export declare function canAll(principal: Principal | null | undefined, keys: readonly PermissionKey[]): boolean;
export declare function canAny(principal: Principal | null | undefined, keys: readonly PermissionKey[]): boolean;
export declare function explain(principal: Principal | null | undefined, key: PermissionKey): Explanation;
export declare function requirePermission<P extends Principal>(principal: P | null | undefined, key: PermissionKey): P;
export declare function requireRole<P extends Principal>(principal: P | null | undefined, roles: RoleKey | readonly RoleKey[]): P;
export declare function requireMfa<P extends Principal>(principal: P | null | undefined): P;

// Snapshot

export interface MembershipRow {
  clientId: string;
  roleKey: RoleKey;
  flags: RoleFlags;
  grantedAt: string;
  grantedVia: GrantedVia;
  permissions: PermissionKey[];
}

export interface PrincipalSnapshot {
  clientId: string;
  identity: Identity;
  session: Session;
  enrolledAt: string | null;
  memberships: MembershipRow[];
}

export declare const PROVIDERS: readonly Provider[];
export declare const AAL_LEVELS: readonly Aal[];
export declare const GRANTED_VIA: readonly GrantedVia[];

/** Builds a deep-frozen Principal; throws AuthError('unavailable') on any malformed or foreign row. */
export declare function createPrincipal(snapshot: PrincipalSnapshot): Principal;

// Model

export type RoleFlagName = 'self_assignable' | 'manages_members' | 'mfa_required';
export type ClientState = 'registered' | 'live';

export interface ModelRoleInput {
  description?: string;
  self_assignable?: boolean;
  manages_members?: boolean;
  mfa_required?: boolean;
  permissions?: PermissionKey[];
}

export interface ModelInput {
  client: string;
  roles: Record<RoleKey, ModelRoleInput>;
  permissions: Record<PermissionKey, string>;
}

export interface CanonicalModelRole {
  readonly description: string;
  readonly manages_members: boolean;
  readonly mfa_required: boolean;
  readonly permissions: readonly PermissionKey[];
  readonly self_assignable: boolean;
}

export interface CanonicalModel {
  readonly client: string;
  readonly roles: Readonly<Record<RoleKey, CanonicalModelRole>>;
  readonly permissions: Readonly<Record<PermissionKey, string>>;
}

export type Reach = 'future_joiners' | { readonly holders: number };

export type ModelDiffEntry =
  | { readonly kind: 'permission_added' | 'permission_removed' | 'permission_description_changed'; readonly permission: PermissionKey }
  | { readonly kind: 'role_added'; readonly role: RoleKey; readonly reach?: 'future_joiners' }
  | { readonly kind: 'role_removed' | 'role_description_changed'; readonly role: RoleKey }
  | {
      readonly kind: 'role_flag_changed';
      readonly role: RoleKey;
      readonly flag: RoleFlagName;
      readonly from: boolean;
      readonly to: boolean;
      readonly reach: Reach;
    }
  | { readonly kind: 'mapping_added' | 'mapping_removed'; readonly role: RoleKey; readonly permission: PermissionKey; readonly reach: { readonly holders: number } };

export type ModelRefusal =
  | { readonly rule: 'role_held' | 'promotes_holders'; readonly role: RoleKey; readonly holders: readonly string[] }
  | { readonly rule: 'no_manager_would_remain' };

export interface ModelChangePlan {
  readonly changed: boolean;
  readonly diff: readonly ModelDiffEntry[];
  readonly refusals: readonly ModelRefusal[];
  readonly model: CanonicalModel;
}

export declare const ROLE_FLAGS: readonly RoleFlagName[];
export declare const CLIENT_STATES: readonly ClientState[];

export declare function validateModel(model: unknown, options?: { clientId?: string }): CanonicalModel;
export declare function canonicalModelJson(model: unknown): string;
export declare function modelHash(model: unknown): Promise<string>;
export declare function planModelChange(
  current: unknown | null,
  next: unknown,
  context: { state: ClientState; holders?: Record<RoleKey, readonly string[]> },
): ModelChangePlan;

// Configuration

export type RouteName = 'signIn' | 'signUp' | 'verify' | 'callback' | 'forgot' | 'reset' | 'mfa' | 'signOut';

export interface ClientConfigInput {
  clientId: string;
  supabaseUrl: string;
  publishableKey: string;
  /** `prefix` is an absolute path; every other entry is one path segment under it. */
  routes?: Partial<Record<RouteName | 'prefix', string>>;
  origin: string;
  allowedReturnPaths: string[];
  defaultReturnPath: string;
  providers: { email: boolean; google: boolean };
  session?: { accessTokenMinutes?: number };
  brand?: { name: string; logoUrl?: string; colors?: Record<string, string>; fontStack?: string };
  copy?: Record<string, string>;
  selfSignup: boolean;
}

export interface ValidatedClientConfig {
  readonly clientId: string;
  readonly supabaseUrl: string;
  readonly publishableKey: string;
  /** Absolute paths: `prefix` plus one entry per route. */
  readonly routes: Readonly<Record<RouteName | 'prefix', string>>;
  readonly origin: string;
  readonly allowedReturnPaths: readonly string[];
  readonly defaultReturnPath: string;
  readonly providers: { readonly email: boolean; readonly google: boolean };
  readonly session: { readonly accessTokenMinutes: number };
  readonly brand: {
    readonly name: string;
    readonly logoUrl?: string;
    readonly colors: Readonly<Record<string, string>>;
    readonly fontStack?: string;
  } | null;
  readonly copy: Readonly<Record<string, string>>;
  readonly selfSignup: boolean;
}

export declare const ROUTE_NAMES: readonly RouteName[];
export declare function validateClientConfig(config: unknown): ValidatedClientConfig;

// Redirects

export declare function resolveReturnPath(
  next: unknown,
  config: Pick<ValidatedClientConfig, 'origin' | 'allowedReturnPaths' | 'defaultReturnPath'>,
): string;

// Canonical JSON and fingerprints

export declare function canonicalJson(value: unknown): string;
export declare function sha256Hex(text: string): Promise<string>;
export declare function requestFingerprint(input: {
  operation: string;
  clientId: string | null;
  actorId: string;
  payload: unknown;
}): Promise<string>;
