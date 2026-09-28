// Declarations for `@briqvent/dwarpal/browser`: the headless controller, its
// closed state and error sets, and the optional default screens. The view's
// principal is display state only; authorization happens on the server.

import type { ClientConfigInput, Principal, RoleKey, RouteName, ValidatedClientConfig } from '../core/index.js';

export type BrowserState =
  | 'idle'
  | 'submitting'
  | 'sent'
  | 'error'
  | 'expired_link'
  | 'already_used'
  | 'mfa_enrol'
  | 'mfa_challenge'
  | 'setup_pending'
  | 'no_access'
  | 'signed_in'
  | 'offline';

export type BrowserErrorCode =
  | 'invalid_input'
  | 'invalid_credentials'
  | 'email_unverified'
  | 'weak_password'
  | 'same_password'
  | 'rate_limited'
  | 'mfa_invalid_code'
  | 'provider_unavailable'
  | 'method_disabled'
  | 'session_ended'
  | 'unavailable';

export declare const BROWSER_STATES: readonly BrowserState[];
export declare const BROWSER_ERROR_CODES: readonly BrowserErrorCode[];

export interface MfaEnrolment {
  readonly qrCode: string;
  readonly secret: string;
  readonly uri: string;
}

export interface MfaView {
  readonly mode: 'enrol' | 'challenge';
  readonly optional: boolean;
  readonly enrolment: MfaEnrolment | null;
}

export interface SignOutResult {
  /** `unconfirmed`: Auth could not be reached or its answer was not confirmed. */
  readonly remote: 'revoked' | 'unconfirmed' | 'skipped';
  /** `failed`: the browser refused to remove stored state; this page never resumes it. */
  readonly local: 'cleared' | 'failed';
}

export interface AuthView {
  readonly screen: RouteName | null;
  readonly state: BrowserState;
  readonly error: BrowserErrorCode | null;
  readonly setupReason: 'unknown_client' | 'no_default_role' | 'unavailable' | null;
  /** A verification or recovery link waits for the user's click. */
  readonly link: boolean;
  readonly recoveryPending: boolean;
  readonly mfa: MfaView | null;
  readonly principal: Principal | null;
  readonly withheldRoles: readonly RoleKey[];
  /** The validated return path once signed in. */
  readonly next: string | null;
  readonly resendAvailableAt: number | null;
  readonly signOut: SignOutResult | null;
  readonly canRetry: boolean;
}

export interface WebStorageLike {
  readonly length: number;
  key(index: number): string | null;
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
  removeItem(key: string): void;
}

export interface BrowserEnvironment {
  readonly location: { readonly href: string };
  readonly history: { readonly state?: unknown; replaceState(state: unknown, unused: string, url: string): void };
  readonly localStorage: WebStorageLike | null;
  readonly sessionStorage: WebStorageLike | null;
  navigate(url: string): void;
}

export interface AuthControllerOptions {
  /** Validated with core's validateClientConfig; a secret key is refused. */
  config: ClientConfigInput | ValidatedClientConfig;
  /** Defaults to the page's window. */
  env?: BrowserEnvironment;
  fetch?: typeof fetch;
  now?: () => number;
  /** Deadline for each Auth or PostgREST request; default 20000 ms. */
  requestTimeoutMs?: number;
  /** Lets users skip MFA enrolment; withheld roles then stay withheld. Default false. */
  mfaEnrolOptional?: boolean;
  /** Navigate to the validated return path once signed in on a kit route. Default true. */
  autoNavigate?: boolean;
  autoRefreshToken?: boolean;
}

export interface AuthController {
  readonly config: ValidatedClientConfig;
  getView(): AuthView;
  /** Display state only; never an authorization decision. */
  getPrincipal(): Principal | null;
  subscribe(listener: (view: AuthView) => void): () => void;
  dispose(): void;
  start(): Promise<AuthView>;
  signIn(input: { email: string; password: string }): Promise<AuthView>;
  signUp(input: { email: string; password: string }): Promise<AuthView>;
  resendConfirmation(input?: { email?: string }): Promise<AuthView>;
  confirmLink(): Promise<AuthView>;
  startGoogle(): Promise<AuthView>;
  requestRecovery(input: { email: string }): Promise<AuthView>;
  updatePassword(input: { password: string }): Promise<AuthView>;
  startMfaEnrol(): Promise<AuthView>;
  verifyMfa(input: { code: string }): Promise<AuthView>;
  skipMfaEnrol(): Promise<AuthView>;
  retry(): Promise<AuthView>;
  signOut(): Promise<AuthView>;
}

export declare function createAuthController(options: AuthControllerOptions): AuthController;

export declare const DEFAULT_COPY: Readonly<Record<string, string>>;

export interface MountedScreens {
  unmount(): void;
}

export declare function mountAuthScreens(
  root: HTMLElement,
  controller: AuthController,
  options?: { copy?: Record<string, string>; now?: () => number },
): MountedScreens;
