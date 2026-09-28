// Type declarations for @briqvent/dwarpal/server/operator. Operator shell
// only: this client holds the project's secret key.

import type { ClientConfigInput, ValidatedClientConfig, ValidationIssue } from '../core/index.js';

export type OperatorErrorCode =
  | 'config_invalid'
  | 'model_invalid'
  | 'request_conflict'
  | 'email_unverified'
  | 'unavailable'
  | 'invalid_argument'
  | 'unknown_client'
  | 'unknown_role'
  | 'unknown_user'
  | 'not_manager_role'
  | 'last_manager'
  | 'model_refused'
  | 'ambiguous_user'
  | 'lookup_incomplete'
  | 'request_in_progress'
  | 'run_superseded'
  | 'lease_expired'
  | 'outcome_unknown'
  | 'prerequisite_missing'
  | 'migration_failed'
  | 'no_model';

export declare const OPERATOR_ERROR_CODES: readonly OperatorErrorCode[];

/**
 * How to converge after a write whose outcome is unknown (always present on
 * `outcome_unknown`, and on an MFA reset failure that left its claim pending).
 */
export type RecoveryTag = 'rerun_same_request_id' | 'rerun_same_arguments' | 'rerun_lookup_before_invite' | 'rerun_migrate';
export declare const RECOVERY: readonly RecoveryTag[];
export declare const ADMIN_CALL_TIMEOUT_MS: 20000;

export interface ModelRefusalDetail {
  readonly rule: string;
  /** `roles.#i`: the role's position among the model file's role keys in UTF-16 order. */
  readonly role?: string;
  readonly holderCount?: number;
  readonly holders?: readonly string[];
}

/** Bounded, sanitized fields: stages, reason tags, counts, UUIDs, structural paths. */
export interface OperatorErrorDetails {
  readonly stage?: string;
  readonly reason?: string;
  readonly recovery?: RecoveryTag;
  readonly issues?: readonly ValidationIssue[];
  readonly refusals?: readonly ModelRefusalDetail[];
  readonly [field: string]: unknown;
}

export declare class OperatorError extends Error {
  constructor(code: OperatorErrorCode, details?: Record<string, unknown>);
  readonly name: 'OperatorError';
  readonly code: OperatorErrorCode;
  readonly details: OperatorErrorDetails;
  toJSON(): { name: 'OperatorError'; code: OperatorErrorCode; message: string; details: OperatorErrorDetails };
}

export declare function isOperatorError(value: unknown): value is OperatorError;

export interface OperatorClientOptions {
  supabaseUrl: string;
  /** `sb_secret_…`, or a legacy service_role JWT (accepted with a warning). */
  secretKey: string;
  /** Needed only by doctor's probe. */
  publishableKey?: string | null;
  /** Management API access for migrate and doctor's catalog checks. */
  management?: { token?: string | null; projectRef?: string | null; url?: string } | null;
  /** Per admin API call abort deadline, in ms (at most and by default 20000). */
  adminTimeoutMs?: number;
  /** Per PostgREST and Management API call deadline, in ms (at most and by default 20000). */
  rpcTimeoutMs?: number;
  fetch?: typeof fetch;
  /** Monotonic clock in ms for the mfa-reset claim deadline (default performance.now). */
  monotonicNow?: () => number;
  onWarning?: (code: 'legacy_service_role_key') => void;
}

export interface ClientRegistration {
  readonly result: 'registered' | 'updated' | 'unchanged';
  readonly clientId: string;
  readonly state: 'registered' | 'live';
}

export interface ModelApplication {
  readonly result: 'dry_run' | 'applied' | 'unchanged';
  readonly clientId: string;
  readonly requestId: string | null;
  readonly modelHash: string;
  /** False when the database hashed the model differently from core: a parity defect. */
  readonly hashMatchesFile: boolean;
  readonly diff: readonly unknown[];
  readonly changed?: boolean;
  readonly refusals?: readonly ModelRefusalDetail[];
}

export interface ModelExport {
  readonly clientId: string;
  /** The canonical model file text, exactly; null while no model is applied. */
  readonly modelJson: string | null;
  readonly modelHash: string | null;
  readonly lastAppliedHash: string | null;
}

export interface ManagerChange<R extends string> {
  readonly result: R;
  readonly userId: string;
  readonly clientId: string;
  readonly roleKey: string;
}

export interface MfaResetOutcome {
  readonly outcome: 'proceed' | 'resume' | 'completed';
  readonly replayed: boolean;
  readonly result: 'reset' | 'no_factors';
  readonly factorsSeen: readonly string[];
  readonly factorsDeleted: readonly string[];
}

export interface MigrationReport {
  readonly applied: readonly { version: string; sha256: string }[];
  readonly alreadyInstalled: readonly string[];
  readonly unknownInstalled: readonly string[];
}

export interface DoctorCheck {
  readonly id: string;
  readonly mode: 'catalog' | 'public' | 'probe' | 'host';
  readonly status: 'ok' | 'fail' | 'not_run';
  readonly reason?: string;
  readonly [field: string]: unknown;
}

export interface DoctorReport {
  /** `incomplete` when no check failed but at least one could not run. */
  readonly status: 'ok' | 'fail' | 'incomplete';
  readonly probeRan: boolean;
  readonly counts: { readonly ok: number; readonly fail: number; readonly not_run: number };
  readonly checks: readonly DoctorCheck[];
}

export interface OperatorClient {
  registerClient(input: { clientId: string; displayName: string; signupPolicy: 'open' | 'closed' }): Promise<ClientRegistration>;
  applyModel(model: unknown, options?: { dryRun?: boolean; requestId?: string | null }): Promise<ModelApplication>;
  exportModel(clientId: string): Promise<ModelExport>;
  bootstrapManager(input: { clientId: string; roleKey: string; requestId: string } & ({ userId: string } | { email: string; invite?: boolean })):
    Promise<ManagerChange<'granted' | 'already_member'> | { readonly result: 'setup_pending'; readonly userId: string; readonly clientId: string; readonly roleKey: string }>;
  revokeManager(input: { clientId: string; roleKey: string; userId: string; requestId: string }): Promise<ManagerChange<'revoked' | 'not_member'>>;
  mfaReset(input: { userId: string; requestId: string }): Promise<MfaResetOutcome>;
  checkConfig(config: ClientConfigInput | unknown): ValidatedClientConfig;
  migrate(options?: { migrationsDir?: string }): Promise<MigrationReport>;
  doctor(options?: {
    clientId?: string | null;
    config?: ClientConfigInput | unknown | null;
    model?: unknown;
    probe?: { email: string; password: string } | null;
    hostOrigin?: string | null;
    migrationsDir?: string;
  }): Promise<DoctorReport>;
}

export declare function createOperatorClient(options: OperatorClientOptions): OperatorClient;
