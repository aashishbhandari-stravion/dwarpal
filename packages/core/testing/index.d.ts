// Type declarations for @briqvent/dwarpal/testing (synthetic fixture).

import type { Aal, CanonicalModel, Principal, RoleKey } from '../index.js';

export declare const FIXTURE_CLIENT_ID: 'fixture-client';
export declare const FIXTURE_OTHER_CLIENT_ID: 'fixture-other-client';
export declare const FIXTURE_MODEL: CanonicalModel;

export type FixtureUser =
  | 'patron'
  | 'otherPatron'
  | 'clerk'
  | 'patronClerk'
  | 'lead'
  | 'coordinator'
  | 'leadCoordinator'
  | 'enrolledNoRoles'
  | 'notEnrolled';

export declare const FIXTURE_USER_IDS: Readonly<Record<FixtureUser, string>>;

export declare function fixturePrincipal(options: {
  roles: RoleKey[];
  aal?: Aal;
  userId?: string;
  enrolledAt?: string | null;
}): Principal;

export type FixturePrincipalName =
  | 'patron'
  | 'otherPatron'
  | 'clerkAal1'
  | 'clerkAal2'
  | 'patronClerkAal1'
  | 'patronClerkAal2'
  | 'leadAal1'
  | 'leadAal2'
  | 'coordinator'
  | 'leadCoordinatorAal1'
  | 'enrolledNoRoles'
  | 'notEnrolled';

export declare const fixturePrincipals: Readonly<Record<FixturePrincipalName, Principal>>;
