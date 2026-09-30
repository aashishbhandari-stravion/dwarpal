# Business requirements

This document consolidates the agreed scope behind Dwarpal's current implementation. It adds no new product scope. Technical contracts and mechanisms are maintained in the [design](design.md); implementation and verification status are maintained in the [README](../README.md#verification-status).

Documentation status: proposed consolidation for review. Product status: pre-release; hosted verification and consuming-site acceptance remain open.

## Purpose and intended outcomes

Websites need consistent account access and controlled access to business functions without rebuilding their sign-in and permission systems for every brand. Dwarpal provides that reusable foundation while allowing each website to define its roles, permissions, branding and business-record rules.

The intended outcomes are a consistent account experience, reusable access controls across websites, explicit responsibility for privileged changes, and access decisions that remain correct when roles change or requests fail and are retried. No quantified savings, service-level commitment or production-readiness claim is established by this document.

## Users and responsibilities

| Actor | Need and responsibility |
| --- | --- |
| Visitor or account holder | Create and verify an account, sign in, recover access, complete required MFA, and sign out. |
| Member or staff user | Access only the capabilities granted by their active roles for the current website. |
| Membership manager | Grant and revoke ordinary roles within their authorized website. |
| Operator | Configure the website's access model, appoint or remove managers, diagnose setup and perform controlled MFA recovery. |
| Integrating application team | Configure the experience, enforce access at protected data boundaries, and own links to business records. |

A person may hold several roles. Manager authority and operator authority have different scopes; ordinary managers cannot appoint other managers.

## Functional requirements

The identifiers below organize existing scope for this document; they do not introduce a new contract version.

| ID | Required business outcome | Acceptance outcome |
| --- | --- | --- |
| BR-01 | Provide verified account registration, password sign-in, account recovery and sign-out, with optional Google sign-in. | Valid users can complete supported flows; invalid, expired or failed flows show a truthful, recoverable outcome. Existing-account responses do not disclose whether an address is registered. |
| BR-02 | Make the account experience reusable across website brands. | Branding, copy and account routes can change through configuration; an application may use the default screens or supply its own interface. |
| BR-03 | Allow each website to define roles and permissions and assign several roles to a user. | Access is granted only by active roles for the selected website; unknown permissions and another website's roles do not grant access. |
| BR-04 | Require stronger authentication for roles designated as sensitive. | Until MFA is satisfied, those roles contribute no access; other active roles continue to contribute their permitted access. |
| BR-05 | Enroll eligible users once under the website's signup policy. | Initial self-assignable roles are granted once. Later sign-ins and retries do not restore revoked access or silently add newly introduced default roles. |
| BR-06 | Delegate ordinary membership administration safely. | A manager may grant and revoke non-manager roles only within their authorized website; manager appointment and removal remain operator responsibilities. |
| BR-07 | Preserve access-model integrity during administration. | Unsafe changes that remove held roles, promote existing holders into manager authority, or remove the last manager of a live website are refused without partial changes. |
| BR-08 | Keep a reliable record of access administration. | Model and membership changes are auditable. Retried requests do not duplicate changes; conflicting reuse of a request identity is refused. |
| BR-09 | Support controlled recovery when a user's MFA access must be reset. | Only the operator can reset factors; recovery is auditable and retries or interrupted runs do not silently perform a different reset. The reset affects the identity across the shared project. |
| BR-10 | Give applications a trustworthy basis for access decisions. | Protected operations use verified identity and current website access. If required checks cannot be completed, the operation is refused or reported unavailable. |
| BR-11 | Preserve application ownership of business records. | Applications enforce which specific records a user may access and explicitly manage identity-to-record links; an email match alone never establishes ownership. |
| BR-12 | Make integration and operational readiness inspectable. | Teams have versioned source, documentation, reusable examples and setup diagnostics; unperformed or blocked verification is visibly distinct from a pass. |

## Quality requirements

- Security: ordinary users cannot obtain another website's authority, promote themselves into management, or bypass required MFA. Browser visibility and navigation are insufficient to protect private data.
- Reliability: retries, concurrent requests and interrupted operations have defined outcomes. Dependency failure does not silently grant access or report an uncertain write as completed.
- Privacy: privileged credentials stay outside browser and ordinary request handling. Diagnostics avoid credential and private user-data exposure.
- Reuse: a second website can use different role keys, branding and routes without modifying the shared package.
- Maintainability: consumers can identify the package and contract version and reproduce relevant checks. Compatibility changes require an explicit contract decision.

Capacity, availability targets, support response times, retention policy and recovery objectives must be agreed for each deployment where required. This scope does not promise numerical targets for them.

## Boundaries and dependencies

Dwarpal targets websites using Supabase Auth, with a static or server-rendered front end and an optional Node back end. Website teams remain responsible for their hosting, provider configuration, email delivery, optional Google setup, business data and production operations.

The current scope excludes an independently hosted identity service, support for other identity providers as the back end, a model-administration UI, a business-data store, automatic protection of existing application routes, cookie-based sessions, and a general relationship- or attribute-based authorization engine. There is no member-directory feature in the current package.

Two supported data-access paths have different session-revocation behavior. Sensitive operations that require a live Auth check use the Node path. A direct database path retains the token-expiry window described in the [architecture](architecture.md#two-data-access-paths). A deployment must explicitly accept the behavior of its chosen path.

## Acceptance and evidence

Implementation, local verification, hosted verification, acceptance by a consuming website and release acceptance are distinct outcomes. Passing a synthetic test does not establish real email delivery, Google sign-in, real-device MFA or production readiness.

The [verification status](../README.md#verification-status) records current coverage. The [design verification cases](design.md#9-test-plan) translate this scope into detailed checks, and the [manual's completion checklist](manual.md#15-checklist-before-you-call-the-integration-done) covers the consuming application. A deployment is accepted only after its required hosted and application outcomes are verified and its owner accepts the remaining limits.
