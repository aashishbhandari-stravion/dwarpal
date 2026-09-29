// The hosted Playwright flows (design 8, hosted acceptance: "Playwright suite
// against the project"): the browser kit's controller and default screens in
// Chromium, talking to Auth and PostgREST of the target, through sign-in and
// its return path, sign-in failures, enrollment outcomes, a revoked
// membership, MFA enrolment and challenge, a confirmation link, recovery and
// sign-out. Links come from the Auth admin API (`generate_link`), so no mail
// is sent; the real SMTP and Google flows stay with their own cases.
//
// A flow gets `b` (the browser: pages per client site) and `backend` (users,
// links, grants, TOTP codes and the Node path of the same project). The
// hosted procedure supplies the target; the offline rehearsal supplies the
// development emulator, and its results are local fixture evidence only.
// Assertions record summaries (states, roles, levels), never a view's
// tokens, secrets or addresses.

export const BROWSER_ALIASES = Object.freeze(['pw_manager', 'pw_member', 'pw_closed', 'pw_nodefault', 'pw_revoked', 'pw_mfa', 'pw_verify', 'pw_recover']);

const EVIL_NEXT = encodeURIComponent('https://evil.example/steal');

function summary(view) {
  const p = view?.principal ?? null;
  return {
    state: view?.state ?? null,
    error: view?.error ?? null,
    roles: p ? [...p.access.roles].sort() : null,
    activeRoles: p ? [...p.access.activeRoles].sort() : null,
    aal: p?.session?.aal ?? null,
    enrolled: p ? typeof p.access.enrolledAt === 'string' : null,
  };
}

async function signIn(b, backend, page, creds) {
  await backend.beforeSignIn();
  return b.act(page, 'signIn', { email: creds.email, password: creds.password });
}

export const FLOWS = Object.freeze([
  {
    id: 'PW.sign_in_redirect',
    async run(b, backend, check) {
      const member = await backend.user('pw_member');
      const tab = await b.tab('open');
      const page = await tab.open(`/account/sign-in?next=${EVIL_NEXT}`);
      const first = await signIn(b, backend, page, member);
      check.assert('first sign-in: joined as member, signed in', { state: 'signed_in', roles: ['member'], enrolled: true, aal: 'aal1' },
        (({ state, roles, enrolled, aal }) => ({ state, roles, enrolled, aal }))(summary(first)));
      check.assert('an external return path is refused for the default', '/app', first.next);
      const enrolledAt = first.principal?.access?.enrolledAt ?? null;
      await b.act(page, 'signOut');
      const again = await tab.open('/account/sign-in?next=%2Fapp%2Forders');
      const second = await signIn(b, backend, again, member);
      check.assert('second sign-in: signed in, enrolled once (same enrolment time)', { state: 'signed_in', sameEnrolment: true },
        { state: second.state, sameEnrolment: second.principal?.access?.enrolledAt === enrolledAt && enrolledAt !== null });
      check.assert('an allowed return path is kept', '/app/orders', second.next);
      check.assert('no page error', [], tab.errors());
      await tab.close();
    },
  },
  {
    id: 'PW.sign_in_failures',
    async run(b, backend, check) {
      const member = await backend.user('pw_member');
      const tab = await b.tab('open');
      const page = await tab.open('/account/sign-in');
      const wrong = await signIn(b, backend, page, { email: member.email, password: `${member.password}x` });
      check.assert('wrong password: invalid_credentials', { state: 'error', error: 'invalid_credentials' }, { state: wrong.state, error: wrong.error });
      const unknown = await signIn(b, backend, page, { email: backend.unusedEmail(), password: member.password });
      check.assert('unknown address: the same answer', { state: 'error', error: 'invalid_credentials' }, { state: unknown.state, error: unknown.error });
      check.assert('no session stored', [], await b.sessionKeys(page));
      await tab.close();
    },
  },
  {
    id: 'PW.enrollment_states',
    async run(b, backend, check) {
      const closedUser = await backend.user('pw_closed');
      const closed = await b.tab('closed');
      const denied = await signIn(b, backend, await closed.open('/account/sign-in'), closedUser);
      check.assert('invite-only client: no_access, no role', { state: 'no_access', roles: [] }, { state: denied.state, roles: summary(denied).roles });
      await closed.close();
      const pendingUser = await backend.user('pw_nodefault');
      const noDefault = await b.tab('noDefault');
      const pending = await signIn(b, backend, await noDefault.open('/account/sign-in'), pendingUser);
      check.assert('client without a self-assignable role: setup_pending (no_default_role), with a retry', { state: 'setup_pending', setupReason: 'no_default_role', canRetry: true },
        { state: pending.state, setupReason: pending.setupReason, canRetry: pending.canRetry });
      check.assert('no page error', [], [...closed.errors(), ...noDefault.errors()]);
      await noDefault.close();
    },
  },
  {
    id: 'PW.revoked_no_access',
    async run(b, backend, check) {
      const user = await backend.user('pw_revoked');
      const tab = await b.tab('open');
      const page = await tab.open('/account/sign-in');
      const first = await signIn(b, backend, page, user);
      check.assert('joined', { state: 'signed_in', roles: ['member'] }, (({ state, roles }) => ({ state, roles }))(summary(first)));
      await backend.revoke('pw_revoked', 'member');
      await b.act(page, 'signOut');
      const again = await signIn(b, backend, await tab.open('/account/sign-in'), user);
      check.assert('after a manager revoke: signed in with no membership, no_access; nothing re-granted', { state: 'no_access', roles: [], enrolled: true },
        (({ state, roles, enrolled }) => ({ state, roles, enrolled }))(summary(again)));
      await tab.close();
    },
  },
  {
    id: 'PW.mfa',
    async run(b, backend, check) {
      const user = await backend.user('pw_mfa');
      const tab = await b.tab('open');
      const page = await tab.open('/account/sign-in');
      const joined = await signIn(b, backend, page, user);
      check.assert('joined as member', 'signed_in', joined.state);
      await backend.grant('pw_mfa', 'staff');
      await b.act(page, 'signOut');
      const mfaPage = await tab.open('/account/sign-in');
      const withheld = await signIn(b, backend, mfaPage, user);
      check.assert('MFA role held: enrolment offered, staff withheld at aal1', { state: 'mfa_enrol', withheld: ['staff'], aal: 'aal1' },
        { state: withheld.state, withheld: [...withheld.withheldRoles], aal: summary(withheld).aal });
      const enrol = await b.act(mfaPage, 'startMfaEnrol');
      const secret = enrol.mfa?.enrolment?.secret ?? null;
      check.assert('a TOTP enrolment was created', true, typeof secret === 'string');
      backend.secret(secret);
      const verified = await b.act(mfaPage, 'verifyMfa', { code: await backend.totp('pw_mfa', secret) });
      check.assert('verified: aal2, staff active, nothing withheld', { state: 'signed_in', aal: 'aal2', activeRoles: ['member', 'staff'], withheld: [] },
        { state: verified.state, aal: summary(verified).aal, activeRoles: summary(verified).activeRoles, withheld: [...verified.withheldRoles] });
      await b.act(mfaPage, 'signOut');
      const page2 = await tab.open('/account/sign-in');
      const challenged = await signIn(b, backend, page2, user);
      check.assert('next sign-in: challenged, not enrolled again', { state: 'mfa_challenge', mode: 'challenge' }, { state: challenged.state, mode: challenged.mfa?.mode ?? null });
      const passed = await b.act(page2, 'verifyMfa', { code: await backend.totp('pw_mfa', secret) });
      check.assert('challenge passed: aal2 with staff active', { state: 'signed_in', aal: 'aal2', activeRoles: ['member', 'staff'] },
        (({ state, aal, activeRoles }) => ({ state, aal, activeRoles }))(summary(passed)));
      check.assert('one verified factor on the account', 1, await backend.verifiedFactors('pw_mfa'));
      check.assert('no page error', [], tab.errors());
      await tab.close();
    },
  },
  {
    id: 'PW.verify_link',
    async run(b, backend, check) {
      const { tokenHash } = await backend.signupLink('pw_verify');
      const path = `/account/verify?token_hash=${tokenHash}&type=email&next=${EVIL_NEXT}`;
      const tab = await b.tab('open');
      const page = await tab.open(path);
      check.assert('the link is stripped from the address bar', false, new URL(page.url()).searchParams.has('token_hash'));
      check.assert('loading the page does not confirm the address', false, await backend.confirmed('pw_verify'));
      const confirmed = await b.act(page, 'confirmLink');
      check.assert('one click confirms and signs in, joined, safe return path', { state: 'signed_in', roles: ['member'], next: '/app' },
        { state: confirmed.state, roles: summary(confirmed).roles, next: confirmed.next });
      check.assert('the address is confirmed in Auth', true, await backend.confirmed('pw_verify'));
      await tab.close();
      const other = await b.tab('open');
      const reusedPage = await other.open(path);
      const reused = await b.act(reusedPage, 'confirmLink');
      check.assert('the used link opened again: expired_link, no session', { state: 'expired_link', keys: [] }, { state: reused.state, keys: await b.sessionKeys(reusedPage) });
      check.assert('no page error', [], other.errors());
      await other.close();
    },
  },
  {
    id: 'PW.recovery',
    async run(b, backend, check) {
      const user = await backend.user('pw_recover');
      const { tokenHash } = await backend.recoveryLink('pw_recover');
      const tab = await b.tab('open');
      const page = await tab.open(`/account/reset?token_hash=${tokenHash}&type=recovery`);
      const pending = await b.act(page, 'confirmLink');
      check.assert('the recovery link opens a pending reset', { screen: 'reset', recoveryPending: true }, { screen: pending.screen, recoveryPending: pending.recoveryPending });
      const second = await tab.open('/account/sign-in');
      const confined = await b.view(second);
      check.assert('a second tab cannot escape the pending reset', { screen: 'reset', recoveryPending: true }, { screen: confined.screen, recoveryPending: confined.recoveryPending });
      const fresh = backend.newPassword();
      const updated = await b.act(page, 'updatePassword', { password: fresh });
      check.assert('the new password is accepted and the reset completes', { error: null, recoveryPending: false }, { error: updated.error, recoveryPending: updated.recoveryPending });
      await b.act(page, 'signOut');
      const signInPage = await tab.open('/account/sign-in');
      const old = await signIn(b, backend, signInPage, user);
      check.assert('the old password no longer works', { state: 'error', error: 'invalid_credentials' }, { state: old.state, error: old.error });
      const now = await signIn(b, backend, signInPage, { email: user.email, password: fresh });
      check.assert('the new password signs in', 'signed_in', now.state);
      check.assert('no page error', [], tab.errors());
      await tab.close();
    },
  },
  {
    id: 'PW.sign_out',
    async run(b, backend, check) {
      const member = await backend.user('pw_member');
      const tab = await b.tab('open');
      const page = await tab.open('/account/sign-in');
      check.assert('signed in', 'signed_in', (await signIn(b, backend, page, member)).state);
      const token = await b.accessToken(page);
      backend.secret(token);
      check.assert('the Node path accepts the browser session', 200, await backend.nodeStatus(token));
      const out = await b.act(page, 'signOut');
      check.assert('sign-out: revoked at Auth and cleared locally', { remote: 'revoked', local: 'cleared' }, { remote: out.signOut?.remote ?? null, local: out.signOut?.local ?? null });
      check.assert('every kit key removed from storage', [], await b.kitKeys(page));
      check.assert('the Node path refuses the signed-out token on the next request', 401, await backend.nodeStatus(token));
      await tab.close();
    },
  },
]);
