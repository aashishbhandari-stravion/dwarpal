// Provider flows on the hosted project: TOTP enrol/challenge/verify and
// self-unenrol (automated, with the harness's own authenticator); one real
// SMTP confirmation delivered to an authorized mailbox (the operator pastes
// the received link); one interactive Google sign-in with the authorized
// test identity (PKCE, redirect to the harness's loopback callback).
// Every secret involved (factor secret, link token, auth code, tokens) is
// held in memory and registered with the redactor.

import { randomBytes } from 'node:crypto';
import { attempt, ensureClient, bootstrap } from '../lib/world.js';
import { managersModel } from '../lib/fixtures.js';
import { awaitCallback } from '../lib/interactive.js';
import { pkcePair } from '../lib/hosted.js';
import { Blocked } from '../lib/status.js';
import { CALLBACK_PATH } from './target.js';

export function smtpAddress(recipient, runId) {
  return recipient.includes('{tag}') ? recipient.replace('{tag}', `hv${runId}-smtp`) : recipient;
}

/** token (or token_hash) and type from a pasted confirmation link. */
export function parseConfirmationLink(text) {
  let url;
  try {
    url = new URL(text.trim());
  } catch {
    return null;
  }
  const token = url.searchParams.get('token_hash') ?? url.searchParams.get('token');
  const type = url.searchParams.get('type');
  return token && type ? { token, type } : null;
}

async function principalAt(ctx, clientId, token) {
  const node = await ctx.hosted.nodeEndpoint(clientId);
  try {
    return await node.get(token);
  } finally {
    await node.close();
  }
}

export const procedures = [
  {
    id: 'providers',
    group: 'providers',
    requiresTargets: ['T.identity', 'T.signing_keys', 'T.auth_settings'],
    async run(ctx) {
      await ensureClient(ctx, 'D', { model: managersModel(ctx.ids.D) });
      await bootstrap(ctx, 'D', 'totp_user', 'chief');
      let aal2 = null;
      await attempt(ctx, 'P.totp.enrol_challenge', async (check) => {
        const first = await ctx.actors.signIn('totp_user');
        const before = await principalAt(ctx, ctx.ids.D, first.accessToken);
        check.assert('aal1: MFA role held but withheld', { aal: 'aal1', roles: ['chief'], activeRoles: [], mfaPending: true },
          { aal: before.body?.principal?.session?.aal, roles: before.body?.principal?.access?.roles, activeRoles: before.body?.principal?.access?.activeRoles, mfaPending: before.body?.principal?.access?.mfaPending });
        aal2 = await ctx.actors.aal2('totp_user');
        check.assert('verified factor raises the session to aal2', 'aal2', aal2.claims?.aal);
        const factors = await ctx.hosted.admin.factors(ctx.actors.get('totp_user').id);
        check.assert('one verified TOTP factor', [{ type: 'totp', status: 'verified' }], factors.map((f) => ({ type: f.type, status: f.status })));
        const after = await principalAt(ctx, ctx.ids.D, aal2.accessToken);
        check.assert('resolveSession: aal2 and the MFA role active', { aal: 'aal2', activeRoles: ['chief'], mfaPending: false },
          { aal: after.body?.principal?.session?.aal, activeRoles: after.body?.principal?.access?.activeRoles, mfaPending: after.body?.principal?.access?.mfaPending });
      });
      await attempt(ctx, 'P.totp.unenrol_self', async (check) => {
        if (aal2 === null) throw new Blocked('no_aal2_session');
        const actor = ctx.actors.get('totp_user');
        check.assert('user at aal2 removes their own factor', 200, await ctx.hosted.auth.unenroll(aal2.accessToken, actor.factor.id));
        check.assert('no factor remains', [], await ctx.hosted.admin.factors(actor.id));
        const again = await ctx.actors.signIn('totp_user');
        check.assert('a new session is aal1', 'aal1', again.claims?.aal);
      });
    },
  },
  {
    id: 'smtp',
    group: 'smtp',
    requiresTargets: ['T.identity', 'T.auth_settings'],
    async run(ctx) {
      const address = smtpAddress(ctx.descriptor.identities.smtpRecipients[0], ctx.runId);
      ctx.redactor.alias(address, 'smtp_user');
      const password = randomBytes(24).toString('base64url');
      ctx.redactor.secret(password, 'password');
      let typedDomain = null;
      await attempt(ctx, 'P.smtp.confirmation_delivered', async (check) => {
        const existing = (await ctx.hosted.admin.listPage(1, 1000)).find((u) => u.email?.toLowerCase() === address.toLowerCase());
        if (existing) throw new Blocked('smtp_recipient_already_registered');
        ctx.ledger.intent('user', 'smtp_user', { email: 'smtp_recipient' });
        const sentAt = new Date(ctx.clock.now()).toISOString();
        const signUp = await ctx.hosted.auth.signUp(address, password);
        check.assert('sign-up accepted without a session (confirmation required)', { status: 200, session: false }, { status: signUp.status, session: signUp.session });
        if (signUp.userId) {
          ctx.ledger.created('user', 'smtp_user', { id: signUp.userId.toLowerCase() });
          ctx.redactor.alias(signUp.userId, 'smtp_user');
        }
        ctx.prompt.say(`A confirmation e-mail was sent at ${sentAt} to the authorized recipient (smtp_user).`);
        const link = parseConfirmationLink(await ctx.prompt.ask('When it arrives, paste the confirmation link (used once, never stored):'));
        check.assert('a confirmation link was received and pasted', true, link !== null);
        typedDomain = (await ctx.prompt.ask('Type the domain of the From address exactly as the message shows it:')).toLowerCase();
        const verified = await ctx.hosted.auth.verifyTokenHash(link.type, link.token);
        check.assert('the delivered link verifies', 200, verified.status);
        const user = await ctx.hosted.admin.getUser(signUp.userId);
        check.assert('the address is confirmed in Auth', true, typeof user.user?.email_confirmed_at === 'string');
        ctx.observe('P.smtp delivery', { sentAt, verifiedAt: new Date(ctx.clock.now()).toISOString() });
      });
      await attempt(ctx, 'P.smtp.custom_sender', async (check) => {
        const s = ctx.state.authSettings ?? await ctx.hosted.management.authSettings();
        const authorized = ctx.descriptor.identities.smtpSenderDomain ?? null;
        check.assert('custom SMTP configured', true, s.customSmtp);
        check.assert('configured sender domain is the authorized one', authorized, s.senderDomain);
        check.assert('received From domain is the authorized one', authorized, typedDomain);
      });
    },
  },
  {
    id: 'google',
    group: 'google',
    requiresTargets: ['T.identity', 'T.signing_keys', 'T.auth_settings'],
    async run(ctx) {
      await attempt(ctx, 'P.google.sign_in', async (check) => {
        const expected = ctx.descriptor.identities.google.email.toLowerCase();
        ctx.redactor.alias(ctx.descriptor.identities.google.email, 'google_user');
        const { verifier, challenge } = pkcePair();
        ctx.redactor.secret(verifier, 'pkce_verifier');
        const redirect = `http://localhost:${ctx.callbackPort}${CALLBACK_PATH}`;
        // A Supabase user already linked to the identity is not this run's to delete.
        const preexisting = (await ctx.hosted.admin.listPage(1, 1000)).find((u) => u.email?.toLowerCase() === expected);
        ctx.observe('P.google identity already had a Supabase user', { preexisting: preexisting !== undefined });
        const pending = awaitCallback(ctx.callbackPort, CALLBACK_PATH);
        if (!preexisting) ctx.ledger.intent('user', 'google_user', { email: 'google_identity' });
        ctx.prompt.say(`Open this URL in a browser and sign in with the authorized Google test identity:\n${ctx.hosted.auth.authorizeUrl('google', redirect, challenge)}`);
        const params = await pending;
        const code = params.get('code');
        check.assert('the callback carried an authorization code', true, typeof code === 'string' && code !== '');
        const exchanged = await ctx.hosted.auth.exchangePkce(code, verifier);
        check.assert('PKCE exchange', 200, exchanged.status);
        const session = exchanged.session;
        if (!preexisting) ctx.ledger.created('user', 'google_user', { id: session.userId });
        ctx.redactor.alias(session.userId, 'google_user');
        const me = await ctx.hosted.auth.user(session.accessToken);
        const identities = Array.isArray(me.user?.identities) ? me.user.identities.map((i) => i.provider) : [];
        check.assert('Auth lists a google identity', true, identities.includes('google'));
        check.assert('the signed-in address is the authorized identity', expected, String(me.user?.email ?? '').toLowerCase());
        const p = await principalAt(ctx, 'rls-demo', session.accessToken);
        check.assert('resolveSession reports provider google and the verified address', { status: 200, google: true, verified: expected },
          { status: p.status, google: (p.body?.principal?.identity?.providers ?? []).includes('google'), verified: String(p.body?.principal?.identity?.verifiedEmail ?? '').toLowerCase() });
      });
    },
  },
];
