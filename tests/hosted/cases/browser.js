// The hosted Playwright suite (design 8; the flows are in browser/flows.js):
// the browser kit's prebuilt bundle in Chromium against the target's Auth
// and PostgREST, on three run clients: open (PW), invite-only (PWC) and
// registered without a model (PWN). The browser may reach only the project
// and the harness's own loopback sites; every request is logged with the
// run's calls. Sign-ins made by the browser draw on the same budget as the
// harness's own. Links come from the admin API; no mail is sent.

import { randomBytes } from 'node:crypto';
import { attempt, ensureClient, bootstrap, managerWrite, requireAction } from '../lib/world.js';
import { browserModel } from '../lib/fixtures.js';
import { HostedError } from '../lib/hosted.js';
import { Blocked } from '../lib/status.js';
import { totp, stepAt } from '../lib/totp.js';
import { chromium, chromiumAvailable } from '../lib/chromium.js';
import { startSite } from '../browser/site.js';
import { createBrowser } from '../browser/driver.js';
import { FLOWS } from '../browser/flows.js';

function hostedBackend(ctx, { manager, node }) {
  const created = new Map();
  const lastStep = new Map();
  const idOf = (alias) => created.get(alias) ?? ctx.actors.get(alias).id;
  const newPassword = () => {
    const password = randomBytes(24).toString('base64url');
    ctx.redactor.secret(password, 'password');
    return password;
  };
  const write = async (fn, alias, role) => {
    const r = await managerWrite(ctx, fn, manager.accessToken, 'PW', alias, role);
    if (r.kind !== 'value') throw new HostedError(fn, r.status, r.code ?? null);
  };
  return {
    beforeSignIn: () => ctx.hosted.auth.reserveSignIn(),
    user: (alias) => ctx.actors.user(alias),
    unusedEmail() {
      const email = ctx.actors.email('pw_nobody');
      ctx.redactor.alias(email, 'pw_nobody');
      return email;
    },
    grant: (alias, role) => write('grant_membership', alias, role),
    revoke: (alias, role) => write('revoke_membership', alias, role),
    async signupLink(alias) {
      requireAction(ctx, 'create_users');
      const email = ctx.actors.email(alias);
      ctx.redactor.alias(email, alias);
      ctx.ledger.intent('user', alias, { confirmed: false });
      const link = await ctx.hosted.admin.generateLink('signup', email, newPassword());
      ctx.ledger.created('user', alias, { id: link.userId });
      ctx.redactor.alias(link.userId, alias);
      created.set(alias, link.userId);
      return { tokenHash: link.tokenHash };
    },
    async recoveryLink(alias) {
      return { tokenHash: (await ctx.hosted.admin.generateLink('recovery', ctx.actors.get(alias).email)).tokenHash };
    },
    async confirmed(alias) {
      const u = await ctx.hosted.admin.getUser(idOf(alias));
      return typeof u.user?.email_confirmed_at === 'string';
    },
    /** A code for a time step this factor has not used, away from a step boundary. */
    async totp(alias, secret) {
      let now = ctx.clock.now() / 1000;
      if (lastStep.get(alias) === stepAt(now) || 30 - (now % 30) < 3) {
        await ctx.clock.sleep((30 - (now % 30)) * 1000 + 500);
        now = ctx.clock.now() / 1000;
      }
      lastStep.set(alias, stepAt(now));
      return totp(secret, now);
    },
    async verifiedFactors(alias) {
      return (await ctx.hosted.admin.factors(idOf(alias))).filter((f) => f.status === 'verified').length;
    },
    secret(value) {
      if (typeof value === 'string' && value.length >= 6) ctx.redactor.secret(value, 'browser_secret');
    },
    newPassword,
    nodeStatus: async (token) => (await node.get(token)).status,
  };
}

export const procedures = [{
  id: 'browser',
  group: 'browser',
  requiresTargets: ['T.identity', 'T.signing_keys', 'T.auth_settings'],
  async run(ctx) {
    if (!chromiumAvailable()) throw new Blocked('chromium_unavailable');
    requireAction(ctx, 'totp');
    await ensureClient(ctx, 'PW', { model: browserModel(ctx.ids.PW) });
    await ensureClient(ctx, 'PWC', { model: browserModel(ctx.ids.PWC), policy: 'closed' });
    await ensureClient(ctx, 'PWN');
    await bootstrap(ctx, 'PW', 'pw_manager', 'keeper');
    const manager = await ctx.actors.signIn('pw_manager');
    const common = { supabaseUrl: ctx.hosted.origin, publishableKey: ctx.creds.SUPABASE_PUBLISHABLE_KEY };
    const sites = {};
    const node = await ctx.hosted.nodeEndpoint(ctx.ids.PW);
    let b = null;
    try {
      sites.open = await startSite({ ...common, clientId: ctx.ids.PW, selfSignup: true });
      sites.closed = await startSite({ ...common, clientId: ctx.ids.PWC, selfSignup: false });
      sites.noDefault = await startSite({ ...common, clientId: ctx.ids.PWN, selfSignup: true });
      const loopbackSites = Object.values(sites).map((s) => s.origin);
      ctx.observe('browser suite', { chromium: 'playwright-core', sites: Object.keys(sites), bundle: 'packages/browser/dist' });
      b = await createBrowser({ chromium, sites, admits: (origin) => ctx.gate.admits(origin, loopbackSites), onRequest: (entry) => ctx.gate.record(entry) });
      const backend = hostedBackend(ctx, { manager, node });
      for (const flow of FLOWS) await attempt(ctx, flow.id, (check) => flow.run(b, backend, check));
    } finally {
      await b?.close();
      for (const site of Object.values(sites)) await site.close();
      await node.close();
    }
  },
}];
