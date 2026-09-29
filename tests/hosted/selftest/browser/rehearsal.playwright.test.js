// Offline rehearsal of the hosted Playwright flows (browser/flows.js) against
// the development Auth emulator (packages/emulator) in Chromium. It checks
// the flows' own logic and assertions; it is local fixture evidence, never
// hosted proof: every record it could produce is not_run / not_hosted, and
// nothing here reaches a network beyond loopback.
//
//   node --test tests/hosted/selftest/browser/rehearsal.playwright.test.js

import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { chromium } from 'playwright-core';
import { startAuthEmulator } from '../../../../packages/emulator/index.js';
import { createAuthServer } from '../../../../packages/server/index.js';
import { FLOWS } from '../../browser/flows.js';
import { startSite } from '../../browser/site.js';
import { createBrowser } from '../../browser/driver.js';
import { browserModel } from '../../lib/fixtures.js';
import { CaseCheck, normaliseRecord } from '../../lib/status.js';
import { CASES } from '../../lib/inventory.js';

const IDS = { open: 'rehearsal-p', closed: 'rehearsal-pc', noDefault: 'rehearsal-pn' };

function emulatorBackend(emulator) {
  const { controls } = emulator;
  const users = new Map();
  // The emulator's clock moves only when told (TOTP steps below); the Node path reads the same clock.
  const server = createAuthServer({ supabaseUrl: emulator.origin, publishableKey: emulator.publishableKey, clientId: IDS.open, now: () => Date.parse(controls.snapshot().now) });
  const record = (alias) => controls.snapshot().users.find((u) => u.userId === users.get(alias).userId);
  const password = () => randomBytes(18).toString('base64url');
  const seed = (alias, confirmed) => {
    const email = `${alias.replace(/_/g, '-')}@example.test`;
    const pw = password();
    const { userId } = controls.seedUser({ email, password: pw, confirmed });
    users.set(alias, { email, password: pw, userId });
    return users.get(alias);
  };
  return {
    beforeSignIn: async () => {},
    user: async (alias) => users.get(alias) ?? seed(alias, true),
    unusedEmail: () => 'nobody@example.test',
    grant: async (alias, role) => { controls.setMembership({ userId: users.get(alias).userId, clientId: IDS.open, roleKey: role, present: true }); },
    revoke: async (alias, role) => { controls.setMembership({ userId: users.get(alias).userId, clientId: IDS.open, roleKey: role, present: false }); },
    signupLink: async (alias) => ({ tokenHash: controls.issueLink({ type: 'email', email: seed(alias, false).email }).tokenHash }),
    recoveryLink: async (alias) => ({ tokenHash: controls.issueLink({ type: 'recovery', email: users.get(alias).email }).tokenHash }),
    confirmed: async (alias) => record(alias).confirmed,
    async totp(alias) {
      controls.advanceTime(30_000);
      const factors = record(alias).factors;
      return controls.totpCode({ factorId: factors[factors.length - 1].factorId });
    },
    verifiedFactors: async (alias) => record(alias).factors.filter((f) => f.status === 'verified').length,
    secret: () => {},
    newPassword: password,
    async nodeStatus(token) {
      try {
        await server.resolveSession({ headers: { authorization: `Bearer ${token}` } });
        return 200;
      } catch (error) {
        return error?.code === 'invalid_token' || error?.code === 'expired' || error?.code === 'no_token' ? 401 : 500;
      }
    },
  };
}

test('hosted browser flows rehearse in Chromium against the emulator (local fixture, not hosted evidence)', async (t) => {
  const emulator = await startAuthEmulator();
  t.after(() => emulator.close());
  const { controls } = emulator;
  const manager = controls.seedUser({ email: 'pw-manager@example.test', password: randomBytes(18).toString('base64url') });
  controls.seedClient({ clientId: IDS.open, signupPolicy: 'open', model: browserModel(IDS.open), state: 'live', managerUserId: manager.userId, managerRoleKey: 'keeper' });
  controls.seedClient({ clientId: IDS.closed, signupPolicy: 'closed', model: browserModel(IDS.closed) });
  controls.seedClient({ clientId: IDS.noDefault, signupPolicy: 'open', model: null });

  const common = { supabaseUrl: emulator.origin, publishableKey: emulator.publishableKey };
  const sites = {
    open: await startSite({ ...common, clientId: IDS.open, selfSignup: true }),
    closed: await startSite({ ...common, clientId: IDS.closed, selfSignup: false }),
    noDefault: await startSite({ ...common, clientId: IDS.noDefault, selfSignup: true }),
  };
  t.after(async () => { for (const s of Object.values(sites)) await s.close(); });
  const allowed = [emulator.origin, ...Object.values(sites).map((s) => s.origin)];
  const requests = [];
  const b = await createBrowser({ chromium, sites, admits: (origin) => allowed.includes(origin), onRequest: (e) => requests.push(e) });
  t.after(() => b.close());

  const backend = emulatorBackend(emulator);
  const outcomes = {};
  for (const flow of FLOWS) {
    const check = new CaseCheck(flow.id);
    await flow.run(b, backend, check);
    outcomes[flow.id] = check.assertions.filter((a) => !a.ok).map((a) => ({ name: a.name, expected: a.expected, observed: a.observed }));
    // A rehearsal record can never pass a hosted case.
    const rec = normaliseRecord({ id: flow.id, status: check.ok ? 'passed' : 'failed', assertions: check.assertions.map((a) => ({ ...a, evidence: 'local' })) }, { hosted: false });
    assert.equal(rec.status, 'not_run');
  }
  assert.deepEqual(outcomes, Object.fromEntries(FLOWS.map((f) => [f.id, []])));
  assert.deepEqual(FLOWS.map((f) => f.id).sort(), CASES.filter((c) => c.procedure === 'browser').map((c) => c.id).sort());
  // The fence held: nothing blocked, nothing outside loopback reached.
  assert.deepEqual(requests.filter((r) => r.blocked), []);
  assert.ok(requests.every((r) => allowed.includes(new URL(r.url).origin)));
});
