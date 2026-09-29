// Harness self-test, not hosted evidence: runs every hosted procedure, in
// the real order, against the local rehearsal target (rehearsal-fixture.js)
// with hosted provenance off. It checks the procedures' requests, parsing,
// expectations, ledger and cleanup end to end; every record must come out
// not_run/not_hosted, whatever the rehearsal observed.
//
//   DWARPAL_PG_BIN=<bin> node tests/sql/run.js tests/hosted/selftest/sql/rehearsal.test.js

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { withDatabase } from '../../../sql/harness/db.js';
import { createRehearsal } from './rehearsal-fixture.js';
import { CASES, ACTION_CLASSES } from '../../lib/inventory.js';
import { PROCEDURES } from '../../lib/procedures.js';
import { runProcedures } from '../../lib/runner.js';
import { Redactor } from '../../lib/redact.js';
import { Evidence } from '../../lib/evidence.js';
import { Ledger } from '../../lib/ledger.js';
import { createGate } from '../../lib/net.js';
import { createHosted } from '../../lib/hosted.js';
import { Actors, newRunId } from '../../lib/actors.js';
import { clientIds } from '../../lib/fixtures.js';
import { createPrompter } from '../../lib/interactive.js';
import { PUBLIC_ROOT } from '../../lib/paths.js';

// Cases the rehearsal cannot reach: real providers need a human and real mail
// or Google; the duplicate-address case is refused by Auth (and by the fixture).
const UNREHEARSABLE = new Map([
  ['P.smtp.confirmation_delivered', 'blocked'],
  ['P.smtp.custom_sender', 'blocked'],
  ['P.google.sign_in', 'blocked'],
  ['L32.email_two_matches', 'not_run'],
]);

// Findings the rehearsal reproduces on the real migration (see README, open questions).
const KNOWN_FINDINGS = new Map([
  ['L29.live.no_manager_refused', 'refusal names the holder'],
]);

async function rehearse(db, { selection = null, mutate = async () => {} } = {}) {
  const policiesSql = fs.readFileSync(path.join(PUBLIC_ROOT, 'examples', 'rls-consumer', 'policies.sql'), 'utf8');
  const r = await createRehearsal(db, { policiesSql });
  const dir = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'dwh-rehearsal-')), 'evidence');
  try {
    await mutate(r, db);
    const redactor = new Redactor();
    const evidence = new Evidence(dir, redactor);
    const ledger = new Ledger(path.join(dir, 'state', 'ledger.jsonl'));
    const gate = createGate({ fetch: r.fetch, onCall: (c) => evidence.append('calls.jsonl', c) });
    gate.open([r.target.url]);
    const actions = new Set(Object.keys(ACTION_CLASSES).filter((a) => a !== 'send_email' && a !== 'interactive_sign_in'));
    const hosted = createHosted({
      gate, target: r.target, creds: r.creds, redactor, limits: { signInsPerFiveMinutes: 100_000 }, sleep: r.clock.sleep, clockNow: r.clock.now,
      managementOrigin: r.target.url, cliEnv: r.cliEnv,
    });
    const runId = newRunId();
    const descriptor = { identities: { emailTemplate: 'rehearsal+{tag}@example.test' }, limits: { maxTokenLifetimeSeconds: 3600 }, callbackPort: 54329 };
    const caps = { publishable_key: true, secret_key: true, management_token: true, smtp_recipient: false, google_identity: false, interactive: false };
    const ctx = {
      hosted, ledger, redactor, gate, creds: r.creds, descriptor, runId, caps, actions, clock: r.clock,
      actors: new Actors({ hosted, ledger, redactor, template: descriptor.identities.emailTemplate, runId, actions, sleep: r.clock.sleep }),
      ids: clientIds(runId), state: {}, prompt: createPrompter({ enabled: false }), callbackPort: 54329,
      identity: { urlMatches: true, refConfirmed: true, authorizationCurrent: true, sourceClean: true },
    };
    const { records, summary } = await runProcedures({ procedures: PROCEDURES, ctx, selection, capabilities: caps, actions, hosted: false, evidence });
    const { leaks } = evidence.finalize([ledger.file]);
    return { records, summary, leaks, dir, ledger, creds: r.creds };
  } finally {
    await r.close();
  }
}

function failingNames(records, id) {
  return records.get(id).assertions.filter((a) => !a.ok).map((a) => a.name);
}

test('every hosted procedure rehearses end to end and nothing passes without hosted provenance', { timeout: 600_000 }, async () => {
  await withDatabase(async (db) => {
    const { records, summary, leaks, dir, ledger, creds } = await rehearse(db);
    const report = [...records.values()].map((x) => ({ id: x.id, status: x.status, rehearsal: `${x.rehearsal?.status}:${x.rehearsal?.reason}` }));
    fs.writeFileSync(path.join(path.dirname(dir), 'rehearsal-report.json'), JSON.stringify(report, null, 2));
    process.stdout.write(`# rehearsal report: ${path.join(path.dirname(dir), 'rehearsal-report.json')}\n`);

    assert.deepEqual(leaks, [], 'no evidence leak');
    assert.equal(summary.verdict, 'incomplete');
    assert.deepEqual([...records.values()].filter((x) => x.status !== 'not_run' || x.reason !== 'not_hosted').map((x) => x.id), []);
    const unexpected = [];
    for (const c of CASES) {
      const rec = records.get(c.id);
      const want = UNREHEARSABLE.get(c.id) ?? (KNOWN_FINDINGS.has(c.id) ? 'failed' : 'passed');
      if (rec.rehearsal.status !== want) unexpected.push(`${c.id}: ${rec.rehearsal.status}:${rec.rehearsal.reason} (wanted ${want})`);
    }
    if (unexpected.length > 0) {
      const obs = fs.readFileSync(path.join(dir, 'observations.jsonl'), 'utf8').split('\n').filter((l) => /"ok":false|procedure_error|: error"/.test(l)).slice(0, 40);
      process.stdout.write(`# failing observations:\n${obs.map((l) => `# ${l.slice(0, 600)}`).join('\n')}\n`);
    }
    assert.deepEqual(unexpected, []);
    for (const [id, name] of KNOWN_FINDINGS) assert.deepEqual(failingNames(records, id), [name], id);
    // Cleanup left nothing the ledger could remove.
    assert.deepEqual(ledger.outstanding().filter((e) => e.kind !== 'client').map((e) => `${e.kind}:${e.key}`), []);
    // No credential reached any evidence file, including the ledger.
    for (const file of [...fs.readdirSync(dir).map((f) => path.join(dir, f)), ledger.file]) {
      if (!fs.statSync(file).isFile()) continue;
      const text = fs.readFileSync(file, 'utf8');
      for (const secret of Object.values(creds).filter((v) => v.startsWith('sb'))) assert.ok(!text.includes(secret), `${file} holds a credential`);
    }
  });
});

test('sensitivity: a widened grant and a session check that ignores sign-out fail the cases that must catch them', { timeout: 600_000 }, async () => {
  await withDatabase(async (db) => {
    const { records } = await rehearse(db, {
      selection: new Set(['L28.sql.execute.authenticated', 'L28.sql.execute.anon', 'L25.signout.node', 'L25.ban.node']),
      mutate: async (r) => {
        const postgres = await db.connection('postgres');
        await postgres.query('grant execute on function auth_kit_private.register_client_impl(text, text, text) to authenticated');
        // Auth that forgets signed-out sessions: /user keeps answering 200.
        r.fake.hooks.set('user', async ({ cred }) => {
          if (cred.kind !== 'user') return undefined;
          for (const session of r.fake.sessions.values()) session.revoked = false;
          return undefined;
        });
      },
    });
    const status = (id) => `${records.get(id).rehearsal.status}`;
    assert.equal(status('T.schema'), 'failed', 'the grant assertion reports the widening');
    assert.equal(status('L28.sql.execute.authenticated'), 'failed');
    assert.equal(status('L28.sql.execute.anon'), 'passed');
    assert.equal(status('L25.signout.node'), 'failed');
    assert.equal(status('L25.ban.node'), 'passed', 'a ban is still refused');
    assert.ok(failingNames(records, 'L28.sql.execute.authenticated').some((n) => n.startsWith('catalog and impersonation agree')));
    assert.deepEqual(failingNames(records, 'L25.signout.node'), ['next Node request refused']);
  });
});
