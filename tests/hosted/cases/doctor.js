// L33 doctor modes under Max's D1 amendment A: with only the secret key the
// privileged catalog checks are not_run and the report is incomplete; with
// the Management token catalog mode inspects the real catalog; --probe adds
// a separately reported disposable-user mode. Two deliberate widenings are
// applied for the detection cases and always revoked:
//
//   W1  SELECT on a private table to authenticated: visible to the catalog
//       only (no probe call can observe it)
//   W2  EXECUTE on an operator wrapper and its implementation to
//       authenticated: visible to both modes (the probe's null-argument call
//       then reaches the implementation and is refused as invalid_argument)

import path from 'node:path';
import { attempt, requireAction } from '../lib/world.js';
import { GRANT_VIOLATIONS_SQL } from '../lib/sqlprobe.js';

export const WIDENINGS = Object.freeze({
  W1: {
    grant: 'grant select on auth_kit_private.request_log to authenticated',
    revoke: 'revoke select on auth_kit_private.request_log from authenticated',
    marker: 'request_log',
  },
  W2: {
    grant: 'grant execute on function auth_kit.register_client(text, text, text) to authenticated; grant execute on function auth_kit_private.register_client_impl(text, text, text) to authenticated',
    revoke: 'revoke execute on function auth_kit.register_client(text, text, text) from authenticated; revoke execute on function auth_kit_private.register_client_impl(text, text, text) from authenticated',
    marker: 'register_client',
  },
});

const CATALOG_IDS = ['schema_version', 'grants', 'memberships_without_events', 'exposed_schemas'];
const PROBE_IDS = ['probe_sign_in', 'probe_authenticated_effective_access', 'probe_authenticated_operator_wrapper', 'probe_authenticated_private_schema',
  'probe_anon_user_wrapper', 'probe_anon_helper', 'probe_anon_private_schema', 'probe_sign_out'];

function statuses(report, ids) {
  const out = {};
  for (const id of ids) out[id] = report?.checks?.find((c) => c.id === id)?.status ?? 'absent';
  return out;
}

function modeOf(report, id) {
  return report?.checks?.find((c) => c.id === id)?.mode ?? null;
}

export async function revertWidenings(ctx, keys = Object.keys(WIDENINGS)) {
  for (const key of keys) {
    await ctx.hosted.management.exec(WIDENINGS[key].revoke);
    ctx.ledger.removed('grant_widening', key);
  }
}

export const procedures = [{
  id: 'doctor',
  group: 'doctor',
  requiresTargets: ['T.identity', 'T.signing_keys', 'T.schema'],
  async run(ctx) {
    const probeUser = await ctx.actors.user('probe_user');
    const configArgs = [];
    if (ctx.descriptor.doctor?.configFile) configArgs.push('--config', path.resolve(ctx.descriptor.doctor.configFile));
    const doctor = async (args, opts) => {
      const r = await ctx.hosted.cli(['doctor', ...configArgs, ...args], opts);
      ctx.observe(`doctor ${args.join(' ') || '(catalog)'}${opts?.management === false ? ' without Management token' : ''}`, { exit: r.code, report: r.json });
      return r;
    };
    const probeArgs = ['--probe', '--probe-email', probeUser.email];
    const probeEnv = { extraEnv: { AUTH_KIT_PROBE_PASSWORD: probeUser.password } };

    await attempt(ctx, 'L33.secret_only_incomplete', async (check) => {
      const r = await doctor([], { management: false });
      check.assert('exit 5 and status incomplete', { exit: 5, status: 'incomplete' }, { exit: r.code, status: r.json?.status });
      check.assert('privileged catalog checks not_run', Object.fromEntries(CATALOG_IDS.map((id) => [id, 'not_run'])), statuses(r.json, CATALOG_IDS));
      check.assert('reason is the missing Management token', true, r.json?.checks?.filter((c) => CATALOG_IDS.includes(c.id)).every((c) => c.reason === 'management_token_missing'));
      check.assert('public signing-key check ran', { status: 'ok', mode: 'public' }, { status: statuses(r.json, ['signing_keys']).signing_keys, mode: modeOf(r.json, 'signing_keys') });
      check.assert('no actor probe claimed', false, r.json?.probeRan);
    });

    await attempt(ctx, 'L33.catalog_ok', async (check) => {
      const r = await doctor([]);
      check.assert('exit 0 and status ok', { exit: 0, status: 'ok' }, { exit: r.code, status: r.json?.status });
      check.assert('catalog checks ran and passed', Object.fromEntries(CATALOG_IDS.map((id) => [id, 'ok'])), statuses(r.json, CATALOG_IDS));
      check.assert('catalog checks reported in catalog mode', true, CATALOG_IDS.every((id) => modeOf(r.json, id) === 'catalog'));
      check.assert('no violations', 0, r.json?.checks?.find((c) => c.id === 'grants')?.violationCount);
    });

    await attempt(ctx, 'L33.probe_mode', async (check) => {
      const r = await doctor(probeArgs, probeEnv);
      check.assert('exit 0 and status ok', { exit: 0, status: 'ok', probeRan: true }, { exit: r.code, status: r.json?.status, probeRan: r.json?.probeRan });
      check.assert('every probe check ok', Object.fromEntries(PROBE_IDS.map((id) => [id, 'ok'])), statuses(r.json, PROBE_IDS));
      check.assert('probe checks reported in their own mode', true, PROBE_IDS.every((id) => modeOf(r.json, id) === 'probe'));
    });

    const widen = ['L33.catalog_detects_widening', 'L33.probe_detects_widening', 'L33.widening_reverted'];
    if (!widen.some((id) => ctx.wants(id))) return;
    requireAction(ctx, 'catalog_mutation');
    const applied = [];
    try {
      for (const key of Object.keys(WIDENINGS)) {
        ctx.ledger.intent('grant_widening', key);
        applied.push(key);
        await ctx.hosted.management.exec(WIDENINGS[key].grant);
        ctx.ledger.created('grant_widening', key);
      }
      await attempt(ctx, 'L33.catalog_detects_widening', async (check) => {
        const r = await doctor([]);
        check.assert('exit 1 and status fail', { exit: 1, status: 'fail' }, { exit: r.code, status: r.json?.status });
        const violations = r.json?.checks?.find((c) => c.id === 'grants')?.violations ?? [];
        check.assert('grants check failed', 'fail', statuses(r.json, ['grants']).grants);
        check.assert('W1 reported', true, violations.some((v) => v.object.includes(WIDENINGS.W1.marker) && v.grantee === 'authenticated' && v.actual === true));
        check.assert('W2 reported', true, violations.some((v) => v.object.includes(WIDENINGS.W2.marker) && v.grantee === 'authenticated' && v.actual === true));
      });
      await attempt(ctx, 'L33.probe_detects_widening', async (check) => {
        const r = await doctor(probeArgs, probeEnv);
        const wrapper = r.json?.checks?.find((c) => c.id === 'probe_authenticated_operator_wrapper');
        check.assert('probe mode reports the widened operator wrapper', { status: 'fail', mode: 'probe' }, { status: wrapper?.status, mode: wrapper?.mode });
        ctx.observe('W1 is catalog-only: the probe makes no private-table read', { probeChecksFailing: r.json?.checks?.filter((c) => c.mode === 'probe' && c.status === 'fail').map((c) => c.id) });
      });
    } finally {
      await revertWidenings(ctx, applied);
    }
    await attempt(ctx, 'L33.widening_reverted', async (check) => {
      check.assert('grant assertion empty again', 0, Number(await ctx.hosted.management.read(GRANT_VIOLATIONS_SQL)));
      const r = await doctor([]);
      check.assert('catalog mode ok again', { exit: 0, status: 'ok' }, { exit: r.code, status: r.json?.status });
    });
  },
}];
