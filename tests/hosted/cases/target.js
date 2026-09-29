// Target prerequisites (T.*). Read-only: signing keys, Auth settings,
// Management API reachability and the SQL probe channel, installed schema,
// exposed schemas, the example consumer's policies and the L26 orders
// fixture. The owner installs
// and configures all of these; the harness only checks them.

import { readMigrations, DEFAULT_MIGRATIONS_DIR } from '../../../packages/server/lib/migrate.js';
import { attempt } from '../lib/world.js';
import { ANON_CLAIMS, MEMBERSHIP_SQL, GRANT_VIOLATIONS_SQL, RLS_CONSUMER_SQL, ORDERS_CONSUMER_SQL } from '../lib/sqlprobe.js';

export const CALLBACK_PATH = '/hosted/callback';

export const procedures = [{
  id: 'target',
  group: 'target',
  async run(ctx) {
    const { hosted } = ctx;

    await attempt(ctx, 'T.identity', async (check) => {
      check.assert('environment URL is the descriptor project URL', true, ctx.identity.urlMatches);
      check.assert('invocation confirmed the project ref', true, ctx.identity.refConfirmed);
      check.assert('authorization is current', true, ctx.identity.authorizationCurrent);
      check.assert('key kinds', { publishable: true, secret: true }, { publishable: ctx.caps.publishable_key, secret: ctx.caps.secret_key });
      check.assert('public source tree is clean', true, ctx.identity.sourceClean);
    });

    await attempt(ctx, 'T.signing_keys', async (check) => {
      const res = await hosted.auth.jwks();
      const keys = Array.isArray(res.json?.keys) ? res.json.keys : [];
      check.assert('JWKS answered', 200, res.status);
      check.assert('asymmetric keys present', true, keys.some((k) => k?.kty === 'EC' || k?.kty === 'RSA'));
      check.assert('no symmetric key published', 0, keys.filter((k) => k?.kty === 'oct').length);
    });

    await attempt(ctx, 'T.management', async (check) => {
      const who = await hosted.management.read(MEMBERSHIP_SQL);
      check.assert('session role may act as anon, authenticated and service_role', [true, true, true], [who.anon, who.authenticated, who.service_role]);
      check.assert('PostgreSQL 15 or later', true, Number(who.server_version) >= 150000);
      const outcomes = await hosted.management.probe([{ role: 'anon', claims: ANON_CLAIMS, sql: "select 'probe-ok'" }]);
      check.assert('probe channel round-trips', [{ outcome: 'value', value: 'probe-ok' }], outcomes);
      const after = await hosted.management.read(`select jsonb_build_object('user', current_user, 'role', current_setting('role'),
        'claims', coalesce(current_setting('request.jwt.claims', true), ''))::text as result`);
      check.assert('no role or claims survive a probe', { role: 'none', claims: '' }, { role: after.role, claims: after.claims });
    });

    await attempt(ctx, 'T.schema', async (check) => {
      const files = readMigrations(DEFAULT_MIGRATIONS_DIR);
      ctx.observe('migration files', files.map((f) => ({ version: f.version, sha256: f.sha256 })));
      const installed = await hosted.management.read(`select coalesce(jsonb_agg(version order by version), '[]'::jsonb)::text as result from auth_kit_private.migrations`);
      check.assert('installed versions equal the repository files', files.map((f) => f.version), installed);
      check.assert('grant assertion is empty', 0, Number(await hosted.management.read(GRANT_VIOLATIONS_SQL)));
    });

    await attempt(ctx, 'T.exposed_schemas', async (check) => {
      const { schemas } = await hosted.management.postgrestConfig();
      check.assert('auth_kit exposed', true, schemas.includes('auth_kit'));
      check.assert('app exposed (example consumer)', true, schemas.includes('app'));
      check.assert('auth_kit_private never exposed', false, schemas.includes('auth_kit_private'));
    });

    await attempt(ctx, 'T.rls_consumer', async (check) => {
      const state = await hosted.management.read(RLS_CONSUMER_SQL);
      check.assert('app.notes exists with forced RLS', { table: true, rls: true }, { table: state.table, rls: state.rls });
      check.assert('the four example policies', ['notes_delete', 'notes_insert', 'notes_select', 'notes_update'], state.policies);
    });

    await attempt(ctx, 'T.orders_consumer', async (check) => {
      const state = await hosted.management.read(ORDERS_CONSUMER_SQL);
      check.assert('app.orders exists with forced RLS', { table: true, rls: true }, { table: state.table, rls: state.rls ?? false });
      check.assert('one policy, orders_select', ['orders_select'], state.policies ?? []);
      const qual = String(state.qual ?? '');
      check.assert('the policy names orders-demo and both order keys', true, ['orders-demo', 'orders:read:any', 'orders:read:own', 'auth.uid()'].every((part) => qual.includes(part)));
      check.assert('authenticated may only SELECT; anon nothing', { authenticated: ['SELECT'], anon: null }, { authenticated: state.authenticated ?? null, anon: state.anon ?? null });
    });

    await attempt(ctx, 'T.auth_settings', async (check) => {
      const s = await hosted.management.authSettings();
      ctx.state.authSettings = s;
      ctx.observe('auth settings (selected, non-secret)', { ...s, allowList: s.allowList.length });
      check.assert('TOTP enrol and verify enabled', [true, true], [s.totpEnroll, s.totpVerify]);
      check.assert('e-mail confirmation required', true, s.emailConfirmationRequired);
      const max = ctx.descriptor.limits?.maxTokenLifetimeSeconds ?? 3600;
      check.assert('access token lifetime known and within the run limit', true, Number.isInteger(s.jwtExpSeconds) && s.jwtExpSeconds > 0 && s.jwtExpSeconds <= max);
      if (ctx.actions.has('interactive_sign_in')) {
        check.assert('harness callback allow-listed exactly', true, s.allowList.includes(`http://localhost:${ctx.callbackPort}${CALLBACK_PATH}`));
        check.assert('Google provider enabled', true, s.googleEnabled);
      }
      if (ctx.actions.has('send_email')) check.assert('custom SMTP configured', true, s.customSmtp);
    });
  },
}];
