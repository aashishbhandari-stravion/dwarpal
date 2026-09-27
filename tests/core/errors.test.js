import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  AUTH_ERROR_CODES,
  AuthError,
  isAuthError,
  createPrincipal,
  validateClientConfig,
  validateModel,
  planModelChange,
  requirePermission,
} from '@briqvent/dwarpal';
import { fixturePrincipals } from '@briqvent/dwarpal/testing';

// Synthetic marker shaped like a secret key; assembled at runtime so secret
// scanners do not flag the test source.
const SECRET = ['sb', 'secret', 'MARKERsecret0123456789'].join('_');
const ATTACKER = 'MARKER<script>alert(1)</script>\r\nSet-Cookie: x=1';

function surfaces(err) {
  return [err.message, String(err), JSON.stringify(err), JSON.stringify(err.issues ?? []), err.stack ?? ''].join('\n');
}

function capture(fn) {
  try {
    fn();
  } catch (err) {
    return err;
  }
  assert.fail('expected a throw');
}

test('the error set is the closed contract list', () => {
  assert.deepEqual([...AUTH_ERROR_CODES], [
    'no_token', 'invalid_token', 'expired', 'email_unverified', 'mfa_required', 'forbidden',
    'unavailable', 'provider_unavailable', 'config_invalid', 'model_invalid', 'request_conflict',
  ]);
  assert.ok(Object.isFrozen(AUTH_ERROR_CODES));
  for (const c of AUTH_ERROR_CODES) {
    const err = new AuthError(c);
    assert.equal(err.code, c);
    assert.equal(err.name, 'AuthError');
    assert.ok(err instanceof Error && isAuthError(err));
    assert.deepEqual(err.issues, []);
  }
  assert.equal(isAuthError(new Error('forbidden')), false);
  assert.equal(isAuthError({ code: 'forbidden' }), false);
});

test('unknown codes are refused without echoing the value', () => {
  for (const bad of [ATTACKER, 'Forbidden', '', undefined, 403]) {
    const err = capture(() => new AuthError(bad));
    assert.ok(err instanceof TypeError);
    assert.ok(!err.message.includes('MARKER'));
  }
});

test('code and issues cannot be rewritten after construction', () => {
  const err = new AuthError('forbidden');
  assert.throws(() => { err.code = 'unavailable'; }, TypeError);
  const withIssues = new AuthError('model_invalid', { issues: [{ path: 'a', rule: 'b', value: SECRET }] });
  assert.deepEqual(withIssues.issues, [{ path: 'a', rule: 'b' }]);
  assert.throws(() => { withIssues.issues.push({ path: 'x', rule: 'y' }); }, TypeError);
  // Issues are carried only by the two validation codes.
  assert.deepEqual(new AuthError('forbidden', { issues: [{ path: 'a', rule: 'b' }] }).issues, []);
});

test('config errors never echo secrets or attacker strings', () => {
  const err = capture(() => validateClientConfig({
    clientId: ATTACKER,
    supabaseUrl: `https://${ATTACKER}`,
    publishableKey: SECRET,
    origin: ATTACKER,
    allowedReturnPaths: [ATTACKER],
    defaultReturnPath: ATTACKER,
    providers: { email: ATTACKER, google: false },
    selfSignup: ATTACKER,
    [ATTACKER]: SECRET,
    copy: { [ATTACKER]: SECRET },
  }));
  assert.equal(err.code, 'config_invalid');
  assert.ok(err.issues.length > 5);
  assert.ok(!surfaces(err).includes('MARKER'), surfaces(err));
});

test('model errors never echo attacker keys or values', () => {
  const err = capture(() => validateModel({
    client: ATTACKER,
    roles: { [ATTACKER]: { manages_members: ATTACKER }, ok: { manages_members: true, permissions: [ATTACKER, 'undeclared:key'] } },
    permissions: { [ATTACKER]: SECRET },
    [ATTACKER]: 1,
  }));
  assert.equal(err.code, 'model_invalid');
  assert.ok(!surfaces(err).includes('MARKER'), surfaces(err));
  const planErr = capture(() => planModelChange(null, { client: 'x', roles: {}, permissions: {} }, { state: ATTACKER, holders: { [ATTACKER]: [SECRET] } }));
  assert.ok(!surfaces(planErr).includes('MARKER'), surfaces(planErr));
});

test('snapshot and evaluation errors carry no input data', () => {
  const err = capture(() => createPrincipal({ clientId: ATTACKER, identity: { userId: SECRET }, session: {}, enrolledAt: null, memberships: [] }));
  assert.equal(err.code, 'unavailable');
  assert.ok(!surfaces(err).includes('MARKER'));
  const denied = capture(() => requirePermission(fixturePrincipals.patron, ATTACKER));
  assert.equal(denied.code, 'forbidden');
  assert.ok(!surfaces(denied).includes('MARKER'));
});
