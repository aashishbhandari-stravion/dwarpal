// Compile-only check of the emulator declarations as a test would use them.

import { startAuthEmulator } from '../../../packages/emulator/index.js';
import type { AuthEmulator, FaultMode, FixtureOperation, FixtureSnapshot } from '../../../packages/emulator/index.js';

async function scenario(): Promise<void> {
  const emulator: AuthEmulator = await startAuthEmulator({ port: 0, now: 0, linkTtlSeconds: 600, log: (entry) => void entry.status });
  const origin: string = emulator.origin;
  const key: string = emulator.publishableKey;
  const { userId, factorId } = emulator.controls.seedUser({ email: 'a@example.test', password: 'fixture-password', aal: 'aal2' });
  emulator.controls.seedClient({ clientId: 'studio', signupPolicy: 'open', model: {}, state: 'live', managerUserId: userId, managerRoleKey: 'steward' });
  const { tokenHash } = emulator.controls.issueLink({ type: 'recovery', email: 'a@example.test' });
  const changed: boolean = emulator.controls.setMembership({ userId, clientId: 'studio', roleKey: 'member', present: false }).changed;
  const operation: FixtureOperation = 'join_client';
  const mode: FaultMode = 'lost_after_commit';
  emulator.controls.setFault({ operation, mode });
  emulator.controls.advanceTime(1000);
  if (factorId !== undefined) void emulator.controls.totpCode({ factorId });
  emulator.controls.setOAuthAccount(null);
  emulator.controls.setEmailConfirmed({ userId, confirmed: true });
  const snapshot: FixtureSnapshot = emulator.controls.snapshot();
  const synthetic: true = snapshot.synthetic;
  void [origin, key, tokenHash, changed, synthetic, snapshot.clients[0]?.enrollments[0]?.grantedRoles];
  await emulator.close();

  // @ts-expect-error only loopback hosts are accepted
  await startAuthEmulator({ host: '0.0.0.0' });
  // @ts-expect-error unknown fault modes are rejected
  emulator.controls.setFault({ operation: 'join_client', mode: 'slow' });
  // @ts-expect-error unknown operations are rejected
  emulator.controls.setFault({ operation: 'drop_table', mode: 'http_503' });
}

void scenario;
