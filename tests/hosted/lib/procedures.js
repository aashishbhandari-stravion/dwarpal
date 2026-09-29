// Procedure order. Revocation starts early so its wait for token expiry
// overlaps the other work; cleanup always runs last.

import { procedures as target } from '../cases/target.js';
import { procedures as routing } from '../cases/routing.js';
import { procedures as policy } from '../cases/policy.js';
import { procedures as matrix } from '../cases/matrix.js';
import { procedures as revocation } from '../cases/revocation.js';
import { procedures as enrollment } from '../cases/enrollment.js';
import { procedures as model } from '../cases/model.js';
import { procedures as requests } from '../cases/requests.js';
import { procedures as scope } from '../cases/scope.js';
import { procedures as bootstrap } from '../cases/bootstrap.js';
import { procedures as managers } from '../cases/managers.js';
import { procedures as mfaReset } from '../cases/mfa-reset.js';
import { procedures as doctor } from '../cases/doctor.js';
import { procedures as providers } from '../cases/providers.js';
import { procedures as cleanup } from '../cases/cleanup.js';

const [revocationStart, revocationFinish] = revocation;

export const PROCEDURES = Object.freeze([
  ...target,
  revocationStart,
  ...routing,
  ...policy,
  ...matrix,
  ...enrollment,
  ...model,
  ...requests,
  ...scope,
  ...bootstrap,
  ...managers,
  ...mfaReset,
  ...doctor,
  ...providers,
  revocationFinish,
  ...cleanup,
]);
