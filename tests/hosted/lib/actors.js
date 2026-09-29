// Disposable actors for one run. Every user is created through the Auth
// admin API with a confirmed address (no e-mail is sent), a generated
// password held only in memory, and a ledger intent written before the
// create call. Addresses come from the descriptor's authorized template with
// a per-run tag, so a later run never meets an earlier run's users, and a
// crashed run's users can be found again from the ledger and the template.

import { randomBytes } from 'node:crypto';
import { totp, stepAt } from './totp.js';
import { Blocked } from './status.js';
import { HostedError } from './hosted.js';

export function newRunId() {
  return randomBytes(4).toString('hex');
}

export function emailFor(template, runId, alias) {
  return template.replace('{tag}', `hv${runId}-${alias.replace(/_/g, '-')}`);
}

export class Actors {
  /**
   * @param {{ hosted: object, ledger: import('./ledger.js').Ledger, redactor: import('./redact.js').Redactor,
   *           template: string | null, runId: string, actions: Set<string>, sleep?: (ms: number) => Promise<void> }} deps
   */
  constructor({ hosted, ledger, redactor, template, runId, actions, sleep = (ms) => new Promise((r) => setTimeout(r, ms)) }) {
    Object.assign(this, { hosted, ledger, redactor, template, runId, actions, sleep });
    this.users = new Map();
    this.lastStep = new Map();
  }

  require(action) {
    if (!this.actions.has(action)) throw new Blocked(`${action}_not_authorized`);
  }

  email(alias) {
    if (this.template === null) throw new Blocked('email_template_missing');
    return emailFor(this.template, this.runId, alias);
  }

  /** Creates (once) and returns the actor. */
  async user(alias, { confirm = true } = {}) {
    if (this.users.has(alias)) return this.users.get(alias);
    this.require('create_users');
    const email = this.email(alias);
    const password = randomBytes(24).toString('base64url');
    this.redactor.secret(password, 'password');
    this.redactor.alias(email, alias);
    this.ledger.intent('user', alias, { confirmed: confirm });
    const { id } = await this.hosted.admin.createUser(email, password, { confirm });
    this.ledger.created('user', alias, { id });
    this.redactor.alias(id, alias);
    const actor = { alias, email, password, id, factor: null };
    this.users.set(alias, actor);
    return actor;
  }

  async signIn(alias) {
    this.require('mutations');
    const actor = this.users.get(alias) ?? await this.user(alias);
    return this.hosted.auth.signIn(actor.email, actor.password);
  }

  /** Enrols one TOTP factor (once) and returns an aal2 session. */
  async aal2(alias) {
    this.require('totp');
    const actor = this.users.get(alias) ?? await this.user(alias);
    const first = await this.signIn(alias);
    if (actor.factor === null) {
      const factor = await this.hosted.auth.enrollTotp(first.accessToken, `hv-${alias}`);
      this.redactor.alias(factor.id, `${alias}.factor`);
      actor.factor = factor;
    }
    return this.verify(actor, first.accessToken);
  }

  /** Challenge and verify with a code for a time step not used before by this factor. */
  async verify(actor, aal1Token) {
    for (let attempt = 0; attempt < 3; attempt += 1) {
      let now = Date.now() / 1000;
      if (this.lastStep.get(actor.factor.id) === stepAt(now)) {
        await this.sleep((30 - (now % 30)) * 1000 + 500);
        now = Date.now() / 1000;
      }
      this.lastStep.set(actor.factor.id, stepAt(now));
      try {
        return await this.hosted.auth.challengeAndVerify(aal1Token, actor.factor.id, totp(actor.factor.secret, now));
      } catch (error) {
        // A code at a step boundary can be judged against the next step; one more step is tried.
        if (!(error instanceof HostedError) || error.stage !== 'factor_verify' || error.status !== 422) throw error;
      }
    }
    throw new Blocked('totp_verify_refused');
  }

  get(alias) {
    const actor = this.users.get(alias);
    if (!actor) throw new Error(`actor ${alias} was not provisioned`);
    return actor;
  }
}
