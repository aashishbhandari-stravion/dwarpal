// Optional default screens: renders the controller's view into one root
// element, with `ak-` prefixed classes from styles.css, the configured brand
// and copy. Every text is set with textContent and every attribute from a
// fixed name, so neither copy nor any answer can inject markup. The screens
// hold no auth state of their own; each action goes to the controller and
// each new view replaces the rendered tree. Passwords are never re-filled.

export const DEFAULT_COPY = Object.freeze({
  'signIn.title': 'Sign in to {brand}',
  'signIn.submit': 'Sign in',
  'signIn.google': 'Continue with Google',
  'signIn.forgot': 'Forgot your password?',
  'signIn.toSignUp': 'Create an account',
  'signUp.title': 'Create your {brand} account',
  'signUp.submit': 'Create account',
  'signUp.toSignIn': 'Already have an account? Sign in',
  'field.email': 'E-mail address',
  'field.password': 'Password',
  'field.newPassword': 'New password',
  'field.code': 'Six-digit code',
  'verify.title': 'Confirm your e-mail address',
  'verify.confirm': 'Confirm my e-mail address',
  'verify.waiting': 'Open the link we sent to your e-mail address.',
  'sent.email': 'If the address can be used, we have sent it an e-mail. Open the link in it to continue.',
  'sent.recovery': 'If an account uses this address, we have sent it a link to set a new password.',
  'resend.submit': 'Send the e-mail again',
  'resend.wait': 'You can ask for another e-mail in {seconds} s.',
  'forgot.title': 'Reset your password',
  'forgot.submit': 'Send reset link',
  'reset.title': 'Set a new password',
  'reset.confirm': 'Continue to set a new password',
  'reset.submit': 'Save new password',
  'reset.pending': 'Set a new password to finish, or sign out.',
  'reset.waiting': 'Open the password reset link from your e-mail, or ask for a new one.',
  'link.expired': 'This link has expired or is not valid. Ask for a new one.',
  'link.used': 'This link has already been used.',
  'mfa.title': 'Two-step verification',
  'mfa.challenge': 'Enter the code from your authenticator app.',
  'mfa.enrol': 'Your role needs two-step verification. Set up an authenticator app to continue.',
  'mfa.enrolStart': 'Set up authenticator',
  'mfa.scan': 'Scan this code with your authenticator app, or enter the key below, then type the code it shows.',
  'mfa.submit': 'Verify',
  'mfa.skip': 'Not now',
  'withheld.intro': 'These roles stay inactive until you complete two-step verification:',
  'callback.title': 'Signing you in',
  'callback.working': 'Finishing sign-in…',
  'callback.retry': 'Start Google sign-in again',
  'signOut.title': 'Sign out',
  'signOut.submit': 'Sign out everywhere',
  'signOut.done': 'You are signed out on this device.',
  'signOut.remoteUnconfirmed': 'We could not confirm that your other sessions were signed out. Sign out again when you are online.',
  'signOut.localFailed': 'This browser would not let us remove your session. Close the browser or clear this site\'s data.',
  'state.submitting': 'Working…',
  'state.signedIn': 'You are signed in.',
  'state.continue': 'Continue',
  'state.setupPending': 'Your account is not ready yet. Please try again in a moment.',
  'state.noAccess': 'Your account has no access to {brand}. Ask the site to grant you access.',
  'state.offline': 'You appear to be offline, or the service could not be reached.',
  'state.retry': 'Try again',
  'state.toSignIn': 'Go to sign in',
  'error.invalid_input': 'Check the details you entered.',
  'error.invalid_credentials': 'The e-mail address or password is not correct.',
  'error.email_unverified': 'Confirm your e-mail address first. Open the link we sent you.',
  'error.weak_password': 'Choose a longer or less common password.',
  'error.same_password': 'Choose a password different from your current one.',
  'error.rate_limited': 'Too many attempts. Wait a moment and try again.',
  'error.mfa_invalid_code': 'That code did not work. Check your authenticator app and try again.',
  'error.provider_unavailable': 'Google sign-in could not be completed. Start again.',
  'error.method_disabled': 'This sign-in method is not available here.',
  'error.session_ended': 'Your session has ended. Sign in again.',
  'error.unavailable': 'The service is not available right now.',
});

const TITLE_KEYS = Object.freeze({
  signIn: 'signIn.title', signUp: 'signUp.title', verify: 'verify.title', callback: 'callback.title',
  forgot: 'forgot.title', reset: 'reset.title', mfa: 'mfa.title', signOut: 'signOut.title',
});

/**
 * @param {HTMLElement} root
 * @param {ReturnType<typeof import('./controller.js').createAuthController>} controller
 * @param {{ copy?: Record<string, string>, now?: () => number }} [options]
 */
export function mountAuthScreens(root, controller, options = {}) {
  const config = controller.config;
  const doc = root.ownerDocument;
  const now = options.now ?? (() => Date.now());
  const copy = { ...DEFAULT_COPY, ...config.copy, ...(options.copy ?? {}) };
  const brandName = config.brand?.name ?? '';
  let lastEmail = '';
  let lastScreen = null;
  let timer = null;

  root.classList.add('ak-root');
  if (config.brand) {
    for (const [key, value] of Object.entries(config.brand.colors)) root.style.setProperty(`--ak-color-${key}`, value);
    if (config.brand.fontStack) root.style.setProperty('--ak-font', config.brand.fontStack);
  }

  const text = (key, values = {}) => {
    const template = typeof copy[key] === 'string' ? copy[key] : key;
    return template.replace(/\{(brand|seconds)\}/g, (_, name) => (name === 'brand' ? brandName : String(values[name] ?? '')));
  };

  function el(tag, className, children = [], attrs = {}) {
    const node = doc.createElement(tag);
    if (className) node.className = className;
    for (const [name, value] of Object.entries(attrs)) {
      if (value === false || value === null || value === undefined) continue;
      node.setAttribute(name, value === true ? '' : String(value));
    }
    for (const child of [children].flat()) {
      if (child === null || child === undefined || child === false) continue;
      node.append(typeof child === 'string' ? doc.createTextNode(child) : child);
    }
    return node;
  }

  const button = (label, onClick, { kind = 'primary', disabled = false, type = 'button' } = {}) => {
    const node = el('button', `ak-button ak-button--${kind}`, label, { type, disabled });
    if (onClick) node.addEventListener('click', onClick);
    return node;
  };

  const link = (label, href) => el('a', 'ak-link', label, { href });

  function field(name, labelKey, type, autocomplete, value = '') {
    const id = `ak-${name}`;
    const input = el('input', 'ak-input', [], { id, name, type, autocomplete, required: true });
    if (value) input.value = value;
    if (name === 'code') {
      input.setAttribute('inputmode', 'numeric');
      input.setAttribute('pattern', '[0-9]{6}');
      input.setAttribute('maxlength', '6');
    }
    return el('div', 'ak-field', [el('label', 'ak-label', text(labelKey), { for: id }), input]);
  }

  function form(fields, submitLabel, busy, onSubmit) {
    const node = el('form', 'ak-form', [...fields, button(submitLabel, null, { type: 'submit', disabled: busy })], { novalidate: true });
    node.addEventListener('submit', (event) => {
      event.preventDefault();
      const values = {};
      for (const [key, value] of new FormData(node).entries()) values[key] = typeof value === 'string' ? value : '';
      if (typeof values.email === 'string') lastEmail = values.email;
      onSubmit(values);
    });
    return node;
  }

  function status(view) {
    let message = null;
    let tone = 'info';
    if (view.state === 'error') {
      message = text(`error.${view.error}`);
      tone = 'error';
    } else if (view.state === 'offline') {
      message = text('state.offline');
      tone = 'error';
    } else if (view.state === 'submitting') {
      message = text(view.screen === 'callback' ? 'callback.working' : 'state.submitting');
    } else if (view.state === 'expired_link') {
      message = text('link.expired');
      tone = 'error';
    } else if (view.state === 'already_used') {
      message = text('link.used');
    }
    return el('p', `ak-status ak-status--${tone}`, message ?? '', { role: tone === 'error' ? 'alert' : 'status', 'aria-live': 'polite', hidden: message === null });
  }

  function resendBlock(view) {
    const wait = view.resendAvailableAt === null ? 0 : Math.ceil((view.resendAvailableAt - now()) / 1000);
    clearTimeout(timer);
    if (wait > 0) timer = setTimeout(() => render(controller.getView()), 1000);
    return el('div', 'ak-actions', [
      button(text('resend.submit'), () => controller.resendConfirmation({ email: lastEmail || undefined }), { kind: 'secondary', disabled: wait > 0 || view.state === 'submitting' }),
      wait > 0 ? el('p', 'ak-hint', text('resend.wait', { seconds: wait })) : null,
    ]);
  }

  function withheld(view) {
    if (view.withheldRoles.length === 0) return null;
    return el('div', 'ak-withheld', [
      el('p', 'ak-hint', text('withheld.intro')),
      el('ul', 'ak-list', view.withheldRoles.map((role) => el('li', 'ak-list-item', role))),
    ]);
  }

  function retryButton(view) {
    return view.canRetry ? button(text('state.retry'), () => controller.retry()) : null;
  }

  // Outcomes drawn the same way on every screen; null when the screen draws
  // its own. A pending recovery keeps its reset form, and the sign-out page
  // keeps its button whatever state the session is in.
  function common(view) {
    if (view.screen === 'reset' && view.recoveryPending) return null;
    if (view.screen === 'signOut' && ['signed_in', 'no_access', 'setup_pending'].includes(view.state)) return null;
    switch (view.state) {
      case 'signed_in':
        return [el('p', 'ak-message', text('state.signedIn')), withheld(view), view.next ? link(text('state.continue'), view.next) : null];
      case 'setup_pending':
        return [el('p', 'ak-message', text('state.setupPending')), el('div', 'ak-actions', [retryButton(view)])];
      case 'no_access':
        return [el('p', 'ak-message', text('state.noAccess')), el('div', 'ak-actions', [button(text('signOut.submit'), () => controller.signOut(), { kind: 'secondary' })])];
      case 'offline':
      case 'error':
        return view.canRetry ? [el('div', 'ak-actions', [retryButton(view)])] : null;
      default:
        return null;
    }
  }

  function body(view) {
    const busy = view.state === 'submitting';
    const routes = config.routes;
    switch (view.screen) {
      case 'signUp':
        if (view.state === 'sent') return [el('p', 'ak-message', text('sent.email')), resendBlock(view)];
        return [
          form([field('email', 'field.email', 'email', 'email', lastEmail), field('password', 'field.password', 'password', 'new-password')],
            text('signUp.submit'), busy, (v) => controller.signUp({ email: v.email, password: v.password })),
          el('p', 'ak-links', [link(text('signUp.toSignIn'), routes.signIn)]),
        ];
      case 'verify':
        if (view.link) return [button(text('verify.confirm'), () => controller.confirmLink(), { disabled: busy })];
        if (view.state === 'expired_link' || view.state === 'already_used') return [link(text('state.toSignIn'), routes.signIn)];
        if (view.error === 'email_unverified' || view.state === 'sent') return [el('p', 'ak-message', text('verify.waiting')), resendBlock(view)];
        return [el('p', 'ak-message', text('verify.waiting'))];
      case 'forgot':
        if (view.state === 'sent') return [el('p', 'ak-message', text('sent.recovery'))];
        return [form([field('email', 'field.email', 'email', 'email', lastEmail)], text('forgot.submit'), busy, (v) => controller.requestRecovery({ email: v.email }))];
      case 'reset':
        if (view.recoveryPending) {
          return [
            el('p', 'ak-message', text('reset.pending')),
            form([field('password', 'field.newPassword', 'password', 'new-password')], text('reset.submit'), busy, (v) => controller.updatePassword({ password: v.password })),
            el('div', 'ak-actions', [button(text('signOut.submit'), () => controller.signOut(), { kind: 'secondary', disabled: busy })]),
          ];
        }
        if (view.link) return [button(text('reset.confirm'), () => controller.confirmLink(), { disabled: busy })];
        return [el('p', 'ak-message', text('reset.waiting')), link(text('forgot.submit'), routes.forgot)];
      case 'mfa':
        return mfaBody(view, busy);
      case 'callback':
        if (view.error === 'provider_unavailable') {
          return [el('div', 'ak-actions', [button(text('callback.retry'), () => controller.startGoogle())]), link(text('state.toSignIn'), routes.signIn)];
        }
        return [];
      case 'signOut':
        if (view.signOut) {
          return [
            el('p', 'ak-message', text('signOut.done')),
            view.signOut.remote === 'unconfirmed' ? el('p', 'ak-status ak-status--error', text('signOut.remoteUnconfirmed'), { role: 'alert' }) : null,
            view.signOut.local === 'failed' ? el('p', 'ak-status ak-status--error', text('signOut.localFailed'), { role: 'alert' }) : null,
            link(text('state.toSignIn'), routes.signIn),
          ];
        }
        return [button(text('signOut.submit'), () => controller.signOut(), { disabled: busy })];
      default:
        return signInBody(view, busy);
    }
  }

  function signInBody(view, busy) {
    const routes = config.routes;
    const parts = [];
    if (config.providers.email) {
      parts.push(form([field('email', 'field.email', 'email', 'email', lastEmail), field('password', 'field.password', 'password', 'current-password')],
        text('signIn.submit'), busy, (v) => controller.signIn({ email: v.email, password: v.password })));
    }
    if (config.providers.google) parts.push(el('div', 'ak-actions', [button(text('signIn.google'), () => controller.startGoogle(), { kind: 'secondary', disabled: busy })]));
    if (view.error === 'email_unverified' || view.state === 'sent') {
      if (view.state === 'sent') parts.unshift(el('p', 'ak-message', text('sent.email')));
      parts.push(resendBlock(view));
    }
    const links = [];
    if (config.providers.email) links.push(link(text('signIn.forgot'), routes.forgot));
    if (config.providers.email && config.selfSignup) links.push(link(text('signIn.toSignUp'), routes.signUp));
    if (links.length > 0) parts.push(el('p', 'ak-links', links));
    return parts;
  }

  function mfaBody(view, busy) {
    const mfa = view.mfa;
    if (!mfa) return [link(text('state.toSignIn'), config.routes.signIn)];
    const codeForm = form([field('code', 'field.code', 'text', 'one-time-code')], text('mfa.submit'), busy, (v) => controller.verifyMfa({ code: v.code }));
    if (mfa.mode === 'challenge') return [el('p', 'ak-message', text('mfa.challenge')), codeForm];
    const parts = [el('p', 'ak-message', text('mfa.enrol')), withheld(view)];
    if (!mfa.enrolment) {
      parts.push(el('div', 'ak-actions', [button(text('mfa.enrolStart'), () => controller.startMfaEnrol(), { disabled: busy })]));
    } else {
      parts.push(
        el('p', 'ak-hint', text('mfa.scan')),
        el('img', 'ak-qr', [], { src: mfa.enrolment.qrCode, alt: '', width: 180, height: 180 }),
        el('code', 'ak-secret', mfa.enrolment.secret),
        codeForm,
      );
    }
    if (mfa.optional) parts.push(el('div', 'ak-actions', [button(text('mfa.skip'), () => controller.skipMfaEnrol(), { kind: 'secondary', disabled: busy })]));
    return parts;
  }

  function render(view) {
    const screen = view.screen ?? 'signIn';
    const heading = el('h1', 'ak-title', text(TITLE_KEYS[screen]), { tabindex: '-1' });
    const header = el('header', 'ak-header', [
      config.brand?.logoUrl ? el('img', 'ak-logo', [], { src: config.brand.logoUrl, alt: brandName }) : null,
      heading,
    ]);
    const content = common(view) ?? body(view);
    const card = el('section', 'ak-card', [header, status(view), ...content], {
      'data-ak-screen': screen, 'data-ak-state': view.state, 'aria-busy': view.state === 'submitting' ? 'true' : 'false',
    });
    root.replaceChildren(card);
    if (screen !== lastScreen) {
      lastScreen = screen;
      heading.focus?.({ preventScroll: true });
    }
  }

  const unsubscribe = controller.subscribe(render);
  render(controller.getView());
  return {
    unmount() {
      clearTimeout(timer);
      unsubscribe();
      root.replaceChildren();
      root.classList.remove('ak-root');
    },
  };
}
