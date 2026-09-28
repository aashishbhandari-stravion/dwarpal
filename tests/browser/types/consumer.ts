// Compile-only consumer check of the browser declarations, through the
// package name so the `exports` map's `./browser` types condition is used.

import {
  BROWSER_STATES,
  BROWSER_ERROR_CODES,
  createAuthController,
  mountAuthScreens,
  type AuthView,
  type BrowserState,
  type BrowserErrorCode,
} from '@briqvent/dwarpal/browser';

const states: readonly BrowserState[] = BROWSER_STATES;
const codes: readonly BrowserErrorCode[] = BROWSER_ERROR_CODES;

const controller = createAuthController({
  config: {
    clientId: 'studio',
    supabaseUrl: 'https://project.supabase.co',
    publishableKey: 'sb_publishable_example',
    origin: 'https://studio.example',
    allowedReturnPaths: ['/app'],
    defaultReturnPath: '/app',
    providers: { email: true, google: false },
    selfSignup: true,
  },
  mfaEnrolOptional: false,
});

async function flow(root: HTMLElement): Promise<void> {
  const screens = mountAuthScreens(root, controller, { copy: { 'signIn.title': 'Welcome' } });
  const view: AuthView = await controller.start();
  if (view.state === 'signed_in' && view.principal) {
    const roles: readonly string[] = view.principal.access.activeRoles;
    void roles;
  }
  if (view.signOut?.remote === 'unconfirmed') screens.unmount();
  await controller.signIn({ email: 'a@example.test', password: 'secret' });
  // @ts-expect-error states are a closed set
  const wrong: BrowserState = 'signed_out';
  void wrong;
}

void states;
void codes;
void flow;
