// Skeletons written by `auth-kit init` (design 9 step 1). They hold
// placeholders only: no project URL, key or token. The environment example
// lists variable names with empty values and belongs outside the repository
// once filled in.

const CONFIG = {
  clientId: 'example',
  supabaseUrl: 'https://your-project-ref.supabase.co',
  publishableKey: 'sb_publishable_replace-me',
  origin: 'https://www.example.com',
  allowedReturnPaths: ['/'],
  defaultReturnPath: '/',
  providers: { email: true, google: false },
  selfSignup: true,
};

const MODEL = {
  client: 'example',
  roles: {
    manager: { manages_members: true, mfa_required: true, permissions: ['members:manage', 'records:read:any'] },
    member: { self_assignable: true, permissions: ['records:read:own'] },
  },
  permissions: {
    'members:manage': 'grant and revoke non-manager roles',
    'records:read:own': "read records linked to the user's own id",
    'records:read:any': 'read any record',
  },
};

const ENV_EXAMPLE = `# auth-kit operator environment. Keep the filled-in copy outside any repository.
SUPABASE_URL=
# Secret key (sb_secret_...): operator shell only, never a web server or browser.
SUPABASE_SECRET_KEY=
# Management API personal access token, for migrate and doctor's catalog checks.
SUPABASE_ACCESS_TOKEN=
# Only for a custom domain: the project ref.
SUPABASE_PROJECT_REF=
# For doctor --probe: the publishable key and the disposable probe user's password.
SUPABASE_PUBLISHABLE_KEY=
AUTH_KIT_PROBE_PASSWORD=
`;

export const INIT_FILES = Object.freeze({
  'auth-kit.config.json': `${JSON.stringify(CONFIG, null, 2)}\n`,
  'auth-model.json': `${JSON.stringify(MODEL, null, 2)}\n`,
  '.env.example': ENV_EXAMPLE,
});
