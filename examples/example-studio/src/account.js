// Entry of the auth pages. The public configuration (already validated by the build) is inlined at
// build time by vite.config.js (`__AUTH_CONFIG__`); it holds the project URL
// and the publishable key only.

import '@briqvent/dwarpal/browser/styles.css';
import { createAuthController, mountAuthScreens } from '@briqvent/dwarpal/browser';

/* global __AUTH_CONFIG__ */
const controller = createAuthController({ config: __AUTH_CONFIG__ });
mountAuthScreens(document.getElementById('dwarpal-auth'), controller);
controller.start();
