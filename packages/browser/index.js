// Public browser entry (`@briqvent/dwarpal/browser`): the headless controller,
// its closed state and error sets, and the optional default screens. The
// stylesheet ships separately as `packages/browser/styles.css`.

export { createAuthController, BROWSER_STATES } from './controller.js';
export { BROWSER_ERROR_CODES } from './lib/codes.js';
export { mountAuthScreens, DEFAULT_COPY } from './screens.js';
