// Type declarations for @briqvent/dwarpal/server/hono. Hono is an optional
// peer dependency; install it to use this entry.

import type { MiddlewareHandler } from 'hono';
import type { Principal } from '../core/index.js';
import type { AuthServer } from './index.js';

/**
 * Sets `c.var.principal` for a live session; otherwise answers
 * `{ error: 'no_token' | 'invalid_token' | 'expired' }` with 401, or
 * `{ error: 'unavailable' }` with 503.
 */
export declare function honoMiddleware(authServer: Pick<AuthServer, 'resolveSession'>): MiddlewareHandler<{ Variables: { principal: Principal } }>;
