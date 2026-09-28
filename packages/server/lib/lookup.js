// `bootstrap-manager --email` resolution (design 4.1, R5, L32). The listing
// is accepted only once it is known to be complete: a page shorter than the
// page size, with no `next` link, and a total count (when Auth sends one)
// no larger than the users seen. Reaching the page cap first, or any
// inconsistency between those signals, refuses with lookup_incomplete: an
// unread page could hold another match, so uniqueness is never claimed from a
// partial scan. Emails are compared case-insensitively and never printed.

import { OperatorError } from './operator-error.js';

export const PAGE_SIZE = 1000;
export const PAGE_CAP = 10;

/**
 * @param {{ listUsersPage(page: number, perPage: number): Promise<{ users: { id: string, email: string | null, confirmed: boolean }[], hasNext: boolean, total: number | null }> }} admin
 * @param {string} email
 * @returns {Promise<{ confirmed: string[], unconfirmed: string[], pages: number }>}
 */
export async function scanForEmail(admin, email, { pageSize = PAGE_SIZE, pageCap = PAGE_CAP } = {}) {
  const wanted = email.toLowerCase();
  const confirmed = new Set();
  const unconfirmed = new Set();
  const seen = new Set();
  for (let page = 1; page <= pageCap; page += 1) {
    const { users, hasNext, total } = await admin.listUsersPage(page, pageSize);
    for (const user of users) {
      seen.add(user.id);
      if (typeof user.email === 'string' && user.email.toLowerCase() === wanted) {
        (user.confirmed ? confirmed : unconfirmed).add(user.id);
      }
    }
    if (users.length < pageSize) {
      if (hasNext || (total !== null && total > seen.size)) {
        throw new OperatorError('lookup_incomplete', { pages: page, reason: 'inconsistent_listing' });
      }
      return { confirmed: [...confirmed], unconfirmed: [...unconfirmed], pages: page };
    }
  }
  throw new OperatorError('lookup_incomplete', { pages: pageCap, reason: 'page_cap' });
}
