// Whether the Chromium build playwright-core expects is installed locally.
// Checked offline, so `plan` can report the browser suite as blocked.

import fs from 'node:fs';
import { chromium } from 'playwright-core';

export { chromium };

export function chromiumAvailable() {
  try {
    return fs.existsSync(chromium.executablePath());
  } catch {
    return false;
  }
}
