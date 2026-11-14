#!/usr/bin/env node

/**
 *
 * ARD_FILING_CONFIRMED (packages/core/lib/patent-gates.ts) gates whether the
 * tarball at all. This reads that flag straight from the monorepo source
 * (only available at publish time, from a real checkout — never shipped
 * itself) and fails the publish if the flag is false but package.json's
 */

const fs = require('fs');
const path = require('path');

const PACKAGE_ROOT = path.resolve(__dirname, '..');
const PATENT_GATES_PATH = path.resolve(
  PACKAGE_ROOT,
  '..',
  'core',
  'lib',
  'patent-gates.ts'
);

// above). mpesa has no such flag — it's always excluded from the published
// tarball, filing status aside — so its check is independent and
// silently stops enforcing the mpesa exclusion too (that's the exact bug
// this guard now exists to prevent; TODO 466/df-TK-Week-12).
const ARD_REQUIRED_EXCLUSIONS = [
  'dist/agent-identity/**',
  'dist/internal.js',
];
const MPESA_REQUIRED_EXCLUSIONS = ['dist/mpesa/**'];

if (!fs.existsSync(PATENT_GATES_PATH)) {
  console.error(
  );
  process.exit(1);
}

const gatesSource = fs.readFileSync(PATENT_GATES_PATH, 'utf8');
const match = gatesSource.match(
  /export const ARD_FILING_CONFIRMED\s*=\s*(true|false)/
);
if (!match) {
  console.error(
  );
  process.exit(1);
}


const pkg = JSON.parse(
  fs.readFileSync(path.join(PACKAGE_ROOT, 'package.json'), 'utf8')
);
const files = pkg.files || [];

let failed = false;

  console.log(
  );
} else {
    pattern => !files.includes(`!${pattern}`)
  );
    console.error(
    );
      console.error(`  - "!${m}"`);
    }
    console.error(
      `\nAdd the missing negated glob(s) to "files" before publishing, or wait until ARD_FILING_CONFIRMED flips to true.\n`
    );
    failed = true;
  } else {
    console.log(
    );
  }
}

const missingMpesa = MPESA_REQUIRED_EXCLUSIONS.filter(
  pattern => !files.includes(`!${pattern}`)
);
if (missingMpesa.length > 0) {
  console.error(
  );
  for (const m of missingMpesa) {
    console.error(`  - "!${m}"`);
  }
  console.error(
    `\nAdd the missing negated glob(s) to "files" before publishing.\n`
  );
  failed = true;
} else {
  console.log(
  );
}

if (failed) {
  process.exit(1);
}
