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

const REQUIRED_EXCLUSIONS = [
  'dist/agent-identity/**',
  'dist/internal.js',
];

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


  console.log(
  );
  process.exit(0);
}

const pkg = JSON.parse(
  fs.readFileSync(path.join(PACKAGE_ROOT, 'package.json'), 'utf8')
);
const files = pkg.files || [];

const missing = REQUIRED_EXCLUSIONS.filter(
  pattern => !files.includes(`!${pattern}`)
);

if (missing.length > 0) {
  console.error(
  );
  for (const m of missing) {
    console.error(`  - "!${m}"`);
  }
  console.error(
    `\nAdd the missing negated glob(s) to "files" before publishing, or wait until ARD_FILING_CONFIRMED flips to true.\n`
  );
  process.exit(1);
}

console.log(
);
