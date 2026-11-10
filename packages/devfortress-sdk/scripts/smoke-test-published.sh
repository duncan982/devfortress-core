#!/usr/bin/env bash
set -euo pipefail

# Fresh-tarball smoke test (TODO 167).
#
# devfortress-sdk@4.9.2 was live and broken on npm for an unknown period
# because nothing independently installed the just-published artifact from
# the real registry (only workspace:*-linked consumers touched it, which
# never exercises the published tarball's own "files" allowlist / require
# graph). Run this manually after every `npm publish` from this package —
# it is NOT wired into any build/CI step and must not auto-run.
#
# Usage:
#   bash scripts/smoke-test-published.sh [version]
#   (defaults to the version currently in package.json, i.e. the one you
#   presumably just published)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION="${1:-$(node -p "require('$PACKAGE_ROOT/package.json').version")}"

echo "[smoke-test-published] Installing devfortress-sdk@${VERSION} from the real npm registry into a scratch directory..."

SCRATCH_DIR=$(mktemp -d -t devfortress-sdk-smoke-XXXXXX)
trap 'rm -rf "$SCRATCH_DIR"' EXIT

cd "$SCRATCH_DIR"
npm init -y >/dev/null 2>&1
if ! npm install --no-save "devfortress-sdk@${VERSION}" --registry https://registry.npmjs.org/ >/tmp/devfortress-sdk-smoke-install.log 2>&1; then
  echo "[smoke-test-published] FAILED — could not install devfortress-sdk@${VERSION} from the registry:"
  cat /tmp/devfortress-sdk-smoke-install.log
  exit 1
fi

echo "[smoke-test-published] Install OK. Requiring/importing published entry points..."

cat > smoke.cjs <<'EOF'
const assert = require('assert');
const main = require('devfortress-sdk');
assert(main && typeof main === 'object', 'main entry point did not resolve to an object');
require('devfortress-sdk/quick');
console.log('[smoke-test-published] require() OK for "." and "./quick"');
EOF

if ! node smoke.cjs; then
  echo "[smoke-test-published] FAILED — require() smoke test threw."
  exit 1
fi

cat > smoke.mjs <<'EOF'
import * as main from 'devfortress-sdk';
if (!main || typeof main !== 'object') {
  throw new Error('ESM import did not resolve to an object');
}
console.log('[smoke-test-published] import OK for "."');
EOF

if ! node smoke.mjs; then
  echo "[smoke-test-published] FAILED — ESM import smoke test threw."
  exit 1
fi

echo "[smoke-test-published] OK — devfortress-sdk@${VERSION} installs and loads cleanly from the real npm registry."
