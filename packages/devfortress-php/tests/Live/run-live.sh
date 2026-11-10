#!/usr/bin/env bash
# Runs the live PHPUnit group against the LOCAL platform and LOCAL Postgres only.
#
# Creates a throwaway project (with a fresh key and its key ID) owned by the dev
# user, runs the group, then deletes the project and its events. The key lives
# in a shell variable only; nothing about it is printed.
#
#   packages/devfortress-php/tests/Live/run-live.sh
#
# Needs: the platform on http://localhost:3001 (warm), psql, curl, a local
# Postgres URL (DF_TEST_DATABASE_URL, or a 127.0.0.1 DIRECT_DATABASE_URL in .env.local).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG="$(cd "$HERE/../.." && pwd)"
ROOT="$(cd "$PKG/../.." && pwd)"
BASE="${DF_LIVE_BASE_URL:-http://localhost:3001}"
DEV_EMAIL="dev-admin@apiforge.local"

DB_URL="${DF_TEST_DATABASE_URL:-}"
if [ -z "$DB_URL" ] && [ -f "$ROOT/.env.local" ]; then
  DB_URL="$(grep -E '^DIRECT_DATABASE_URL=postgres[^[:space:]]*(127\.0\.0\.1|localhost)' "$ROOT/.env.local" | tail -1 | cut -d= -f2- | awk '{print $1}')"
fi
case "$DB_URL" in
  *127.0.0.1*|*localhost*) ;;
  *) echo "run-live: no LOCAL Postgres URL found; refusing to run against anything else" >&2; exit 2 ;;
esac
DB_URL="${DB_URL%%\?*}"
db() { psql "$DB_URL" -X -q -t -A -v ON_ERROR_STOP=1 -c "$1"; }

curl -sf -m 90 "$BASE/api/health" >/dev/null || { echo "run-live: platform not reachable at $BASE" >&2; exit 2; }
curl -s -m 90 -o /dev/null -X POST "$BASE/api/auth/dev" -H 'content-type: application/json' -d '{"role":"OWNER"}'
USER_ID="$(db "SELECT id FROM \"User\" WHERE email = '$DEV_EMAIL'")"
[ -n "$USER_ID" ] || { echo "run-live: dev user unavailable" >&2; exit 2; }

PROJECT_ID="php$(openssl rand -hex 11)"
KEY="vx_live_phptest_$(openssl rand -hex 12)"
KEY_ID="$(printf %s "$KEY" | sha256sum | cut -c1-32)"
cleanup() {
  db "DELETE FROM \"LiveThreatEvent\" WHERE \"projectId\" = '$PROJECT_ID'" >/dev/null 2>&1 || true
  db "DELETE FROM \"ApiProject\" WHERE id = '$PROJECT_ID'" >/dev/null 2>&1 || true
}
trap cleanup EXIT
db "INSERT INTO \"ApiProject\" (id, name, slug, \"createdById\", \"surveillanceApiKey\", \"surveillanceKeyId\", \"updatedAt\") VALUES ('$PROJECT_ID', 'phpunit php sdk', 'phpunit-php-sdk-$PROJECT_ID', '$USER_ID', '$KEY', '$KEY_ID', now())" >/dev/null

cd "$PKG"
DF_LIVE_API_KEY="$KEY" DF_LIVE_PROJECT_ID="$PROJECT_ID" DF_LIVE_BASE_URL="$BASE" vendor/bin/phpunit --group live "$@"
