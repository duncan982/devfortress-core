#!/bin/bash
# =============================================================================
# DevFortress — Open-Core Validation Runner
# =============================================================================
# Runs sdk-validation-v3.sh and client-application-validation-v3.sh against
# the open-core local instance (localhost:3001) using the open-core credentials
# stored in devfortress-core/validations/validation.env.
#
# Usage:
#   bash scripts/run-validations-open-core.sh
#   bash scripts/run-validations-open-core.sh --app hubcommerce
#   bash scripts/run-validations-open-core.sh --app hubcommerce --include-filing4
#   bash scripts/run-validations-open-core.sh --sdk-only
#   bash scripts/run-validations-open-core.sh --client-only
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Paths
OPEN_CORE_ENV="${REPO_ROOT}/validations/validation.env"
# Set PRIVATE_VALIDATIONS_DIR to the path of your private devfortress/validations directory
PRIVATE_VALIDATIONS_DIR="${PRIVATE_VALIDATIONS_DIR:-}"
if [ -z "$PRIVATE_VALIDATIONS_DIR" ]; then
  echo "ERROR: PRIVATE_VALIDATIONS_DIR env var must be set to the path of your private validations directory."
  echo "  export PRIVATE_VALIDATIONS_DIR=/path/to/devfortress/validations"
  exit 1
fi
SDK_SCRIPT="${PRIVATE_VALIDATIONS_DIR}/sdk-validation-v3.sh"
CLIENT_SCRIPT="${PRIVATE_VALIDATIONS_DIR}/client-application-validation-v3.sh"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'; BOLD='\033[1m'

# ── Preflight checks ──────────────────────────────────────────────────────────
if [ ! -f "$OPEN_CORE_ENV" ]; then
  echo -e "${RED}✗ Open-core validation.env not found at: ${OPEN_CORE_ENV}${NC}"
  echo -e "  Create it and fill in your credentials from http://localhost:3001/dashboard/credentials"
  exit 1
fi

if grep -q "FILL_IN" "$OPEN_CORE_ENV"; then
  echo -e "${YELLOW}⚠  validation.env still contains FILL_IN placeholders.${NC}"
  echo -e "  Fill in real values from http://localhost:3001/dashboard/credentials before running."
  exit 1
fi

if [ ! -f "$SDK_SCRIPT" ]; then
  echo -e "${RED}✗ SDK validation script not found at: ${SDK_SCRIPT}${NC}"
  exit 1
fi

if [ ! -f "$CLIENT_SCRIPT" ]; then
  echo -e "${RED}✗ Client validation script not found at: ${CLIENT_SCRIPT}${NC}"
  exit 1
fi

# ── Parse flags ───────────────────────────────────────────────────────────────
RUN_SDK=true
RUN_CLIENT=true
PASS_THROUGH_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --sdk-only)    RUN_CLIENT=false; shift ;;
    --client-only) RUN_SDK=false;    shift ;;
    *)             PASS_THROUGH_ARGS+=("$1"); shift ;;
  esac
done

# Default --app hubcommerce if no --app flag was passed
HAS_APP_FLAG=false
for arg in "${PASS_THROUGH_ARGS[@]+"${PASS_THROUGH_ARGS[@]}"}"; do
  [[ "$arg" == "--app" ]] && HAS_APP_FLAG=true
done
if [ "$HAS_APP_FLAG" = "false" ]; then
  PASS_THROUGH_ARGS+=("--app" "hubcommerce")
fi

echo -e "${BOLD}${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║     DevFortress Open-Core Validation Runner                   ║${NC}"
echo -e "${BOLD}${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Platform : http://localhost:3001 (open-core)"
echo -e "  Client   : http://localhost:3000 (hubcommerce)"
echo -e "  Env file : ${OPEN_CORE_ENV}"
echo ""

# ── Open-core platform lifecycle ─────────────────────────────────────────────
# The SDK validation scripts start the platform from their own PROJECT_ROOT
# (the private repo). We must start the open-core platform first so they detect
# it as already running and skip their own startup.
OC_PLATFORM_PID_FILE=/tmp/oc-platform.pid
OC_PLATFORM_OWNED=false

_start_oc_platform() {
  if curl -s --max-time 3 http://localhost:3001/api/health 2>/dev/null | grep -q '"status"'; then
    local running_pid
    running_pid=$(lsof -i :3001 -t 2>/dev/null | head -1)
    local running_dir=""
    if [ -n "$running_pid" ]; then
      running_dir=$(readlink -f "/proc/$running_pid/cwd" 2>/dev/null || true)
    fi
    if [[ "$running_dir" == *"devfortress-core"* ]]; then
      echo -e "  ${GREEN}✅ Open-core platform already running (pid $running_pid)${NC}"
      return 0
    else
      echo -e "  ${YELLOW}⚠ Port 3001 is occupied by a different process — stopping it${NC}"
      kill "$running_pid" 2>/dev/null || true
      sleep 3
    fi
  fi

  echo -e "  ${BOLD}Starting open-core platform (devfortress-core) on port 3001...${NC}"
  nohup bash -c "cd ${REPO_ROOT} && pnpm run dev" > /tmp/oc-platform.log 2>&1 &
  echo $! > "$OC_PLATFORM_PID_FILE"
  OC_PLATFORM_OWNED=true

  local elapsed=0
  while [ $elapsed -lt 120 ]; do
    if curl -s --max-time 3 http://localhost:3001/api/health 2>/dev/null | grep -q '"status"'; then
      echo -e "  ${GREEN}✅ Open-core platform ready (${elapsed}s)${NC}"
      return 0
    fi
    sleep 3; elapsed=$((elapsed + 3))
  done
  echo -e "  ${RED}✗ Open-core platform failed to start — check /tmp/oc-platform.log${NC}"
  return 1
}

_stop_oc_platform() {
  if [ "$OC_PLATFORM_OWNED" = "true" ] && [ -f "$OC_PLATFORM_PID_FILE" ]; then
    echo -e "  Stopping open-core platform..."
    local pid
    pid=$(cat "$OC_PLATFORM_PID_FILE")
    kill "$pid" 2>/dev/null || true
    rm -f "$OC_PLATFORM_PID_FILE"
  fi
}

_start_oc_platform || exit 1
trap _stop_oc_platform EXIT

# ── Helper: run a script with open-core env vars exported at highest priority ──
# Pre-exports all vars from the open-core validation.env before calling the
# script. The validation scripts skip vars already set in the environment, so
# open-core values take precedence over anything in the private validation.env.
_run_with_env() {
  local target_script="$1"
  shift

  # Export every non-comment, non-blank line from the open-core env file
  while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    if [[ "$line" =~ ^([A-Za-z_][A-Za-z0-9_]*)= ]]; then
      export "$line" 2>/dev/null || true
    fi
  done < "$OPEN_CORE_ENV"

  bash "$target_script" "$@"
  return $?
}

# ── Run SDK validation ────────────────────────────────────────────────────────
SDK_EXIT=0
if [ "$RUN_SDK" = "true" ]; then
  echo -e "${BOLD}▶ Running SDK Validation (sdk-validation-v3.sh)...${NC}"
  echo ""
  _run_with_env "$SDK_SCRIPT" "${PASS_THROUGH_ARGS[@]+"${PASS_THROUGH_ARGS[@]}"}" || SDK_EXIT=$?
  echo ""
fi

# ── Run Client validation ─────────────────────────────────────────────────────
CLIENT_EXIT=0
if [ "$RUN_CLIENT" = "true" ]; then
  echo -e "${BOLD}▶ Running Client Application Validation (client-application-validation-v3.sh)...${NC}"
  echo ""
  _run_with_env "$CLIENT_SCRIPT" "${PASS_THROUGH_ARGS[@]+"${PASS_THROUGH_ARGS[@]}"}" || CLIENT_EXIT=$?
  echo ""
fi

# ── Final summary ─────────────────────────────────────────────────────────────
echo -e "${BOLD}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║     Open-Core Validation Runner — Complete                    ║${NC}"
echo -e "${BOLD}╚═══════════════════════════════════════════════════════════════╝${NC}"
[ "$RUN_SDK" = "true" ]    && { [ "$SDK_EXIT" -eq 0 ]    && echo -e "  SDK Validation    : ${GREEN}✅ PASSED${NC}" || echo -e "  SDK Validation    : ${RED}❌ FAILED (exit $SDK_EXIT)${NC}"; }
[ "$RUN_CLIENT" = "true" ] && { [ "$CLIENT_EXIT" -eq 0 ] && echo -e "  Client Validation : ${GREEN}✅ PASSED${NC}" || echo -e "  Client Validation : ${RED}❌ FAILED (exit $CLIENT_EXIT)${NC}"; }
echo ""

OVERALL_EXIT=$(( SDK_EXIT + CLIENT_EXIT ))
exit $OVERALL_EXIT
