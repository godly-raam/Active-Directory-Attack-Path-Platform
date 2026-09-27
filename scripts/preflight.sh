#!/usr/bin/env bash
#
# preflight.sh - Verify the local attack box can build the lab.
#
# Checks (in order):
#   1. Required CLI tooling is present (az, terraform, ansible-playbook, jq).
#   2. Azure CLI is authenticated.
#   3. The selected subscription is Enabled.
#   4. Best-effort detection of Azure free-trial / credit offer.
#
# This script is READ-ONLY against Azure. It never creates or modifies
# resources. Run it before `terraform apply`.
#
# Usage:
#   ./scripts/preflight.sh [subscription-id-or-name]

set -euo pipefail

RED=$'\033[31m'; GRN=$'\033[32m'; YLW=$'\033[33m'; RST=$'\033[0m'
ok()   { printf '%s[ ok ]%s %s\n' "$GRN" "$RST" "$*"; }
warn() { printf '%s[warn]%s %s\n' "$YLW" "$RST" "$*"; }
fail() { printf '%s[fail]%s %s\n' "$RED" "$RST" "$*"; }

missing=0
for tool in az terraform jq ansible-playbook; do
  if command -v "$tool" >/dev/null 2>&1; then
    ok "$tool found: $(command -v "$tool")"
  else
    fail "$tool NOT found on PATH"
    missing=1
  fi
done

if [ "$missing" -ne 0 ]; then
  fail "Install missing tooling before continuing (see docs/runbook.md)."
  exit 1
fi

echo
if ! az account show >/dev/null 2>&1; then
  fail "Azure CLI is not authenticated. Run: az login"
  exit 1
fi

if [ "${1:-}" != "" ]; then
  az account set --subscription "$1"
fi

SUB_JSON="$(az account show -o json)"
SUB_NAME="$(jq -r '.name'   <<<"$SUB_JSON")"
SUB_ID="$(jq -r '.id'     <<<"$SUB_JSON")"
SUB_STATE="$(jq -r '.state' <<<"$SUB_JSON")"
SUB_USER="$(jq -r '.user.name' <<<"$SUB_JSON")"

ok "Authenticated as: $SUB_USER"
ok "Active subscription: $SUB_NAME ($SUB_ID)"
if [ "$SUB_STATE" = "Enabled" ]; then
  ok "Subscription state: Enabled"
else
  fail "Subscription state is '$SUB_STATE' (expected Enabled)"
  exit 1
fi

# Best-effort credit / offer detection. The CLI does not expose the offer
# GUID directly in `account show`, so probe for common free-trial signals.
echo
if az consumption budget list -o none 2>/dev/null; then
  warn "Verify remaining credit manually: Cost Management + Billing > Credits."
else
  warn "Could not read budgets (permission or offer limitation)."
fi

# Newer CLI exposes a subscription 'tags'/'managedBy' blob for some offers;
# look for a free-trial marker without failing if absent.
OFFER_HINT="$(az rest --method get \
  --url "https://management.azure.com/subscriptions/${SUB_ID}?api-version=2022-12-01" \
  -o json 2>/dev/null | jq -r '.tags // {} | to_entries[]? | "\(.key)=\(.value)"' 2>/dev/null || true)"
if grep -qi 'free\|trial\|credit' <<<"$OFFER_HINT"; then
  ok "Free-trial/credit marker detected on the subscription."
else
  warn "No explicit free-trial marker found. Confirm this is the \$200 free"
  warn "trial subscription before applying, or set subscription_id explicitly."
fi

echo
ok "Preflight complete. Proceed to docs/cost.md, then: make plan && make apply"
