#!/usr/bin/env bash
#
# generate-inventory.sh - Rebuild ansible/inventory/hosts.yml from Terraform.
#
# Terraform already writes the inventory via the local_file resource, but this
# script is the one-shot way to regenerate it after an apply without touching
# the rest of the state.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_DIR="$ROOT/terraform"
OUT="$ROOT/ansible/inventory/hosts.yml"

pushd "$TF_DIR" >/dev/null
INV="$(terraform output -raw ansible_inventory_yaml 2>/dev/null || true)"
ADMIN_USER="$(terraform output -raw admin_username 2>/dev/null || true)"
popd >/dev/null

if [ -z "$INV" ]; then
  printf 'No ansible_inventory_yaml output found. Apply Terraform first.\n' >&2
  exit 1
fi

printf '%s\n' "$INV" > "$OUT"
printf 'Wrote %s (admin_user=%s)\n' "$OUT" "$ADMIN_USER"
