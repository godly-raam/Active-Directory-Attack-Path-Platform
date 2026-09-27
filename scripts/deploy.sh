#!/usr/bin/env bash
#
# deploy.sh - Build the range end to end.
#
#   1. preflight (auth + tooling)
#   2. print the cost estimate and require explicit confirmation
#   3. terraform init/fmt/validate/plan
#   4. terraform apply
#   5. emit the Ansible inventory
#
# Everything is gated behind a confirmation prompt because this burns real
# free-trial credit.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_DIR="$ROOT/terraform"

if [ ! -f "$TF_DIR/terraform.tfvars" ]; then
  printf 'terraform/terraform.tfvars not found.\n'
  printf 'Copy terraform/terraform.tfvars.example -> terraform.tfvars and edit it.\n'
  exit 1
fi

if [ "${SKIP_PREFLIGHT:-0}" != "1" ]; then
  "$ROOT/scripts/preflight.sh" "${1:-}"
fi

printf '\n=== Estimated cost (see docs/cost.md) ===\n'
printf 'Typical 8h build/test session: ~$18-26 for the full 15-host topology.\n'
printf 'Idle racks up the same hourly rate until autoshutdown or destroy.\n\n'
read -r -p 'Type "apply" to provision real Azure resources: ' ANS
if [ "$ANS" != "apply" ]; then
  printf 'Aborted.\n'
  exit 1
fi

pushd "$TF_DIR" >/dev/null
terraform init -upgrade
terraform fmt -recursive
terraform validate
terraform plan -out=range.tfplan
terraform apply range.tfplan
popd >/dev/null

printf '\n=== Generating Ansible inventory ===\n'
"$ROOT/scripts/generate-inventory.sh"

printf '\nNext: configure SSH/WinRM + VPN, then run the Ansible site playbook.\n'
printf 'See docs/runbook.md.\n'
