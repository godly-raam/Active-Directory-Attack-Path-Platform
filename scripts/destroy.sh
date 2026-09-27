#!/usr/bin/env bash
#
# destroy.sh - Tear the range down to stop all billing.
#
# Deletes the lab resource group (and therefore every billable resource in
# it). Key Vault and disk soft-delete are purged by the provider config so
# nothing keeps accruing cost.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TF_DIR="$ROOT/terraform"

pushd "$TF_DIR" >/dev/null
if [ ! -d .terraform ]; then
  terraform init -upgrade
fi

printf '\nThis will DESTROY all resources managed by Terraform.\n'
read -r -p 'Type "destroy" to continue: ' ANS
if [ "$ANS" != "destroy" ]; then
  printf 'Aborted.\n'
  exit 1
fi

terraform destroy -auto-approve
popd >/dev/null

printf '\nRange destroyed. Verify no stray resources:\n'
printf '  az group list -o table\n'
