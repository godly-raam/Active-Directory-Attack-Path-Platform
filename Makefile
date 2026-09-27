.RECIPEPREFIX := >
TF := terraform
SHELL := /usr/bin/env bash

.PHONY: help preflight init fmt validate plan apply deploy destroy inventory ansible syntax test

help: ## List available targets
> @grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

preflight: ## Check Azure auth, tooling, and print the cost model
> ./scripts/preflight.sh

init: ## terraform init
> cd terraform && $(TF) init -upgrade

fmt: ## terraform fmt
> cd terraform && $(TF) fmt -recursive

validate: ## terraform validate
> cd terraform && $(TF) validate

plan: ## terraform plan (writes range.tfplan)
> cd terraform && $(TF) plan -out=range.tfplan

apply: ## terraform apply of range.tfplan
> cd terraform && $(TF) apply range.tfplan

deploy: ## Full build: preflight + apply + inventory
> ./scripts/deploy.sh

destroy: ## Destroy all Azure resources (stops billing)
> ./scripts/destroy.sh

inventory: ## Regenerate the Ansible inventory from Terraform outputs
> ./scripts/generate-inventory.sh

ansible: ## Configure the range end to end
> ansible-playbook -i ansible/inventory/hosts.yml ansible/site.yml

syntax: ## Ansible syntax check (no Azure required)
> ansible-playbook -i ansible/inventory/hosts.example.yml ansible/site.yml --syntax-check

test: ## Run the attack-path engine test suite
> cd attack-path-engine && python3 -m pytest
