data "azurerm_client_config" "current" {}

# ==========================================================================
# Generated credentials
# ==========================================================================

resource "random_password" "admin" {
  length           = 24
  min_lower        = 2
  min_upper        = 2
  min_numeric      = 2
  min_special      = 2
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>?"
}

resource "random_password" "dsrm" {
  length           = 24
  min_lower        = 2
  min_upper        = 2
  min_numeric      = 2
  min_special      = 2
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>?"
}

resource "random_string" "kv_suffix" {
  length  = 5
  lower   = true
  upper   = false
  numeric = true
  special = false
}

# ==========================================================================
# Key Vault - the only place credentials live at rest
# ==========================================================================

resource "azurerm_key_vault" "range" {
  name                = "kv-${local.name_prefix}-${random_string.kv_suffix.result}"
  location            = azurerm_resource_group.range.location
  resource_group_name = azurerm_resource_group.range.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  # A lab is destroyed and rebuilt often; purge protection would prevent the
  # vault name from being reclaimed on the next apply.
  purge_protection_enabled   = false
  soft_delete_retention_days = 7
  enable_rbac_authorization  = false

  tags = local.common_tags
}

resource "azurerm_key_vault_access_policy" "deployer" {
  key_vault_id = azurerm_key_vault.range.id
  tenant_id    = data.azurerm_client_config.current.tenant_id
  object_id    = data.azurerm_client_config.current.object_id

  secret_permissions = ["Get", "List", "Set", "Delete", "Purge", "Recover"]
}

# --------------------------------------------------------------------------
# Secrets
# --------------------------------------------------------------------------

resource "azurerm_key_vault_secret" "admin_password" {
  name         = "range-admin-password"
  value        = local.admin_password
  key_vault_id = azurerm_key_vault.range.id

  depends_on = [azurerm_key_vault_access_policy.deployer]
  tags       = local.common_tags
}

resource "azurerm_key_vault_secret" "dsrm_password" {
  name         = "range-dsrm-password"
  value        = random_password.dsrm.result
  key_vault_id = azurerm_key_vault.range.id

  depends_on = [azurerm_key_vault_access_policy.deployer]
  tags       = local.common_tags
}

resource "azurerm_key_vault_secret" "admin_username" {
  name         = "range-admin-username"
  value        = var.admin_username
  key_vault_id = azurerm_key_vault.range.id

  depends_on = [azurerm_key_vault_access_policy.deployer]
  tags       = local.common_tags
}

# Per-forest directory-services restore-mode password. Kept distinct so a
# single leaked value does not unlock every forest.
resource "azurerm_key_vault_secret" "forest_dsrm" {
  for_each = var.forests

  name         = "forest-${each.key}-dsrm-password"
  value        = random_password.dsrm.result
  key_vault_id = azurerm_key_vault.range.id

  depends_on = [azurerm_key_vault_access_policy.deployer]
  tags       = local.common_tags
}
