provider "azurerm" {
  subscription_id = var.subscription_id != "" ? var.subscription_id : null

  features {
    resource_group {
      # A short-lived range destroys its resource group wholesale. Without this
      # Terraform refuses to delete a group that still contains resources.
      prevent_deletion_if_contains_resources = false
    }
    key_vault {
      # Purge on destroy so soft-deleted vaults do not occupy the namespace and
      # block re-applies during rapid build/test/destroy cycles.
      purge_soft_delete_on_destroy    = true
      recover_soft_deleted_key_vaults = true
    }
    virtual_machine {
      delete_os_disk_on_deletion = true
    }
  }
}
