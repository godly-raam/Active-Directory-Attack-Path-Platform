# ==========================================================================
# Generated Ansible inventory
# ==========================================================================

locals {
  inventory_yaml = yamlencode({
    all = {
      vars = {
        ansible_user                         = var.admin_username
        ansible_password                     = "__FETCH_FROM_KEY_VAULT__"
        ansible_connection                   = "winrm"
        ansible_winrm_transport              = "ntlm"
        ansible_winrm_scheme                 = "http"
        ansible_port                         = 5985
        ansible_winrm_server_cert_validation = "ignore"
        primary_domain                       = local.primary_domain
        primary_netbios                      = local.primary_netbios
        primary_dc                           = local.primary_dc.hostname
        primary_dc_ip                        = local.primary_dns_ip
        dsrm_password                        = "__FETCH_FROM_KEY_VAULT__"
      }
      children = {
        domain_controllers = {
          hosts = {
            for d in local.dcs : d.hostname => {
              ansible_host = d.ip
              dc_domain    = d.domain
              dc_netbios   = d.netbios
              dc_kind      = d.role
              dc_forest    = d.key
            }
          }
        }
        member_servers = {
          hosts = {
            for s in local.servers : s.name => {
              ansible_host = s.ip
              server_role  = s.role
            }
          }
        }
        workstations = {
          hosts = { for w in local.workstations : w.name => { ansible_host = w.ip } }
        }
        file_servers       = { hosts = { for s in local.servers : s.name => { ansible_host = s.ip } if s.role == "file" } }
        sql_servers        = { hosts = { for s in local.servers : s.name => { ansible_host = s.ip } if s.role == "sql" } }
        adcs_servers       = { hosts = { for s in local.servers : s.name => { ansible_host = s.ip } if s.role == "adcs" } }
        iis_servers        = { hosts = { for s in local.servers : s.name => { ansible_host = s.ip } if s.role == "iis" } }
        management_servers = { hosts = { for s in local.servers : s.name => { ansible_host = s.ip } if s.role == "mgmt" } }
      }
    }
  })
}

resource "local_file" "ansible_inventory" {
  filename        = var.ansible_inventory_path
  content         = local.inventory_yaml
  file_permission = "0600"
}

# ==========================================================================
# Cost estimate (kept as an output so it is visible at plan time)
# ==========================================================================

locals {
  vm_hourly_total = sum([
    for v in local.vm_specs : lookup(var.hourly_price_usd, v.size, var.hourly_price_usd["Standard_B2s"])
  ])
  disk_hourly_total = (length(local.vm_specs) * 0.0133) + (length(local.data_disk_specs) * 0.0133)
  network_hourly    = (var.enable_vpn_gateway ? var.hourly_price_usd_gateway : 0) + (var.enable_bastion ? var.hourly_price_usd_gateway : 0)
  est_hourly_total  = local.vm_hourly_total + local.disk_hourly_total + local.network_hourly
}

# ==========================================================================
# Outputs
# ==========================================================================

output "resource_group_name" {
  description = "Resource group containing the whole range."
  value       = azurerm_resource_group.range.name
}

output "location" {
  value = azurerm_resource_group.range.location
}

output "admin_username" {
  value = var.admin_username
}

output "key_vault_name" {
  description = "Key Vault holding the range admin password and VPN root cert."
  value       = azurerm_key_vault.range.name
}

output "key_vault_uri" {
  value = azurerm_key_vault.range.vault_uri
}

output "vpn_gateway_public_ip" {
  description = "Public IP of the point-to-site VPN gateway - the only public entry point."
  value       = var.enable_vpn_gateway ? azurerm_public_ip.vpn[0].ip_address : null
}

output "vpn_client_cert_path" {
  description = "Generated client certificate for Kali (local, git-ignored)."
  value       = local_file.vpn_client_cert.filename
}

output "vpn_client_key_path" {
  value = local_file.vpn_client_key.filename
}

output "vpn_root_cert_path" {
  value = local_file.vpn_root_cert.filename
}

output "ansible_inventory_yaml" {
  description = "YAML inventory for Ansible."
  value       = local.inventory_yaml
}

output "inventory_file" {
  value = local_file.ansible_inventory.filename
}

output "host_summary" {
  description = "Host counts by tier."
  value = {
    domain_controllers = local.dc_count
    member_servers     = local.server_count
    workstations       = local.workstation_count
    total              = local.total_host_count
    target             = var.expected_host_count
    matches_target     = local.total_host_count == var.expected_host_count
  }
}

output "estimated_hourly_cost_usd" {
  description = "Rough pay-as-you-go estimate for the full topology (see docs/cost.md)."
  value = {
    compute_and_disks = tonumber(format("%.3f", local.vm_hourly_total + local.disk_hourly_total))
    network           = tonumber(format("%.3f", local.network_hourly))
    total_per_hour    = tonumber(format("%.2f", local.est_hourly_total))
    total_8h_session  = tonumber(format("%.2f", local.est_hourly_total * 8))
    total_24h         = tonumber(format("%.2f", local.est_hourly_total * 24))
  }
}
