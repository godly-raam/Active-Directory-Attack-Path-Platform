# ==========================================================================
# Global / naming
# ==========================================================================

variable "subscription_id" {
  description = "Azure subscription ID. Empty string uses the az CLI active subscription."
  type        = string
  default     = ""
}

variable "location" {
  description = "Azure region. Pick one close to you to reduce latency (does not change price much)."
  type        = string
  default     = "eastus"
}

variable "prefix" {
  description = "Short lowercase prefix used for every resource name."
  type        = string
  default     = "adrange"

  validation {
    condition     = can(regex("^[a-z0-9]{3,12}$", var.prefix))
    error_message = "prefix must be 3-12 lowercase alphanumeric characters."
  }
}

variable "environment" {
  description = "Environment tag value."
  type        = string
  default     = "lab"
}

variable "tags" {
  description = "Additional tags merged onto every resource."
  type        = map(string)
  default     = {}
}

# ==========================================================================
# Network layout
# ==========================================================================

variable "vnet_address_space" {
  description = "Address space for the lab VNet."
  type        = list(string)
  default     = ["10.10.0.0/16"]
}

variable "subnet_cidrs" {
  description = "CIDRs for the segmented tiers. Keep /24s for host clarity."
  type = object({
    gateway      = string
    bastion      = string
    management   = string
    dc           = string
    servers      = string
    workstations = string
  })
  default = {
    gateway      = "10.10.0.0/27"
    bastion      = "10.10.0.32/27"
    management   = "10.10.0.64/27"
    dc           = "10.10.10.0/24"
    servers      = "10.10.20.0/24"
    workstations = "10.10.30.0/24"
  }
}

variable "vpn_client_address_pool" {
  description = "Point-to-site address pool handed to the Kali attack box over OpenVPN."
  type        = list(string)
  default     = ["172.16.10.0/24"]
}

# ==========================================================================
# Topology - forests, domains and their domain controllers
# ==========================================================================

variable "forests" {
  description = <<-EOT
    Forest roots keyed by a short name. Each forest gets its own root domain
    and one or more DCs. Add/remove forests here to reshape the lab.
  EOT
  type = map(object({
    domain  = string
    netbios = string
    dcs     = list(string)
  }))
  default = {
    corp = {
      domain  = "corp.contoso.lab"
      netbios = "CORP"
      dcs     = ["DC01"]
    }
    partner = {
      domain  = "partner.fabrikam.lab"
      netbios = "PARTNER"
      dcs     = ["DC02"]
    }
  }
}

variable "child_domains" {
  description = "Child domains keyed by short name. parent references a key in var.forests."
  type = map(object({
    domain  = string
    netbios = string
    parent  = string
    dcs     = list(string)
  }))
  default = {
    emea = {
      domain  = "emea.corp.contoso.lab"
      netbios = "EMEA"
      parent  = "corp"
      dcs     = ["DC03"]
    }
  }
}

variable "forest_trusts" {
  description = <<-EOT
    Forest trusts to create. 'a' and 'b' are keys in var.forests. Used by the
    cross-forest abuse scenario (SID-history / trust-key).
  EOT
  type = list(object({
    a         = string
    b         = string
    direction = string
  }))
  default = [
    { a = "corp", b = "partner", direction = "Bidirectional" }
  ]
}

variable "parent_domain_key" {
  description = "Which forest key acts as the primary (attack starting) domain. Must be a key in var.forests."
  type        = string
  default     = "corp"
}

# ==========================================================================
# Member servers and workstations
# ==========================================================================

variable "member_servers" {
  description = <<-EOT
    Member servers keyed by a short role name. 'role' drives which Ansible
    role / misconfiguration set is applied. Scale by adding or removing keys.
  EOT
  type = map(object({
    name = string
    role = string
    size = string
  }))
  default = {
    file = { name = "SRV-FILE01", role = "file", size = "Standard_B2s" }
    sql  = { name = "SRV-SQL01", role = "sql", size = "Standard_B2ms" }
    adcs = { name = "SRV-ADCS01", role = "adcs", size = "Standard_B2s" }
    iis  = { name = "SRV-IIS01", role = "iis", size = "Standard_B2s" }
    mgmt = { name = "SRV-MGMT01", role = "mgmt", size = "Standard_B2s" }
    app  = { name = "SRV-APP01", role = "app", size = "Standard_B2s" }
  }
}

variable "workstation_count" {
  description = "Number of workstations (WS01..WSnn)."
  type        = number
  default     = 6

  validation {
    condition     = var.workstation_count >= 0 && var.workstation_count <= 20
    error_message = "workstation_count must be between 0 and 20."
  }
}

variable "workstation_os" {
  description = <<-EOT
    "server2022" (default, deployable on a plain free trial) or "windows11"
    (requires an eligible Windows client license / Visual Studio subscription).
  EOT
  type        = string
  default     = "server2022"

  validation {
    condition     = contains(["server2022", "windows11"], var.workstation_os)
    error_message = "workstation_os must be server2022 or windows11."
  }
}

# ==========================================================================
# VM sizing
# ==========================================================================

variable "vm_size_dc" {
  description = "Size for domain controllers. B2s is the practical minimum for a responsive Server-with-GUI."
  type        = string
  default     = "Standard_B2s"
}

variable "vm_size_workstation" {
  description = "Size for workstations."
  type        = string
  default     = "Standard_B2s"
}

variable "vm_size_standard" {
  description = "Default size for member servers."
  type        = string
  default     = "Standard_B2s"
}

variable "os_disk_size_gb" {
  description = "OS disk size in GB."
  type        = number
  default     = 127
}

variable "os_disk_storage_type" {
  description = "OS disk storage account type (StandardSSD_LRS is the cost/performance sweet spot)."
  type        = string
  default     = "StandardSSD_LRS"
}

variable "server_image" {
  description = "Windows Server image reference (publisher/offer/sku/version)."
  type = object({
    publisher = string
    offer     = string
    sku       = string
    version   = string
  })
  default = {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-datacenter-g2"
    version   = "latest"
  }
}

variable "workstation_image" {
  description = "Windows 11 client image reference (only used when workstation_os = windows11)."
  type = object({
    publisher = string
    offer     = string
    sku       = string
    version   = string
  })
  default = {
    publisher = "MicrosoftWindowsDesktop"
    offer     = "windows-11"
    sku       = "win11-23h2-ent"
    version   = "latest"
  }
}

# ==========================================================================
# Access / creds
# ==========================================================================

variable "admin_username" {
  description = "Local administrator / domain admin username for the lab."
  type        = string
  default     = "rangeadmin"
}

variable "admin_password" {
  description = "Admin password. Leave empty to generate one and store it in Key Vault."
  type        = string
  default     = ""
  sensitive   = true
}

variable "enable_vpn_gateway" {
  description = <<-EOT
    Deploy the point-to-site VPN gateway. This is the recommended (and only
    network-level) entry point for the Kali attack box.
  EOT
  type        = bool
  default     = true
}

variable "vpn_gateway_sku" {
  description = "VPN gateway SKU. VpnGw1 is the cheapest SKU that supports OpenVPN."
  type        = string
  default     = "VpnGw1"
}

variable "enable_bastion" {
  description = "Deploy Azure Bastion as an optional browser-RDP fallback (adds ~$0.19/hr)."
  type        = bool
  default     = false
}

variable "enable_auto_shutdown" {
  description = "Attach a daily auto-shutdown schedule to every VM as a cost safety net."
  type        = bool
  default     = true
}

variable "auto_shutdown_time" {
  description = "Daily auto-shutdown time in HHMM (24h, local to auto_shutdown_timezone)."
  type        = string
  default     = "2300"
}

variable "auto_shutdown_timezone" {
  description = "IANA timezone for the auto-shutdown schedule."
  type        = string
  default     = "UTC"
}

variable "sharphound_share_path" {
  description = "UNC path on the management server used to stage SharpHound output for pickup over VPN."
  type        = string
  default     = "C:\\RangeShare"
}

variable "ansible_inventory_path" {
  description = "Where Terraform writes the generated Ansible inventory."
  type        = string
  default     = "../ansible/inventory/hosts.yml"
}

variable "expected_host_count" {
  description = "Target Windows host count (DCs + servers + workstations). Informational output only."
  type        = number
  default     = 15
}

variable "hourly_price_usd" {
  description = <<-EOT
    Approximate pay-as-you-go USD/hour for Windows VMs by size. These are
    ESTIMATES for the cost output only; verify against the Azure pricing
    calculator for your region. Update here rather than in the code.
  EOT
  type        = map(number)
  default = {
    Standard_B1ms   = 0.086
    Standard_B2s    = 0.1216
    Standard_B2ms   = 0.2432
    Standard_B4ms   = 0.4864
    Standard_D2s_v3 = 0.192
    Standard_D4s_v3 = 0.384
  }
}

variable "hourly_price_usd_gateway" {
  description = "Estimated USD/hour for a VpnGw1 gateway."
  type        = number
  default     = 0.19
}

variable "hourly_price_usd_bastion" {
  description = "Estimated USD/hour for Azure Bastion Basic; pricing varies by Bastion SKU and region."
  type        = number
  default     = 0.19
}
