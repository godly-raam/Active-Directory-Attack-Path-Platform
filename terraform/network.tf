# ==========================================================================
# Resource group
# ==========================================================================

resource "azurerm_resource_group" "range" {
  name     = local.rg_name
  location = var.location
  tags     = local.common_tags
}

# ==========================================================================
# Virtual network and tier-segmented subnets
# ==========================================================================

resource "azurerm_virtual_network" "range" {
  name                = "vnet-${local.name_prefix}"
  location            = azurerm_resource_group.range.location
  resource_group_name = azurerm_resource_group.range.name
  address_space       = var.vnet_address_space
  tags                = local.common_tags
}

# Reserved names: Azure requires these exact subnet names for the gateway and
# for Bastion. They contain no workloads.
resource "azurerm_subnet" "gateway" {
  name                 = "GatewaySubnet"
  resource_group_name  = azurerm_resource_group.range.name
  virtual_network_name = azurerm_virtual_network.range.name
  address_prefixes     = [var.subnet_cidrs.gateway]
}

resource "azurerm_subnet" "bastion" {
  count                = var.enable_bastion ? 1 : 0
  name                 = "AzureBastionSubnet"
  resource_group_name  = azurerm_resource_group.range.name
  virtual_network_name = azurerm_virtual_network.range.name
  address_prefixes     = [var.subnet_cidrs.bastion]
}

resource "azurerm_subnet" "management" {
  name                 = "snet-management"
  resource_group_name  = azurerm_resource_group.range.name
  virtual_network_name = azurerm_virtual_network.range.name
  address_prefixes     = [var.subnet_cidrs.management]
}

resource "azurerm_subnet" "dc" {
  name                 = "snet-dc"
  resource_group_name  = azurerm_resource_group.range.name
  virtual_network_name = azurerm_virtual_network.range.name
  address_prefixes     = [var.subnet_cidrs.dc]
}

resource "azurerm_subnet" "servers" {
  name                 = "snet-servers"
  resource_group_name  = azurerm_resource_group.range.name
  virtual_network_name = azurerm_virtual_network.range.name
  address_prefixes     = [var.subnet_cidrs.servers]
}

resource "azurerm_subnet" "workstations" {
  name                 = "snet-workstations"
  resource_group_name  = azurerm_resource_group.range.name
  virtual_network_name = azurerm_virtual_network.range.name
  address_prefixes     = [var.subnet_cidrs.workstations]
}

# ==========================================================================
# Application security groups
#
# ASGs (not bare IPs) are the segmentation primitive: an NSG rule can say
# "workstations -> file server" without per-VM NSGs, and re-IPing a host does
# not silently widen access.
# ==========================================================================

resource "azurerm_application_security_group" "asg" {
  for_each = local.asg_names

  name                = "${each.value}-${local.name_prefix}"
  location            = azurerm_resource_group.range.location
  resource_group_name = azurerm_resource_group.range.name
  tags                = local.common_tags
}

# ==========================================================================
# Network security groups, one per tier
# ==========================================================================

resource "azurerm_network_security_group" "tier" {
  for_each = {
    dc           = "snet-dc"
    servers      = "snet-servers"
    workstations = "snet-workstations"
    management   = "snet-management"
  }

  name                = "nsg-${each.key}-${local.name_prefix}"
  location            = azurerm_resource_group.range.location
  resource_group_name = azurerm_resource_group.range.name
  tags                = local.common_tags
}

resource "azurerm_subnet_network_security_group_association" "tier" {
  for_each = azurerm_network_security_group.tier

  subnet_id = {
    dc           = azurerm_subnet.dc.id
    servers      = azurerm_subnet.servers.id
    workstations = azurerm_subnet.workstations.id
    management   = azurerm_subnet.management.id
  }[each.key]
  network_security_group_id = each.value.id
}

# --------------------------------------------------------------------------
# DC tier NSG
# --------------------------------------------------------------------------

# Administrative access only over the VPN (the Kali box) or from the mgmt ASG.
resource "azurerm_network_security_rule" "dc_admin_vpn_in" {
  name                                       = "allow-admin-in-vpn"
  resource_group_name                        = azurerm_resource_group.range.name
  network_security_group_name                = azurerm_network_security_group.tier["dc"].name
  priority                                   = 100
  direction                                  = "Inbound"
  access                                     = "Allow"
  protocol                                   = "Tcp"
  source_address_prefixes                    = var.vpn_client_address_pool
  destination_application_security_group_ids = [azurerm_application_security_group.asg["dc"].id]
  source_port_range                          = "*"
  destination_port_ranges                    = ["53", "88", "135", "139", "389", "445", "464", "636", "3268", "3269", "3389", "5985", "9389"]
}

resource "azurerm_network_security_rule" "dc_admin_mgmt_in" {
  name                                       = "allow-admin-in-mgmt"
  resource_group_name                        = azurerm_resource_group.range.name
  network_security_group_name                = azurerm_network_security_group.tier["dc"].name
  priority                                   = 110
  direction                                  = "Inbound"
  access                                     = "Allow"
  protocol                                   = "Tcp"
  source_application_security_group_ids      = [azurerm_application_security_group.asg["mgmt"].id]
  destination_application_security_group_ids = [azurerm_application_security_group.asg["dc"].id]
  source_port_range                          = "*"
  destination_port_ranges                    = ["53", "88", "135", "139", "389", "445", "464", "636", "3268", "3269", "3389", "5985", "9389"]
}

# Workstations need the full AD client port set to authenticate.
resource "azurerm_network_security_rule" "dc_from_workstations" {
  name                                       = "allow-workstations-ad-in"
  resource_group_name                        = azurerm_resource_group.range.name
  network_security_group_name                = azurerm_network_security_group.tier["dc"].name
  priority                                   = 200
  direction                                  = "Inbound"
  access                                     = "Allow"
  protocol                                   = "Tcp"
  source_application_security_group_ids      = [azurerm_application_security_group.asg["ws"].id]
  destination_application_security_group_ids = [azurerm_application_security_group.asg["dc"].id]
  source_port_range                          = "*"
  destination_port_ranges                    = ["53", "88", "135", "139", "389", "445", "464", "636", "3268", "3269"]
}

# Member servers authenticate to the domain too.
resource "azurerm_network_security_rule" "dc_from_servers" {
  name                        = "allow-servers-ad-in"
  resource_group_name         = azurerm_resource_group.range.name
  network_security_group_name = azurerm_network_security_group.tier["dc"].name
  priority                    = 210
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_address_prefix       = var.subnet_cidrs.servers
  destination_address_prefix  = var.subnet_cidrs.dc
  source_port_range           = "*"
  destination_port_ranges     = ["53", "88", "135", "139", "389", "445", "464", "636", "3268", "3269"]
}

# UDP is required for Kerberos, DNS, NTP, kpasswd.
resource "azurerm_network_security_rule" "dc_udp_ad_in" {
  name                        = "allow-ad-udp-in"
  resource_group_name         = azurerm_resource_group.range.name
  network_security_group_name = azurerm_network_security_group.tier["dc"].name
  priority                    = 220
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Udp"
  source_address_prefix       = "VirtualNetwork"
  destination_address_prefix  = var.subnet_cidrs.dc
  source_port_range           = "*"
  destination_port_ranges     = ["53", "88", "123", "389", "464"]
}

# DC-to-DC replication (RPC dynamic range included).
resource "azurerm_network_security_rule" "dc_replication_in" {
  name                        = "allow-dc-replication-in"
  resource_group_name         = azurerm_resource_group.range.name
  network_security_group_name = azurerm_network_security_group.tier["dc"].name
  priority                    = 230
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_address_prefix       = var.subnet_cidrs.dc
  destination_address_prefix  = var.subnet_cidrs.dc
  source_port_range           = "*"
  destination_port_ranges     = ["53", "88", "135", "389", "445", "464", "636", "3268", "3269", "49152-65535"]
}

# --------------------------------------------------------------------------
# Server tier NSG
# --------------------------------------------------------------------------

resource "azurerm_network_security_rule" "servers_admin_vpn_in" {
  name                        = "allow-admin-in-vpn"
  resource_group_name         = azurerm_resource_group.range.name
  network_security_group_name = azurerm_network_security_group.tier["servers"].name
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_address_prefixes     = var.vpn_client_address_pool
  destination_address_prefix  = var.subnet_cidrs.servers
  source_port_range           = "*"
  destination_port_ranges     = ["80", "135", "139", "443", "445", "1433", "3389", "5985", "636", "389"]
}

resource "azurerm_network_security_rule" "servers_admin_mgmt_in" {
  name                                  = "allow-admin-in-mgmt"
  resource_group_name                   = azurerm_resource_group.range.name
  network_security_group_name           = azurerm_network_security_group.tier["servers"].name
  priority                              = 110
  direction                             = "Inbound"
  access                                = "Allow"
  protocol                              = "Tcp"
  source_application_security_group_ids = [azurerm_application_security_group.asg["mgmt"].id]
  destination_address_prefix            = var.subnet_cidrs.servers
  source_port_range                     = "*"
  destination_port_ranges               = ["80", "135", "139", "443", "445", "1433", "3389", "5985", "636", "389"]
}

resource "azurerm_network_security_rule" "ws_to_file_smb" {
  name                                       = "allow-workstations-file-smb"
  resource_group_name                        = azurerm_resource_group.range.name
  network_security_group_name                = azurerm_network_security_group.tier["servers"].name
  priority                                   = 200
  direction                                  = "Inbound"
  access                                     = "Allow"
  protocol                                   = "Tcp"
  source_application_security_group_ids      = [azurerm_application_security_group.asg["ws"].id]
  destination_application_security_group_ids = [azurerm_application_security_group.asg["file"].id]
  source_port_range                          = "*"
  destination_port_ranges                    = ["139", "445"]
}

resource "azurerm_network_security_rule" "ws_to_iis_web" {
  name                                       = "allow-workstations-iis-web"
  resource_group_name                        = azurerm_resource_group.range.name
  network_security_group_name                = azurerm_network_security_group.tier["servers"].name
  priority                                   = 210
  direction                                  = "Inbound"
  access                                     = "Allow"
  protocol                                   = "Tcp"
  source_application_security_group_ids      = [azurerm_application_security_group.asg["ws"].id]
  destination_application_security_group_ids = [azurerm_application_security_group.asg["iis"].id]
  source_port_range                          = "*"
  destination_port_ranges                    = ["80", "443"]
}

# AD CS web enrollment is deliberately reachable from the workstation tier so
# the ESC8 relay path is exercisable.
resource "azurerm_network_security_rule" "ws_to_adcs_web" {
  name                                       = "allow-workstations-adcs-web"
  resource_group_name                        = azurerm_resource_group.range.name
  network_security_group_name                = azurerm_network_security_group.tier["servers"].name
  priority                                   = 220
  direction                                  = "Inbound"
  access                                     = "Allow"
  protocol                                   = "Tcp"
  source_application_security_group_ids      = [azurerm_application_security_group.asg["ws"].id]
  destination_application_security_group_ids = [azurerm_application_security_group.asg["adcs"].id]
  source_port_range                          = "*"
  destination_port_ranges                    = ["80", "443"]
}

resource "azurerm_network_security_rule" "app_to_sql" {
  name                                       = "allow-app-iis-sql"
  resource_group_name                        = azurerm_resource_group.range.name
  network_security_group_name                = azurerm_network_security_group.tier["servers"].name
  priority                                   = 230
  direction                                  = "Inbound"
  access                                     = "Allow"
  protocol                                   = "Tcp"
  source_application_security_group_ids      = [azurerm_application_security_group.asg["app"].id, azurerm_application_security_group.asg["iis"].id]
  destination_application_security_group_ids = [azurerm_application_security_group.asg["sql"].id]
  source_port_range                          = "*"
  destination_port_ranges                    = ["1433"]
}

# Explicit segmentation: workstations must not talk straight to SQL.
resource "azurerm_network_security_rule" "ws_deny_sql" {
  name                                       = "deny-workstations-sql"
  resource_group_name                        = azurerm_resource_group.range.name
  network_security_group_name                = azurerm_network_security_group.tier["servers"].name
  priority                                   = 300
  direction                                  = "Inbound"
  access                                     = "Deny"
  protocol                                   = "Tcp"
  source_application_security_group_ids      = [azurerm_application_security_group.asg["ws"].id]
  destination_application_security_group_ids = [azurerm_application_security_group.asg["sql"].id]
  source_port_range                          = "*"
  destination_port_range                     = "1433"
}

# --------------------------------------------------------------------------
# Workstation tier NSG
# --------------------------------------------------------------------------

resource "azurerm_network_security_rule" "ws_admin_vpn_in" {
  name                        = "allow-admin-in-vpn"
  resource_group_name         = azurerm_resource_group.range.name
  network_security_group_name = azurerm_network_security_group.tier["workstations"].name
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_address_prefixes     = var.vpn_client_address_pool
  destination_address_prefix  = var.subnet_cidrs.workstations
  source_port_range           = "*"
  destination_port_ranges     = ["135", "139", "445", "3389", "5985"]
}

resource "azurerm_network_security_rule" "ws_admin_mgmt_in" {
  name                                  = "allow-admin-in-mgmt"
  resource_group_name                   = azurerm_resource_group.range.name
  network_security_group_name           = azurerm_network_security_group.tier["workstations"].name
  priority                              = 110
  direction                             = "Inbound"
  access                                = "Allow"
  protocol                              = "Tcp"
  source_application_security_group_ids = [azurerm_application_security_group.asg["mgmt"].id]
  destination_address_prefix            = var.subnet_cidrs.workstations
  source_port_range                     = "*"
  destination_port_ranges               = ["135", "139", "445", "3389", "5985"]
}

# --------------------------------------------------------------------------
# Management tier NSG
# --------------------------------------------------------------------------

resource "azurerm_network_security_rule" "mgmt_admin_in" {
  name                        = "allow-admin-in-vpn"
  resource_group_name         = azurerm_resource_group.range.name
  network_security_group_name = azurerm_network_security_group.tier["management"].name
  priority                    = 100
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_address_prefixes     = var.vpn_client_address_pool
  destination_address_prefix  = var.subnet_cidrs.management
  source_port_range           = "*"
  destination_port_ranges     = ["22", "3389", "5985", "5986", "445"]
}

# --------------------------------------------------------------------------
# Internet lockdown on every tier. Azure's default AllowVnetInBound stays, so
# the lab remains internally usable; only the public path is closed.
# --------------------------------------------------------------------------

resource "azurerm_network_security_rule" "deny_internet_in" {
  for_each = azurerm_network_security_group.tier

  name                        = "deny-internet-inbound"
  resource_group_name         = azurerm_resource_group.range.name
  network_security_group_name = each.value.name
  priority                    = 4000
  direction                   = "Inbound"
  access                      = "Deny"
  protocol                    = "*"
  source_address_prefix       = "Internet"
  destination_address_prefix  = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
}
