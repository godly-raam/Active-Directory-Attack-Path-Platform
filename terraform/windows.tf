# ==========================================================================
# Windows hosts
#
# Every host is described once in local.vm_specs, then fanned out to a NIC, an
# ASG association, a VM, and (optionally) an auto-shutdown schedule. Adding a
# key to var.member_servers or bumping var.workstation_count is all it takes
# to change the topology.
# ==========================================================================

locals {
  vm_specs = merge(
    {
      for d in local.dcs : d.hostname => {
        name    = d.hostname
        ip      = d.ip
        size    = d.size
        subnet  = azurerm_subnet.dc.id
        asg     = "dc"
        image   = var.server_image
        role    = "dc"
        kind    = "dc"
        domain  = d.domain
        dc_role = d.role
        # A forest root is its own resolver. A child DC resolves the parent
        # first, then itself.
        dns = d.role == "forest_root" ? [d.ip] : [local.primary_dns_ip, d.ip]
      }
    },
    {
      for s in local.servers : s.name => {
        name    = s.name
        ip      = s.ip
        size    = s.size
        subnet  = azurerm_subnet.servers.id
        asg     = local.server_role_to_asg[s.role]
        image   = var.server_image
        role    = s.role
        kind    = "server"
        domain  = local.primary_domain
        dc_role = null
        dns     = [local.primary_dns_ip]
      }
    },
    {
      for w in local.workstations : w.name => {
        name    = w.name
        ip      = w.ip
        size    = w.size
        subnet  = azurerm_subnet.workstations.id
        asg     = "ws"
        image   = var.workstation_os == "windows11" ? var.workstation_image : var.server_image
        role    = "workstation"
        kind    = "workstation"
        domain  = local.primary_domain
        dc_role = null
        dns     = [local.primary_dns_ip]
      }
    },
  )

  # Servers that get an extra data disk.
  data_disk_specs = {
    for k, v in local.vm_specs : k => v if contains(["sql", "file"], v.role)
  }
}

# --------------------------------------------------------------------------
# Windows 11 marketplace agreement (only when the client image is selected)
# --------------------------------------------------------------------------

resource "azurerm_marketplace_agreement" "win11" {
  count = var.workstation_os == "windows11" ? 1 : 0

  publisher = var.workstation_image.publisher
  offer     = var.workstation_image.offer
  plan      = var.workstation_image.sku
}

# --------------------------------------------------------------------------
# Network interfaces (static IPs, no public IPs anywhere)
# --------------------------------------------------------------------------

resource "azurerm_network_interface" "vm" {
  for_each = local.vm_specs

  name                = "nic-${lower(each.key)}"
  location            = azurerm_resource_group.range.location
  resource_group_name = azurerm_resource_group.range.name
  tags                = merge(local.common_tags, { hostname = each.key, role = each.value.role })
  dns_servers         = each.value.dns

  ip_configuration {
    name                          = "internal"
    subnet_id                     = each.value.subnet
    private_ip_address_allocation = "Static"
    private_ip_address            = each.value.ip
  }

  # Azure Accelerated Networking is not supported on B-series.
  accelerated_networking_enabled = false
}

resource "azurerm_network_interface_application_security_group_association" "vm" {
  for_each = local.vm_specs

  network_interface_id          = azurerm_network_interface.vm[each.key].id
  application_security_group_id = azurerm_application_security_group.asg[each.value.asg].id
}

# --------------------------------------------------------------------------
# Virtual machines
# --------------------------------------------------------------------------

resource "azurerm_windows_virtual_machine" "vm" {
  for_each = local.vm_specs

  name                = each.value.name
  computer_name       = each.value.name
  location            = azurerm_resource_group.range.location
  resource_group_name = azurerm_resource_group.range.name
  size                = each.value.size
  admin_username      = var.admin_username
  admin_password      = local.admin_password

  network_interface_ids = [azurerm_network_interface.vm[each.key].id]

  # Unattended-update reboots can interrupt Ansible runs; patch explicitly.
  enable_automatic_updates = false
  provision_vm_agent       = true
  timezone                 = "UTC"

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = var.os_disk_storage_type
    disk_size_gb         = var.os_disk_size_gb
  }

  source_image_reference {
    publisher = each.value.image.publisher
    offer     = each.value.image.offer
    sku       = each.value.image.sku
    version   = each.value.image.version
  }

  tags = merge(local.common_tags, {
    hostname = each.key
    role     = each.value.role
    kind     = each.value.kind
  })

  depends_on = [azurerm_marketplace_agreement.win11]
}

# --------------------------------------------------------------------------
# Data disks for the SQL and file servers
# --------------------------------------------------------------------------

resource "azurerm_managed_disk" "data" {
  for_each = local.data_disk_specs

  name                 = "disk-data-${lower(each.key)}"
  location             = azurerm_resource_group.range.location
  resource_group_name  = azurerm_resource_group.range.name
  storage_account_type = var.os_disk_storage_type
  create_option        = "Empty"
  disk_size_gb         = 128
  tags                 = merge(local.common_tags, { hostname = each.key })
}

resource "azurerm_virtual_machine_data_disk_attachment" "data" {
  for_each = local.data_disk_specs

  managed_disk_id    = azurerm_managed_disk.data[each.key].id
  virtual_machine_id = azurerm_windows_virtual_machine.vm[each.key].id
  lun                = 0
  caching            = "ReadWrite"
}

# --------------------------------------------------------------------------
# Auto-shutdown safety net
#
# The single most effective guard against leaving the range running. Every VM
# stops daily at the configured local time, bounding worst-case cost.
# --------------------------------------------------------------------------

resource "azurerm_dev_test_global_vm_shutdown_schedule" "vm" {
  for_each = var.enable_auto_shutdown ? local.vm_specs : {}

  virtual_machine_id    = azurerm_windows_virtual_machine.vm[each.key].id
  location              = azurerm_resource_group.range.location
  enabled               = true
  daily_recurrence_time = var.auto_shutdown_time
  timezone              = var.auto_shutdown_timezone

  notification_settings {
    enabled = false
  }
}
