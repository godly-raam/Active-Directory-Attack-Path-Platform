# ==========================================================================
# Point-to-site VPN gateway
#
# This is the ONLY network-level path into the range. The Kali attack box
# connects over OpenVPN and receives an address from vpn_client_address_pool,
# which is why every NSG references the "vpn" application security group.
#
# Azure Bastion (below, optional) only offers browser RDP/SSH - it does not
# expose the lab to local tooling - so it is a fallback, not the primary path.
# ==========================================================================

# --------------------------------------------------------------------------
# Certificate authority and client certificate.
#
# The gateway trusts a self-signed root. A client certificate signed by that
# root is generated and written locally (git-ignored) for import into Kali.
# --------------------------------------------------------------------------

resource "tls_private_key" "vpn_root" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "vpn_root" {
  private_key_pem       = tls_private_key.vpn_root.private_key_pem
  validity_period_hours = 8760

  subject {
    common_name  = "adrange-vpn-root"
    organization = "AD Cyber Range Lab"
  }

  is_ca_certificate = true
  allowed_uses      = ["cert_signing", "crl_signing", "digital_signature"]
}

resource "tls_private_key" "vpn_client" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "vpn_client" {
  private_key_pem = tls_private_key.vpn_client.private_key_pem

  subject {
    common_name  = "range-vpn-client"
    organization = "AD Cyber Range Lab"
  }
}

resource "tls_locally_signed_cert" "vpn_client" {
  cert_request_pem      = tls_cert_request.vpn_client.cert_request_pem
  ca_private_key_pem    = tls_private_key.vpn_root.private_key_pem
  ca_cert_pem           = tls_self_signed_cert.vpn_root.cert_pem
  validity_period_hours = 8760

  is_ca_certificate = false
  allowed_uses      = ["client_auth", "digital_signature", "key_encipherment"]
}

# Azure wants base64-encoded DER for the trust anchor, not armored PEM.
locals {
  vpn_root_cert_b64 = replace(
    replace(
      replace(tls_self_signed_cert.vpn_root.cert_pem, "-----BEGIN CERTIFICATE-----", ""),
      "-----END CERTIFICATE-----", ""
    ),
    "\n", ""
  )
}

resource "local_file" "vpn_root_cert" {
  filename        = "${path.module}/../certs/vpn-root.cer"
  content         = tls_self_signed_cert.vpn_root.cert_pem
  file_permission = "0644"
}

resource "local_file" "vpn_client_cert" {
  filename        = "${path.module}/../certs/vpn-client.crt"
  content         = tls_locally_signed_cert.vpn_client.cert_pem
  file_permission = "0600"
}

resource "local_file" "vpn_client_key" {
  filename        = "${path.module}/../certs/vpn-client.key"
  content         = tls_private_key.vpn_client.private_key_pem
  file_permission = "0600"
}

# --------------------------------------------------------------------------
# Gateway
# --------------------------------------------------------------------------

resource "azurerm_public_ip" "vpn" {
  count = var.enable_vpn_gateway ? 1 : 0

  name                = "pip-vpn-${local.name_prefix}"
  location            = azurerm_resource_group.range.location
  resource_group_name = azurerm_resource_group.range.name
  allocation_method   = "Static"
  sku                 = "Standard"
  zones               = ["1", "2", "3"]
  tags                = local.common_tags
}

resource "azurerm_virtual_network_gateway" "vpn" {
  count = var.enable_vpn_gateway ? 1 : 0

  name                = "vgw-${local.name_prefix}"
  location            = azurerm_resource_group.range.location
  resource_group_name = azurerm_resource_group.range.name

  type     = "Vpn"
  vpn_type = "RouteBased"
  sku      = var.vpn_gateway_sku

  active_active = false
  enable_bgp    = false

  ip_configuration {
    name                          = "vnetGatewayConfig"
    public_ip_address_id          = azurerm_public_ip.vpn[0].id
    private_ip_address_allocation = "Dynamic"
    subnet_id                     = azurerm_subnet.gateway.id
  }

  vpn_client_configuration {
    address_space        = var.vpn_client_address_pool
    vpn_client_protocols = ["OpenVPN"]

    # Azure requires the trust anchor before clients can authenticate.
    root_certificate {
      name             = "adrange-root"
      public_cert_data = local.vpn_root_cert_b64
    }
  }

  tags = local.common_tags
}

# Optional browser-RDP fallback. Off by default because it adds cost without
# giving local tooling a route into the lab.
resource "azurerm_public_ip" "bastion" {
  count = var.enable_bastion ? 1 : 0

  name                = "pip-bastion-${local.name_prefix}"
  location            = azurerm_resource_group.range.location
  resource_group_name = azurerm_resource_group.range.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.common_tags
}

resource "azurerm_bastion_host" "bastion" {
  count = var.enable_bastion ? 1 : 0

  name                = "bas-${local.name_prefix}"
  location            = azurerm_resource_group.range.location
  resource_group_name = azurerm_resource_group.range.name
  sku                 = "Standard"
  tags                = local.common_tags

  ip_configuration {
    name                 = "configuration"
    subnet_id            = azurerm_subnet.bastion[0].id
    public_ip_address_id = azurerm_public_ip.bastion[0].id
  }
}

resource "azurerm_key_vault_secret" "vpn_root_cert" {
  name         = "vpn-root-cert-pem"
  value        = tls_self_signed_cert.vpn_root.cert_pem
  key_vault_id = azurerm_key_vault.range.id

  depends_on = [azurerm_key_vault_access_policy.deployer]
  tags       = local.common_tags
}
