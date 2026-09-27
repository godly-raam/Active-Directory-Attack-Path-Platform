locals {
  name_prefix = "${var.prefix}-${var.environment}"
  rg_name     = "rg-${local.name_prefix}"

  common_tags = merge(
    {
      project     = "ad-cyber-range"
      environment = var.environment
      managed_by  = "terraform"
      purpose     = "isolated-offensive-security-lab"
    },
    var.tags
  )

  # ------------------------------------------------------------------
  # Domain controllers (forest roots + child domains) flattened
  # ------------------------------------------------------------------
  forest_dcs = flatten([
    for fkey, f in var.forests : [
      for dc in f.dcs : {
        key      = fkey
        hostname = dc
        domain   = f.domain
        netbios  = f.netbios
        role     = "forest_root"
        parent   = null
      }
    ]
  ])

  child_dcs = flatten([
    for ckey, c in var.child_domains : [
      for dc in c.dcs : {
        key      = ckey
        hostname = dc
        domain   = c.domain
        netbios  = c.netbios
        role     = "child"
        parent   = c.parent
      }
    ]
  ])

  # Stable ordering: sort by hostname so IP assignment is deterministic.
  dcs_sorted = sort([for d in concat(local.forest_dcs, local.child_dcs) : d.hostname])
  dcs_raw    = concat(local.forest_dcs, local.child_dcs)

  dcs = [
    for i, h in local.dcs_sorted : merge(
      [for d in local.dcs_raw : d if d.hostname == h][0],
      {
        index = i
        ip    = cidrhost(var.subnet_cidrs.dc, 10 + i)
        size  = var.vm_size_dc
      }
    )
  ]

  # ------------------------------------------------------------------
  # Member servers: deterministic IPs by sorted role key
  # ------------------------------------------------------------------
  server_keys = keys(var.member_servers)

  servers = [
    for k in local.server_keys : merge(var.member_servers[k], {
      key   = k
      index = index(local.server_keys, k)
      ip    = cidrhost(var.subnet_cidrs.servers, 10 + index(local.server_keys, k))
    })
  ]

  # ------------------------------------------------------------------
  # Workstations
  # ------------------------------------------------------------------
  workstations = [
    for i in range(var.workstation_count) : {
      key   = format("ws%02d", i + 1)
      name  = format("WS%02d", i + 1)
      index = i
      ip    = cidrhost(var.subnet_cidrs.workstations, 10 + i)
      size  = var.vm_size_workstation
    }
  ]

  # ------------------------------------------------------------------
  # Primary domain the member servers and workstations join
  # ------------------------------------------------------------------
  primary_domain_key = var.parent_domain_key
  primary_forest     = var.forests[var.parent_domain_key]
  primary_domain     = local.primary_forest.domain
  primary_netbios    = local.primary_forest.netbios

  primary_dc = [
    for d in local.dcs : d
    if d.key == local.primary_domain_key && d.role == "forest_root"
  ][0]

  # DNS for every non-DC NIC points at the primary forest DC.
  primary_dns_ip = local.primary_dc.ip

  realm_upper = upper(local.primary_domain)

  # ------------------------------------------------------------------
  # Counts / cost bookkeeping
  # ------------------------------------------------------------------
  dc_count          = length(local.dcs)
  server_count      = length(local.servers)
  workstation_count = length(local.workstations)
  total_host_count  = local.dc_count + local.server_count + local.workstation_count

  # ------------------------------------------------------------------
  # Admin password: explicit value wins, otherwise generated.
  # ------------------------------------------------------------------
  admin_password = var.admin_password != "" ? var.admin_password : random_password.admin.result

  # ------------------------------------------------------------------
  # Application security groups - the segmentation primitives referenced by
  # the NSG rules. ASGs let one NSG rule express "workstations -> file server"
  # without per-VM NSGs.
  # ------------------------------------------------------------------
  asg_names = {
    mgmt = "asg-mgmt"
    dc   = "asg-dc"
    file = "asg-file"
    sql  = "asg-sql"
    adcs = "asg-adcs"
    iis  = "asg-iis"
    app  = "asg-app"
    ws   = "asg-workstations"
  }

  # Map each member-server role to its ASG key.
  server_role_to_asg = {
    file = "file"
    sql  = "sql"
    adcs = "adcs"
    iis  = "iis"
    app  = "app"
    mgmt = "mgmt"
  }
}
