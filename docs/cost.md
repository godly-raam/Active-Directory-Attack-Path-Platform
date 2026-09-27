# Cost Model

> **Read this before `terraform apply`.** These are estimates for the default
> topology in `eastus`, pay-as-you-go, Windows Server images. Prices change and
> vary by region — confirm against the
> [Azure pricing calculator](https://azure.microsoft.com/pricing/calculator/)
> before a long session. The live estimate is also printed by
> `terraform output estimated_hourly_cost_usd`.

## What the free trial gives you

- **$200 credit, 30 days.** That is the budget. It is *not* a perpetual free
  tier for 15 Windows VMs.
- The free account's 750 hours of B1s applies to a single small VM, not to a
  15-host Windows range. **Do not count on it here.**

## Default topology

| Tier | Count | Size | Windows $/hr (est.) |
|------|------:|------|--------------------:|
| Domain controllers | 3 | Standard_B2s | 0.1216 each |
| Member servers (file, ADCS, IIS, mgmt, app) | 5 | Standard_B2s | 0.1216 each |
| Member server (SQL) | 1 | Standard_B2ms | 0.2432 |
| Workstations | 6 | Standard_B2s | 0.1216 each |
| **Compute subtotal** | **15** | | **~1.95 $/hr** |

| Add-on | $/hr (est.) |
|--------|------------:|
| Managed OS disks (15 × ~128 GB StandardSSD) | ~0.20 |
| Data disks (SQL + file, 2 × 128 GB) | ~0.03 |
| VPN gateway (VpnGw1) — the only public entry point | ~0.19 |
| Azure Bastion (optional, off by default) | ~0.19 |
| **Total (Bastion off)** | **~$2.36/hr** |

## Scenario costs

| Session | Hours | Estimated cost |
|---------|------:|---------------:|
| Smoke test (boot, verify trust, destroy) | 3 | ~$7 |
| Full demo recording session | 8 | ~$19 |
| Long day left running | 24 | ~$57 |
| Full 30 days left running (don't) | 720 | ~$1,700 (capped at $200 credit) |

A realistic build → seed → test → record → destroy cycle fits comfortably in
**$25-60**, leaving most of the $200 for iteration.

## The three cost controls

1. **`enable_auto_shutdown = true`** (default). Every VM stops daily at
   `auto_shutdown_time` in `auto_shutdown_timezone`. This bounds the worst case
   even if you forget.
2. **`terraform destroy`** (`make destroy` / `scripts/destroy.sh`). Deletes the
   entire resource group, so nothing keeps billing. **This is the only control
   that stops disk charges.**
3. **Right-size via variables.** `vm_size_dc`, `vm_size_workstation`,
   `vm_size_standard`, and per-server `size` in `var.member_servers` are the
   biggest lever. Dropping workstations to zero removes ~$0.73/hr.

## What still bills after "shutdown"

Deallocating a VM stops **compute** billing but **not** managed-disk billing
(~$0.013/hr per disk). Auto-shutdown is a safety net, not a substitute for
`terraform destroy`. If you are pausing more than a few hours, destroy.

## Assumptions

- Region `eastus`, pay-as-you-go rates, Windows Server license included in the
  hourly rate shown by the pricing calculator.
- No premium disks, no load balancers, no NAT gateways, negligible egress.
- The VPN gateway is billed regardless of connected clients and takes
  **30-45 minutes** to deploy — budget for it and do not destroy/recreate it
  repeatedly within a session.
