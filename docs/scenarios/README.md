# Scenarios

Nine independently toggleable misconfigurations, each mapped to MITRE ATT&CK.
The numbering matches the `misconfig_*` Ansible roles and the toggles in
`ansible/group_vars/all.yml`.

| # | Doc | Scenario | Toggle |
|---|-----|----------|--------|
| 1 | [01-kerberoasting.md](01-kerberoasting.md) | Kerberoasting | `misconfig.kerberoast` |
| 2 | [02-asrep-roasting.md](02-asrep-roasting.md) | AS-REP roasting | `misconfig.asrep` |
| 3 | [03-unconstrained-delegation.md](03-unconstrained-delegation.md) | Unconstrained delegation | `misconfig.unconstrained_delegation` |
| 4 | [04-constrained-delegation.md](04-constrained-delegation.md) | Constrained delegation / protocol transition | `misconfig.constrained_delegation` |
| 5 | [05-adcs-esc1.md](05-adcs-esc1.md) | AD CS ESC1 + ESC8 | `misconfig.adcs_esc1`, `misconfig.adcs_esc8` |
| 6 | [06-trust-abuse.md](06-trust-abuse.md) | Cross-forest trust abuse | `misconfig.trust_abuse` |
| 7 | [07-acl-abuse.md](07-acl-abuse.md) | ACL abuse | `misconfig.acl_abuse` |
| 8 | [08-dcsync.md](08-dcsync.md) | DCSync rights | `misconfig.dcsync` |
| 9 | [09-sysvol-creds.md](09-sysvol-creds.md) | SYSVOL GPP cpassword | `misconfig.sysvol_creds` |

## Seeded ground truth

These are the objects the range creates. Use them to sanity-check BloodHound
output and attack results.

| Object | Type | Notes |
|--------|------|-------|
| `aanderson`, `bbrown` | Users | Members of Domain Admins, live in `OU=Engineering` |
| `cclark` | User | Member of Tier1_Admins; holds WriteDACL over Tier1_Admins (scenario 7) |
| `ddavis` | User | Member of Tier0-Admins |
| `eevans` | User | HelpDesk; holds GenericAll over `OU=Engineering` (scenario 7) |
| `fanderson` | User | Member of SQL-Admins |
| `svc_sql`, `svc_iis`, `svc_backup`, `svc_monitor` | Users | SPN-bearing service accounts (scenario 1) |
| `nopreauth_svc`, `legacy_kiosk` | Users | Kerberos pre-auth disabled (scenario 2) |
| `svc_dcsync` | User | Directory replication extended rights (scenario 8) |
| `vendor_svc` | User (partner forest) | Member of CORP `Backup-Operators` (scenario 6) |
| `SRV-APP01$` | Computer | TrustedForDelegation (scenario 3) |
| `SRV-IIS01$` | Computer | TrustedToAuthForDelegation + msDS-AllowedToDelegateTo (scenario 4) |
| `SRV-ADCS01` | Server | Enterprise Root CA `CORP-Range-CA` (scenario 5) |

The seeded passwords (`default_password`, `service_password`,
`sysvol_gpp_plaintext_password`) are intentionally weak and live in
`ansible/group_vars/all.yml`. This is a throwaway lab; never reuse them.

## Workflow for each scenario

1. Build the range with the toggle enabled (default).
2. Collect BloodHound data as a domain user.
3. Run the attack as the documented low-privilege principal.
4. Confirm the escalation the scenario is designed to demonstrate.
5. Re-run the attack-path engine and compare against the previous report.

To produce a clean baseline and seed one path at a time, disable all
`misconfig.*` toggles, collect, then re-enable one toggle and re-run
`ansible-playbook site.yml --tags <scenario>`.

## Detection and telemetry

Scenario-level "Detection" sections list the Windows event IDs and Sysmon
events the activity generates. The range ships `LAB-Sysmon-Audit` as a
placeholder GPO; wire it to a collector if you want to build detections
alongside the attacks.
