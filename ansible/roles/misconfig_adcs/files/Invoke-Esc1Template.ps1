# ==========================================================================
# Creates an ESC1-style certificate template.
#
# ESC1 requires all of:
#   * Enrollee supplies the subject (msPKI-Certificate-Name-Flag = 1)
#   * Client Authentication EKU
#   * No manager approval / no authorized signatures
#   * Low-privileged principals hold the Enroll right
#
# Rather than hand-building every pKIX attribute, this copies the built-in
# "User" template via ADSI and mutates only the security-relevant fields.
# ==========================================================================
$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$TemplateName = 'ESC1-User'
$TemplateDisplay = 'ESC1 User'
$ClientAuthEku = '1.3.6.1.5.5.7.3.2'

$configNC = (Get-ADRootDSE).configurationNamingContext
$tplContainerDN = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$configNC"
$sourceDN = "CN=User,$tplContainerDN"

$existing = Get-ADObject -SearchBase $tplContainerDN -Filter "name -eq '$TemplateName'" -ErrorAction SilentlyContinue
if ($existing) {
    Write-Output "OK template already exists: $TemplateName"
    return
}

# ------------------------------------------------------------------
# 1. Allocate a unique template OID under the CA's template OID prefix.
# ------------------------------------------------------------------
$oidContainerDN = "CN=OID,CN=Public Key Services,CN=Services,$configNC"
$base = $null
$caOidObjs = Get-ADObject -SearchBase $oidContainerDN -Filter * -Properties 'msPKI-Cert-Template-OID' -ErrorAction SilentlyContinue
foreach ($o in $caOidObjs) {
    $v = $o.'msPKI-Cert-Template-OID'
    if ($v) { $base = $v; break }
}
if (-not $base) {
    throw "Could not determine the CA template OID prefix. Create one template via the GUI once, then re-run."
}

$maxSeg = 0
$templates = Get-ADObject -SearchBase $tplContainerDN -Filter * -Properties 'msPKI-Cert-Template-OID'
foreach ($t in $templates) {
    $v = $t.'msPKI-Cert-Template-OID'
    if ($v -and $v.StartsWith($base)) {
        $tail = $v.Substring($base.Length).TrimStart('.')
        if ($tail -match '^\d+$') {
            $n = [int]$tail
            if ($n -gt $maxSeg) { $maxSeg = $n }
        }
    }
}
$newOid = "$base.$($maxSeg + 1)"

# ------------------------------------------------------------------
# 2. Copy the built-in User template.
# ------------------------------------------------------------------
$container = [ADSI]"LDAP://$tplContainerDN"
$new = $container.CopyHere("LDAP://$sourceDN", "CN=$TemplateName")
if (-not $new) { throw "ADSI CopyHere failed for template $TemplateName" }

# ------------------------------------------------------------------
# 3. Apply the vulnerable attributes.
# ------------------------------------------------------------------
$new.Put('displayName', $TemplateDisplay)
$new.Put('msPKI-Cert-Template-OID', $newOid)
$new.Put('msPKI-Certificate-Name-Flag', 1)      # CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT
$new.Put('msPKI-Enrollment-Flag', 0)            # no manager approval / no signatures
$new.Put('msPKI-Private-Key-Flag', 16)          # allow export of private key
$new.Put('msPKI-Template-Schema-Version', 2)
$new.Put('msPKI-Template-Minor-Revision', 1)
$new.Put('revision', 100)
$new.Put('pKIExtendedKeyUsage', @($ClientAuthEku, '1.3.6.1.5.5.7.3.4'))
$new.SetInfo()

# ------------------------------------------------------------------
# 4. Grant Domain Users the Enroll extended right (GUID 0e10c968-...).
# ------------------------------------------------------------------
$enrollGuid = [Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
$duSid = (Get-ADGroup 'Domain Users').SID
$tplDN = "CN=$TemplateName,$tplContainerDN"
$acl = Get-Acl "AD:\$tplDN"
$hasEnroll = $acl.Access | Where-Object {
    $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]) -eq $duSid -and
    $_.ObjectType -eq $enrollGuid
}
if (-not $hasEnroll) {
    $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $duSid,
        [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
        [System.Security.AccessControl.AccessControlType]::Allow,
        $enrollGuid)
    $acl.AddAccessRule($rule)
    Set-Acl "AD:\$tplDN" $acl
}

# ------------------------------------------------------------------
# 5. Publish the template and restart the CA service.
# ------------------------------------------------------------------
& certutil -SetCATemplates "+$TemplateName" | Out-Null
Restart-Service CertSvc -Force
Write-Output "OK template $TemplateName created (OID $newOid) and published"
