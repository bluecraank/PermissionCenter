<#
.SYNOPSIS
    Exportiert Benutzer, Computer, Gruppen und AD-Berechtigungen für den PermissionCenter-Server.

.DESCRIPTION
    Erzeugt eine JSON-Datei im Format, das der Server unter /api/v1/ad/import bzw. mit
    `pc-server import-ad <datei>` erwartet. Optional wird die Datei direkt hochgeladen.
    Benötigt das PowerShell-Modul ActiveDirectory (RSAT) und Leserechte im AD.

.EXAMPLE
    .\Export-ADData.ps1 -OutFile C:\Temp\ad.json

.EXAMPLE
    .\Export-ADData.ps1 -Server https://permcenter.firma.local:8080
#>
[CmdletBinding()]
param(
    [string] $OutFile = (Join-Path $PWD "ad-export.json"),
    # Basis-URL des PermissionCenter-Servers; wenn gesetzt, wird direkt hochgeladen.
    [string] $Server,
    # Domänencontroller (optional)
    [string] $DomainController,
    # Keine AD-Berechtigungen auslesen (dann bleiben die Angriffspfade leer)
    [switch] $SkipAcl
)

$ErrorActionPreference = 'Stop'
Import-Module ActiveDirectory

$common = @{}
if ($DomainController) { $common.Server = $DomainController }

function ConvertTo-Iso($d) {
    if ($null -eq $d) { return $null }
    return ([datetime]$d).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
}

$domain = Get-ADDomain @common
Write-Host "Domäne: $($domain.DNSRoot) ($($domain.DomainSID))"

Write-Host "Lese Benutzer…"
$users = Get-ADUser -Filter * @common -Properties SamAccountName, UserPrincipalName, DisplayName, Enabled,
    LastLogonDate, PasswordLastSet, whenCreated, MemberOf, PrimaryGroupID, PasswordNeverExpires, ServicePrincipalNames, userAccountControl
Write-Host "Lese Computer…"
$computers = Get-ADComputer -Filter * @common -Properties SamAccountName, Enabled, LastLogonDate,
    PasswordLastSet, whenCreated, MemberOf, PrimaryGroupID, userAccountControl
Write-Host "Lese Gruppen…"
$groups = Get-ADGroup -Filter * @common -Properties Members, Description, GroupScope, GroupCategory, whenCreated

# DN -> SID für die Auflösung von Mitgliedschaften
$dnToSid = @{}
foreach ($o in @($users) + @($computers) + @($groups)) {
    $dnToSid[$o.DistinguishedName.ToLowerInvariant()] = $o.SID.Value
}
function Resolve-Dn([string] $dn) {
    $sid = $dnToSid[$dn.ToLowerInvariant()]
    if ($sid) { return $sid }
    # Fremde Sicherheitsprinzipale: CN=S-1-5-...,CN=ForeignSecurityPrincipals,...
    if ($dn -match '^CN=(S-1-[0-9-]+),') { return $Matches[1] }
    return $null
}

function Convert-Account($a, [bool] $isComputer) {
    $memberOf = @($a.MemberOf | ForEach-Object { Resolve-Dn $_ } | Where-Object { $_ })
    if ($a.PrimaryGroupID) { $memberOf += "$($domain.DomainSID.Value)-$($a.PrimaryGroupID)" }
    [ordered]@{
        sid                 = $a.SID.Value
        sam_account_name    = $a.SamAccountName
        user_principal_name = $a.UserPrincipalName
        display_name        = $a.DisplayName
        distinguished_name  = $a.DistinguishedName
        enabled             = [bool]$a.Enabled
        last_logon          = ConvertTo-Iso $a.LastLogonDate
        password_last_set   = ConvertTo-Iso $a.PasswordLastSet
        created             = ConvertTo-Iso $a.whenCreated
        is_computer         = $isComputer
        password_never_expires  = [bool]$a.PasswordNeverExpires
        service_principal_names = @(if ($isComputer) { } else { $a.ServicePrincipalNames })
        user_account_control = [uint32]$a.userAccountControl
        member_of           = @($memberOf | Select-Object -Unique)
    }
}

# AD-Berechtigungen für die Angriffspfade. Die Bewertung macht der Server; hier fallen nur
# Einträge weg, die nie relevant sind. Das hält den Export auch in großen Domänen klein.
function Get-AclObjects {
    # SYSTEM, SELF, CREATOR OWNER, Enterprise-DCs, Administratoren, Domänen- und Organisations-Admins
    $skip = @{}
    foreach ($s in 'S-1-5-18', 'S-1-5-10', 'S-1-3-0', 'S-1-5-9', 'S-1-5-32-544',
        "$($domain.DomainSID.Value)-512", "$($domain.DomainSID.Value)-519") { $skip[$s] = $true }
    # GENERIC_ALL, GENERIC_WRITE, WRITE_OWNER, WRITE_DAC, CONTROL_ACCESS, WRITE_PROP, SELF
    $relevant = 0x10000000L -bor 0x40000000L -bor 0x80000L -bor 0x40000L -bor 0x100L -bor 0x20L -bor 0x8L
    $kinds = @{ user = 'user'; computer = 'computer'; group = 'group'; domainDNS = 'domain'
        organizationalUnit = 'ou'; container = 'container'; groupPolicyContainer = 'gpo' }
    $filter = '(|(objectClass=user)(objectClass=group)(objectClass=domainDNS)(objectClass=organizationalUnit)(objectClass=container)(objectClass=groupPolicyContainer))'
    $sidType = [Security.Principal.SecurityIdentifier]
    Get-ADObject -LDAPFilter $filter @common -Properties nTSecurityDescriptor, objectSid, displayName, gPLink, gPOptions | ForEach-Object {
        $sd = $_.nTSecurityDescriptor
        if ($null -eq $sd) { return }
        $aces = foreach ($r in $sd.GetAccessRules($true, $true, $sidType)) {
            if ("$($r.AccessControlType)" -ne 'Allow') { continue }
            if ($r.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) { continue }
            $trustee = $r.IdentityReference.Value
            if ($skip.ContainsKey($trustee)) { continue }
            $mask = [int64][int]$r.ActiveDirectoryRights -band 4294967295L
            if (-not ($mask -band $relevant)) { continue }
            [ordered]@{
                trustee     = $trustee
                mask        = $mask
                object_type = if ($r.ObjectType -eq [guid]::Empty) { $null } else { $r.ObjectType.ToString() }
                inherited   = [bool]$r.IsInherited
            }
        }
        $kind = $kinds["$($_.ObjectClass)"]
        if (-not $kind) { $kind = 'container' }
        [ordered]@{
            dn         = $_.DistinguishedName
            sid        = if ($_.objectSid) { $_.objectSid.Value } else { $null }
            kind       = $kind
            display_name = $_.displayName
            owner      = $sd.GetOwner($sidType).Value
            protected  = [bool]$sd.AreAccessRulesProtected
            gp_link    = $_.gPLink
            gp_options = if ($_.gPOptions) { [int]$_.gPOptions } else { 0 }
            aces       = @($aces)
        }
    }
}

$aclObjects = @()
if (-not $SkipAcl) {
    Write-Host "Lese AD-Berechtigungen…"
    $aclObjects = @(Get-AclObjects)
}

$scopeMap = @{ Global = 'global'; DomainLocal = 'domain_local'; Universal = 'universal' }

$snapshot = [ordered]@{
    domain       = $domain.DNSRoot
    domain_sid   = $domain.DomainSID.Value
    collected_at = ConvertTo-Iso (Get-Date)
    machine_account_quota = (Get-ADObject -Identity $domain.DistinguishedName @common -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'
    users        = @(
        @($users | ForEach-Object { Convert-Account $_ $false }) +
        @($computers | ForEach-Object { Convert-Account $_ $true })
    )
    groups       = @($groups | ForEach-Object {
        $scope = if ($_.SID.Value -like 'S-1-5-32-*') { 'builtin' } else { $scopeMap["$($_.GroupScope)"] }
        [ordered]@{
            sid                = $_.SID.Value
            sam_account_name   = $_.SamAccountName
            distinguished_name = $_.DistinguishedName
            description        = $_.Description
            scope              = $scope
            is_security        = ("$($_.GroupCategory)" -eq 'Security')
            members            = @($_.Members | ForEach-Object { Resolve-Dn $_ } | Where-Object { $_ })
            created            = ConvertTo-Iso $_.whenCreated
        }
    })
    acl_objects  = $aclObjects
}

$json = $snapshot | ConvertTo-Json -Depth 6 -Compress
[System.IO.File]::WriteAllText($OutFile, $json, (New-Object System.Text.UTF8Encoding $false))
Write-Host ("Exportiert: {0} Konten, {1} Gruppen, {2} Objekte mit Berechtigungen -> {3}" -f $snapshot.users.Count, $snapshot.groups.Count, $aclObjects.Count, $OutFile)

if ($Server) {
    $uri = $Server.TrimEnd('/') + '/api/v1/ad/import'
    Write-Host "Lade hoch nach $uri …"
    $resp = Invoke-RestMethod -Method Post -Uri $uri -ContentType 'application/json; charset=utf-8' `
        -Body ([System.Text.Encoding]::UTF8.GetBytes($json))
    Write-Host ("Server: {0} Konten, {1} Gruppen übernommen, {2} Befunde" -f $resp.users, $resp.groups, $resp.findings)
}
