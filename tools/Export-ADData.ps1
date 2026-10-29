<#
.SYNOPSIS
    Exportiert Benutzer, Computer und Gruppen des Active Directory für den PermissionCenter-Server.

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
    [string] $DomainController
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
    LastLogonDate, PasswordLastSet, whenCreated, MemberOf, PrimaryGroupID, PasswordNeverExpires, ServicePrincipalNames
Write-Host "Lese Computer…"
$computers = Get-ADComputer -Filter * @common -Properties SamAccountName, Enabled, LastLogonDate,
    PasswordLastSet, whenCreated, MemberOf, PrimaryGroupID
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
        member_of           = @($memberOf | Select-Object -Unique)
    }
}

$scopeMap = @{ Global = 'global'; DomainLocal = 'domain_local'; Universal = 'universal' }

$snapshot = [ordered]@{
    domain       = $domain.DNSRoot
    domain_sid   = $domain.DomainSID.Value
    collected_at = ConvertTo-Iso (Get-Date)
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
}

$json = $snapshot | ConvertTo-Json -Depth 6 -Compress
[System.IO.File]::WriteAllText($OutFile, $json, (New-Object System.Text.UTF8Encoding $false))
Write-Host ("Exportiert: {0} Konten, {1} Gruppen -> {2}" -f $snapshot.users.Count, $snapshot.groups.Count, $OutFile)

if ($Server) {
    $uri = $Server.TrimEnd('/') + '/api/v1/ad/import'
    Write-Host "Lade hoch nach $uri …"
    $resp = Invoke-RestMethod -Method Post -Uri $uri -ContentType 'application/json; charset=utf-8' `
        -Body ([System.Text.Encoding]::UTF8.GetBytes($json))
    Write-Host ("Server: {0} Konten, {1} Gruppen übernommen, {2} Befunde" -f $resp.users, $resp.groups, $resp.findings)
}
