<#
.SYNOPSIS
    Installiert den PermissionCenter-Client als Windows-Dienst oder als geplante Aufgabe.

.DESCRIPTION
    Kopiert pc-client.exe nach "%ProgramFiles%\PermissionCenter", legt eine kommentierte
    Konfiguration unter "%ProgramData%\PermissionCenter\pc-client.toml" an (falls nicht vorhanden)
    und richtet den automatischen Betrieb ein:

      -Mode Service  Windows-Dienst "PermissionCenterClient" (LocalSystem, Autostart, Neustart bei
                     Fehlern). Zeitplan und Update-Prüfung über den Abschnitt [service] der Konfiguration.
      -Mode Task     Geplante Aufgabe "PermissionCenter-Scan" (täglich, als SYSTEM).

    Lauffähig auf Windows Server 2016 bis 2025. Als Administrator ausführen.

.EXAMPLE
    .\Install-PcClient.ps1 -ServerUrl https://permcenter.firma.local:8080 -ApiToken geheim -PublicKey "Fe52…="

.EXAMPLE
    .\Install-PcClient.ps1 -ServerUrl https://permcenter.firma.local:8080 -Mode Task -At 02:30

.EXAMPLE
    .\Install-PcClient.ps1 -Uninstall
#>
[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    [Parameter(Mandatory, ParameterSetName = 'Install')] [string] $ServerUrl,
    [Parameter(ParameterSetName = 'Install')] [string] $ApiToken,
    # Öffentlicher Schlüssel für signierte OTA-Updates (Ausgabe von "pc-server gen-signing-key")
    [Parameter(ParameterSetName = 'Install')] [string] $PublicKey,
    [Parameter(ParameterSetName = 'Install')] [ValidateSet('Service', 'Task')] [string] $Mode = 'Service',
    [Parameter(ParameterSetName = 'Install')] [string] $ExePath = (Join-Path $PSScriptRoot 'pc-client.exe'),
    # Scan-Uhrzeit (Dienst: [service] scan_time, Aufgabe: Trigger)
    [Parameter(ParameterSetName = 'Install')] [string] $At = '02:00',
    [Parameter(ParameterSetName = 'Install')] [switch] $RunNow,
    [Parameter(Mandatory, ParameterSetName = 'Uninstall')] [switch] $Uninstall
)

$ErrorActionPreference = 'Stop'
$serviceName = 'PermissionCenterClient'
$taskName = 'PermissionCenter-Scan'
$installDir = Join-Path $env:ProgramFiles 'PermissionCenter'
$dataDir = Join-Path $env:ProgramData 'PermissionCenter'
$exe = Join-Path $installDir 'pc-client.exe'
$config = Join-Path $dataDir 'pc-client.toml'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Bitte als Administrator ausführen.'
}

function Remove-Existing {
    if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
        & $exe service uninstall | Out-Null
        Write-Host "Dienst $serviceName entfernt."
    }
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-Host "Geplante Aufgabe $taskName entfernt."
    }
}

if ($Uninstall) {
    if (Test-Path $exe) { Remove-Existing }
    Remove-Item -Recurse -Force $installDir -ErrorAction SilentlyContinue
    Write-Host "Deinstalliert. Daten, Logs und Konfiguration unter $dataDir bleiben erhalten."
    return
}

if (-not (Test-Path $ExePath)) { throw "pc-client.exe nicht gefunden: $ExePath" }
New-Item -ItemType Directory -Force $installDir, $dataDir | Out-Null
if (Test-Path $exe) { Remove-Existing }
Copy-Item $ExePath $exe -Force

# Datenverzeichnis nur für SYSTEM und Administratoren (enthält Token, Scan-Ergebnisse, Logs)
icacls $dataDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
# Programmverzeichnis: SYSTEM muss die EXE beim OTA-Update austauschen können
icacls $installDir /grant '*S-1-5-18:(OI)(CI)F' | Out-Null

if (-not (Test-Path $config)) {
    $text = & $exe init-config 2>$null | Out-String
    $text = $text -replace '(?m)^# url = .*$', "url = `"$ServerUrl`""
    if ($ApiToken) { $text = $text -replace '(?m)^# api_token = .*$', "api_token = `"$ApiToken`"" }
    if ($PublicKey) { $text = $text -replace '(?m)^# public_key = .*$', "public_key = `"$PublicKey`"" }
    $text = $text -replace '(?m)^scan_time = .*$', "scan_time = `"$At`""
    [System.IO.File]::WriteAllText($config, $text, (New-Object System.Text.UTF8Encoding $false))
    Write-Host "Konfiguration angelegt: $config"
} else {
    Write-Host "Vorhandene Konfiguration bleibt unverändert: $config"
}

if ($Mode -eq 'Service') {
    & $exe --config $config service install
    if ($LASTEXITCODE -ne 0) { throw 'Dienstinstallation fehlgeschlagen – siehe Log (pc-client logs --errors).' }
    Start-Service $serviceName
    Write-Host "Dienst $serviceName läuft. Scan täglich um $At (änderbar in $config, Abschnitt [service])."
    if ($RunNow) {
        Start-Process -FilePath $exe -ArgumentList "--config `"$config`" scan" -NoNewWindow -Wait
    }
} else {
    $action = New-ScheduledTaskAction -Execute $exe -Argument "--config `"$config`" scan" -WorkingDirectory $dataDir
    $trigger = New-ScheduledTaskTrigger -Daily -At $At
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 12) `
        -MultipleInstances IgnoreNew -Priority 7
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings `
        -Principal $taskPrincipal -Description 'PermissionCenter: Berechtigungsscan und Upload' -Force | Out-Null
    Write-Host "Geplante Aufgabe '$taskName' täglich um $At registriert."
    if ($RunNow) { Start-ScheduledTask -TaskName $taskName; Write-Host 'Scan gestartet.' }
}
Write-Host "Logs: $dataDir\logs  (oder: pc-client logs)"
