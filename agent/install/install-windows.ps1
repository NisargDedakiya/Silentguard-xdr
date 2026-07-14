<#
.SYNOPSIS
  SilentGuard XDR — Windows agent installer.

.DESCRIPTION
  Installs the agent as a Scheduled Task that runs as SYSTEM (always elevated)
  at startup and restarts on failure, so enforcement — DNS sinkhole domain
  blocking, network isolation, USB blocking — works automatically without any
  "Run as Administrator" juggling. It also disables browser DNS-over-HTTPS via
  enterprise policy (so hosts-file blocking actually takes effect) and flushes
  the DNS cache.

  Must be run from an elevated (Administrator) PowerShell.

.EXAMPLE
  .\install-windows.ps1 -ServerUrl "https://xdr.example:8000" -EnrollToken "<TOKEN>"

.PARAMETER KeepBrowserDoH
  Skip disabling browser DNS-over-HTTPS (leaves DoH as-is).
#>
#Requires -RunAsAdministrator
param(
  [Parameter(Mandatory = $true)] [string]$ServerUrl,
  [Parameter(Mandatory = $true)] [string]$EnrollToken,
  [switch]$KeepBrowserDoH
)
$ErrorActionPreference = 'Stop'

$Root = "$env:ProgramFiles\SilentGuard"
$Src  = Split-Path -Parent $PSScriptRoot   # the agent\ directory
$Task = 'SilentGuardAgent'

Write-Host "==> Installing SilentGuard agent to $Root"
New-Item -ItemType Directory -Force -Path $Root | Out-Null
python -m venv "$Root\venv"
& "$Root\venv\Scripts\pip.exe" install -q --upgrade pip
& "$Root\venv\Scripts\pip.exe" install -q -r "$Src\requirements.txt"
Copy-Item -Recurse -Force "$Src\silentguard_agent" "$Root\"

# Launcher that injects config and starts the agent (enforcement live, no dry-run).
$Wrapper = "$Root\run-agent.cmd"
@"
@echo off
set SG_SERVER_URL=$ServerUrl
set SG_ENROLL_TOKEN=$EnrollToken
cd /d "$Root"
"$Root\venv\Scripts\python.exe" -m silentguard_agent.main
"@ | Set-Content -Encoding ASCII -Path $Wrapper

Write-Host "==> Registering scheduled task '$Task' (SYSTEM, highest privileges, at startup)"
$action    = New-ScheduledTaskAction -Execute $Wrapper
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName $Task -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $Task

if (-not $KeepBrowserDoH) {
  Write-Host "==> Disabling browser DNS-over-HTTPS via policy (so hosts-file blocking works)"
  foreach ($p in @('HKLM:\SOFTWARE\Policies\Google\Chrome',
                   'HKLM:\SOFTWARE\Policies\Microsoft\Edge')) {
    New-Item -Path $p -Force | Out-Null
    Set-ItemProperty -Path $p -Name 'DnsOverHttpsMode' -Value 'off'
  }
}
ipconfig /flushdns | Out-Null

Write-Host ""
Write-Host "Done. The agent runs as SYSTEM (elevated) -> blocklist, isolation and USB blocking are ACTIVE."
Write-Host "  Check the dashboard timeline for the 'Enforcement enabled' event."
Write-Host "  Manage: schtasks /query /tn $Task   |   stop: schtasks /end /tn $Task"
