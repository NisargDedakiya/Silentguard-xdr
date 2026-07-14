<#
.SYNOPSIS  SilentGuard XDR — Windows agent uninstaller.
.PARAMETER RestoreBrowserDoH  Re-enable browser DNS-over-HTTPS (removes the policy).
#>
#Requires -RunAsAdministrator
param([switch]$RestoreBrowserDoH)
$ErrorActionPreference = 'SilentlyContinue'

$Root = "$env:ProgramFiles\SilentGuard"
$Task = 'SilentGuardAgent'

Stop-ScheduledTask -TaskName $Task
Unregister-ScheduledTask -TaskName $Task -Confirm:$false
Remove-Item -Recurse -Force $Root

if ($RestoreBrowserDoH) {
  foreach ($p in @('HKLM:\SOFTWARE\Policies\Google\Chrome',
                   'HKLM:\SOFTWARE\Policies\Microsoft\Edge')) {
    Remove-ItemProperty -Path $p -Name 'DnsOverHttpsMode' -ErrorAction SilentlyContinue
  }
}
Write-Host "SilentGuard agent removed. Review C:\Windows\System32\drivers\etc\hosts and"
Write-Host "delete any leftover '# >>> SilentGuard XDR sinkhole >>>' block if present."
