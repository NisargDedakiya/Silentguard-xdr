<#
.SYNOPSIS
  Build SilentGuard Home into a single Windows .exe.

.DESCRIPTION
  Run this ONCE on a Windows PC that has Python 3.11+ installed. It produces
  dist\SilentGuardHome.exe. The .exe embeds an "administrator" manifest
  (--uac-admin), so double-clicking it raises the UAC prompt automatically —
  no need to right-click "Run as administrator".

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\build-windows.ps1
#>
$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot

Write-Host "==> Installing build dependencies"
python -m pip install --upgrade pip
python -m pip install pyinstaller psutil

Write-Host "==> Building SilentGuardHome.exe"
pyinstaller --noconfirm --onefile --windowed --uac-admin `
    --name SilentGuardHome `
    --hidden-import silentguard_home.app `
    run.py

Write-Host ""
Write-Host "Done. Your app is: dist\SilentGuardHome.exe"
Write-Host "Double-click it (accept the UAC prompt) to run with the admin rights"
Write-Host "that blocking requires."
