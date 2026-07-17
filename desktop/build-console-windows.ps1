<#
.SYNOPSIS  Build SilentGuard Console into a single Windows .exe.
.DESCRIPTION
  Run once on a Windows PC with Python 3.11+. Produces
  dist\SilentGuardConsole.exe — a desktop admin app that connects to your
  SilentGuard server (no browser).
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\build-console-windows.ps1
#>
$ErrorActionPreference = 'Stop'
Set-Location -Path $PSScriptRoot

Write-Host "==> Installing build dependencies"
python -m pip install --upgrade pip
python -m pip install pyinstaller requests

Write-Host "==> Building SilentGuardConsole.exe"
pyinstaller --noconfirm --onefile --windowed `
    --name SilentGuardConsole `
    --hidden-import silentguard_console.console_app `
    run_console.py

Write-Host ""
Write-Host "Done: dist\SilentGuardConsole.exe"
Write-Host "Launch it, enter your server URL, and sign in with an admin token or"
Write-Host "your email/password."
