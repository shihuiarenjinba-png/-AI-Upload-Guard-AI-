$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

if (-not (Get-Command py -ErrorAction SilentlyContinue)) { throw "Python launcher 'py' is required." }

$Venv = Join-Path $Root ".venv-build"
if (Test-Path $Venv) { Remove-Item -Recurse -Force $Venv }
py -3 -m venv $Venv
$Python = Join-Path $Venv "Scripts\python.exe"
& $Python -m pip install --upgrade pip
& $Python -m pip install pyinstaller pillow "pypdf>=6.0,<7"

& $Python -m PyInstaller --noconfirm --clean --onefile --windowed `
  --name "AIUploadGuard" `
  --collect-all PIL `
  --collect-all pypdf `
  desktop_entry.py

Write-Host "Built: $Root\dist\AIUploadGuard.exe"
Write-Host "Before sale: run SALES_RELEASE_CHECKLIST.md, regression tests, PDF metadata/XMP verification, network-egress verification, JA/EN UI smoke, malware scan, Authenticode signing, then SHA256 the signed artifact."
