# Local/dev installer for public orca into independent host bin root (never .grok).
$ErrorActionPreference = "Stop"
$OrcaRoot = Split-Path -Parent $PSScriptRoot
$BinDir = if ($env:ORCA_BIN_DIR) { $env:ORCA_BIN_DIR } else { Join-Path $env:USERPROFILE ".orca\bin" }
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null
$candidates = @((Join-Path $OrcaRoot "target\release\orca.exe"), (Join-Path $OrcaRoot "target\debug\orca.exe"))
$src = $candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $src) { Write-Error "build orca first"; exit 1 }
$dest = Join-Path $BinDir "orca.exe"
$tmp = Join-Path $BinDir (".orca.tmp." + $PID)
Copy-Item -Force $src $tmp
Move-Item -Force $tmp $dest
Write-Host "Installed $src -> $dest"
Write-Host "Host update: orca update --check | orca update --to <archive.tar.gz>"
