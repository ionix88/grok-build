# Local/dev installer skeleton for the public `orca` binary on Windows.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$BinDir = if ($env:ORCA_BIN_DIR) { $env:ORCA_BIN_DIR } else { Join-Path $HOME ".orca\bin" }
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

$Candidates = @(
    (Join-Path $Root "target\release\orca.exe"),
    (Join-Path $Root "target\debug\orca.exe"),
    (Join-Path $Root "target\release\orca"),
    (Join-Path $Root "target\debug\orca")
)
$Src = $Candidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $Src) {
    Write-Error "build orca first: cargo build -p xai-grok-pager-bin --release --locked"
}
$Dest = Join-Path $BinDir "orca.exe"
Copy-Item -Force $Src $Dest
Write-Host "Installed $Src -> $Dest"
Write-Host "Ensure $BinDir is on PATH, then run: orca --version"
