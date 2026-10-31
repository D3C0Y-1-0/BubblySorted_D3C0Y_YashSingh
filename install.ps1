# Hedwig installer for Windows (PowerShell).
# Usage: irm https://github.com/D3C0Y-1-0/BubblySorted_D3C0Y_YashSingh/releases/latest/download/install.ps1 | iex
$ErrorActionPreference = "Stop"

$Repo = "D3C0Y-1-0/BubblySorted_D3C0Y_YashSingh"

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Host "Installing uv..."
    Invoke-RestMethod https://astral.sh/uv/install.ps1 | Invoke-Expression
    $env:Path = "$env:USERPROFILE\.local\bin;$env:Path"
}

Write-Host "Finding the latest Hedwig release..."
$Release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest"
$Wheel = $Release.assets | Where-Object { $_.name -like "*.whl" } | Select-Object -First 1
if (-not $Wheel) {
    throw "Could not find a Hedwig wheel in the latest release."
}

Write-Host "Installing $($Wheel.browser_download_url)"
uv tool install --force --python 3.12 "hedwig @ $($Wheel.browser_download_url)"
if ($LASTEXITCODE -ne 0) {
    throw "uv tool install failed (exit code $LASTEXITCODE)."
}

# uv writes informational messages (e.g. "already in PATH") to stderr. Under
# Windows PowerShell 5.1 with ErrorActionPreference=Stop, redirected native
# stderr becomes a terminating error, so relax it for this best-effort step.
$ErrorActionPreference = "Continue"
uv tool update-shell *> $null
$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "Hedwig installed. Open a new terminal and run: hedwig config"
