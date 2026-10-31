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
uv tool update-shell 2>$null

Write-Host ""
Write-Host "Hedwig installed. Open a new terminal and run: hedwig config"
