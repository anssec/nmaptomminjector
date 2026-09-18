<#!
.SYNOPSIS
Builds a single-file portable Windows application for Nmap MindMap Injector.

.DESCRIPTION
Creates release\NmapMindmap.exe.  The resulting executable includes Python,
Tkinter, and the embedded VAPT test-case database, so recipients do not need
to install Python, pip packages, or Nmap.

Run from this project folder:
    powershell -ExecutionPolicy Bypass -File .\build_portable.ps1
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSCommandPath
$venvPath = Join-Path $projectRoot '.build-venv'
$pythonExe = Join-Path $venvPath 'Scripts\python.exe'
$entryPoint = Join-Path $projectRoot 'nmap_mindmap_gui.py'
$releaseDir = Join-Path $projectRoot 'release'
$readmePath = Join-Path $projectRoot 'README_PORTABLE.md'
$portableZip = Join-Path $releaseDir 'NmapMindmap-Portable-Windows-x64.zip'

if (-not (Test-Path -LiteralPath $entryPoint -PathType Leaf)) {
    throw "Entry point was not found: $entryPoint"
}

if (-not (Test-Path -LiteralPath $pythonExe -PathType Leaf)) {
    Write-Host 'Creating an isolated build environment...'
    python -m venv $venvPath
}

Write-Host 'Installing the packaging tool...'
& $pythonExe -m pip install --upgrade pip pyinstaller

Write-Host 'Building the portable executable...'
& $pythonExe -m PyInstaller `
    --noconfirm `
    --clean `
    --onefile `
    --windowed `
    --hidden-import vapt_db `
    --name NmapMindmap `
    --distpath $releaseDir `
    --workpath (Join-Path $projectRoot 'build') `
    --specpath (Join-Path $projectRoot 'build') `
    $entryPoint

if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller failed with exit code $LASTEXITCODE"
}

if (-not (Test-Path -LiteralPath $releaseDir)) {
    New-Item -ItemType Directory -Path $releaseDir | Out-Null
}

Copy-Item -LiteralPath $readmePath -Destination (Join-Path $releaseDir 'README.md') -Force
Compress-Archive `
    -LiteralPath @((Join-Path $releaseDir 'NmapMindmap.exe'), (Join-Path $releaseDir 'README.md')) `
    -DestinationPath $portableZip `
    -Force

Write-Host ''
Write-Host 'Portable app created:' -ForegroundColor Green
Write-Host (Join-Path $releaseDir 'NmapMindmap.exe') -ForegroundColor Green
Write-Host $portableZip -ForegroundColor Green
