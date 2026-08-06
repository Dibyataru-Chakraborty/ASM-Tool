param(
    [Parameter(Mandatory = $true)]
    [string]$ProjectRoot
)

$ErrorActionPreference = "Stop"
$bundleRoot = $PSScriptRoot
$sourceRoot = Join-Path $bundleRoot "files"
$project = (Resolve-Path $ProjectRoot).Path
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$backupRoot = Join-Path $project ".extended-tools-backup-$timestamp"

if (-not (Test-Path $sourceRoot)) {
    throw "The files directory was not found beside this script."
}

$files = Get-ChildItem -Path $sourceRoot -Recurse -File
foreach ($file in $files) {
    $relative = $file.FullName.Substring($sourceRoot.Length).TrimStart('\', '/')
    $destination = Join-Path $project $relative
    $destinationDirectory = Split-Path $destination -Parent

    if (Test-Path $destination) {
        $backup = Join-Path $backupRoot $relative
        New-Item -ItemType Directory -Path (Split-Path $backup -Parent) -Force | Out-Null
        Copy-Item $destination $backup -Force
    }

    New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
    Copy-Item $file.FullName $destination -Force
    Write-Host "Applied: $relative"
}

Write-Host ""
Write-Host "Feature files applied successfully."
if (Test-Path $backupRoot) {
    Write-Host "Backup created at: $backupRoot"
}
Write-Host "Merge backend.env.extended-tools.example into backend/.env manually."
