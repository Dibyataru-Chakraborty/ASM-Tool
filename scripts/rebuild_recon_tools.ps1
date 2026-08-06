param()

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

Push-Location $projectRoot
try {
    Write-Host "Validating Docker Compose configuration..."
    docker compose config --quiet

    Write-Host "Building the pinned recon installer and backend..."
    docker compose build pd_installer backend

    Write-Host "Recreating the one-shot installer against the existing tool volume..."
    docker compose up --force-recreate --no-deps pd_installer

    Write-Host "Recreating application services with the validated tools..."
    docker compose up -d --build --force-recreate backend frontend nginx

    Write-Host "Running non-scanning startup checks inside the backend..."
    docker compose exec -T backend python check_recon_tools.py

    Write-Host "Recon tools rebuilt and verified successfully."
}
finally {
    Pop-Location
}
