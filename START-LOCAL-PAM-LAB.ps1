# ==============================================================================
# Authentic Local PAM Lab Launcher (PowerShell)
# Starts HashiCorp Vault Server, configures Safes/Policies, and executes live tests
# ==============================================================================

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  STARTING AUTHENTIC LOCAL PAM LAB (HashiCorp Vault)      " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $scriptDir) { $scriptDir = (Get-Location).Path }
Set-Location $scriptDir

# 1. Start Native HashiCorp Vault Server in a separate window
$vaultBin = Join-Path $scriptDir "bin\vault.exe"
if (-not (Test-Path $vaultBin)) {
    Write-Error "Vault binary not found at $vaultBin."
    exit 1
}

Write-Host "`n[1/4] Starting local HashiCorp Vault Server (:8200)..." -ForegroundColor Yellow
Start-Process -FilePath $vaultBin -ArgumentList "server", "-dev", "-dev-listen-address=0.0.0.0:8200", "-dev-root-token-id=root"

Write-Host "Waiting 3 seconds for Vault engine to initialize..." -ForegroundColor Gray
Start-Sleep -Seconds 3

# 2. Configure Safes, Policies, and Users
Write-Host "`n[2/4] Provisioning Safes, RBAC Policies, and Users..." -ForegroundColor Yellow
$setupScript = Join-Path $scriptDir "scripts\setup-vault-windows.ps1"
& $setupScript -VaultUrl "http://127.0.0.1:8200" -RootToken "root"

# 3. Open Real Vault Web UI in Browser
Write-Host "`n[3/4] Opening official HashiCorp Vault Web UI in your browser..." -ForegroundColor Yellow
Start-Process "http://127.0.0.1:8200/ui"

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host " [OK] VAULT SERVER AND SAFES ARE LIVE!" -ForegroundColor Green
Write-Host " Web UI: http://127.0.0.1:8200/ui (Sign in with Token: root)" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green

Write-Host "`nSCREENSHOT OPPORTUNITY 1 (Vault Web UI):" -ForegroundColor Cyan
Write-Host "   - In your browser, log in with Token: root"
Write-Host "   - Click on 'secret/' to see all 4 Safes (windows-admin, service-accounts, etc.)"
Write-Host "   - Snip and save: screenshots/phase3-vault-safes.png"
Write-Host "   - Click 'Policies' and snip: screenshots/phase2-vault-policies.png"

Write-Host "`n----------------------------------------------------------"
Read-Host "Press Enter to run the live tests (Bob 403 test, Alice 200 test, and Apps)..."

# 4. Run Live Tests
Write-Host "`n>>> [TEST 1] Running RBAC Access Control Test (Bob Denied vs Alice Allowed)..." -ForegroundColor Yellow
$rbacScript = Join-Path $scriptDir "scripts\test-vault-rbac.ps1"
& $rbacScript -VaultUrl "http://127.0.0.1:8200"

Write-Host "`n>>> [TEST 2] Running Application Security Transformation..." -ForegroundColor Yellow
Write-Host "`n--- Before: Legacy Hardcoded Secret ---" -ForegroundColor Red
python apps\before_hardcoded_app.py

Write-Host "`n--- After: Dynamically Retrieved from Vault REST API ---" -ForegroundColor Green
$env:VAULT_ADDR = "http://127.0.0.1:8200"
$env:VAULT_TOKEN = "root"
python apps\after_vault_app.py

Write-Host "`n>>> [TEST 3] Running Privileged Access Review and Compliance Scanner..." -ForegroundColor Yellow
$auditScript = Join-Path $scriptDir "scripts\privileged-access-review.ps1"
& $auditScript

Write-Host "`n==========================================================" -ForegroundColor Green
Write-Host " [OK] ALL LIVE TESTS EXECUTED NATIVELY ON YOUR PC!" -ForegroundColor Green
Write-Host " You can now take real screenshots of this PowerShell window!" -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
