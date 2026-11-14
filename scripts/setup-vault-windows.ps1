# ==============================================================================
# Phase 2 & 3: Provision Local Native HashiCorp Vault on Windows
# Executes against running local vault.exe server at http://127.0.0.1:8200
# ==============================================================================

[CmdletBinding()]
param(
    [string]$VaultUrl = "http://127.0.0.1:8200",
    [string]$RootToken = "root"
)

$env:VAULT_ADDR = $VaultUrl
$env:VAULT_TOKEN = $RootToken
$vaultBin = Join-Path $PSScriptRoot "..\bin\vault.exe"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [Phase 2] Configuring Native HashiCorp Vault on Windows   " -ForegroundColor Cyan
Write-Host " Endpoint: $VaultUrl" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Enable KV v2 secret engine at secret/
Write-Host "[+] Enabling KV-v2 secret engine at 'secret/'..." -ForegroundColor Yellow
& $vaultBin secrets enable -path=secret kv-v2 2>$null

# 2. Upload Policies
Write-Host "[+] Uploading HCL RBAC Policies..." -ForegroundColor Yellow
$policyDir = Join-Path $PSScriptRoot "..\vault\policies"
& $vaultBin policy write pam-admin (Join-Path $policyDir "pam-admin.hcl")
& $vaultBin policy write pam-operator (Join-Path $policyDir "pam-operator.hcl")
& $vaultBin policy write pam-auditor (Join-Path $policyDir "pam-auditor.hcl")
& $vaultBin policy write pam-rotation-engine (Join-Path $policyDir "pam-rotation-engine.hcl")
& $vaultBin policy write webapp-approle (Join-Path $policyDir "webapp-approle.hcl")

# 3. Enable userpass authentication
Write-Host "[+] Enabling userpass authentication..." -ForegroundColor Yellow
& $vaultBin auth enable userpass 2>$null

# 4. Provision Users
Write-Host "[+] Provisioning users: alice (pam-operator), bob (unprivileged)..." -ForegroundColor Yellow
& $vaultBin write auth/userpass/users/alice password="AliceSecureLab2026!" policies="pam-operator"
& $vaultBin write auth/userpass/users/bob password="BobStandardLab2026!" policies="default"

# 5. Enable AppRole
Write-Host "[+] Enabling AppRole authentication..." -ForegroundColor Yellow
& $vaultBin auth enable approle 2>$null
& $vaultBin write auth/approle/role/webapp-role secret_id_ttl=24h token_ttl=1h policies="webapp-approle"

# 6. Onboard Initial Safes (Phase 3)
Write-Host "[+] Onboarding initial privileged credentials into safes..." -ForegroundColor Yellow
& $vaultBin kv put secret/windows-admin/win-app01 `
    username="Administrator" `
    password="WinAppLocalAdminInitial2026!" `
    system="WIN-APP01" `
    owner="Infrastructure Team" `
    account_type="WindowsLocalAdmin" `
    rotation_period="30d"

& $vaultBin kv put secret/linux-root/linux01 `
    username="appadmin" `
    password="LabP@ssw0rdLinux2026!" `
    system="LINUX01" `
    owner="DevOps Team" `
    account_type="LinuxLocalSudo" `
    rotation_period="30d"

& $vaultBin kv put secret/service-accounts/svc_webapp `
    username="svc_webapp" `
    password="P@ssword123!SecureLab" `
    system="DC01.lab.local" `
    owner="Identity / Web Team" `
    account_type="ADServiceAccount" `
    rotation_period="30d" `
    last_rotated=(Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")

& $vaultBin kv put secret/aws/iam-user `
    username="lab-pam-svc" `
    access_key_id="AKIAIOSFODNN7EXAMPLE" `
    secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" `
    system="AWS Cloud (Lab Account)" `
    owner="Cloud Security Team" `
    account_type="AWSIAMUser" `
    rotation_period="90d"

Write-Host "==========================================================" -ForegroundColor Green
Write-Host " [OK] Native Vault Configuration & Onboarding Complete!    " -ForegroundColor Green
Write-Host " Open Web UI in browser: http://127.0.0.1:8200/ui         " -ForegroundColor Green
Write-Host " Token: root                                              " -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green

