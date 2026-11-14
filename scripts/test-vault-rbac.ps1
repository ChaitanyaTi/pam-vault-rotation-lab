<#
.SYNOPSIS
    Automates Phase 2 RBAC Validation: Verifies access denial for Bob and permitted access for Alice.

.DESCRIPTION
    1. Authenticates as user 'bob' via Vault userpass API.
    2. Attempts to retrieve 'secret/data/service-accounts/svc_webapp' -> Validates 403 Forbidden.
    3. Authenticates as user 'alice' via Vault userpass API.
    4. Attempts to retrieve 'secret/data/service-accounts/svc_webapp' -> Validates 200 OK.
    5. Attempts to retrieve 'secret/data/windows-admin/win-app01' as Alice -> Validates 403 Forbidden.
    6. Summarizes evidence for Phase 2 screenshot and audit log.

.NOTES
    Lab: PAM Vault & Rotation Lab - Phase 2
#>

[CmdletBinding()]
param(
    [string]$VaultUrl = $(if ($env:VAULT_ADDR) { $env:VAULT_ADDR } else { 'http://127.0.0.1:8200' })
)

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [Phase 2] Vault Access Model & RBAC Verification Test   " -ForegroundColor Cyan
Write-Host " Target Vault: $VaultUrl" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

function Login-VaultUser {
    param([string]$Username, [string]$Password)
    $authBody = @{ password = $Password } | ConvertTo-Json
    try {
        $resp = Invoke-RestMethod -Method Post -Uri "$VaultUrl/v1/auth/userpass/login/$Username" `
                                  -Body $authBody -ContentType "application/json" -ErrorAction Stop
        return $resp.auth.client_token
    } catch {
        Write-Error "Failed to authenticate as $Username : $_"
        return $null
    }
}

# --- TEST 1: Bob (Unprivileged User) ---
Write-Host "`n>>> [TEST 1] Authenticating as Bob (Policy: default, no PAM access)..." -ForegroundColor Yellow
$bobToken = Login-VaultUser -Username "bob" -Password "BobStandardLab2026!"

if ($bobToken) {
    Write-Host "[+] Bob authenticated successfully. Acquired client token." -ForegroundColor Gray
    Write-Host "[*] Bob attempting to read: secret/data/service-accounts/svc_webapp" -ForegroundColor Yellow
    
    try {
        $headers = @{ "X-Vault-Token" = $bobToken }
        $data = Invoke-RestMethod -Method Get -Uri "$VaultUrl/v1/secret/data/service-accounts/svc_webapp" `
                                  -Headers $headers -ErrorAction Stop
        Write-Host "[FAIL] SECURITY ALERT: Bob was able to read service-account secrets!" -ForegroundColor Red
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode -eq 403) {
            Write-Host "[PASS] EXPECTED RESULT: HTTP 403 FORBIDDEN - Access Denied for user Bob." -ForegroundColor Green
            Write-Host "       Error details: $($_.Exception.Message)" -ForegroundColor Gray
        } else {
            Write-Host "[!] Unexpected status code: $statusCode" -ForegroundColor Red
        }
    }
}

# --- TEST 2: Alice (Operator Privileges on service-accounts safe) ---
Write-Host "`n>>> [TEST 2] Authenticating as Alice (Policy: pam-operator)..." -ForegroundColor Yellow
$aliceToken = Login-VaultUser -Username "alice" -Password "AliceSecureLab2026!"

if ($aliceToken) {
    Write-Host "[+] Alice authenticated successfully. Acquired client token." -ForegroundColor Gray
    Write-Host "[*] Alice attempting to read: secret/data/service-accounts/svc_webapp" -ForegroundColor Yellow
    
    try {
        $headers = @{ "X-Vault-Token" = $aliceToken }
        $data = Invoke-RestMethod -Method Get -Uri "$VaultUrl/v1/secret/data/service-accounts/svc_webapp" `
                                  -Headers $headers -ErrorAction Stop
        Write-Host "[PASS] SUCCESS: HTTP 200 OK - Alice retrieved secret successfully." -ForegroundColor Green
        Write-Host "       Account: $($data.data.data.username)" -ForegroundColor Gray
        Write-Host "       System:  $($data.data.data.system)" -ForegroundColor Gray
        Write-Host "       Owner:   $($data.data.data.owner)" -ForegroundColor Gray
    } catch {
        Write-Host "[FAIL] Alice was unable to retrieve service account: $_" -ForegroundColor Red
    }

    # --- TEST 3: Alice boundary test on windows-admin safe (Least Privilege) ---
    Write-Host "`n>>> [TEST 3] Boundary Check: Alice attempting to read secret/data/windows-admin/win-app01..." -ForegroundColor Yellow
    try {
        $headers = @{ "X-Vault-Token" = $aliceToken }
        $data = Invoke-RestMethod -Method Get -Uri "$VaultUrl/v1/secret/data/windows-admin/win-app01" `
                                  -Headers $headers -ErrorAction Stop
        Write-Host "[FAIL] SECURITY ALERT: Alice accessed windows-admin outside her authorized safe!" -ForegroundColor Red
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($statusCode -eq 403) {
            Write-Host "[PASS] BOUNDARY ENFORCED: HTTP 403 FORBIDDEN - Alice denied access to windows-admin safe." -ForegroundColor Green
        }
    }
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " [Phase 2] RBAC Verification Complete. Capture Screenshots!" -ForegroundColor Cyan
Write-Host " Check /var/log/vault_audit.log on VAULT01 for HMAC-hashed audit events." -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

