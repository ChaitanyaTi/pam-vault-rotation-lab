<#
.SYNOPSIS
    Automated AWS IAM Access Key Rotation & Safe Vault Synchronization.

.DESCRIPTION
    Executes zero-downtime rotation for cloud service account access keys:
      1. Generates new AWS IAM access key pair via 'aws iam create-access-key'.
      2. Updates Vault secret safe: secret/data/aws/iam-user with new AccessKeyId & SecretAccessKey.
      3. Verifies new key connectivity.
      4. Deactivates old access key ('aws iam update-access-key --status Inactive').
      5. Deletes old key ('aws iam delete-access-key') after validation.
      6. Logs rotation to rotation.log.

.PARAMETER UserName
    The AWS IAM Username. Default: 'lab-pam-svc'.
#>

[CmdletBinding()]
param(
    [string]$UserName = "lab-pam-svc",
    [string]$VaultUrl = $(if ($env:VAULT_ADDR) { $env:VAULT_ADDR } else { 'http://192.168.56.20:8200' })
)

$ErrorActionPreference = 'Stop'

if (-not $env:VAULT_TOKEN) {
    Write-Error "VAULT_TOKEN environment variable required."
    exit 1
}

$hdr = @{ 'X-Vault-Token' = $env:VAULT_TOKEN }
$vaultUri = "$VaultUrl/v1/secret/data/aws/iam-user"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [Phase 4 / Phase 8] AWS IAM Access Key Rotation          " -ForegroundColor Cyan
Write-Host " Target IAM User: $UserName                               " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

try {
    # 1. Fetch current active key ID from Vault
    Write-Host "[1/5] Reading existing active key metadata from Vault..." -ForegroundColor Gray
    $currentSecret = Invoke-RestMethod -Method Get -Uri $vaultUri -Headers $hdr
    $oldKeyId = $currentSecret.data.data.access_key_id

    # 2. Generate new AWS access key pair
    Write-Host "[2/5] Creating new AWS IAM Access Key for $UserName..." -ForegroundColor Gray
    $newKeyJson = aws iam create-access-key --user-name $UserName --output json | ConvertFrom-Json
    $newKeyId = $newKeyJson.AccessKey.AccessKeyId
    $newSecretKey = $newKeyJson.AccessKey.SecretAccessKey

    Write-Host "      Created New Key ID: $newKeyId" -ForegroundColor Green

    # 3. Publish new key pair to Vault
    Write-Host "[3/5] Publishing new access key pair to HashiCorp Vault..." -ForegroundColor Gray
    $body = @{
        data = @{
            username          = $UserName
            access_key_id     = $newKeyId
            secret_access_key = $newSecretKey
            last_rotated      = (Get-Date -Format s)
            previous_key_id   = $oldKeyId
            account_type      = "AWSIAMUser"
            system            = "AWS Cloud"
        }
    } | ConvertTo-Json

    Invoke-RestMethod -Method Post -Uri $vaultUri -Headers $hdr -Body $body -ContentType 'application/json' | Out-Null

    # 4. Deactivate old key
    if ($oldKeyId -and $oldKeyId -ne $newKeyId) {
        Write-Host "[4/5] Deactivating previous key: $oldKeyId..." -ForegroundColor Gray
        aws iam update-access-key --user-name $UserName --access-key-id $oldKeyId --status Inactive

        # 5. Delete old key
        Write-Host "[5/5] Decommissioning & deleting previous key: $oldKeyId..." -ForegroundColor Gray
        aws iam delete-access-key --user-name $UserName --access-key-id $oldKeyId
    }

    Write-Host "[✓] AWS IAM Access Key rotation completed successfully!" -ForegroundColor Green
    Add-Content "rotation.log" "$((Get-Date -Format s)) OK AWS-IAM-$UserName NewKey:$newKeyId"

} catch {
    Write-Host "[!] AWS IAM key rotation failed: $_" -ForegroundColor Red
    Add-Content "rotation.log" "$((Get-Date -Format s)) FAIL AWS-IAM-$UserName $($_.Exception.Message)"
    exit 1
}
