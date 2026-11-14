<#
.SYNOPSIS
    Automated Credential Rotation for Windows Local Administrator Account on WIN-APP01.

.DESCRIPTION
    Phase 4: Rotates local Administrator accounts using PowerShell Remoting (WinRM).
    Workflow:
      1. Stage new password in secret/data/windows-admin/win-app01_pending
      2. Remotely reset local user password using Set-LocalUser or [ADSI]
      3. Verify local authentication
      4. Publish active credentials to Vault safe: secret/data/windows-admin/win-app01

.PARAMETER TargetHost
    Target server hostname or IP address. Default: 'WIN-APP01'

.PARAMETER LocalAdminUser
    Target local account. Default: 'Administrator'
#>

[CmdletBinding()]
param(
    [string]$TargetHost = "WIN-APP01",
    [string]$LocalAdminUser = "Administrator",
    [string]$VaultUrl = $(if ($env:VAULT_ADDR) { $env:VAULT_ADDR } else { 'http://192.168.56.20:8200' })
)

$ErrorActionPreference = 'Stop'

if (-not $env:VAULT_TOKEN) {
    Write-Error "CRITICAL: VAULT_TOKEN environment variable is missing."
    exit 1
}

$hdr  = @{ 'X-Vault-Token' = $env:VAULT_TOKEN }
$base = "$VaultUrl/v1/secret/data/windows-admin/"

function New-SecurePassword {
    $c = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%'.ToCharArray()
    -join (1..22 | ForEach-Object { $c[[System.Security.Cryptography.RandomNumberGenerator]::GetInt32($c.Length)] })
}

function Save-Vault($name, $data) {
    $body = @{ data = $data } | ConvertTo-Json
    Invoke-RestMethod -Method Post -Uri ($base + $name) -Headers $hdr -Body $body -ContentType 'application/json' | Out-Null
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [Phase 4] Rotating Local Administrator on $TargetHost    " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

try {
    $newPwd = New-SecurePassword
    Write-Host "[1/4] Staging pending local admin password in Vault..." -ForegroundColor Gray
    Save-Vault "$($TargetHost.ToLower())_pending" @{
        username   = $LocalAdminUser
        password   = $newPwd
        system     = $TargetHost
        status     = "PENDING"
        staged_at  = (Get-Date -Format s)
    }

    Write-Host "[2/4] Executing remote password reset on $TargetHost via WinRM..." -ForegroundColor Gray
    Invoke-Command -ComputerName $TargetHost -ScriptBlock {
        param($User, $Pwd)
        $sec = ConvertTo-SecureString $Pwd -AsPlainText -Force
        Set-LocalUser -Name $User -Password $sec
    } -ArgumentList $LocalAdminUser, $newPwd

    Write-Host "[3/4] Verifying local administrator credentials..." -ForegroundColor Gray
    # Verification using System.DirectoryServices.AccountManagement with Machine context
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Machine', $TargetHost)
    if (-not $ctx.ValidateCredentials($LocalAdminUser, $newPwd)) {
        throw "Failed to validate credentials on $TargetHost for user $LocalAdminUser"
    }

    Write-Host "[4/4] Publishing verified password to Vault..." -ForegroundColor Gray
    Save-Vault ($TargetHost.ToLower()) @{
        username     = $LocalAdminUser
        password     = $newPwd
        system       = $TargetHost
        account_type = "WindowsLocalAdmin"
        last_rotated = (Get-Date -Format s)
    }

    Write-Host "[✓] Local Administrator password on $TargetHost rotated successfully!" -ForegroundColor Green
    Add-Content "rotation.log" "$((Get-Date -Format s)) OK LocalAdmin-$TargetHost"

} catch {
    Write-Host "[!] Local admin rotation failed: $_" -ForegroundColor Red
    Add-Content "rotation.log" "$((Get-Date -Format s)) FAIL LocalAdmin-$TargetHost $($_.Exception.Message)"
    exit 1
}
