<#
.SYNOPSIS
    Automates Phase 1 of the PAM Lab: Provisioning Active Directory OUs, Users, and Groups.

.DESCRIPTION
    Executes on Domain Controller (DC01) in domain 'lab.local'.
    Creates:
      - Organizational Units (OUs): Admins, Service-Accounts, PAM-Groups
      - Service Accounts: svc_webapp, svc_backup
      - Privileged Admins: adm_alice, adm_old (stale user for Phase 7 audit)
      - Standard Users: bob
      - Security Groups: GG-PAM-Windows-Admins, GG-PAM-Requestors
      - Group Memberships: adm_alice -> GG-PAM-Windows-Admins

.NOTES
    Author: Chaitanya
    Lab: PAM Vault & Rotation Lab
    Target OS: Windows Server 2019/2022 (Domain Controller)
#>

[CmdletBinding()]
param(
    [string]$DomainDN = "DC=lab,DC=local",
    [string]$InitialPassword = "P@ssword123!SecureLab"
)

Import-Module ActiveDirectory -ErrorAction Stop

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [Phase 1] PAM Lab Active Directory Provisioning Starting " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$secPassword = ConvertTo-SecureString $InitialPassword -AsPlainText -Force

# 1. Create Organizational Units (OUs)
$OUs = @(
    @{ Name = "Admins";           Path = $DomainDN },
    @{ Name = "Service-Accounts"; Path = $DomainDN },
    @{ Name = "PAM-Groups";       Path = $DomainDN }
)

foreach ($ou in $OUs) {
    $targetPath = $ou.Path
    $ouName = $ou.Name
    $ouDN = "OU=$ouName,$targetPath"
    
    if (-not (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$ouDN'" -ErrorAction SilentlyContinue)) {
        Write-Host "[+] Creating OU: $ouDN" -ForegroundColor Green
        New-ADOrganizationalUnit -Name $ouName -Path $targetPath -ProtectedFromAccidentalDeletion $false
    } else {
        Write-Host "[-] OU already exists: $ouDN" -ForegroundColor Yellow
    }
}

# 2. Create Security Groups in OU=PAM-Groups
$Groups = @(
    @{ Name = "GG-PAM-Windows-Admins"; Description = "Privileged administrators with tier-1/tier-2 access" },
    @{ Name = "GG-PAM-Requestors";     Description = "Standard users eligible to request JIT privileged access" }
)

foreach ($grp in $Groups) {
    $grpDN = "CN=$($grp.Name),OU=PAM-Groups,$DomainDN"
    if (-not (Get-ADGroup -Filter "SamAccountName -eq '$($grp.Name)'" -ErrorAction SilentlyContinue)) {
        Write-Host "[+] Creating Security Group: $($grp.Name)" -ForegroundColor Green
        New-ADGroup -Name $grp.Name `
                    -GroupScope Global `
                    -GroupCategory Security `
                    -Path "OU=PAM-Groups,$DomainDN" `
                    -Description $grp.Description
    } else {
        Write-Host "[-] Group already exists: $($grp.Name)" -ForegroundColor Yellow
    }
}

# 3. Create Users and Service Accounts
$Users = @(
    @{
        SamAccountName = "svc_webapp";
        UserPrincipalName = "svc_webapp@lab.local";
        DisplayName = "Service Account - Web App";
        Path = "OU=Service-Accounts,$DomainDN";
        AccountType = "ServiceAccount";
        Description = "Web Application Service Account for Vault Secret Management"
    },
    @{
        SamAccountName = "svc_backup";
        UserPrincipalName = "svc_backup@lab.local";
        DisplayName = "Service Account - Backup";
        Path = "OU=Service-Accounts,$DomainDN";
        AccountType = "ServiceAccount";
        Description = "Backup Engine Service Account"
    },
    @{
        SamAccountName = "adm_alice";
        UserPrincipalName = "adm_alice@lab.local";
        DisplayName = "Alice Administrator (Privileged)";
        Path = "OU=Admins,$DomainDN";
        AccountType = "PrivilegedAdmin";
        Description = "Privileged Administrator Account for Alice"
    },
    @{
        SamAccountName = "bob";
        UserPrincipalName = "bob@lab.local";
        DisplayName = "Bob StandardUser";
        Path = "CN=Users,$DomainDN";
        AccountType = "StandardUser";
        Description = "Standard end-user requesting JIT elevation"
    },
    @{
        SamAccountName = "adm_old";
        UserPrincipalName = "adm_old@lab.local";
        DisplayName = "Stale Admin (Audit Finding Plant)";
        Path = "OU=Admins,$DomainDN";
        AccountType = "StaleAdmin";
        Description = "Stale Privileged Account intended for Phase 7 Audit Detection"
    }
)

foreach ($u in $Users) {
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$($u.SamAccountName)'" -ErrorAction SilentlyContinue)) {
        Write-Host "[+] Creating User: $($u.SamAccountName) in $($u.Path)" -ForegroundColor Green
        New-ADUser -SamAccountName $u.SamAccountName `
                   -UserPrincipalName $u.UserPrincipalName `
                   -Name $u.SamAccountName `
                   -DisplayName $u.DisplayName `
                   -Path $u.Path `
                   -AccountPassword $secPassword `
                   -Enabled $true `
                   -PasswordNeverExpires ($u.AccountType -eq "ServiceAccount") `
                   -Description $u.Description
    } else {
        Write-Host "[-] User already exists: $($u.SamAccountName)" -ForegroundColor Yellow
    }
}

# 4. Assign adm_alice to GG-PAM-Windows-Admins and bob to GG-PAM-Requestors
Write-Host "[+] Assigning adm_alice to GG-PAM-Windows-Admins..." -ForegroundColor Green
Add-ADGroupMember -Identity "GG-PAM-Windows-Admins" -Members "adm_alice" -ErrorAction SilentlyContinue

Write-Host "[+] Assigning bob to GG-PAM-Requestors..." -ForegroundColor Green
Add-ADGroupMember -Identity "GG-PAM-Requestors" -Members "bob" -ErrorAction SilentlyContinue

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [Phase 1] AD Provisioning Complete! Summary:" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Get-ADGroupMember -Identity "GG-PAM-Windows-Admins" | Select-Object Name, SamAccountName, DistinguishedName | Format-Table -AutoSize
Get-ADUser -Filter * -SearchBase "OU=Service-Accounts,$DomainDN" | Select-Object SamAccountName, Enabled, PasswordNeverExpires | Format-Table -AutoSize
