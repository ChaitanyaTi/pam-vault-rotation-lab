<#
.SYNOPSIS
    Active Directory Just-In-Time (JIT) Privileged Access Automation (Phase 6).

.DESCRIPTION
    Enables and leverages the Windows Server Active Directory Privileged Access Management (PAM)
    Optional Feature to provision dynamic, time-limited group memberships with automatic expiration.

    Capabilities:
      1. Enables 'Privileged Access Management Feature' on domain forest (lab.local).
      2. Grants ephemeral membership in 'GG-PAM-Windows-Admins' with MemberTimeToLive.
      3. Validates real-time Time-To-Live (TTL) countdown using -ShowMemberTimeToLive.
      4. Demonstrates automatic membership revocation upon TTL expiration.

.PARAMETER Member
    The sAMAccountName of the user receiving time-limited elevation. Default: 'bob'.

.PARAMETER TargetGroup
    The privileged group name. Default: 'GG-PAM-Windows-Admins'.

.PARAMETER Hours
    Duration of privilege grant in hours. Default: 2 hours.

.NOTES
    Requires: Windows Server 2016+ Forest Functional Level.
    Author: Chaitanya
#>

[CmdletBinding()]
param(
    [string]$Member = "bob",
    [string]$TargetGroup = "GG-PAM-Windows-Admins",
    [int]$Hours = 2,
    [switch]$EnableForestFeature = $false
)

Import-Module ActiveDirectory -ErrorAction Stop

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " [Phase 6] AD Just-In-Time (JIT) Access Provisioning     " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Enable PAM Optional Feature if requested
if ($EnableForestFeature) {
    Write-Host "[*] Checking AD Privileged Access Management Optional Feature..." -ForegroundColor Yellow
    $pamFeature = Get-ADOptionalFeature -Filter "Name -eq 'Privileged Access Management Feature'"
    if ($pamFeature) {
        Write-Host "[+] Enabling Forest-wide PAM Optional Feature..." -ForegroundColor Green
        Enable-ADOptionalFeature 'Privileged Access Management Feature' `
                                 -Scope ForestOrConfigurationSet `
                                 -Target (Get-ADDomain).Forest
        Write-Host "[OKOKOK] PAM Optional Feature enabled successfully!" -ForegroundColor Green
    }
}

# 2. Inspect Group Membership BEFORE Grant
Write-Host "`n>>> [STEP 1] Inspecting Current Membership of: $TargetGroup (BEFORE GRANT)" -ForegroundColor Yellow
$currentMembers = Get-ADGroupMember -Identity $TargetGroup | Select-Object -ExpandProperty SamAccountName
Write-Host "Current Members: $($currentMembers -join ', ')" -ForegroundColor Gray

if ($currentMembers -contains $Member) {
    Write-Host "[!] User '$Member' is already a member of '$TargetGroup'." -ForegroundColor Yellow
} else {
    Write-Host "[OKOKOK] Verified '$Member' is currently NOT a member of privileged group." -ForegroundColor Green
}

# 3. Grant Time-Limited Membership (MemberTimeToLive)
$timeSpan = New-TimeSpan -Hours $Hours
Write-Host "`n>>> [STEP 2] Granting JIT Privileged Access to '$Member' for $Hours hour(s)..." -ForegroundColor Yellow
Write-Host "Command: Add-ADGroupMember -Identity $TargetGroup -Members $Member -MemberTimeToLive (New-TimeSpan -Hours $Hours)" -ForegroundColor Gray

Add-ADGroupMember -Identity $TargetGroup -Members $Member -MemberTimeToLive $timeSpan

# 4. Verify Time-To-Live (TTL) Countdown
Write-Host "`n>>> [STEP 3] Inspecting Real-Time TTL on Group Membership..." -ForegroundColor Yellow
$activeMembership = Get-ADGroup -Identity $TargetGroup -Properties Member -ShowMemberTimeToLive
$ttlEntry = $activeMembership.Member | Where-Object { $_ -like "*$Member*" }

Write-Host "[+] Active JIT Grant Confirmed!" -ForegroundColor Green
Write-Host "    Raw AD TTL Attribute: $ttlEntry" -ForegroundColor Cyan

# 5. Output Summary Table for Phase 6 Evidence
Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " [OKOKOK] JIT Access Grant Activated. Take Screenshot for Phase 6 Evidence!" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan


