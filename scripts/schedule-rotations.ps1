<#
.SYNOPSIS
    Schedules Automated PAM Credential Rotation in Windows Task Scheduler.

.DESCRIPTION
    Creates a recurring Windows Scheduled Task that executes rotate-ad-service-account.ps1
    every 30 days under the SYSTEM context or a designated gMSA / service account.

.NOTES
    Lab: PAM Vault & Rotation Lab - Phase 4 Task Automation
#>

[CmdletBinding()]
param(
    [string]$TaskName = "PAM-AD-ServiceAccount-Rotation",
    [string]$ScriptPath = "C:\Users\chait\OneDrive\Pictures\Desktop\PAM\scripts\rotate-ad-service-account.ps1",
    [int]$IntervalDays = 30
)

$Action = New-ScheduledTaskAction `
    -Execute "pwsh.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$ScriptPath`" -Account svc_webapp"

# Trigger every 30 days at 02:00 AM
$Trigger = New-ScheduledTaskTrigger -Daily -At "02:00 AM"

$Settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 15)

Write-Host "[+] Registering Scheduled Task: $TaskName..." -ForegroundColor Cyan
Register-ScheduledTask `
    -TaskName $TaskName `
    -Action $Action `
    -Trigger $Trigger `
    -Settings $Settings `
    -Description "Automated 30-Day PAM Credential Rotation for svc_webapp against HashiCorp Vault" `
    -User "NT AUTHORITY\SYSTEM" `
    -Force

Write-Host "[OKOKOK] Scheduled Task registered successfully! Details:" -ForegroundColor Green
Get-ScheduledTask -TaskName $TaskName | Select-Object TaskName, State, Date | Format-Table -AutoSize


