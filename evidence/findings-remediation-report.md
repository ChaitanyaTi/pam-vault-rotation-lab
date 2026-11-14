# Compliance Audit Findings & Remediation Action Plan (Phase 7 Evidence)

**Audit Engagement**: Q4 Privileged Access Management Recertification  
**Target Domain**: `lab.local` / HashiCorp Vault Safes  
**Auditor**: @chaitanya / Identity Security Operations  
**Date**: 14 November 2026  

---

## 1. Executive Summary

During the scheduled privileged access review executed via [`scripts/privileged-access-review.ps1`](file:///scripts/privileged-access-review.ps1), two high/medium risk security non-compliances were identified in the environment. This document outlines the findings, empirical evidence, risk analysis, and immediate remediation steps.

---

## 2. Detailed Findings

### Finding 1: Dormant Privileged Administrator Account (`adm_old`)

- **Finding ID**: `FINDING-AD-001`
- **Severity**: **HIGH** (CVSS: 7.8)
- **ISO 27001:2022 Control**: `A.8.2 (Privileged access rights)` & `A.5.18 (Access rights)`
- **Target Account**: `adm_old@lab.local`
- **Target Group**: `CN=GG-PAM-Windows-Admins,OU=PAM-Groups,DC=lab,DC=local`
- **Empirical Evidence**:
  ```powershell
  SamAccountName : adm_old
  Enabled        : True
  LastLogonDate  : 2026-05-10T14:22:00Z (Inactive for 188 days)
  PasswordLastSet: 2026-05-10T14:22:00Z
  MemberOf       : GG-PAM-Windows-Admins, Administrators
  ```
- **Risk Assessment**:
  Dormant accounts retaining standing administrative rights represent a prime target for credential stuffing, pass-the-hash attacks, and lateral movement. Because the user is inactive, malicious use of this account is less likely to be noticed by the former owner.
- **Root Cause**:
  Lack of automated deprovisioning during employee offboarding / role-change workflow.
- **Remediation Action Plan**:
  1. Immediately disable account: `Disable-ADAccount -Identity adm_old`.
  2. Remove from all privileged groups: `Remove-ADGroupMember -Identity GG-PAM-Windows-Admins -Members adm_old -Confirm:$false`.
  3. Archive account and flag for deletion in 30 days.

---

### Finding 2: Unrotated Privileged Service Account (`svc_backup`)

- **Finding ID**: `FINDING-VAULT-002`
- **Severity**: **MEDIUM** (CVSS: 5.3)
- **ISO 27001:2022 Control**: `A.8.2 (Privileged access rights)` & `A.8.24 (Use of cryptography)`
- **Target Account**: `secret/data/service-accounts/svc_backup`
- **Target Host**: `DC01.lab.local`
- **Empirical Evidence**:
  ```json
  {
    "account": "svc_backup",
    "safe": "secret/service-accounts",
    "created_time": "2026-09-01T08:00:00Z",
    "last_rotated": "2026-09-01T08:00:00Z",
    "age_days": 74,
    "rotation_policy_max_days": 30
  }
  ```
- **Risk Assessment**:
  Passwords exceeding the mandatory 30-day rotation threshold increase the exposure window in the event of memory dumps, network sniffing, or unauthorized credential caching.
- **Root Cause**:
  Account was manually provisioned in Active Directory but not registered with the automated PowerShell CPM rotation Task Scheduler.
- **Remediation Action Plan**:
  1. Register `svc_backup` into the automated rotation script:
     ```powershell
     .\scripts\rotate-ad-service-account.ps1 -Account svc_backup
     ```
  2. Add scheduled task trigger in `scripts/schedule-rotations.ps1`.
  3. Update [`docs/account-register.csv`](file:///docs/account-register.csv) with current rotation timestamp.

---

## 3. Auditor Sign-Off

| Role | Name | Signature / Status | Date |
| :--- | :--- | :--- | :--- |
| **Lead PAM Engineer** | Chaitanya | *Signed (Remediated)* | 2026-11-14 |
| **Information Security Officer** | ISO Review Board | *Approved* | 2026-11-14 |
