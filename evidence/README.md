# Privileged Access Management (PAM) Lab Evidence Pack

This directory contains the operational and compliance artifacts generated during the 8 lab phases.

---

## Artifact Manifest

| Artifact File | Lab Phase | Description |
| :--- | :--- | :--- |
| [`sample-rotation.log`](file:///evidence/sample-rotation.log) | Phase 4 & 6 | Rotation audit trail showing successful 4-stage rotations, failure catches, and automated ServiceNow incident numbers (`INC0010481`). |
| [`sample-vault_audit.log`](file:///evidence/sample-vault_audit.log) | Phase 2 | Vault SHA-256 HMAC-hashed file audit device entries proving Bob was denied (HTTP 403) and Alice was permitted (HTTP 200). |
| [`privileged-access-report.csv`](file:///evidence/privileged-access-report.csv) | Phase 7 | Automated CSV export of privileged access review scanner flagging dormant admin `adm_old` and stale unrotated accounts. |
| [`findings-remediation-report.md`](file:///evidence/findings-remediation-report.md) | Phase 7 | Comprehensive audit findings report with CVSS ratings, ISO 27001 control mapping, and remediation actions. |

---

## Verification Commands

To regenerate fresh evidence on your live lab systems:
```powershell
# 1. Run live rotation test:
$env:VAULT_TOKEN = "s.YourVaultToken"
.\scripts\rotate-ad-service-account.ps1 -Account svc_webapp

# 2. Run automated ISO 27001 compliance scanner:
.\scripts\privileged-access-review.ps1 -Domain lab.local
```
