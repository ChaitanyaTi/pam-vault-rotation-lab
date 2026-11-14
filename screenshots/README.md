# Lab Screenshot Inventory & Evidence Guide

As specified in the build guide: *"Take a screenshot at the end of every step. Interviewers care more about those than the happy path."*

Store all captured screenshots in this directory using the standardized naming conventions below:

---

## Required Screenshots by Phase

| Phase | Recommended Filename | What to Capture in Screenshot | Acceptance / Validation Criteria |
| :---: | :--- | :--- | :--- |
| **1** | `phase1-network-diagram.png` | Network topology diagram showing DC01, WIN-APP01, LINUX01, VAULT01 | Shows host-only subnet (192.168.56.0/24) and static IPs |
| **1** | `phase1-ad-users-groups.png` | Active Directory Users & Computers (ADUC) on DC01 | OUs (`Admins`, `Service-Accounts`, `PAM-Groups`), users (`adm_alice`, `svc_webapp`, `adm_old`), and groups |
| **2** | `phase2-vault-policies.png` | Vault UI / CLI showing loaded policies | `pam-admin`, `pam-operator`, `pam-auditor` visible in `vault policy list` |
| **2** | `phase2-bob-denied-test.png` | Terminal running test script as user `bob` | Shows HTTP 403 Forbidden reading `secret/data/service-accounts/*` |
| **2** | `phase2-alice-allowed-test.png`| Terminal running test script as user `alice` | Shows HTTP 200 OK reading `secret/data/service-accounts/*` |
| **2** | `phase2-audit-log.png` | Vault audit log tail (`/var/log/vault_audit.log`) | HMAC-hashed entries for both Bob's denied and Alice's allowed requests |
| **3** | `phase3-vault-safes.png` | Vault Web UI displaying the 4 safes | `windows-admin`, `linux-root`, `service-accounts`, `aws` |
| **3** | `phase3-app-code-diff.png` | Side-by-side IDE comparison or terminal run | Hardcoded password in `before_hardcoded_app.py` vs API fetch in `after_vault_app.py` |
| **4** | `phase4-rotation-success.png`| PowerShell console running `rotate-ad-service-account.ps1` | Shows 4 stages passing, new version in Vault, and `OK` written to `rotation.log` |
| **4** | `phase4-rotation-failures.png`| Console output from 3 simulated failures | Shows failure stages: token expired, complexity error, vault down |
| **5** | `phase5-jumpserver-session-replay.png` | JumpServer web replay screen | Asciinema/video replay showing terminal commands executed by `alice` on `LINUX01` |
| **5** | `phase5-command-filter-blocked.png` | Terminal error in JumpServer session | Shows command filter blocking `rm -rf` with policy warning message |
| **6** | `phase6-servicenow-catalog-request.png`| ServiceNow PDI Service Portal | Submitted Privileged Access Elevation Request with duration and justification |
| **6** | `phase6-jit-group-ttl.png` | PowerShell console on DC01 | Shows `Get-ADGroup -ShowMemberTimeToLive` with real-time TTL countdown on `bob` |
| **6** | `phase6-servicenow-incident.png` | ServiceNow incident list / form | Auto-generated Incident ticket (`INC0010481`) from rotation failure catch block |
| **7** | `phase7-audit-html-report.png` | Web browser rendering `privileged-access-report.html` | Highlights flagged findings: dormant `adm_old` and unrotated service account |
| **7** | `phase7-security-events.png` | Windows Event Viewer on DC01 | Filtered view of Event IDs `4728` (member added) and `4724` (password reset) |
| **8** | `phase8-aws-cloudtrail.png` | AWS CloudTrail Event History console | Shows `CreateAccessKey`, `UpdateAccessKey`, and S3 `GetObject` events |
| **8** | `phase8-entra-roles.png` | Microsoft Entra Admin Center | Role assignments blade showing test user assigned `User Administrator` |

