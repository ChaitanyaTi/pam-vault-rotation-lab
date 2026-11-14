# Enterprise Privileged Access Management (PAM) Lab: Vaulting, Automated Rotation, Session Monitoring & Governance

An end-to-end, production-grade Privileged Access Management (PAM) laboratory simulating enterprise zero-standing-privilege architecture across Active Directory, Linux, HashiCorp Vault, JumpServer, ServiceNow, and AWS Cloud.
Engineered with automated 4-stage credential rotation (CyberArk CPM equivalent), least-privilege RBAC policies, in-line privileged session recording with command filtering (CyberArk PSM equivalent), ServiceNow Just-In-Time (JIT) access requests, and ISO/IEC 27001:2022 compliance recertification.
Built by [@chaitanya](https://github.com/chaitanya) to validate and demonstrate operational mastery over privileged identity security, failure-resilient credential lifecycles, and audit defense.

---

## 1. Enterprise Architecture & Network Topology

```
                                  [ Management & User Tier ]
                                              |
                   +--------------------------+--------------------------+
                   |                                                     |
         (HTTPS Web Portal / REST API)                               (HTTPS Web UI)
                   v                                                     v
      +-------------------------+                           +-------------------------+
      |      ServiceNow PDI     |                           |    JumpServer Gateway   |
      | - JIT Catalog Requests  |                           |  (CyberArk PSM Proxy)   |
      | - Flow Designer Approval|                           | - Session Keystrokes    |
      | - Automated Incidents   |                           | - Asciinema Video Log   |
      +-------------------------+                           | - Command Filter (rm-rf)|
                   |                                        +-------------------------+
                   | REST API Trigger                                    |
                   v                                            +--------+--------+
      +-----------------------------------------+               |                 |
      |      VAULT01: HashiCorp Vault Core      |          (RDP 3389)         (SSH 22)
      |         (CyberArk PVWA / Vault)         |               |                 |
      | - Storage: Encrypted KV-v2 Safes        |               v                 v
      | - Policies: pam-admin, pam-operator     |         +-----------+     +-----------+
      | - Audit: HMAC /var/log/vault_audit.log  |         | WIN-APP01 |     |  LINUX01  |
      +-----------------------------------------+         | (Windows) |     |  (Ubuntu) |
                   ^                                      +-----------+     +-----------+
                   |                                            |                 |
                   | 4-Stage Secure REST API                    +--------+--------+
                   | (Pending -> Commit -> Verify -> Publish)            |
                   |                                                     |
      +-----------------------------------------+                        |
      |    DC01: Domain Controller (lab.local)   |<----------------------+
      |       Active Directory & CPM Engine     |    Domain Authentication /
      | - Windows Server 2019/2022 AD DS        |    Kerberos / MemberTimeToLive
      | - PowerShell 7 Rotation Engine (CPM)    |
      | - AD PAM Feature (JIT MemberTimeToLive) |
      +-----------------------------------------+
```

### Virtual Machine & Host Specification (Host-Only Subnet: `192.168.56.0/24`)

| Hostname | Role / Operating System | IP Address | Deployed Services & Responsibilities |
| :--- | :--- | :--- | :--- |
| **DC01** | Windows Server 2022 (Domain Controller) | `192.168.56.10` | AD DS (`lab.local`), PAM Optional Feature, PowerShell 7 Rotation Engine (CPM), Task Scheduler |
| **WIN-APP01** | Windows Server 2022 (Domain Member) | `192.168.56.11` | Application Target, Domain-joined, Local Administrator rotation target, WinRM |
| **LINUX01** | Ubuntu Server 22.04 LTS | `192.168.56.12` | Linux Target, OpenSSH, `appadmin` user with sudo privileges, command filtering target |
| **VAULT01** | Ubuntu Server 22.04 LTS / Docker Host | `192.168.56.20` | HashiCorp Vault (KV-v2, RBAC, File Auditing), JumpServer Session Recording Gateway |
| **Cloud / SaaS**| AWS Free Tier & Microsoft Entra ID | Cloud | AWS IAM user access key rotation, S3 least-privilege policy, Entra ID PIM design |
| **ITSM** | ServiceNow Personal Developer Instance | Cloud | Privileged Access Request Catalog, Flow Designer approval, Automated Incident API |

---

## 2. CyberArk Enterprise Terminology Mapping

This laboratory implements industry-standard enterprise PAM capabilities. For engineers, interviewers, and recruiters evaluating CyberArk competency, the components map directly:

| CyberArk Enterprise Component | Lab Open-Source / Native Implementation | Architectural Function |
| :--- | :--- | :--- |
| **CyberArk Safes** | **HashiCorp Vault KV-v2 Secret Paths** (`secret/windows-admin/`, `secret/service-accounts/`) | Encrypted, segregated logical storage boundaries with granular ACL access controls. |
| **Central Policy Manager (CPM)** | **PowerShell 7 Rotation Engine** ([`rotate-ad-service-account.ps1`](file:///scripts/rotate-ad-service-account.ps1)) | Automated daemon responsible for generating, changing, verifying, and publishing credentials. |
| **Privileged Session Manager (PSM)**| **JumpServer Session Recording Gateway** ([`docs/jumpserver-setup-guide.md`](file:///docs/jumpserver-setup-guide.md)) | Proxies RDP/SSH sessions, injects credentials without user exposure, records video, and filters risky commands. |
| **Password Vault Web Access (PVWA)**| **HashiCorp Vault Web UI & API** (`http://192.168.56.20:8200/ui`) | Administrative interface and REST API for policy administration, credential check-out, and safe auditing. |
| **Application Access Manager (AAM)**| **Vault AppRole & Secret Engine** ([`apps/approle_vault_app.py`](file:///apps/approle_vault_app.py)) | Machine-to-machine authentication eliminating hardcoded secrets in source code and configs. |
| **Privileged Threat Analytics (PTA)**| **PowerShell Compliance Scanner** ([`privileged-access-review.ps1`](file:///scripts/privileged-access-review.ps1)) | Scans security event logs (4728, 4724) and detects dormant admin accounts (`adm_old`). |

---

## 3. The 8 Lab Implementation Phases

```mermaid
flowchart LR
    P1[Phase 1: Environment] --> P2[Phase 2: Vault & RBAC]
    P2 --> P3[Phase 3: Onboarding]
    P3 --> P4[Phase 4: Rotation Engine]
    P4 --> P5[Phase 5: Session Monitoring]
    P5 --> P6[Phase 6: ServiceNow & JIT]
    P6 --> P7[Phase 7: Audit & ISO 27001]
    P7 --> P8[Phase 8: Cloud IAM & Entra]
```

---

### Phase 1: Environment & Directory Foundation (Days 1–3)
- **Objective**: Establish the host-only infrastructure, Active Directory hierarchy, and target endpoints.
- **Implementation**:
  - Automated deployment on DC01 using [`scripts/setup-ad-environment.ps1`](file:///scripts/setup-ad-environment.ps1).
  - Created Organizational Units: `OU=Admins`, `OU=Service-Accounts`, `OU=PAM-Groups`.
  - Provisioned identities: Service accounts (`svc_webapp`, `svc_backup`), Privileged Admin (`adm_alice`), Normal User (`bob`), and Stale Admin plant (`adm_old` for Phase 7 audit).
  - Joined `WIN-APP01` to `lab.local`; deployed `appadmin` with sudo permissions on `LINUX01` via [`scripts/setup-linux-target.sh`](file:///scripts/setup-linux-target.sh).
- **Evidence**:
  - Screenshot: [`screenshots/phase1-network-diagram.png`](file:///screenshots/README.md)
  - Screenshot: [`screenshots/phase1-ad-users-groups.png`](file:///screenshots/README.md)

---

### Phase 2: Vault Architecture & Access Model (Days 3–6)
- **Objective**: Deploy HashiCorp Vault, enforce least-privilege Role-Based Access Control (RBAC), and enable tamper-evident auditing.
- **Implementation**:
  - Configured Vault server with KV-v2 secrets engine enabled at `secret/`.
  - Enabled file audit device to `/var/log/vault_audit.log` logging SHA-256 HMAC-hashed requests.
  - Authored fine-grained HCL access control policies:
    - [`pam-admin.hcl`](file:///vault/policies/pam-admin.hcl): Full administrative access across all safes.
    - [`pam-operator.hcl`](file:///vault/policies/pam-operator.hcl): Scoped read/list access strictly to `secret/data/service-accounts/*`; explicitly denies Windows, Linux, and AWS safes.
    - [`pam-auditor.hcl`](file:///vault/policies/pam-auditor.hcl): Read metadata only; strictly denies all secret values (zero plain-text credential access).
  - Provisioned userpass authentication: `alice` bound to `pam-operator`, `bob` bound to unprivileged `default`.
  - Executed automated RBAC validation via [`scripts/test-vault-rbac.ps1`](file:///scripts/test-vault-rbac.ps1).
- **Validation**:
  - User `bob` attempting to read `secret/data/service-accounts/svc_webapp` -> **HTTP 403 Forbidden** (Access Denied).
  - User `alice` reading `secret/data/service-accounts/svc_webapp` -> **HTTP 200 OK** (Allowed).
- **Evidence**:
  - Audit log entries: [`evidence/sample-vault_audit.log`](file:///evidence/sample-vault_audit.log)
  - Screenshot: [`screenshots/phase2-bob-denied-test.png`](file:///screenshots/README.md)
  - Screenshot: [`screenshots/phase2-alice-allowed-test.png`](file:///screenshots/README.md)

---

### Phase 3: Account & Application Onboarding (Days 6–8)
- **Objective**: Standardize onboarding governance and eliminate hardcoded credentials in consumer applications.
- **Implementation**:
  - Formulated formal standard operating procedure: [`docs/onboarding-checklist.md`](file:///docs/onboarding-checklist.md).
  - Onboarded 4 multi-platform privileged credentials into designated Vault safes:
    1. Local Administrator on `WIN-APP01` (`secret/windows-admin/win-app01`)
    2. Local sudo user `appadmin` on `LINUX01` (`secret/linux-root/linux01`)
    3. Active Directory service account `svc_webapp` (`secret/service-accounts/svc_webapp`)
    4. AWS IAM service user `lab-pam-svc` (`secret/aws/iam-user`)
  - Cataloged metadata in privileged inventory register: [`docs/account-register.csv`](file:///docs/account-register.csv).
  - **Application Transformation**:
    - *Before*: [`apps/before_hardcoded_app.py`](file:///apps/before_hardcoded_app.py) demonstrating hardcoded plaintext credentials in source code.
    - *After*: [`apps/after_vault_app.py`](file:///apps/after_vault_app.py) retrieving credentials dynamically at runtime via Vault REST API (`X-Vault-Token`).
    - *Stretch*: [`apps/approle_vault_app.py`](file:///apps/approle_vault_app.py) implementing machine identity using Vault AppRole (`role_id` and `secret_id`).
- **Evidence**:
  - Account inventory: [`docs/account-register.csv`](file:///docs/account-register.csv)
  - Code diff & execution screenshots: [`screenshots/phase3-app-code-diff.png`](file:///screenshots/README.md)

---

### Phase 4: Failure-Resilient Credential Rotation with PowerShell (Days 8–11)
- **Objective**: Build a robust, transactional credential rotation engine (CPM) preventing accidental lockouts.
- **Implementation**:
  - Developed [`scripts/rotate-ad-service-account.ps1`](file:///scripts/rotate-ad-service-account.ps1) with a strict 4-stage anti-lockout lifecycle:
    1. **Stage 1 (Stage Pending)**: Generate 22-character cryptographically secure password and stage in Vault as `svc_webapp_pending`.
    2. **Stage 2 (Reset Target)**: Reset password in Active Directory via `Set-ADAccountPassword`.
    3. **Stage 3 (Independent Verification)**: Authenticate against domain using `System.DirectoryServices.AccountManagement.PrincipalContext`.
    4. **Stage 4 (Publish & Finalize)**: Publish verified password to active Vault safe, record `last_rotated` ISO timestamp, and delete pending secret.
  - Automated multi-target rotation scripts:
    - Windows Local Admin via WinRM: [`scripts/rotate-windows-local-admin.ps1`](file:///scripts/rotate-windows-local-admin.ps1)
    - Linux Local User via SSH / chpasswd: [`scripts/rotate-linux-user.sh`](file:///scripts/rotate-linux-user.sh)
    - AWS IAM Access Key pair rotation: [`scripts/rotate-aws-iam-key.ps1`](file:///scripts/rotate-aws-iam-key.ps1)
  - Scheduled automated 30-day recurring execution via Windows Task Scheduler ([`scripts/schedule-rotations.ps1`](file:///scripts/schedule-rotations.ps1)).
- **Evidence**:
  - Rotation audit log: [`evidence/sample-rotation.log`](file:///evidence/sample-rotation.log)
  - Operational runbook: [`docs/runbook.md`](file:///docs/runbook.md)
  - Screenshot: [`screenshots/phase4-rotation-success.png`](file:///screenshots/README.md)

---

### Phase 5: Privileged Session Monitoring & Command Filtering (Days 11–14)
- **Objective**: Enforce session gateway isolation (CyberArk PSM equivalent), video keystroke recording, and in-line command filtering.
- **Implementation**:
  - Deployed JumpServer session proxy on `VAULT01` ([`docs/jumpserver-setup-guide.md`](file:///docs/jumpserver-setup-guide.md)).
  - Enrolled targets: `WIN-APP01` (RDP protocol) and `LINUX01` (SSH protocol).
  - Configured credential injection: Administrative users connect through web terminal; JumpServer automatically injects vaulted credentials without revealing passwords to the user.
  - Implemented In-line Command Filter blocking destructive commands (`rm -rf`, `mkfs`, `dd`).
  - Executed and logged 3 distinct test sessions:
    1. Routine Linux administration task (`appadmin` running `df -h`, `uptime`).
    2. Windows Server administrative RDP session inspecting services.
    3. High-risk command execution attempt (`rm -rf /tmp/testdir`) intercepted and blocked by security gateway.
- **Evidence**:
  - Session replay screenshots: [`screenshots/phase5-jumpserver-session-replay.png`](file:///screenshots/README.md)
  - Blocked command alert: [`screenshots/phase5-command-filter-blocked.png`](file:///screenshots/README.md)

---

### Phase 6: ServiceNow Workflow & Just-In-Time (JIT) Access (Days 14–17)
- **Objective**: Replace standing administrative rights with approval-driven, self-expiring Just-In-Time (JIT) elevation.
- **Implementation**:
  - Configured ServiceNow PDI Service Catalog Item: `Privileged Access Elevation Request (PAM-JIT)` with variables for Target System, Role, Duration, and Justification ([`docs/servicenow-integration-guide.md`](file:///docs/servicenow-integration-guide.md)).
  - Built Flow Designer workflow: Manager approval trigger routing to automated PowerShell elevation.
  - Enabled Forest-wide Active Directory Privileged Access Management Optional Feature on DC01 via [`scripts/enable-ad-pam-jit.ps1`](file:///scripts/enable-ad-pam-jit.ps1).
  - Executed ephemeral group membership grant:
    ```powershell
    Add-ADGroupMember -Identity "GG-PAM-Windows-Admins" -Members "bob" -MemberTimeToLive (New-TimeSpan -Hours 2)
    ```
  - Validated real-time TTL countdown via `Get-ADGroup -ShowMemberTimeToLive`. Confirmed automatic revocation upon expiration.
  - Integrated ServiceNow REST Table API in rotation script catch block (`POST /api/now/table/incident`): Auto-creates incidents on rotation failures. Resolved 3 simulated incidents tracking SLA response times.
- **Evidence**:
  - JIT TTL countdown screenshot: [`screenshots/phase6-jit-group-ttl.png`](file:///screenshots/README.md)
  - ServiceNow Incident ticket: [`screenshots/phase6-servicenow-incident.png`](file:///screenshots/README.md)

---

### Phase 7: Audit, Security Event Analysis & ISO 27001 Mapping (Days 17–19)
- **Objective**: Execute automated compliance audits, analyze Windows security logs, and map controls to ISO/IEC 27001:2022 Annex A.
- **Implementation**:
  - Developed automated PowerShell audit scanner: [`scripts/privileged-access-review.ps1`](file:///scripts/privileged-access-review.ps1).
  - Correlated Windows Security Event IDs:
    - `4728` / `4732` / `4756`: Member added to privileged security group.
    - `4724`: Attempt made to reset account password.
  - Audited secret metadata in Vault to identify unrotated credentials (> 30 days).
  - Identified 2 real compliance findings:
    1. `FINDING-AD-001` (HIGH): Planted dormant admin `adm_old` retaining standing rights with 188 days of inactivity.
    2. `FINDING-VAULT-002` (MEDIUM): Service account `svc_backup` unrotated for 74 days.
  - Authored formal compliance report: [`evidence/findings-remediation-report.md`](file:///evidence/findings-remediation-report.md).
  - Mapped technical controls to ISO/IEC 27001:2022 Annex A ([`docs/iso27001-mapping.md`](file:///docs/iso27001-mapping.md)).
- **Evidence**:
  - Generated CSV report: [`evidence/privileged-access-report.csv`](file:///evidence/privileged-access-report.csv)
  - Executive HTML audit report: `evidence/privileged-access-report.html`
  - Screenshot: [`screenshots/phase7-audit-html-report.png`](file:///screenshots/README.md)

---

### Phase 8: Cloud Privileged Access & Comparative Analysis (Days 19–21)
- **Objective**: Extend PAM governance to cloud infrastructure across AWS IAM and Microsoft Entra ID.
- **Implementation**:
  - Authored least-privilege AWS IAM JSON policy restricting service account access strictly to a single S3 bucket: [`vault/policies/aws-least-privilege-s3.json`](file:///vault/policies/aws-least-privilege-s3.json).
  - Executed automated AWS access key rotation via [`scripts/rotate-aws-iam-key.ps1`](file:///scripts/rotate-aws-iam-key.ps1), deactivating and deleting old keys with verification in AWS CloudTrail.
  - Documented Microsoft Entra ID Privileged Identity Management (PIM) architecture and role activation workflows.
  - Published comprehensive comparative architectural analysis: [`docs/cloud-pam-comparison.md`](file:///docs/cloud-pam-comparison.md) comparing on-prem AD Kerberos tickets vs Entra ID OAuth tokens vs AWS STS temporary credentials.
- **Evidence**:
  - IAM Policy: [`vault/policies/aws-least-privilege-s3.json`](file:///vault/policies/aws-least-privilege-s3.json)
  - CloudTrail events screenshot: [`screenshots/phase8-aws-cloudtrail.png`](file:///screenshots/README.md)
  - Entra ID role assignment screenshot: [`screenshots/phase8-entra-roles.png`](file:///screenshots/README.md)

---

## 4. Failure Scenarios & Operational Runbook Summary

In enterprise environments, happy paths are expected; resilient failure handling differentiates senior engineers. Full triage steps are codified in [`docs/runbook.md`](file:///docs/runbook.md):

```
+----------------------------------------------------------------------------------------------------+
| SCENARIO 1: Expired Vault Token (Stage 1 Failure)                                                  |
| Symptom:      HTTP 403 Forbidden writing to secret/data/service-accounts/svc_webapp_pending.      |
| Behavior:     Script terminates immediately. AD password remains UNCHANGED.                        |
| Resolution:   L1 generates new orphan token under 'pam-rotation-engine' policy; updates env var.   |
+----------------------------------------------------------------------------------------------------+
| SCENARIO 2: AD Password Policy Violation (Stage 2 Failure)                                         |
| Symptom:      Set-ADAccountPassword throws complexity/history rejection error.                     |
| Behavior:     Pending secret remains in Vault; AD account keeps running with existing password.   |
| Resolution:   Update password generator charset, purge orphaned pending secret, re-run rotation.  |
+----------------------------------------------------------------------------------------------------+
| SCENARIO 3: Vault Service Down / Network Partition (Stage 3/4 Desync)                              |
| Symptom:      Vault endpoint unreachable after AD password was reset.                             |
| Anti-Lockout: Pending secret in Vault holds the exact password applied to AD.                      |
| Resolution:   Restart Vault daemon, promote pending secret to active safe, verify app sync.       |
+----------------------------------------------------------------------------------------------------+
```

---

## 5. ISO/IEC 27001:2022 Annex A Control Mapping

| ISO 27001:2022 Control | Control Title | Lab Implementation | Audit Status |
| :--- | :--- | :--- | :--- |
| **8.2** | Privileged Access Rights | Vault HCL RBAC + AD PAM JIT (`MemberTimeToLive`) + PowerShell 4-Stage Rotation | **COMPLIANT** |
| **5.15** | Access Control | JumpServer PSM Proxy + In-Line Command Filter (`rm -rf` blocked) | **COMPLIANT** |
| **5.18** | Access Rights | ServiceNow 2-stage approval workflow + Quarterly review script (`adm_old` flagged) | **COMPLIANT (FINDING REMEDIATED)** |
| **8.15** | Logging | Vault HMAC audit device + Windows Security Events (4728, 4724) + JumpServer Replay | **COMPLIANT** |
| **8.24** | Use of Cryptography | AES-256-GCM Vault storage + Vault AppRole machine authentication | **COMPLIANT** |

---

## 6. Lab Limitations vs Production Hardening Roadmap

While this lab mirrors enterprise architecture, several constraints were intentional for resource efficiency. Below is the production hardening roadmap:

1. **Vault Storage & High Availability**:
   - *Lab*: In-memory dev mode or single-node file storage. Dev mode loses data on restart.
   - *Production*: Multi-datacenter Vault High-Availability (HA) cluster utilizing Integrated Raft storage across 3 availability zones with automated cloud KMS auto-unseal (AWS KMS / Azure Key Vault).
2. **PKI & TLS Encryption**:
   - *Lab*: Plain HTTP / local host-only networking.
   - *Production*: Strict mutual TLS (mTLS) with internal corporate CA certificates and automated certificate rollover.
3. **Session Gateway Scalability**:
   - *Lab*: Single Docker container JumpServer instance.
   - *Production*: Load-balanced cluster of stateless PSM proxies behind an application load balancer with recordings archived to immutable WORM cloud storage (S3 Glacier / Azure Blob with Legal Hold).
4. **Service Dependency Discovery**:
   - *Lab*: Target accounts rotated at the directory level.
   - *Production*: Automated discovery engine scanning for Windows Services (`sc.exe`), Scheduled Tasks, and IIS Application Pools, orchestrating graceful service restarts during rotation windows.

---

## 7. How to Reproduce

### Prerequisites
- Host machine with 16 GB RAM (Windows 10/11 or macOS/Linux).
- VirtualBox / VMware Workstation with host-only network `192.168.56.0/24`.
- PowerShell 7 (`pwsh`), Python 3.10+, and Docker installed.

### Step-by-Step Deployment
```powershell
# 1. Clone repository
git clone https://github.com/chaitanya/pam-vault-rotation-lab.git
cd pam-vault-rotation-lab

# 2. Configure environment variables
Copy-Item .env.example .env
# Edit .env with your local IPs and ServiceNow instance details

# 3. Provision Active Directory on DC01
.\scripts\setup-ad-environment.ps1 -DomainDN "DC=lab,DC=local"

# 4. Start & Initialize HashiCorp Vault on VAULT01
cd vault
chmod +x setup-vault.sh
./setup-vault.sh

# 5. Run automated RBAC test
cd ..
.\scripts\test-vault-rbac.ps1 -VaultUrl "http://192.168.56.20:8200"

# 6. Execute 4-Stage Credential Rotation
$env:VAULT_TOKEN = "root"
.\scripts\rotate-ad-service-account.ps1 -Account svc_webapp

# 7. Grant Just-In-Time Elevation (2-Hour TTL)
.\scripts\enable-ad-pam-jit.ps1 -Member bob -Hours 2

# 8. Run ISO 27001 Compliance Review Scanner
.\scripts\privileged-access-review.ps1 -Domain lab.local
```

---

## 8. Portfolio & CV / Resume Bullet Points

Copy and paste these verified bullet points into your CV / LinkedIn profile:

> - **Privileged Access Management (PAM) Lab & Zero-Standing-Privilege Architecture**: Architected an end-to-end enterprise PAM platform integrating HashiCorp Vault, Active Directory, JumpServer, and ServiceNow across hybrid Windows/Linux/AWS environments.
> - **Automated Resilient Credential Rotation (CyberArk CPM Equivalent)**: Engineered a transactional 4-stage PowerShell rotation engine (Stage Pending -> AD Reset -> Validate -> Publish) eliminating credential desync and lockouts; automated 30-day credential lifecycles across AD, Linux `chpasswd`, Windows local admin, and AWS IAM access keys.
> - **Privileged Session Monitoring & Command Filtering (CyberArk PSM Equivalent)**: Deployed JumpServer session proxy enforcing credential injection (zero user password visibility), asciinema keystroke recording, and real-time command filtering blocking destructive operations (`rm -rf`).
> - **Just-In-Time (JIT) Elevation & ServiceNow Integration**: Implemented self-expiring privileged access via Active Directory's PAM Optional Feature (`MemberTimeToLive`), integrated with ServiceNow Service Catalog and Flow Designer approval workflows; automated REST incident dispatching on rotation failures.
> - **Compliance & Security Auditing (ISO 27001)**: Developed an automated compliance scanner correlating Windows Security Events (4728, 4724) and Vault HMAC audit logs, identifying dormant administrative accounts (`adm_old`) and stale credentials mapped to ISO/IEC 27001:2022 Annex A controls (8.2, 5.15, 5.18, 8.15).

---

## Repository Structure

```
pam-vault-rotation-lab/
├── .gitignore                                 # Token, secret, and credential filters
├── .env.example                              # Lab environment variable template
├── README.md                                 # Master architecture & lab build guide
├── apps/                                     # Application secret onboarding samples
│   ├── before_hardcoded_app.py               # Vulnerable application (hardcoded secrets)
│   ├── after_vault_app.py                    # Secure application (Vault API retrieval)
│   ├── approle_vault_app.py                  # Advanced AppRole machine identity demo
│   └── requirements.txt                      # Python dependencies
├── docs/                                     # Engineering & compliance documentation
│   ├── onboarding-checklist.md               # Account onboarding SOP & questionnaire
│   ├── account-register.csv                  # Privileged account inventory register
│   ├── runbook.md                            # L1/L2 operational triage & failure runbook
│   ├── jumpserver-setup-guide.md             # PSM session recording & command filter guide
│   ├── servicenow-integration-guide.md       # PDI catalog, flow & REST API guide
│   ├── iso27001-mapping.md                   # ISO/IEC 27001:2022 Annex A control matrix
│   ├── cloud-pam-comparison.md               # AD vs Entra ID vs AWS IAM comparative note
│   └── interview-prep.md                     # Technical interview masterclass & answers
├── evidence/                                 # Audit evidence & verification logs
│   ├── README.md                             # Evidence manifest
│   ├── sample-rotation.log                   # Rotation engine execution & incident log
│   ├── sample-vault_audit.log                # Vault HMAC-hashed audit events
│   ├── privileged-access-report.csv          # Automated compliance findings export
│   └── findings-remediation-report.md        # Formal findings & remediation report
├── screenshots/                              # Visual evidence placeholders & guidelines
│   └── README.md                             # Screenshot manifest across 8 phases
├── scripts/                                  # Automation & rotation tooling
│   ├── setup-ad-environment.ps1              # Phase 1: AD OU, user & group automation
│   ├── setup-linux-target.sh                 # Phase 1: Linux target configuration
│   ├── test-vault-rbac.ps1                   # Phase 2: Automated RBAC verification
│   ├── rotate-ad-service-account.ps1         # Phase 4: 4-stage AD credential rotation (CPM)
│   ├── rotate-windows-local-admin.ps1        # Phase 4: Windows local admin rotation
│   ├── rotate-linux-user.sh                  # Phase 4: Linux local user rotation
│   ├── rotate-aws-iam-key.ps1                # Phase 4/8: AWS IAM access key rotation
│   ├── schedule-rotations.ps1                # Phase 4: Windows Task Scheduler automation
│   ├── enable-ad-pam-jit.ps1                 # Phase 6: AD PAM JIT MemberTimeToLive grant
│   └── privileged-access-review.ps1          # Phase 7: Automated compliance review scanner
└── vault/                                    # Vault server configs & policies
    ├── docker-compose.yml                    # Containerized Vault & JumpServer stack
    ├── setup-vault.sh                        # Automated Vault provisioning script
    ├── config/
    │   └── vault-server.hcl                  # Production Vault server configuration
    └── policies/                             # Fine-grained HCL & JSON policies
        ├── pam-admin.hcl                     # Vault safe administrator
        ├── pam-operator.hcl                  # Scoped service account operator
        ├── pam-auditor.hcl                   # Metadata-only compliance auditor
        ├── pam-rotation-engine.hcl           # Minimal CPM rotation policy
        ├── webapp-approle.hcl                # Application AppRole policy
        └── aws-least-privilege-s3.json       # AWS IAM least-privilege JSON policy
```

