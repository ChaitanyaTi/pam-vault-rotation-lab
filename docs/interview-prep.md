# Privileged Access Management (PAM) Technical Interview Masterclass

This guide provides in-depth, production-tested answers to the core technical interview questions for Privileged Access Management, Identity Security, and CyberArk / HashiCorp Vault engineering roles.

---

### Question 1: "Why rotate a service account password, and what breaks if you do it badly?"

#### The "Why":
1. **Lateral Movement & Credential Dumping**: Service account credentials often have broad permissions across systems (e.g., Domain Admin, DB Admin, local administrator). If an endpoint is compromised, attackers dump credentials from memory (`LSASS`), disk cache, or code repositories. Regular rotation bounds the window of vulnerability.
2. **Compliance & Governance**: Standards like ISO 27001 (A.8.2) and PCI-DSS (Requirement 8) strictly mandate maximum cryptographic lifespans for privileged credentials.

#### What breaks if you do it badly (Failure Modes):
- **Service Outages (Logon Failure 1069)**: In Windows environments, background services (`services.msc`), scheduled tasks, and IIS Application Pools cache credentials. If you change the password in Active Directory without updating the local Windows Service Control Manager (`sc.exe`), the service crashes upon restart with:
  `Error 1069: The service did not start due to a logon failure.`
- **Account Lockout Cascades**: Hardcoded applications or distributed worker nodes attempting to reconnect with the old cached password generate rapid bad-password attempts, exceeding the domain lockout threshold and locking the account across the entire domain.
- **Application Downtime**: Clustered applications without zero-downtime rollover mechanisms will fail mid-transaction.

---

### Question 2: "What happens if rotation fails halfway, and how did you prevent a lockout?"

#### The Problem:
A naive rotation script simply changes the Active Directory password and then tries to write to the vault. If the script crashes, network drops, or the vault rejects the write after AD has updated, **the new password is lost forever**. The administrator is locked out, the vault holds an outdated password, and production is down.

#### How we prevented lockout (The 4-Stage Staging Pattern):
In our PowerShell CPM engine (`rotate-ad-service-account.ps1`), we implemented a **staged transactional workflow**:
```
Stage 1: Generate password -> Stage in Vault as '_pending'
Stage 2: Reset password in target (Active Directory)
Stage 3: Verify authentication via independent API (PrincipalContext.ValidateCredentials)
Stage 4: Publish to active Vault safe & archive pending state
```
1. **Stage 1 Failure**: If Vault is down or token is invalid, the script aborts *before* touching AD. Current AD password remains untouched; zero production impact.
2. **Stage 2 Failure**: If AD rejects the password (e.g. complexity policy), the old password in AD is still active. The `_pending` secret in Vault is simply discarded.
3. **Stage 3/4 Failure**: If verification fails or Vault becomes unreachable after AD has updated, the new password is already safely recorded in Vault under `_pending`. The L1/L2 engineer checks the `_pending` secret, prevents a lockout, and can promote the password without emergency break-glass resets.

---

### Question 3: "How is a vault different from a password manager?"

| Feature | Enterprise Vault (HashiCorp Vault / CyberArk) | Password Manager (1Password / Bitwarden / Keepass) |
| :--- | :--- | :--- |
| **Primary Audience** | Non-human identities, APIs, CI/CD pipelines, and privileged admin sessions. | Human users storing personal and workplace website credentials. |
| **Credential Rotation** | Fully automated via programmatic plugins/CPM scripts without human intervention. | Manual password changes requiring user interaction. |
| **Access Model** | Ephemeral, time-limited tokens, dynamic secret generation, AppRoles, JIT access. | Static credential retrieval with master password decryption. |
| **Session Brokering** | Proxies sessions (PSM/JumpServer), records video/keystrokes, injects credentials without user ever seeing them. | Copies password into user's clipboard or browser autofill. |
| **Audit Trails** | High-throughput, HMAC-hashed, tamper-evident audit logs sent to SIEM. | Basic web event logs (who opened the vault item). |

---

### Question 4: "How does Just-In-Time (JIT) access reduce risk compared with standing admin rights?"

- **Elimination of Standing Privileges**: In traditional setups, `alice` is a permanent member of `Domain Admins`. If Alice's laptop is compromised at 3:00 AM on a Saturday, attackers inherit Domain Admin privileges immediately.
- **Zero Attack Surface Outside Active Windows**: With JIT (via AD PAM Feature `MemberTimeToLive` or Entra PIM), Alice has zero elevated privileges by default. She only receives rights for 2 hours following a ServiceNow ticket approval. If compromised during off-hours, the attacker gains only standard unprivileged access.
- **Audit Correlation**: Every privileged action has an explicit justification, manager approval timestamp, and ticket ID, making compliance audits seamless.

---

### Question 5: "What would you check first if a user cannot retrieve a vaulted credential?"

1. **Vault Token & Lease Expiration**: Verify if the user's client token has expired or if the lease exceeded its TTL (`vault token lookup`).
2. **HCL ACL Policy Capabilities**: Check if the user's attached policy explicitly grants `read` capabilities on the exact secret path (e.g. `secret/data/service-accounts/*` vs `secret/service-accounts/*` in KV v2).
3. **Audit Log Inspection**: Inspect `/var/log/vault_audit.log` for HTTP `403 Forbidden` errors matching the user's token HMAC to see the exact denied path.
4. **Target Safe Folder Structure**: Ensure the secret was onboarded under the correct safe path (KV v1 vs KV v2 data path syntax).

---

### Question 6: "How would your lab change in production?"

| Dimension | Lab Environment | Production Enterprise Deployment |
| :--- | :--- | :--- |
| **Vault Storage & HA** | Dev mode (in-memory) or single-node file storage. | Multi-node Vault High-Availability (HA) cluster using Integrated Raft storage across 3 availability zones with automated auto-unseal via AWS KMS / Azure Key Vault. |
| **TLS & PKI** | Plain HTTP / self-signed certificates. | Mutual TLS (mTLS) with corporate PKI certificates and automated renewal. |
| **Session Recording** | Single container JumpServer instance. | Redundant cluster of PSM / Teleport proxy nodes behind a Network Load Balancer with encrypted session recording storage in S3/Blob. |
| **Service Dependency Mapping**| Standalone AD user. | Automated discovery scanning for dependent Windows Services, Scheduled Tasks, and IIS App Pools, with coordinated service restarts during rotation windows. |
| **SIEM Integration** | Local log files (`rotation.log`). | Real-time syslog/Kafka streaming of audit logs into Splunk / Microsoft Sentinel with automated UEBA alerting. |

