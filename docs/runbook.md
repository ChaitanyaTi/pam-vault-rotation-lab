# Privileged Access Management (PAM) Operational Runbook & Incident Triage

This runbook documents standard operational procedures for incident response, failure recovery, and the operational division between Level 1 (Service Desk / SecOps Triage) and Level 2 (PAM Engineering / Identity Architecture).

---

## 1. Operational Tiering: L1 vs L2 Responsibility Split

```
+--------------------------------------------------------------------------------------------------+
|                                    L1 OPERATIONAL TRIAGE (SLA: < 30 MIN)                        |
| - Receive automated ServiceNow incident alert from rotation engine.                             |
| - Verify host connectivity: ICMP ping and port checks (DC01: 9389/636, VAULT01: 8200).          |
| - Validate target account status in Active Directory (Enabled vs Locked/Disabled).              |
| - Execute single controlled manual re-test of rotation script.                                  |
| - If rotation fails a second time, escalate immediately to L2 PAM Engineering.                  |
+--------------------------------------------------------------------------------------------------+
                                                 | (Escalate)
                                                 v
+--------------------------------------------------------------------------------------------------+
|                                  L2 PAM ENGINEERING (SLA: < 2 HOURS)                             |
| - Inspect Vault audit logs (/var/log/vault_audit.log) for HMAC-hashed permission denials.       |
| - Review AD Security event logs (Event ID 4724, 4728, 4732) on DC01.                            |
| - Diagnose token lease expiration, AppRole SecretID expiry, or fine-grained ACL policy syntax.  |
| - Issue emergency rollback or credential re-synchronization.                                    |
| - Post-mortem documentation, runbook updates, and problem ticket closure.                       |
+--------------------------------------------------------------------------------------------------+
```

---

## 2. Failure Simulation Scenarios

### Failure Scenario 1: Expired or Invalid Vault Token

```
Stage: STAGE_1_VAULT_STAGE
Result: FAIL (Script terminates before touching Active Directory)
Risk Level: Low (Account in AD remains operational; no lockout)
```

- **Symptom**:
  `rotation.log` reports:
  ```
  2026-11-14T09:15:02Z [FAIL] [svc_webapp] Stage [STAGE_1_VAULT_STAGE] failed. Error: The remote server returned an error: (403) Forbidden.
  ```
  ServiceNow Incident created: `PAM Alert: Automated Rotation Failed for svc_webapp at STAGE_1_VAULT_STAGE`.
- **Root Cause**:
  The environment variable `VAULT_TOKEN` passed to the script is expired, revoked, or lacks `create`/`update` capabilities on `secret/data/service-accounts/*`.
- **Diagnostic Checks (L1/L2)**:
  1. Inspect token capabilities via Vault CLI:
     ```bash
     export VAULT_TOKEN="<token_in_use>"
     vault token lookup
     vault token capabilities secret/data/service-accounts/svc_webapp_pending
     ```
  2. Search `/var/log/vault_audit.log` for HTTP 403 entries matching client token HMAC.
- **Remediation & Fix**:
  1. Issue a new rotation engine token associated with `pam-rotation-engine` policy:
     ```bash
     vault token create -policy=pam-rotation-engine -ttl=720h -orphan
     ```
  2. Update the secure environment variable on DC01:
     ```powershell
     [System.Environment]::SetEnvironmentVariable('VAULT_TOKEN', '<new_token>', 'Machine')
     ```
  3. Re-run rotation script: `.\scripts\rotate-ad-service-account.ps1 -Account svc_webapp`.
- **Escalation Path**: If token generation fails, escalate to Vault Cluster Administrator.

---

### Failure Scenario 2: Active Directory Password Complexity Failure / Account Disabled

```
Stage: STAGE_2_AD_PASSWORD_RESET
Result: FAIL (Staged in Vault, rejected by Domain Controller)
Risk Level: Medium (Pending secret staged in Vault; production account unaffected)
```

- **Symptom**:
  `rotation.log` reports:
  ```
  2026-11-14T10:22:15Z [FAIL] [svc_webapp] Stage [STAGE_2_AD_PASSWORD_RESET] failed. Error: The password does not meet the length, complexity, or history requirements of the domain.
  ```
  ServiceNow Incident created with Priority 2.
- **Root Cause**:
  1. The password generation function generated a string violating Domain Fine-Grained Password Policy (FGPP) or default domain policy (e.g., character reuse or insufficient length).
  2. Alternatively, the target account `svc_webapp` was administratively disabled or locked prior to rotation.
- **Diagnostic Checks (L1/L2)**:
  1. Query target account status in AD:
     ```powershell
     Get-ADUser -Identity svc_webapp -Properties LockedOut, Enabled, PasswordLastSet
     ```
  2. Inspect domain password policy:
     ```powershell
     Get-ADDefaultDomainPasswordPolicy
     Get-ADFineGrainedPasswordPolicy -Filter *
     ```
  3. Review Security Event Log on DC01 for Event ID `4724` (Password reset attempt) to see status code.
- **Remediation & Fix**:
  1. If account is locked or disabled, verify legitimate administrative hold. If cleared, unlock:
     ```powershell
     Unlock-ADAccount -Identity svc_webapp
     ```
  2. Ensure `New-SecurePassword` generator enforces at least 20 characters with uppercase, lowercase, digits, and approved special symbols.
  3. Remove orphaned `_pending` secret from Vault safe to maintain state hygiene:
     ```bash
     vault kv delete secret/service-accounts/svc_webapp_pending
     ```
  4. Trigger manual rotation and verify `PrincipalContext.ValidateCredentials` returns `$true`.

---

### Failure Scenario 3: Vault Service Down / Network Partition

```
Stage: STAGE_1_VAULT_STAGE or STAGE_4_VAULT_PUBLISH
Result: FAIL (Network timeout / connection refused)
Risk Level: High (If during Stage 4: AD password changed, but Vault not updated!)
```

- **Symptom**:
  `rotation.log` reports:
  ```
  2026-11-14T11:05:44Z [FAIL] [svc_webapp] Unable to connect to remote server: http://192.168.56.20:8200
  ```
  Applications querying Vault receive HTTP connection timeouts.
- **Root Cause**:
  `vault.service` process crashed, host VAULT01 is powered off, or host-only virtual adapter is disconnected.
- **Diagnostic Checks (L1/L2)**:
  1. Test network connectivity from DC01:
     ```powershell
     Test-NetConnection -ComputerName 192.168.56.20 -Port 8200
     ```
  2. On VAULT01, check systemd daemon status:
     ```bash
     sudo systemctl status vault
     # If running in container:
     docker ps -a | grep vault
     ```
  3. Inspect Vault server log: `journalctl -u vault.service -n 50 --no-pager`.
- **Remediation & Anti-Lockout Recovery Procedure**:
  1. Restart Vault daemon / container:
     ```bash
     sudo systemctl start vault
     # Or docker restart pam-vault
     ```
  2. If Vault was started in dev mode, note that **dev mode loses in-memory data on restart**. Re-run `vault/setup-vault.sh` to repopulate configuration.
  3. **Stage 4 Desync Recovery (Critical Anti-Lockout Procedure)**:
     - Check `secret/data/service-accounts/svc_webapp_pending` in Vault.
     - If Stage 2 succeeded before Vault went down, the AD account is running with the password stored in `_pending`.
     - Read the password from `_pending` and promote it to active `secret/data/service-accounts/svc_webapp`.
     - This guarantees the consuming application can retrieve the current AD password without downtime.

---

## 3. Incident SLA & Resolution Metrics

| Incident Severity | Classification | Target Response | Target Resolution | Lab Simulation Count |
| :--- | :--- | :--- | :--- | :--- |
| **P1 - Critical** | Vault Cluster Down / Complete Authentication Failure | 15 mins | 1 hour | 1 simulated |
| **P2 - High** | Single Service Account Rotation Failure | 30 mins | 2 hours | 2 simulated |
| **P3 - Medium** | Stale Credential Discovery (> 30 days) | 4 hours | 1 business day | 1 simulated (adm_old) |
| **P4 - Low** | Audit Log Export Failure | 8 hours | 3 business days | 1 simulated |
