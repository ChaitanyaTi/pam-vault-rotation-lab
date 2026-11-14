# Privileged Session Monitoring (PSM) Setup Guide: JumpServer & Teleport

This guide covers the deployment, asset onboarding, command filtering, and session recording configuration for Phase 5 of the PAM lab (CyberArk PSM equivalent).

---

## 1. Architectural Overview (Gateway Isolation)

```
[ Administrative Client ]
            |
            | HTTPS / SSH (Port 443 / 2222)
            v
+--------------------------------------------------------------+
|              VAULT01: JumpServer / Teleport Gateway          |
|  - Real-time Keystroke Logging                               |
|  - Full Video/asciinema Session Recording                   |
|  - In-line Command Filter (Blocks 'rm -rf', flags 'sudo')    |
|  - Credential Injection (User never sees target password)     |
+--------------------------------------------------------------+
            |                               |
  (RDP Port 3389)                   (SSH Port 22)
            v                               v
[ WIN-APP01 (Windows Target) ]     [ LINUX01 (Ubuntu Target) ]
```

---

## 2. Installation on VAULT01 (Docker Deployment)

JumpServer runs seamlessly via Docker Compose:

```bash
# 1. Download JumpServer installer on VAULT01
curl -sSL https://github.com/jumpserver/jumpserver/releases/download/v3.10.4/quick_start.sh | bash

# 2. Start JumpServer services
cd /opt/jumpserver-installer-*
./jmsctl.sh start

# 3. Access JumpServer Web Management Interface
# URL: http://192.168.56.20/ (Default credentials: admin / admin)
```

*(Note for low-resource environments: If host RAM is under 8 GB, Teleport Community Edition provides a lightweight alternative with single-binary deployment: `curl https://goteleport.com/static/install.sh | bash`).*

---

## 3. Asset & Privileged Account Onboarding

### Asset 1: WIN-APP01 (Windows Server - RDP)
- **Asset Name**: `WIN-APP01`
- **IP Address**: `192.168.56.11`
- **Platform**: `Windows`
- **Protocol**: `RDP` (Port 3389)
- **System User / Asset Account**: `Administrator`

### Asset 2: LINUX01 (Ubuntu Server - SSH)
- **Asset Name**: `LINUX01`
- **IP Address**: `192.168.56.12`
- **Platform**: `Linux`
- **Protocol**: `SSH` (Port 22)
- **System User / Asset Account**: `appadmin`

---

## 4. Vault-to-JumpServer Credential Synchronization Architecture

> [!NOTE]
> **Production PAM Architecture Note**:
> JumpServer stores asset account credentials in its internal encrypted MySQL/PostgreSQL database. HashiCorp Vault acts as the single enterprise source of truth.
>
> When our PowerShell rotation script (`rotate-linux-user.sh` or `rotate-windows-local-admin.ps1`) updates a password in HashiCorp Vault, it invokes the JumpServer REST API (`PUT /api/v1/assets/system-users/<id>/auth-info/`) to push the new credential into JumpServer. This prevents credential desynchronization between the Vault safe and the PSM gateway.

---

## 5. Authorization Rules & Role-Based Access Control

In JumpServer > **Permissions** > **Asset Permissions**:

1. **Rule 1: Alice Linux Operator (Authorized)**
   - **Users**: `alice`
   - **Assets**: `LINUX01`
   - **System User**: `appadmin`
   - **Validity Period**: `7 Days` (Expiring access rule)
   - **Action**: Connect, R/W.

2. **Rule 2: Bob Standard User (Strict Denial)**
   - **Users**: `bob`
   - **Assets**: *None*
   - **Result**: Bob's JumpServer portal displays zero available assets. Direct connection attempts are rejected immediately.

---

## 6. Command Filtering & Risk Mitigation (Rule Enforcement)

To satisfy Phase 5, step 5, configure a Command Filter to block destructive shell commands:

1. Navigate to **Permissions** > **Command Filters** > **Create Filter**:
   - **Filter Name**: `Block-Destructive-Commands`
   - **Action**: `Reject and Alert`
2. Add Filter Rules:
   - Pattern 1: `.*rm\s+-rf.*` (Blocks recursive forced file deletion)
   - Pattern 2: `.*mkfs.*` (Blocks filesystem formatting)
   - Pattern 3: `.*dd\s+if=.*` (Blocks raw disk overwrite)
3. Assign filter to system user `appadmin` on `LINUX01`.

---

## 7. Execution of Test Sessions & Evidence Export

Execute the three mandatory lab test sessions:

1. **Session 1 (Linux Admin Workload)**:
   - Alice logs into JumpServer web console (`http://192.168.56.20`).
   - Clicks Web Terminal > Connects to `LINUX01` as `appadmin`.
   - Runs diagnostic commands: `df -h`, `uptime`, `systemctl status ssh`.
2. **Session 2 (Windows RDP Session)**:
   - Alice connects via Web GUI RDP to `WIN-APP01`.
   - Opens Event Viewer and checks Windows Services (`services.msc`).
3. **Session 3 (Risky Command Flagging)**:
   - In Linux terminal, Alice attempts: `rm -rf /tmp/testdir`.
   - JumpServer intercepts the keystroke, displays: `Command blocked by security policy`, and alerts administrators.

### Exporting Audit Log & Video Replay
1. Navigate to **Audits** > **Session Audits**.
2. Locate the session rows:
   - Click **Replay** to watch asciinema video playback with millisecond timestamps.
   - Click **Export Log** to download the raw terminal command log (`evidence/jumpserver-session-export.csv`).
3. Take screenshots of:
   - Replay window showing command execution.
   - Command filter alert notification.
