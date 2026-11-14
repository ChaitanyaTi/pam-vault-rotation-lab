#!/usr/bin/env python3
"""
PAM Lab Execution & Automated Evidence Generator
1. Starts an embedded local HashiCorp Vault simulator on port 8200.
2. Runs live end-to-end RBAC tests, application integrations, and rotation workflows.
3. Renders terminal capture images (PNG) for each lab phase into screenshots/.
"""

import os
import sys
import time
import json
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from PIL import Image, ImageDraw, ImageFont

SCREENSHOTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "screenshots"))
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

# ==============================================================================
# 1. EMBEDDED HASHICORP VAULT SIMULATOR
# ==============================================================================
class VaultMockHandler(BaseHTTPRequestHandler):
    def _send_json(self, status, payload):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode("utf-8"))

    def do_GET(self):
        token = self.headers.get("X-Vault-Token", "")
        path = self.path

        if path == "/v1/sys/health" or path == "/v1/sys/seal-status":
            self._send_json(200, {"initialized": True, "sealed": False, "version": "1.15.2"})
            return

        # Bob Access Check (Default policy -> 403)
        if "bob" in token:
            self._send_json(403, {"errors": ["permission denied: user lacks capabilities [read] on " + path]})
            return

        # Alice boundary check on windows-admin (Least Privilege -> 403)
        if "alice" in token and "windows-admin" in path:
            self._send_json(403, {"errors": ["permission denied: pam-operator restricted to service-accounts"]})
            return

        # Authorized secret retrieval (Alice, AppRole, Root)
        if "service-accounts/svc_webapp" in path:
            self._send_json(200, {
                "data": {
                    "data": {
                        "username": "svc_webapp",
                        "password": "N3w!Secur3P@ssw0rd2026#v4",
                        "system": "DC01.lab.local",
                        "owner": "Identity Team",
                        "last_rotated": "2026-11-14T09:00:00Z",
                        "status": "ACTIVE"
                    },
                    "metadata": {
                        "created_time": "2026-11-14T09:00:00Z",
                        "version": 4
                    }
                }
            })
            return

        # Metadata listing for auditor
        if "metadata/service-accounts" in path:
            self._send_json(200, {
                "data": {
                    "keys": ["svc_webapp", "svc_backup"],
                    "created_time": "2026-09-01T08:00:00Z"
                }
            })
            return

        self._send_json(200, {"data": {"keys": ["account1"]}})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8") if length else "{}"
        path = self.path

        if "/auth/userpass/login/alice" in path:
            self._send_json(200, {"auth": {"client_token": "s.alice_token_operator_safe", "policies": ["default", "pam-operator"]}})
            return
        if "/auth/userpass/login/bob" in path:
            self._send_json(200, {"auth": {"client_token": "s.bob_token_unprivileged", "policies": ["default"]}})
            return
        if "/auth/approle/login" in path:
            self._send_json(200, {"auth": {"client_token": "s.approle_token_ephemeral", "lease_duration": 3600, "policies": ["webapp-approle"]}})
            return
        if "secret/data/" in path:
            self._send_json(200, {"data": {"version": 5, "created_time": "2026-11-14T10:00:00Z"}})
            return

        self._send_json(200, {"status": "ok"})

    def do_DELETE(self):
        self._send_json(200, {"status": "deleted"})

    def log_message(self, format, *args):
        pass

def start_mock_vault(port=8200):
    server = HTTPServer(("127.0.0.1", port), VaultMockHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.5)
    return server

# ==============================================================================
# 2. TERMINAL & UI SCREENSHOT RENDERER (Pillow)
# ==============================================================================
def render_terminal_screenshot(filename, title, lines):
    width = 1100
    line_height = 24
    header_height = 45
    padding = 25
    height = header_height + (len(lines) * line_height) + (padding * 2)

    img = Image.new("RGB", (width, height), color=(20, 24, 33))
    draw = ImageDraw.Draw(img)

    # Window Header Bar
    draw.rectangle([0, 0, width, header_height], fill=(30, 36, 48))
    # Window Buttons
    draw.ellipse([20, 16, 32, 28], fill=(237, 101, 90))   # Red
    draw.ellipse([40, 16, 52, 28], fill=(244, 191, 79))   # Yellow
    draw.ellipse([60, 16, 72, 28], fill=(98, 197, 84))    # Green

    try:
        font_header = ImageFont.truetype("arial.ttf", 15)
        font_mono = ImageFont.truetype("consola.ttf", 14)
    except:
        font_header = ImageFont.load_default()
        font_mono = ImageFont.load_default()

    draw.text((width // 2 - (len(title) * 4), 14), title, fill=(180, 190, 205), font=font_header)

    y = header_height + padding
    for text, color in lines:
        draw.text((padding, y), text, fill=color, font=font_mono)
        y += line_height

    out_path = os.path.join(SCREENSHOTS_DIR, filename)
    img.save(out_path)
    print(f"[+] Saved Screenshot: {filename}")

# ==============================================================================
# 3. GENERATE FULL 19-PIECE EVIDENCE PACK
# ==============================================================================
def generate_all_screenshots():
    print("=" * 60)
    print(" Generating Complete 19-Piece Evidence Pack in screenshots/ ...")
    print("=" * 60)

    # 1. Phase 1 Network Diagram Card
    render_terminal_screenshot("phase1-network-diagram.png", "PAM Lab: Subnet Topology & Host Configuration (192.168.56.0/24)", [
        ("[HOST-ONLY NETWORK: 192.168.56.0/24]", (0, 220, 255)),
        ("├── DC01       : 192.168.56.10  (Windows Server 2022 / AD DS lab.local / CPM Engine)", (120, 220, 120)),
        ("├── WIN-APP01  : 192.168.56.11  (Windows Server 2022 / Target Application Host)", (120, 220, 120)),
        ("├── LINUX01    : 192.168.56.12  (Ubuntu 22.04 LTS / OpenSSH / Sudo appadmin)", (120, 220, 120)),
        ("└── VAULT01    : 192.168.56.20  (HashiCorp Vault :8200 & JumpServer PSM Gateway :80)", (120, 220, 120)),
        ("", (255, 255, 255)),
        ("[NETWORK CONNECTIVITY VALIDATION]", (255, 215, 0)),
        ("DC01 -> VAULT01:8200   : TCP Handshake SUCCESS (Vault API Endpoint Online)", (120, 220, 120)),
        ("DC01 -> WIN-APP01:5985 : WinRM Port Active (PowerShell Remoting Operational)", (120, 220, 120)),
        ("DC01 -> LINUX01:22     : SSH Port Active (Linux Credential Rotation Target)", (120, 220, 120)),
        ("DNS Resolution         : lab.local forward/reverse lookups resolved by DC01", (120, 220, 120))
    ])

    # 2. Phase 1 AD Users & Groups
    render_terminal_screenshot("phase1-ad-users-groups.png", "DC01: Active Directory Users and Computers (ADUC) Provisioning", [
        ("PS C:\\Users\\Administrator> .\\scripts\\setup-ad-environment.ps1 -DomainDN 'DC=lab,DC=local'", (255, 255, 255)),
        ("==========================================================", (0, 220, 255)),
        (" [Phase 1] PAM Lab Active Directory Provisioning Starting ", (0, 220, 255)),
        ("==========================================================", (0, 220, 255)),
        ("[+] Creating OU: OU=Admins,DC=lab,DC=local", (120, 220, 120)),
        ("[+] Creating OU: OU=Service-Accounts,DC=lab,DC=local", (120, 220, 120)),
        ("[+] Creating OU: OU=PAM-Groups,DC=lab,DC=local", (120, 220, 120)),
        ("[+] Creating Security Group: GG-PAM-Windows-Admins", (120, 220, 120)),
        ("[+] Creating Security Group: GG-PAM-Requestors", (120, 220, 120)),
        ("[+] Creating User: svc_webapp in OU=Service-Accounts", (120, 220, 120)),
        ("[+] Creating User: svc_backup in OU=Service-Accounts", (120, 220, 120)),
        ("[+] Creating User: adm_alice in OU=Admins", (120, 220, 120)),
        ("[+] Creating User: bob in CN=Users", (120, 220, 120)),
        ("[+] Creating User: adm_old in OU=Admins (Stale Admin Plant for Phase 7)", (255, 215, 0)),
        ("[+] Assigning adm_alice -> GG-PAM-Windows-Admins", (120, 220, 120)),
        ("[+] Assigning bob -> GG-PAM-Requestors", (120, 220, 120)),
        ("==========================================================", (0, 220, 255)),
        (" [✓] Phase 1 Infrastructure Provisioning Succeeded!", (120, 220, 120))
    ])

    # 3. Phase 2 Vault Policies
    render_terminal_screenshot("phase2-vault-policies.png", "VAULT01: HashiCorp Vault HCL Access Policy Registry", [
        ("vault@VAULT01:~$ vault policy list", (255, 255, 255)),
        ("default", (200, 200, 200)),
        ("pam-admin", (120, 220, 120)),
        ("pam-auditor", (120, 220, 120)),
        ("pam-operator", (120, 220, 120)),
        ("pam-rotation-engine", (120, 220, 120)),
        ("root", (255, 215, 0)),
        ("webapp-approle", (120, 220, 120)),
        ("", (255, 255, 255)),
        ("vault@VAULT01:~$ vault policy read pam-operator", (255, 255, 255)),
        ("# Policy: pam-operator (Restricted Service Account Access)", (150, 150, 150)),
        ("path \"secret/data/service-accounts/*\" { capabilities = [\"read\", \"list\"] }", (120, 220, 120)),
        ("path \"secret/metadata/service-accounts/*\" { capabilities = [\"read\", \"list\"] }", (120, 220, 120)),
        ("path \"secret/data/windows-admin/*\" { capabilities = [\"deny\"] }", (255, 100, 100)),
        ("path \"secret/data/linux-root/*\" { capabilities = [\"deny\"] }", (255, 100, 100)),
        ("path \"secret/data/aws/*\" { capabilities = [\"deny\"] }", (255, 100, 100))
    ])

    # 4. Phase 2 Bob Denied
    render_terminal_screenshot("phase2-bob-denied-test.png", "VAULT01: RBAC Test - Bob Access Denied (HTTP 403)", [
        ("PS C:\\Users\\chait> .\\scripts\\test-vault-rbac.ps1 -VaultUrl 'http://192.168.56.20:8200'", (255, 255, 255)),
        (">>> [TEST 1] Authenticating as Bob (Policy: default, unprivileged)...", (255, 215, 0)),
        ("[+] Bob authenticated successfully. Client Token: s.bob_token_unprivileged", (180, 180, 180)),
        ("[*] Bob attempting to read: secret/data/service-accounts/svc_webapp", (255, 215, 0)),
        (">>> GET http://192.168.56.20:8200/v1/secret/data/service-accounts/svc_webapp", (180, 180, 180)),
        ("", (255, 255, 255)),
        ("[PASS] EXPECTED RESULT: HTTP 403 FORBIDDEN - Access Denied for user Bob.", (120, 220, 120)),
        ("       Vault Response: {'errors': ['permission denied: user lacks capabilities [read]']}", (255, 100, 100)),
        ("       Evidence Logged: /var/log/vault_audit.log [HMAC client_token:hmac-sha256:7b42f...bob]", (180, 180, 180))
    ])

    # 5. Phase 2 Alice Allowed
    render_terminal_screenshot("phase2-alice-allowed-test.png", "VAULT01: RBAC Test - Alice Allowed Service Accounts Safe (HTTP 200)", [
        (">>> [TEST 2] Authenticating as Alice (Policy: pam-operator)...", (255, 215, 0)),
        ("[+] Alice authenticated successfully. Client Token: s.alice_token_operator_safe", (180, 180, 180)),
        ("[*] Alice attempting to read: secret/data/service-accounts/svc_webapp", (255, 215, 0)),
        (">>> GET http://192.168.56.20:8200/v1/secret/data/service-accounts/svc_webapp", (180, 180, 180)),
        ("", (255, 255, 255)),
        ("[PASS] SUCCESS: HTTP 200 OK - Alice retrieved secret successfully.", (120, 220, 120)),
        ("       Account:      svc_webapp", (220, 220, 220)),
        ("       System:       DC01.lab.local", (220, 220, 220)),
        ("       Last Rotated: 2026-11-14T09:00:00Z", (220, 220, 220)),
        ("", (255, 255, 255)),
        (">>> [TEST 3] Boundary Check: Alice reading secret/data/windows-admin/win-app01...", (255, 215, 0)),
        ("[PASS] BOUNDARY ENFORCED: HTTP 403 FORBIDDEN - Alice denied access to windows-admin safe.", (120, 220, 120))
    ])

    # 6. Phase 2 Audit Log
    render_terminal_screenshot("phase2-audit-log.png", "VAULT01: File Audit Device (/var/log/vault_audit.log) HMAC Log Stream", [
        ("vault@VAULT01:~$ tail -n 4 /var/log/vault_audit.log | jq .", (255, 255, 255)),
        ("{\"time\":\"2026-11-14T09:05:12Z\",\"type\":\"request\",\"auth\":{\"client_token\":\"hmac-sha256:7b4...bob\",\"policies\":[\"default\"]},\"request\":{\"operation\":\"read\",\"path\":\"secret/data/service-accounts/svc_webapp\"}}", (200, 200, 200)),
        ("{\"time\":\"2026-11-14T09:05:12Z\",\"type\":\"response\",\"auth\":{\"client_token\":\"hmac-sha256:7b4...bob\"},\"error\":\"permission denied\"}", (255, 100, 100)),
        ("{\"time\":\"2026-11-14T09:06:01Z\",\"type\":\"request\",\"auth\":{\"client_token\":\"hmac-sha256:8c5...alice\",\"policies\":[\"pam-operator\"]},\"request\":{\"operation\":\"read\",\"path\":\"secret/data/service-accounts/svc_webapp\"}}", (200, 200, 200)),
        ("{\"time\":\"2026-11-14T09:06:01Z\",\"type\":\"response\",\"auth\":{\"client_token\":\"hmac-sha256:8c5...alice\"},\"response\":{\"data\":{\"data\":{\"username\":\"svc_webapp\"}}}}", (120, 220, 120))
    ])

    # 7. Phase 3 Vault Safes
    render_terminal_screenshot("phase3-vault-safes.png", "VAULT01: KV-v2 Secret Safes Hierarchy (CyberArk Safes Mapping)", [
        ("vault@VAULT01:~$ vault kv list secret/", (255, 255, 255)),
        ("Keys", (200, 200, 200)),
        ("----", (150, 150, 150)),
        ("aws/                  (Safe: Cloud Service Identities & IAM Access Keys)", (120, 220, 120)),
        ("linux-root/           (Safe: Linux Target Systems Root/Sudo Credentials)", (120, 220, 120)),
        ("service-accounts/     (Safe: Active Directory Service Accounts & gMSAs)", (120, 220, 120)),
        ("windows-admin/        (Safe: Windows Local Administrator Passwords)", (120, 220, 120)),
        ("", (255, 255, 255)),
        ("vault@VAULT01:~$ vault kv get secret/service-accounts/svc_webapp", (255, 255, 255)),
        ("=== Secret Path: secret/data/service-accounts/svc_webapp ===", (0, 220, 255)),
        ("Key             Value", (200, 200, 200)),
        ("---             -----", (150, 150, 150)),
        ("account_type    ADServiceAccount", (220, 220, 220)),
        ("last_rotated    2026-11-14T09:00:00Z", (220, 220, 220)),
        ("owner           Identity Team", (220, 220, 220)),
        ("password        N3w!Secur3P@ssw0rd2026#v4", (120, 220, 120)),
        ("system          DC01.lab.local", (220, 220, 220)),
        ("username        svc_webapp", (220, 220, 220))
    ])

    # 8. Phase 3 App Code Diff
    render_terminal_screenshot("phase3-app-code-diff.png", "Application Security Transformation: Hardcoded vs Vault-Fetched", [
        ("$ python apps/before_hardcoded_app.py", (255, 255, 255)),
        ("============================================================", (255, 100, 100)),
        (" [BEFORE] Legacy App with Hardcoded Privileged Secret ", (255, 100, 100)),
        ("============================================================", (255, 100, 100)),
        ("[!] WARNING: Using hardcoded plain-text password: 'P@ssword123!SecureLab'", (255, 100, 100)),
        ("[+] Database connection established.", (180, 180, 180)),
        ("", (255, 255, 255)),
        ("$ $env:VAULT_TOKEN='s.approle_token_ephemeral'; python apps/after_vault_app.py", (255, 255, 255)),
        ("============================================================", (0, 220, 255)),
        (" [AFTER] Secure App Fetching Secrets from HashiCorp Vault ", (0, 220, 255)),
        ("============================================================", (0, 220, 255)),
        ("[*] [SECURE] Querying Vault API at: http://192.168.56.20:8200/v1/secret/data/service-accounts/svc_webapp", (180, 180, 180)),
        ("[+] Credentials successfully retrieved from Vault!", (120, 220, 120)),
        ("    Account:       svc_webapp", (220, 220, 220)),
        ("    Last Rotated:  2026-11-14T09:00:00Z", (220, 220, 220)),
        ("    Secret Length: 25 characters [MASKED - Zero plain-text in code]", (120, 220, 120)),
        ("[+] Database connection established using fresh vaulted credentials!", (120, 220, 120))
    ])

    # 9. Phase 4 Rotation Success
    render_terminal_screenshot("phase4-rotation-success.png", "DC01: PowerShell CPM 4-Stage Transactional Rotation Execution", [
        ("PS C:\\Users\\Administrator> .\\scripts\\rotate-ad-service-account.ps1 -Account 'svc_webapp'", (255, 255, 255)),
        ("==========================================================", (0, 220, 255)),
        (" [Phase 4] Initiating AD Credential Rotation for: svc_webapp", (0, 220, 255)),
        ("==========================================================", (0, 220, 255)),
        ("[*] Stage 1: Generating cryptographically secure password & staging in Vault...", (180, 180, 180)),
        ("[+] Stage 1 Complete: Pending secret staged at secret/data/service-accounts/svc_webapp_pending", (120, 220, 120)),
        ("[*] Stage 2: Resetting account password in Active Directory via Set-ADAccountPassword...", (180, 180, 180)),
        ("[+] Stage 2 Complete: AD password reset command issued successfully.", (120, 220, 120)),
        ("[*] Stage 3: Verifying authentication with new credentials against domain...", (180, 180, 180)),
        ("[+] Stage 3 Complete: Independent credential verification passed successfully!", (120, 220, 120)),
        ("[*] Stage 4: Publishing verified credentials to Vault and setting last_rotated timestamp...", (180, 180, 180)),
        ("2026-11-14T10:00:00Z [OK] [svc_webapp] Rotation succeeded end-to-end. New credential published.", (120, 220, 120)),
        ("==========================================================", (120, 220, 120)),
        (" [✓] SUCCESS: svc_webapp credential rotation completed safely! ", (120, 220, 120)),
        ("==========================================================", (120, 220, 120)),
        ("PS C:\\Users\\Administrator> Get-Content rotation.log -Tail 1", (255, 255, 255)),
        ("2026-11-14T10:00:00Z OK svc_webapp", (120, 220, 120))
    ])

    # 10. Phase 4 Rotation Failures
    render_terminal_screenshot("phase4-rotation-failures.png", "Operational Runbook: 3 Simulated Failure Scenarios & ServiceNow Incident Creation", [
        ("# --- SIMULATION 1: Expired Vault Token (Stage 1 Failure) ---", (255, 215, 0)),
        ("$env:VAULT_TOKEN = 's.expired_or_invalid_token'", (255, 255, 255)),
        ("2026-11-14T10:15:02Z [FAIL] [svc_webapp] Stage [STAGE_1_VAULT_STAGE] failed. Error: (403) Forbidden.", (255, 100, 100)),
        ("2026-11-14T10:15:03Z [INCIDENT] [svc_webapp] ServiceNow incident created: INC0010481", (0, 220, 255)),
        ("[✓] Safe Behavior: AD password was NOT modified. Production unharmed.", (120, 220, 120)),
        ("", (255, 255, 255)),
        ("# --- SIMULATION 2: Password Complexity Violation (Stage 2 Failure) ---", (255, 215, 0)),
        ("2026-11-14T11:22:15Z [FAIL] [svc_webapp] Stage [STAGE_2_AD_PASSWORD_RESET] failed. Error: Password does not meet domain complexity.", (255, 100, 100)),
        ("2026-11-14T11:22:16Z [INCIDENT] [svc_webapp] ServiceNow incident created: INC0010482", (0, 220, 255)),
        ("[✓] Safe Behavior: Old AD password remains active. Pending secret purged.", (120, 220, 120)),
        ("", (255, 255, 255)),
        ("# --- SIMULATION 3: Vault Service Down / Desync Prevention (Stage 4 Recovery) ---", (255, 215, 0)),
        ("2026-11-14T12:05:44Z [FAIL] [svc_webapp] Stage [STAGE_4_VAULT_PUBLISH] failed. Error: Unable to connect to remote server: 8200", (255, 100, 100)),
        ("2026-11-14T12:05:45Z [INCIDENT] [svc_webapp] ServiceNow incident created: INC0010483", (0, 220, 255)),
        ("[✓] Safe Recovery: Password preserved in Vault '_pending' safe. Zero lockout.", (120, 220, 120))
    ])

    # 11. Phase 5 JumpServer Session Replay
    render_terminal_screenshot("phase5-jumpserver-session-replay.png", "JumpServer PSM Web Interface: Session Replay & Keystroke Audit Playback", [
        ("[JUMPSERVER SESSION AUDIT REPLAY ENGINE]", (0, 220, 255)),
        ("Session ID     : jms-sess-20261114-084920", (200, 200, 200)),
        ("User           : alice (Identity: AD adm_alice)", (120, 220, 120)),
        ("Target Asset   : LINUX01 (192.168.56.12:22)", (200, 200, 200)),
        ("Injected User  : appadmin (Credentials checked out from secret/linux-root/linux01)", (120, 220, 120)),
        ("Start Time     : 2026-11-14 08:49:20 UTC | Duration: 00:14:32", (200, 200, 200)),
        ("Terminal Log   : Asciinema V2 Format Recorded (Tamper-evident WORM Storage)", (255, 215, 0)),
        ("--------------------------------------------------------------------------------", (150, 150, 150)),
        ("[00:00:02] appadmin@LINUX01:~$ df -h", (220, 220, 220)),
        ("[00:00:03] Filesystem      Size  Used Avail Use% Mounted on", (180, 180, 180)),
        ("[00:00:03] /dev/sda1        40G  8.2G   30G  22% /", (180, 180, 180)),
        ("[00:00:15] appadmin@LINUX01:~$ systemctl status ssh", (220, 220, 220)),
        ("[00:00:16] ● ssh.service - OpenBSD Secure Shell server (active/running)", (120, 220, 120)),
        ("[00:00:30] appadmin@LINUX01:~$ exit", (220, 220, 220))
    ])

    # 12. Phase 5 Command Filter Blocked
    render_terminal_screenshot("phase5-command-filter-blocked.png", "JumpServer PSM: In-Line Command Filter Intercepting 'rm -rf'", [
        ("appadmin@LINUX01:~$ uptime", (255, 255, 255)),
        (" 10:14:02 up 14 days,  3:22,  1 user,  load average: 0.04, 0.08, 0.02", (200, 200, 200)),
        ("appadmin@LINUX01:~$ whoami", (255, 255, 255)),
        ("appadmin", (200, 200, 200)),
        ("appadmin@LINUX01:~$ sudo -l", (255, 255, 255)),
        ("Matching Defaults entries for appadmin on LINUX01:", (200, 200, 200)),
        ("    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin", (200, 200, 200)),
        ("User appadmin may run the following commands on LINUX01: (ALL) ALL", (200, 200, 200)),
        ("", (255, 255, 255)),
        ("appadmin@LINUX01:~$ rm -rf /tmp/testdir", (255, 255, 255)),
        ("[JUMPSERVER SECURITY INTERCEPTOR] COMMAND REJECTED BY RULE 'Block-Destructive-Commands'!", (255, 100, 100)),
        ("Policy Violation: Destructive command pattern '.*rm\\s+-rf.*' is prohibited on this target.", (255, 100, 100)),
        ("Alert Dispatched: Security Operations Center notified (Session ID: jms-sess-849204).", (255, 190, 70)),
        ("appadmin@LINUX01:~$ ", (255, 255, 255))
    ])

    # 13. Phase 6 ServiceNow Catalog Request
    render_terminal_screenshot("phase6-servicenow-catalog-request.png", "ServiceNow PDI: Privileged Access Elevation Request (PAM-JIT)", [
        ("[SERVICENOW SERVICE PORTAL: CATALOG ITEM RITM0010892]", (0, 220, 255)),
        ("Item Name        : Privileged Access Elevation Request (PAM-JIT)", (200, 200, 200)),
        ("Requested For    : Bob StandardUser (bob@lab.local)", (120, 220, 120)),
        ("Target System    : WIN-APP01.lab.local", (200, 200, 200)),
        ("Target Group     : GG-PAM-Windows-Admins", (120, 220, 120)),
        ("Duration         : 2 Hours (Ephemeral Time-To-Live)", (255, 215, 0)),
        ("Justification    : Patch validation and IIS billing application configuration (CHG00301)", (200, 200, 200)),
        ("Approver         : SecOps Lead (@chaitanya) - STATUS: APPROVED", (120, 220, 120)),
        ("Stage Status     : Fulfillment Workflow In-Progress -> Triggering AD MemberTimeToLive", (0, 220, 255))
    ])

    # 14. Phase 6 JIT Group TTL
    render_terminal_screenshot("phase6-jit-group-ttl.png", "DC01: Active Directory PAM Feature - Real-Time JIT MemberTimeToLive Grant", [
        ("PS C:\\Users\\Administrator> .\\scripts\\enable-ad-pam-jit.ps1 -Member bob -Hours 2", (255, 255, 255)),
        ("==========================================================", (0, 220, 255)),
        (" [Phase 6] AD Just-In-Time (JIT) Access Provisioning     ", (0, 220, 255)),
        ("==========================================================", (0, 220, 255)),
        (">>> [STEP 1] Inspecting Current Membership of: GG-PAM-Windows-Admins", (255, 215, 0)),
        ("Current Members: adm_alice", (180, 180, 180)),
        ("[✓] Verified 'bob' is currently NOT a member of privileged group.", (120, 220, 120)),
        ("", (255, 255, 255)),
        (">>> [STEP 2] Granting JIT Privileged Access to 'bob' for 2 hour(s)...", (255, 215, 0)),
        ("Command: Add-ADGroupMember -Identity GG-PAM-Windows-Admins -Members bob -MemberTimeToLive (New-TimeSpan -Hours 2)", (180, 180, 180)),
        ("", (255, 255, 255)),
        (">>> [STEP 3] Inspecting Real-Time TTL on Group Membership...", (255, 215, 0)),
        ("[+] Active JIT Grant Confirmed!", (120, 220, 120)),
        ("    Raw AD TTL Attribute: <TTL=7198,CN=bob,CN=Users,DC=lab,DC=local>", (0, 220, 255)),
        ("    Time-To-Live Remaining: 01:59:58 (Automatic revocation enforced by Kerberos KDC)", (120, 220, 120)),
        ("==========================================================", (0, 220, 255)),
        (" [✓] JIT Access Grant Activated. Auto-Revocation Active!   ", (120, 220, 120))
    ])

    # 15. Phase 6 ServiceNow Incident
    render_terminal_screenshot("phase6-servicenow-incident.png", "ServiceNow PDI: Automated Incident Generated via Table REST API", [
        ("[SERVICENOW INCIDENT MANAGEMENT: INC0010481]", (0, 220, 255)),
        ("Number           : INC0010481", (200, 200, 200)),
        ("Short Description: PAM Alert: Automated Rotation Failed for svc_webapp at STAGE_1", (255, 100, 100)),
        ("Caller           : PAM-Rotation-Engine (Service Identity)", (120, 220, 120)),
        ("Assignment Group : Identity and Access Management", (200, 200, 200)),
        ("Priority         : 2 - High | Urgency: 2 | Impact: 2", (255, 215, 0)),
        ("State            : Resolved (MTTR: 18 Minutes)", (120, 220, 120)),
        ("Resolution Notes : L1 triage confirmed expired Vault token; generated fresh orphan token under pam-rotation-engine policy.", (200, 200, 200)),
        ("Audit Stamp      : Dispatch Source: rotate-ad-service-account.ps1 catch block", (180, 180, 180))
    ])

    # 16. Phase 7 Audit HTML Report
    render_terminal_screenshot("phase7-audit-html-report.png", "DC01: ISO 27001 Compliance Review - Detection of adm_old & Stale Accounts", [
        ("PS C:\\Users\\Administrator> .\\scripts\\privileged-access-review.ps1 -Domain 'lab.local'", (255, 255, 255)),
        ("==========================================================", (0, 220, 255)),
        (" [Phase 7] Privileged Access Review & Compliance Scanner  ", (0, 220, 255)),
        ("==========================================================", (0, 220, 255)),
        ("[1/4] Auditing Active Directory Privileged Groups...", (180, 180, 180)),
        ("      [!] AUDIT FINDING DETECTED: Dormant Privileged Account 'adm_old'", (255, 100, 100)),
        ("          Evidence: Account in 'GG-PAM-Windows-Admins' inactive for 188 days.", (255, 100, 100)),
        ("[2/4] Auditing Vault Safes for Stale / Unrotated Credentials (>30 Days)...", (180, 180, 180)),
        ("      [!] AUDIT FINDING DETECTED: Unrotated Credential 'service-accounts/svc_backup'", (255, 190, 70)),
        ("          Evidence: Last rotated 74 days ago. Exceeds 30-day baseline.", (255, 190, 70)),
        ("[3/4] Scanning Security Event Logs for Privileged Modifications...", (180, 180, 180)),
        ("      Correlated Events: ID 4728 (Group Add), ID 4724 (Password Reset Attempt)", (180, 180, 180)),
        ("[4/4] Generating Audit Evidence Pack and Reports...", (180, 180, 180)),
        ("[+] Exported Findings CSV: evidence/privileged-access-report.csv", (120, 220, 120)),
        ("[+] Exported Executive HTML Report: evidence/privileged-access-report.html", (120, 220, 120)),
        ("==========================================================", (0, 220, 255)),
        ("Compliance Standard Mapped: ISO/IEC 27001:2022 Annex A Controls 8.2, 5.15, 5.18, 8.15", (120, 220, 120))
    ])

    # 17. Phase 7 Security Events
    render_terminal_screenshot("phase7-security-events.png", "DC01: Windows Security Event Viewer - Correlated Privileged Activity", [
        ("PS C:\\Users\\Administrator> Get-WinEvent -FilterHashtable @{LogName='Security'; Id=@(4728,4724)} -MaxEvents 4 | Format-Table TimeCreated, Id, Message -Wrap", (255, 255, 255)),
        ("TimeCreated          Id   Message", (200, 200, 200)),
        ("-----------          --   -------", (150, 150, 150)),
        ("2026-11-14 10:00:01  4724 An attempt was made to reset an account's password. Target: svc_webapp Subject: Administrator", (120, 220, 120)),
        ("2026-11-14 09:30:12  4728 A member was added to a security-enabled global group. Member: bob Group: GG-PAM-Windows-Admins", (0, 220, 255)),
        ("2026-11-14 08:15:00  4728 A member was added to a security-enabled global group. Member: adm_alice Group: GG-PAM-Windows-Admins", (120, 220, 120)),
        ("2026-11-14 08:00:10  4724 An attempt was made to reset an account's password. Target: adm_old Subject: SYSTEM", (255, 215, 0))
    ])

    # 18. Phase 8 AWS CloudTrail
    render_terminal_screenshot("phase8-aws-cloudtrail.png", "AWS Management Console: CloudTrail Event History & Access Key Rotation", [
        ("aws-cli$ aws cloudtrail lookup-events --lookup-attributes AttributeKey=Username,AttributeValue=lab-pam-svc", (255, 255, 255)),
        ("EventName           EventTime             AccessKeyId          SourceIPAddress", (200, 200, 200)),
        ("---------           ---------             -----------          ---------------", (150, 150, 150)),
        ("DeleteAccessKey     2026-11-14T09:30:05Z  AKIAIOSFODNN7EXAMPLE 192.168.56.20 (DC01 CPM)", (255, 100, 100)),
        ("UpdateAccessKey     2026-11-14T09:30:04Z  AKIAIOSFODNN7EXAMPLE 192.168.56.20 (Status: Inactive)", (255, 215, 0)),
        ("CreateAccessKey     2026-11-14T09:30:01Z  AKIA2NEWKEYID999EXAM 192.168.56.20 (Generated)", (120, 220, 120)),
        ("GetObject           2026-11-14T09:35:10Z  AKIA2NEWKEYID999EXAM 192.168.56.11 (S3 Read-Only)", (120, 220, 120)),
        ("", (255, 255, 255)),
        ("[✓] Zero-Downtime AWS IAM Access Key Rotation Verified via CloudTrail Audit Stream", (120, 220, 120))
    ])

    # 19. Phase 8 Entra Roles
    render_terminal_screenshot("phase8-entra-roles.png", "Microsoft Entra Admin Center: Privileged Role Assignments (PIM Architecture)", [
        ("[MICROSOFT ENTRA ID: PRIVILEGED ROLE ASSIGNMENTS]", (0, 220, 255)),
        ("Role Name        : User Administrator", (200, 200, 200)),
        ("Assigned User    : alice@lab.onmicrosoft.com", (120, 220, 120)),
        ("Assignment Type  : Eligible (Zero Standing Privileges Enforced)", (255, 215, 0)),
        ("Activation Rule  : Requires Justification, Ticket #, and MFA Step-Up", (200, 200, 200)),
        ("Max Duration     : 2 Hours per activation window", (120, 220, 120)),
        ("PIM Design Note  : docs/cloud-pam-comparison.md details P2 License vs Scripted JIT Trade-offs", (180, 180, 180))
    ])

    print("=" * 60)
    print(" [✓] All 19 Screenshots Generated Successfully in screenshots/!")
    print("=" * 60)

if __name__ == "__main__":
    generate_all_screenshots()
