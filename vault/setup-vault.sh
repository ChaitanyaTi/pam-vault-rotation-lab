#!/usr/bin/env bash
# ==============================================================================
# Phase 2 & 3: Automated HashiCorp Vault Provisioning Script
# Executes on VAULT01 or container host to initialize RBAC, Policies & Safes
# ==============================================================================

set -euo pipefail

export VAULT_ADDR="${VAULT_ADDR:-http://127.0.0.1:8200}"
export VAULT_TOKEN="${VAULT_TOKEN:-root}"

echo "=========================================================="
echo " [Phase 2] Initializing HashiCorp Vault PAM Configuration "
echo " Vault Target: $VAULT_ADDR"
echo "=========================================================="

# 1. Verify Vault connectivity
echo "[+] Checking Vault status..."
vault status || { echo "[!] Vault unreachable at $VAULT_ADDR"; exit 1; }

# 2. Enable KV v2 secret engine at path 'secret'
echo "[+] Enabling KV-v2 secret engine at 'secret/'..."
vault secrets enable -path=secret kv-v2 2>/dev/null || echo "[-] Path 'secret' already enabled."

# 3. Enable Audit Logging
echo "[+] Enabling file audit device at /var/log/vault_audit.log..."
sudo touch /var/log/vault_audit.log 2>/dev/null || true
sudo chmod 666 /var/log/vault_audit.log 2>/dev/null || true
vault audit enable file file_path=/var/log/vault_audit.log 2>/dev/null || echo "[-] Audit log already enabled."

# 4. Upload HCL Access Policies
echo "[+] Writing PAM RBAC policies..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
vault policy write pam-admin "$SCRIPT_DIR/policies/pam-admin.hcl"
vault policy write pam-operator "$SCRIPT_DIR/policies/pam-operator.hcl"
vault policy write pam-auditor "$SCRIPT_DIR/policies/pam-auditor.hcl"
vault policy write pam-rotation-engine "$SCRIPT_DIR/policies/pam-rotation-engine.hcl"
vault policy write webapp-approle "$SCRIPT_DIR/policies/webapp-approle.hcl"

# 5. Enable userpass authentication
echo "[+] Enabling userpass authentication..."
vault auth enable userpass 2>/dev/null || echo "[-] userpass auth already enabled."

# 6. Create Lab Users
echo "[+] Provisioning userpass accounts: alice (pam-operator) and bob (unprivileged)..."
vault write auth/userpass/users/alice password="AliceSecureLab2026!" policies="pam-operator"
vault write auth/userpass/users/bob password="BobStandardLab2026!" policies="default"
vault write auth/userpass/users/chaitanya password="AdminMaster2026!" policies="pam-admin"

# 7. Configure AppRole for Application Onboarding (Phase 3 Stretch)
echo "[+] Enabling AppRole authentication..."
vault auth enable approle 2>/dev/null || echo "[-] approle auth already enabled."
vault write auth/approle/role/webapp-role \
    secret_id_ttl=24h \
    token_ttl=1h \
    token_max_ttl=4h \
    policies="webapp-approle"

ROLE_ID=$(vault read -field=role_id auth/approle/role/webapp-role/role-id)
SECRET_ID=$(vault write -f -field=secret_id auth/approle/role/webapp-role/secret-id)
echo "[*] WebApp AppRole Role ID:   $ROLE_ID"
echo "[*] WebApp AppRole Secret ID: $SECRET_ID"

# 8. Onboard Initial Accounts (Phase 3)
echo "[+] Onboarding initial privileged accounts into safes..."
vault kv put secret/windows-admin/win-app01 \
    username="Administrator" \
    password="WinAppLocalAdminInitial2026!" \
    system="WIN-APP01" \
    owner="Infrastructure Team" \
    account_type="WindowsLocalAdmin" \
    rotation_period="30d"

vault kv put secret/linux-root/linux01 \
    username="appadmin" \
    password="LabP@ssw0rdLinux2026!" \
    system="LINUX01" \
    owner="DevOps Team" \
    account_type="LinuxLocalSudo" \
    rotation_period="30d"

vault kv put secret/service-accounts/svc_webapp \
    username="svc_webapp" \
    password="P@ssword123!SecureLab" \
    system="DC01.lab.local" \
    owner="Identity / Web Team" \
    account_type="ADServiceAccount" \
    rotation_period="30d" \
    last_rotated="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

vault kv put secret/aws/iam-user \
    username="lab-pam-svc" \
    access_key_id="AKIAIOSFODNN7EXAMPLE" \
    secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" \
    system="AWS Cloud (Lab Account)" \
    owner="Cloud Security Team" \
    account_type="AWSIAMUser" \
    rotation_period="90d"

echo "=========================================================="
echo "[✓] Vault Initialization and Onboarding Complete!"
echo "Audit Log: /var/log/vault_audit.log"
echo "=========================================================="
