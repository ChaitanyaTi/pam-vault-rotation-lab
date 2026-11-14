#!/usr/bin/env bash
# ==============================================================================
# Phase 4: Linux Credential Rotation Script (Target: LINUX01)
# Rotates local user (appadmin) using chpasswd and updates HashiCorp Vault.
# ==============================================================================

set -euo pipefail

TARGET_USER="${1:-appadmin}"
VAULT_URL="${VAULT_ADDR:-http://192.168.56.20:8200}"

if [ -z "${VAULT_TOKEN:-}" ]; then
    echo "[!] Error: VAULT_TOKEN environment variable is required." >&2
    exit 1
fi

echo "=========================================================="
echo " [Phase 4] Linux Credential Rotation: $TARGET_USER"
echo "=========================================================="

# 1. Generate high-entropy password (22 chars)
NEW_PASSWORD=$(openssl rand -base64 18 | tr -dc 'a-zA-Z0-9!@#%')

# 2. Stage pending password in Vault
echo "[1/4] Staging pending password in Vault..."
curl -s -X POST \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"data\": {\"username\": \"$TARGET_USER\", \"password\": \"$NEW_PASSWORD\", \"status\": \"PENDING\"}}" \
    "$VAULT_URL/v1/secret/data/linux-root/linux01_pending" >/dev/null

# 3. Change password on local Linux system
echo "[2/4] Applying password change via chpasswd..."
echo "$TARGET_USER:$NEW_PASSWORD" | sudo chpasswd

# 4. Verify authentication using su/pam_authenticate
echo "[3/4] Verifying Linux authentication credentials..."
python3 -c "
import crypt, spwd, sys
user = '$TARGET_USER'
pwd = '$NEW_PASSWORD'
hashed = spwd.getspnam(user).sp_pwdp
if crypt.crypt(pwd, hashed) == hashed:
    print('Password verified.')
else:
    sys.exit(1)
" || { echo "[!] Verification failed!"; exit 1; }

# 5. Publish to Vault
echo "[4/4] Publishing verified password to Vault..."
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
curl -s -X POST \
    -H "X-Vault-Token: $VAULT_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"data\": {\"username\": \"$TARGET_USER\", \"password\": \"$NEW_PASSWORD\", \"last_rotated\": \"$TIMESTAMP\", \"system\": \"LINUX01\"}}" \
    "$VAULT_URL/v1/secret/data/linux-root/linux01" >/dev/null

echo "=========================================================="
echo "[✓] Linux user $TARGET_USER password rotated and vaulted!"
echo "=========================================================="

