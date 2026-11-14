#!/usr/bin/env bash
# ==============================================================================
# Phase 1: Target Linux Server Setup (LINUX01)
# Configures the target Ubuntu Server for PAM integration, SSH, and sudo access.
# ==============================================================================

set -euo pipefail

echo "=========================================================="
echo " [Phase 1] Configuring LINUX01 (Ubuntu Server)"
echo "=========================================================="

# 1. Create appadmin user if not exists
if id "appadmin" &>/dev/null; then
    echo "[-] User 'appadmin' already exists."
else
    echo "[+] Creating 'appadmin' user..."
    sudo useradd -m -s /bin/bash appadmin
    echo "appadmin:LabP@ssw0rdLinux2026!" | sudo chpasswd
fi

# 2. Grant sudo permissions to appadmin
echo "[+] Adding 'appadmin' to sudoers..."
echo "appadmin ALL=(ALL) ALL" | sudo tee /etc/sudoers.d/appadmin
sudo chmod 0440 /etc/sudoers.d/appadmin

# 3. Configure SSH Server for session monitoring & PAM credential injection
echo "[+] Verifying OpenSSH server..."
sudo apt-get update -y
sudo apt-get install -y openssh-server curl jq

sudo systemctl enable ssh
sudo systemctl start ssh

# 4. Display Host IP and connectivity check
echo "=========================================================="
echo "[✓] LINUX01 Configuration Complete!"
echo "IP Address: $(hostname -I | awk '{print $1}')"
echo "Hostname:   $(hostname)"
echo "Test SSH command from DC01 or VAULT01: ssh appadmin@$(hostname -I | awk '{print $1}')"
echo "=========================================================="
