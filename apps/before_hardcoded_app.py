#!/usr/bin/env python3
"""
Vulnerable Application Pattern: Hardcoded Service Account Credentials (BEFORE PAM)

RISK ASSESSMENT:
- High vulnerability: Secret is stored in plain text in source code and git history.
- Rotation nightmare: Changing the password breaks the app until redeployed.
- No auditability: Anyone with code access has direct access to the service account.
- Non-compliant with ISO 27001 (A.8.2 / A.5.15) and NIST SP 800-53 (IA-5).
"""

import time
import sys

# ==============================================================================
# INSECURE: Hardcoded privileged credentials
# ==============================================================================
CONFIG = {
    "db_host": "DC01.lab.local",
    "service_account": "svc_webapp",
    "service_password": "P@ssword123!SecureLab",  # <--- CRITICAL SECURITY FLAW
    "connection_timeout": 30
}

def connect_to_database():
    print(f"[*] [INSECURE] Initiating database connection to {CONFIG['db_host']}...")
    print(f"[*] Authenticating with service account: '{CONFIG['service_account']}'")
    print(f"[!] WARNING: Using hardcoded plain-text password: '{CONFIG['service_password']}'")
    
    # Mocking connection
    time.sleep(0.5)
    print("[+] Database connection established successfully!")
    return True

def run_application_workload():
    if connect_to_database():
        print("[*] Processing billing transaction pipeline...")
        print("[+] Application workload finished.")

if __name__ == "__main__":
    print("=" * 60)
    print(" [BEFORE] Legacy App with Hardcoded Privileged Secret ")
    print("=" * 60)
    run_application_workload()
