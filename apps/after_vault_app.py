#!/usr/bin/env python3
"""
Secure Application Pattern: Vault-Fetched Credentials (AFTER PAM)

SECURITY ADVANTAGES:
- Zero secrets in code: No hardcoded passwords in version control.
- Seamless rotation: Credentials can be rotated automatically by CPM/Vault without redeploying code.
- Full audit trail: Every fetch generates an audit record in Vault (/var/log/vault_audit.log).
- Least privilege: App only needs an ephemeral Vault token with read access to its specific secret safe.
"""

import os
import sys
import time
import requests

VAULT_ADDR = os.getenv("VAULT_ADDR", "http://192.168.56.20:8200")
VAULT_TOKEN = os.getenv("VAULT_TOKEN")

SECRET_PATH = "v1/secret/data/service-accounts/svc_webapp"

def get_secret_from_vault():
    """
    Retrieves the service account credentials dynamically from HashiCorp Vault API.
    Header: X-Vault-Token
    Endpoint: /v1/secret/data/service-accounts/svc_webapp
    """
    if not VAULT_TOKEN:
        print("[!] ERROR: VAULT_TOKEN environment variable is not set.", file=sys.stderr)
        print("    Usage: $env:VAULT_TOKEN='<token>'; python after_vault_app.py", file=sys.stderr)
        sys.exit(1)

    url = f"{VAULT_ADDR.rstrip('/')}/{SECRET_PATH}"
    headers = {
        "X-Vault-Token": VAULT_TOKEN,
        "Accept": "application/json"
    }

    print(f"[*] [SECURE] Querying Vault API at: {url}")
    try:
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()
        
        payload = response.json()
        secret_data = payload.get("data", {}).get("data", {})
        
        username = secret_data.get("username")
        password = secret_data.get("password")
        last_rotated = secret_data.get("last_rotated", "Unknown")

        if not username or not password:
            raise ValueError("Incomplete credentials returned from Vault secret payload.")

        print(f"[+] Credentials successfully retrieved from Vault!")
        print(f"    Account:      {username}")
        print(f"    Last Rotated: {last_rotated}")
        print(f"    Secret Length:{len(password)} characters [MASKED]")
        
        return username, password

    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 403:
            print(f"[!] ACCESS DENIED (403): Token lacks 'read' permission on {SECRET_PATH}", file=sys.stderr)
        else:
            print(f"[!] HTTP error occurred: {http_err}", file=sys.stderr)
        sys.exit(1)
    except Exception as err:
        print(f"[!] Unexpected error fetching secret: {err}", file=sys.stderr)
        sys.exit(1)

def connect_to_database(username, password):
    print(f"[*] Authenticating with service account '{username}' against DC01.lab.local...")
    time.sleep(0.5)
    print("[+] Database connection established using fresh vaulted credentials!")
    return True

def run_application_workload():
    username, password = get_secret_from_vault()
    if connect_to_database(username, password):
        print("[*] Processing billing transaction pipeline...")
        print("[+] Application workload finished securely.")

if __name__ == "__main__":
    print("=" * 60)
    print(" [AFTER] Secure App Fetching Secrets from HashiCorp Vault ")
    print("=" * 60)
    run_application_workload()

