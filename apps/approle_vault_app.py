#!/usr/bin/env python3
"""
Advanced App Pattern: Vault AppRole Authentication (STRETCH GOAL)

Solves the "Secret Zero" problem by providing machine-to-machine authentication:
- Role ID is embedded in application deployment/configuration.
- Secret ID is dynamically injected at runtime (e.g. via systemd or container environment).
- The app logs in via Vault AppRole API, acquires a short-lived token, reads the secret, and runs.
"""

import os
import sys
import time
import requests

VAULT_ADDR = os.getenv("VAULT_ADDR", "http://192.168.56.20:8200")
ROLE_ID = os.getenv("VAULT_ROLE_ID")
SECRET_ID = os.getenv("VAULT_SECRET_ID")

SECRET_PATH = "v1/secret/data/service-accounts/svc_webapp"

def login_with_approle(role_id, secret_id):
    """Logs into Vault using AppRole credentials to obtain a temporary token."""
    login_url = f"{VAULT_ADDR.rstrip('/')}/v1/auth/approle/login"
    payload = {
        "role_id": role_id,
        "secret_id": secret_id
    }
    print(f"[*] Authenticating with Vault AppRole at: {login_url}")
    resp = requests.post(login_url, json=payload, timeout=5)
    resp.raise_for_status()
    auth_data = resp.json()["auth"]
    client_token = auth_data["client_token"]
    ttl = auth_data["lease_duration"]
    print(f"[+] AppRole login successful! Ephemeral token acquired (TTL: {ttl}s).")
    return client_token

def fetch_secret(token):
    """Retrieves secret using the temporary AppRole token."""
    url = f"{VAULT_ADDR.rstrip('/')}/{SECRET_PATH}"
    headers = {"X-Vault-Token": token}
    resp = requests.get(url, headers=headers, timeout=5)
    resp.raise_for_status()
    return resp.json()["data"]["data"]

def main():
    print("=" * 60)
    print(" [STRETCH] AppRole Machine Authentication Demo ")
    print("=" * 60)

    if not ROLE_ID or not SECRET_ID:
        print("[!] Missing VAULT_ROLE_ID or VAULT_SECRET_ID environment variables.")
        print("    Run vault/setup-vault.sh to generate role-id and secret-id.")
        sys.exit(1)

    app_token = login_with_approle(ROLE_ID, SECRET_ID)
    secret_data = fetch_secret(app_token)
    print(f"[+] Retrieved credentials for service account: {secret_data['username']}")
    print(f"    Password successfully read from safe: {secret_data['password'][:3]}********")

if __name__ == "__main__":
    main()

