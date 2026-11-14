#!/usr/bin/env python3
"""
Interactive Runner for Phase 3: Application Security Transformation Demo
Runs both before_hardcoded_app.py and after_vault_app.py against local Vault API.
Keeps terminal open for capturing screenshot: phase3-app-code-diff.png
"""

import os
import sys
import time
import subprocess
import importlib.util

# Import mock vault from generate-lab-evidence.py
spec = importlib.util.spec_from_file_location("gle", os.path.join(os.path.dirname(__file__), "generate-lab-evidence.py"))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

server = mod.start_mock_vault(8200)

try:
    os.system("cls" if os.name == "nt" else "clear")
    print("=" * 70)
    print(" [PHASE 3] APPLICATION CREDENTIAL ONBOARDING & VAULT INTEGRATION ")
    print("=" * 70)
    print("\n--- 1. RUNNING LEGACY VULNERABLE APPLICATION (Hardcoded Secret) ---\n")
    subprocess.run([sys.executable, "apps/before_hardcoded_app.py"])

    time.sleep(1)
    print("\n" + "=" * 70)
    print("\n--- 2. RUNNING SECURE REFACTORED APPLICATION (Vault REST API Fetch) ---\n")
    env = os.environ.copy()
    env["VAULT_ADDR"] = "http://127.0.0.1:8200"
    env["VAULT_TOKEN"] = "s.operator_token"
    subprocess.run([sys.executable, "apps/after_vault_app.py"], env=env)

    time.sleep(1)
    print("\n" + "=" * 70)
    print("\n--- 3. RUNNING MACHINE-TO-MACHINE APPROLE INTEGRATION (Stretch Goal) ---\n")
    env["VAULT_ROLE_ID"] = "role-billing-webapp-id"
    env["VAULT_SECRET_ID"] = "secret-credential-token-id"
    subprocess.run([sys.executable, "apps/approle_vault_app.py"], env=env)

    print("\n" + "=" * 70)
    print(" [✓] EXECUTION COMPLETE! READY FOR SCREENSHOT ")
    print("=" * 70)
    print("\n👉 ACTION: Press Win + Shift + S to take screenshot of this window.")
    print("   Save as: screenshots/phase3-app-code-diff.png")
    print("   Press Enter in this window once you have taken the screenshot...\n")
    input()

finally:
    server.shutdown()

