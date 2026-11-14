# ==============================================================================
# Policy: pam-admin
# Description: Full administrative privileges over all PAM secret safes and engines.
# CyberArk Mapping: Vault Admin / Safe Administrator
# ==============================================================================

# Manage KV v2 secrets across all safes (Windows, Linux, Service Accounts, AWS)
path "secret/data/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "secret/metadata/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Audit device management
path "sys/audit" {
  capabilities = ["read", "sudo"]
}

path "sys/audit/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

# Policy and authentication management
path "sys/policies/acl/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "auth/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

path "sys/auth/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}

