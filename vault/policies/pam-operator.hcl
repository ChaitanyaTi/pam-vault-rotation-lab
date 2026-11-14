# ==============================================================================
# Policy: pam-operator
# Description: Restricted read/list access strictly to service accounts safe.
# CyberArk Mapping: Safe Member (Read/Use credentials only on target safe)
# Assigned to: alice
# ==============================================================================

# Allow reading secrets specifically within the service-accounts safe
path "secret/data/service-accounts/*" {
  capabilities = ["read", "list"]
}

# Allow reading metadata and version history for service accounts
path "secret/metadata/service-accounts/*" {
  capabilities = ["read", "list"]
}

# Explicitly deny access to Windows admin, Linux root, and AWS cloud credentials
path "secret/data/windows-admin/*" {
  capabilities = ["deny"]
}

path "secret/data/linux-root/*" {
  capabilities = ["deny"]
}

path "secret/data/aws/*" {
  capabilities = ["deny"]
}
