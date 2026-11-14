# ==============================================================================
# Policy: pam-auditor
# Description: Compliance and audit access - inspects metadata and versions ONLY.
# Capabilities: Strictly denies secret values (zero plain-text credential access).
# CyberArk Mapping: Safe Auditor / Compliance Reviewer
# ==============================================================================

# Allow listing and viewing metadata (versions, creation dates, rotation timestamps)
path "secret/metadata/*" {
  capabilities = ["read", "list"]
}

# Explicitly deny access to actual credential data values across all safes
path "secret/data/*" {
  capabilities = ["deny"]
}

# Allow auditor to verify audit log configuration
path "sys/audit" {
  capabilities = ["read"]
}

