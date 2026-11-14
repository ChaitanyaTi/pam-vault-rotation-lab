# ==============================================================================
# Policy: pam-rotation-engine
# Description: Minimal least-privilege policy for automated credential rotation scripts (CPM role).
# Allows staging pending passwords, updating verified credentials, and writing rotation metadata.
# ==============================================================================

path "secret/data/*" {
  capabilities = ["create", "read", "update"]
}

path "secret/metadata/*" {
  capabilities = ["read", "list"]
}
