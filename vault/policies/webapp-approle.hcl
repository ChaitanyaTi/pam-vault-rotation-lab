# ==============================================================================
# Policy: webapp-approle
# Description: Least-privilege policy for application identity consuming svc_webapp credentials.
# CyberArk Mapping: Application Access Manager (AAM) / Credential Provider
# ==============================================================================

path "secret/data/service-accounts/svc_webapp" {
  capabilities = ["read"]
}

