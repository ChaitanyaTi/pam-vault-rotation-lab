# ==============================================================================
# HashiCorp Vault Server Configuration (Production / Persistent Lab Mode)
# ==============================================================================

storage "file" {
  path = "/opt/vault/data"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1 # Set to 0 with cert/key in production environments
}

ui = true
api_addr = "http://127.0.0.1:8200"
cluster_addr = "http://127.0.0.1:8201"
disable_mlock = true
