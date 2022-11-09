# general config for signle value vault
ui = true
disable_mlock = false
log_level = "info"
log_format = "json"
max_lease_ttl = "768h"
default_lease_ttl = "768h"
cluster_name = "https://localhost:8200"
api_addr = "https://localhost:8200"

listener "tcp" {
    address = "0.0.0.0:8200"
    cluster_address = "0.0.0.0:8200"
    tls_disable = 1
    tls_cert_file = "c:\vault\tls\vault-full.pem"
    tls_key_file = "c:\vault\tls\/vault-key.pem"
    tls_min_version = "tls12"
}

storage "file" {
    path = "c:\vault\data"
}
