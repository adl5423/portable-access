ui = false
disable_mlock = true
api_addr = "https://127.0.0.1:8200"
cluster_addr = "https://127.0.0.1:8201"

storage "raft" {
  path = "/var/lib/pap-kms/data"
  node_id = "pap-signing-1"
}

listener "tcp" {
  address = "127.0.0.1:8200"
  cluster_address = "127.0.0.1:8201"
  tls_min_version = "tls12"
  tls_cert_file = "/var/lib/pap-kms/credentials/server.crt"
  tls_key_file = "/var/lib/pap-kms/credentials/server.key"
  tls_client_ca_file = "/var/lib/pap-kms/credentials/client-ca.crt"
  tls_require_and_verify_client_cert = true
  max_request_size = 65536
  max_request_duration = "15s"
}

telemetry {
  disable_hostname = true
}
