# Append only after a protected backup and independent seal/recovery custody.
# The existing initialized instance requires the official seal migration ceremony.
seal "static" {
  current_key_id = "REPLACE_WITH_SHA256_OF_THE_INDEPENDENT_RANDOM_32_BYTE_SEAL_KEY"
  current_key = "file:///run/credentials/pap-openbao.service/seal-current"
}
