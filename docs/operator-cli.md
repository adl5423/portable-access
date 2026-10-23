# Operator custody and recovery CLI

`pap-operator` ships with the Python package. Install the release on the operator workstation and the dedicated Linux authority host. The workstation unwraps encrypted recovery material. The Linux receiver issues a five-minute operator certificate and loads its private key through sealed Linux `memfd` descriptors. No command accepts a provider credential, recovery share, CA private key or passphrase as an argument or environment variable.

This tool does not initialize an existing OpenBao installation, reset Raft, bypass an incident lock, or turn a snapshot into a tested disaster-recovery plan. Read [the independent deployment guide](../deploy/linux/README.md), [the recovery contract](operator-recovery.md), and [the cold-boot profile](cold-boot-profile.md) before changing infrastructure custody.

## Custody choices

| Backend | Persistent material | Operational constraint |
| --- | --- | --- |
| `keychain` | Nonextractable RSA-4096 software key in macOS Keychain; public DER and lookup metadata in an owner-only directory | Requires the original accessible Keychain. This is software OS custody, not Secure Enclave or HSM custody. |
| `encrypted-pem` | Passphrase-encrypted PKCS#8 RSA-4096 file in an owner-only directory | The private key enters process memory while unlocked. Keep the passphrase in independent operator custody. |

Create one identity on a trusted operator workstation:

```sh
pap-operator custody-create --backend keychain \
  --directory /absolute/operator-private/operator-key
```

On Linux or another supported Python workstation:

```sh
pap-operator custody-create --backend encrypted-pem \
  --directory /absolute/operator-private/operator-key
```

The PEM command prompts without echo and requires a new passphrase of at least 16 bytes. Automation may supply `--passphrase-fd 3` with an independently inherited descriptor. The descriptor must contain the passphrase, then close. Do not substitute a secret into a shell command, use a plaintext passphrase file, or export it as an environment variable.

The directory contains `keychain-key.json` and `operator-public.der`. The PEM backend also creates `operator-private.pem`, encrypted at rest. New files use mode `0600`, their directory requires `0700`, symlink inputs and unsafe parent directories are rejected, and existing files are never overwritten. The metadata filename is the same for both backends.

Export only the public key for the bootstrap host or an encrypted provider-key creation flow:

```sh
pap-operator public \
  --custody /absolute/operator-private/operator-key/keychain-key.json
```

The result contains the RSA JWK and SHA-256 pin. DER output uses PKCS#1, matching `SecKeyCopyExternalRepresentation`. Public-key parsing also accepts SubjectPublicKeyInfo. Pins cover the exact DER bytes. Do not convert an already pinned key's DER encoding without updating its independently verified pin.

The native backend can read metadata from pre-CLI deployments containing `application_tag` and `public_key_sha256`. It never exports the Keychain private key.

## Inspect and verify an encrypted recovery copy

Copy only the encrypted packet and public receipt off the authority host. Preserve the original packet and retain an independent second encrypted backup. Inspection does not authenticate its metadata:

```sh
pap-operator inspect --packet /absolute/operator-private/bootstrap.enc.json
```

Use a trusted receipt and independently checked provider-machine and local-host identities for verification:

```sh
pap-operator verify \
  --custody /absolute/operator-private/operator-key/keychain-key.json \
  --packet /absolute/operator-private/bootstrap.enc.json \
  --machine-id YOUR_PROVIDER_MACHINE_ID \
  --host-identity-sha256 YOUR_LOCAL_MACHINE_ID_SHA256 \
  --envelope-sha256 YOUR_ENCRYPTED_PACKET_SHA256 \
  --stage initialization-response-received
```

`YOUR_LOCAL_MACHINE_ID_SHA256` is SHA-256 of the target Linux host's `/etc/machine-id` bytes with surrounding whitespace removed. It is distinct from a provider's machine ID. Do not learn the expected identity solely from the packet being verified.

Verification enforces RSA-4096 OAEP with SHA-256 and an empty OAEP label, strict base64, duplicate-free bounded JSON, AES-256-GCM with canonical authenticated metadata, exact custody/deployment pins, both CA/private-key matches and certificate fingerprints. Plaintext exists only in the operator process. Output contains public outcome fields and hashes.

## Prepare static-seal custody before migration

The successor command requires a completed original initialization packet. It generates a fresh 32-byte static-seal key, encrypts it together with the predecessor recovery material, immediately unwraps and validates the new packet, then exclusively creates and rereads the encrypted output and public custody receipt. It leaves the predecessor file intact.

```sh
pap-operator successor \
  --custody /absolute/operator-private/operator-key/keychain-key.json \
  --packet /absolute/operator-private/bootstrap.enc.json \
  --machine-id YOUR_PROVIDER_MACHINE_ID \
  --host-identity-sha256 YOUR_LOCAL_MACHINE_ID_SHA256 \
  --envelope-sha256 YOUR_ENCRYPTED_PACKET_SHA256 \
  --deployment-id YOUR_DEPLOYMENT_ID \
  --output /absolute/operator-private/static-seal.enc.json \
  --receipt /absolute/operator-private/static-seal-custody.json
```

The receipt's `key_id` is SHA-256 of the static key. Put that public pin in the boot and separate custody configurations. Migration still uses the reviewed plan/apply contract in `tools/migrate_static_seal.py`. Creating a successor does not migrate OpenBao or authorize replacing an existing seal root.

Deploy the independent Netlify seal service using its [deployment instructions](../adapters/netlify-seal/README.md). Build that adapter before provisioning. Its public configuration must identify a different site from the application and bind the same deployment, machine, authority origin and key ID. Then provision its private Blobs record directly from encrypted operator custody:

```sh
pap-operator custody-provision \
  --custody /absolute/operator-private/operator-key/keychain-key.json \
  --packet /absolute/operator-private/static-seal.enc.json \
  --machine-id YOUR_PROVIDER_MACHINE_ID \
  --host-identity-sha256 YOUR_LOCAL_MACHINE_ID_SHA256 \
  --envelope-sha256 YOUR_SUCCESSOR_PACKET_SHA256 \
  --config /absolute/checkout/adapters/netlify-seal/src/config.public.json \
  --helper /absolute/checkout/adapters/netlify-seal/tools/provision.mjs \
  --netlify-token-fd 3
```

Provide a short-lived Netlify operator token on separately inherited FD 3 from your operator credential manager. The command passes that descriptor to the trusted helper, streams the canonical private record through stdin, and prints only a public receipt. The helper performs conditional creation and readback. A different or revoked existing record is never overwritten. Use its documented `--revoke` operation when withdrawing custody. Neither the token nor the static key belongs in Netlify application environment variables.

## Add provider-key custody to an existing authority

Fresh bootstrap includes the dedicated derived Transit key. For an existing authority, the KMS command logs in with a five-minute operator mTLS identity and returns a public plan. The SSH host must already be present in a trusted `known_hosts` file. The command requires noninteractive privilege to run the installed receiver on the dedicated host:

```sh
pap-operator kms-provision \
  --custody /absolute/operator-private/operator-key/keychain-key.json \
  --packet /absolute/operator-private/bootstrap.enc.json \
  --machine-id YOUR_PROVIDER_MACHINE_ID \
  --host-identity-sha256 YOUR_LOCAL_MACHINE_ID_SHA256 \
  --envelope-sha256 YOUR_ENCRYPTED_PACKET_SHA256 \
  --target operator@your-authority.example \
  --known-hosts /absolute/operator-private/known_hosts
```

Apply the same invocation with `--apply --plan-sha256 THE_RETURNED_PLAN_HASH` after checking the plan. Automation can check the plan deterministically against its approved deployment policy and supply that hash. The receiver recomputes the plan immediately before applying it.

This operation creates only `transit/keys/pap-provider-credentials`, with type `aes256-gcm96`, `derived=true`, no export or plaintext backup, and daily automatic KMS key rotation. It appends exact read/encrypt/decrypt rules to `pap-issuer` without replacing its signing policy. It rejects an incompatible existing key or provider rule and verifies both writes. It never creates mounts, edits certificate authentication, uses an initial root token, initializes storage or unseals a static-seal deployment.

The automatic KMS rotation protects newly encrypted records using newer key versions. OpenBao keeps older versions to decrypt existing ciphertext. Upstream provider API-key replacement is a separate lifecycle and requires that provider's issuance/revocation API.

## Import and revoke upstream provider credentials

For OpenAI, use a separate project-scoped demo key, created through a provider flow that returns RSA-OAEP-SHA256 ciphertext to the operator's public JWK. Keep the encrypted connector response outside the source repository. The supported custody wrapper schema is `pap.operator.provider-custody.v1`, with `name`, `organization_id`, `project_id`, `recipient_public_der_sha256` and the unmodified connector `creation_result`. Existing encrypted PAP demo custody packets use this schema. The tool checks every supplied identity before unwrapping the connector's version-one base64url ciphertext.

```sh
pap-operator credential-import \
  --custody /absolute/operator-private/operator-key/keychain-key.json \
  --provider openai \
  --encrypted-openai-backup /absolute/operator-private/openai.enc.json \
  --name YOUR_KEY_NAME \
  --organization-id YOUR_OPENAI_ORGANIZATION \
  --project-id YOUR_OPENAI_PROJECT \
  --target operator@your-authority.example \
  --known-hosts /absolute/operator-private/known_hosts
```

NASA, NLR and other provider-side creation flows can supply a credential through a separately inherited `--secret-fd 3` instead of `--encrypted-openai-backup`. Currently supported broker provider names are `openai`, `nasa` and `nlr`. Do not put a credential in `--secret-fd` itself; the argument is the descriptor number. The current free examples document whether they use public `DEMO_KEY` starter credentials or dedicated registered keys.

The root receiver reads its authenticated SSH stdin, resolves the dedicated `pap-admin` and `pap-issuer` accounts, drops all supplementary groups and root privileges to `pap-admin`, and makes one POST to `/v0/connectors/credentials` through `/run/pap-admin/admin.sock`. It checks the socket owner against the admin account and Linux peer credentials against the distinct issuer account. The authority encrypts the credential with provider-specific derived KMS context before persisting it. Neither application deployments nor public HTTP callers can use this import endpoint.

An import is a replacement operation. Rotate centrally by importing the new upstream credential and then revoking the previous credential through the provider. Revoke all broker access to one provider with:

```sh
pap-operator credential-revoke --provider openai \
  --target operator@your-authority.example \
  --known-hosts /absolute/operator-private/known_hosts
```

This revokes access in the central broker. It does not claim the upstream provider has revoked its API key. Use grant/subject revocation for a single application while other applications keep working. Provider imports and revocations perform no automatic retries after uncertain outcomes.

## Historical Shamir recovery and encrypted snapshots

`unseal` is restricted to an existing Shamir deployment with zero partial unseal progress. It checks the configured threshold and submits at most that many distinct shares once over loopback mTLS. It refuses static-seal share submission, which cannot replace a missing external key. Use the same pinned recovery and SSH arguments as `kms-provision`, changing the command to `unseal`.

`snapshot` obtains a Raft snapshot over operator mTLS, transports it through authenticated SSH and encrypts it before exclusively creating the requested `--output` file. This bounded helper accepts snapshots up to 8 MiB. For larger deployments, implement a reviewed streaming encrypted backup pipeline with the same custody and identity checks. It does not silently fall back to plaintext disk. The current helper's receipt explicitly reports `authority_state_included=false`; coordinate a consistent backup of PAP's authorization SQLite state and revocation/replay history separately. A Raft snapshot alone is insufficient to restore PAP's complete authorization state.

No tool in this release performs automatic destructive restore. Test a complete isolated restoration, authorization/revocation continuity and a real changed boot before accepting a deployment for production traffic.

## Failure behavior and boundaries

All receivers require a dedicated trusted Linux root SSH session. They are not public endpoints or generic remote execution tools. SSH uses strict host verification, no TTY, no shell interpolation, explicit timeouts and a small inherited environment that contains no provider credentials. The receiver verifies the local machine identity before using recovered CA material.

A transport timeout can follow a successful mutation. The CLI reports an unknown outcome and does not retry automatically. Inspect protected server/provider state and retain any partial receipt or created file before deciding the next action. File creation uses exclusive creation and fsync; an incomplete output remains as evidence rather than being overwritten.

Python and OpenSSL may retain temporary immutable byte copies until process exit. Disable core dumps and swap exposure on sensitive operator hosts, restrict tracing and process inspection, and treat workstation/root compromise as a custody compromise. The design keeps secrets out of argv, environment variables, application processes, logs and plaintext files. It does not claim that a general-purpose operator process is an HSM.
