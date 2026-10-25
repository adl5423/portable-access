# Operator bootstrap and recovery

Use [pap-operator](operator-cli.md) for supported custody, public-key export and RAM-only recovery transport. This runbook explains the one-shot KMS bootstrap and interrupted-checkpoint contract. Initialize only a fresh dedicated instance; never rerun initialization against existing Raft state.

## Trust and custody

| Material | Normal location and purpose | Recovery treatment |
| --- | --- | --- |
| Enrollment CA private key | Root-owned `/etc/pap/enrollment/ca-key.pem`, inside a `0700` infrastructure directory; supplied to the unprivileged enrollment broker by systemd credentials | Included in the encrypted recovery packet; never distributed to applications |
| Operator CA private key | Generated only in bootstrap process memory; absent from plaintext VM files | Exists persistently only inside the encrypted recovery packet |
| Operator RSA private key | Operator-controlled custody, outside the VM | Unwraps the packet's AES key; never upload it to the VM |
| Operator RSA public key | Root-owned DER file, authenticated by a separate SHA-256 pin | Public; retain alongside the key's lookup metadata |
| Historical Shamir shares / post-migration recovery shares | Bootstrap or reviewed recovery process memory only | All five are encrypted in the original packet; threshold is three. After static-seal migration they authorize recovery operations but cannot substitute for the external seal key |
| Static-seal key | Separate private Netlify custody record; released to a boot recipient, then private guest tmpfs/systemd credentials | Independently encrypted successor packet also retains the key and predecessor recovery. No environment secret or persistent plaintext guest key |
| Boot RSA recipient private key | Fresh per attempt, process memory only | Not a persistent recovery credential; custody encrypts the released seal key to this recipient |
| Initial root token | Bootstrap process memory | Encrypted in the packet for interrupted-bootstrap recovery; revoked on successful completion |
| Issuer mTLS leaf and private key | Private issuer generation directory; one-hour leaf, renewed by the local broker | Replace automatically, including after the old leaf expires |
| Transit issuer private keys | Nonexportable OpenBao Transit storage | Recover through the sealed OpenBao storage backup, not PEM export |

The listener trusts both public CAs, but cert-auth roles separate their privileges. `pap-issuer` trusts only the enrollment CA and exact common name `pap-issuer`. `pap-operator` trusts only the distinct operator CA and exact common name `pap-operator`. A broker able to issue enrollment certificates cannot authenticate as an operator by changing a certificate's common name. Bootstrap tests this denial using an actual enrollment-CA-signed certificate.

Issuer tokens have a five-minute maximum lifetime, no default policy, loopback address binding, and certificate binding. The issuer can create/read P256 keys and sign pinned version one in the dedicated PAP Transit mount. It cannot export, delete, rotate, trim, or reconfigure keys, or edit authentication or policies. The ACL does not enforce a `pap-` name prefix inside this dedicated mount. Keep unrelated application keys in other mounts. Operator tokens are also short lived; their administrative policy is broad and must be treated as privileged access.

All five historical shares are recoverable with one operator RSA key. This is **single-operator custody**, despite the three-of-five threshold. It does not provide a three-person approval quorum. Losing that custody key and all usable recovery copies can make recovery impossible. Compromising it and the original packet exposes CA backups and shares. The successor packet also contains the static-seal key. After migration, losing every external seal-key copy makes storage unrecoverable even if shares and Raft backups remain.

## Historical Shamir initialization prerequisites

Use the enrollment-specific [Linux profile](../deploy/linux/README.md), OpenBao 2.7.1, a synchronized Linux clock, protected persistent storage, and root access on the dedicated host. The helper verifies root ownership, restrictive modes, CA/key consistency, clock synchronization, the operator public-key pin, and the local machine identity. Its endpoint is fixed to `https://127.0.0.1:8200`; it disables environment proxies and redirects.

The listener must already require client certificates and read the combined public trust bundle at `/etc/pap/openbao-client-ca.pem`. Initially that bundle contains only the enrollment CA. The helper adds the newly generated operator public CA and restarts only the still-uninitialized OpenBao service. It verifies the operator trust path before requesting initialization. It never restarts OpenBao after requesting initialization.

The OpenBao configuration must declare this audit device before initialization:

```hcl
audit "file" "pap" {
  description = "PAP security audit"
  options {
    file_path = "/var/lib/pap-kms/audit.jsonl"
    log_raw = "false"
    hmac_accessor = "true"
  }
}
```

Do not enable `unsafe_allow_api_audit_creation`. After unseal, the helper reads `/v1/sys/audit` and requires exactly the `pap/` file device and the settings above before it grants issuer access. OpenBao 2.7's [file-audit documentation](https://openbao.org/docs/audit/file/) recommends [declarative audit configuration](https://openbao.org/docs/configuration/audit/).

Prepare an RSA-4096 public key with exponent 65537, encoded as PKCS#1 DER or DER SubjectPublicKeyInfo. Confirm its SHA-256 fingerprint through a channel independent of its transfer to the host. Verify that the operator can unwrap a synthetic envelope with the actual private-key custody mechanism before initialization. A synthetic software-key round trip alone does not prove that a native keychain implementation accepts the wrapping parameters.

The supported `pap-operator` CLI provisions a native macOS Keychain identity or an encrypted-PEM identity, exports only its public key, and verifies recovery in RAM. Follow [operator custody](operator-cli.md) and retain the key fingerprint and nonsecret lookup metadata in independent custody. Never export the native private key to substitute a generic file workflow.

## Fresh-host plan and apply

Upload only your public operator DER and its independently checked SHA-256 pin. On the designated host, inspect the plan first. This helper journals one-shot initialization and refuses ambiguous retries.

```sh
sudo /opt/pap/venv/bin/python /opt/pap/source/tools/bootstrap_openbao.py \
  --operator-public-key /root/pap-bootstrap/operator-public.der \
  --operator-public-key-sha256 YOUR_VERIFIED_PUBLIC_DER_SHA256 \
  --machine-id YOUR_PROVIDER_MACHINE_ID --plan
```

After reviewing that plan, repeat the same arguments with `--apply`. Copy the encrypted recovery envelope off-host and verify authenticated decryption before enabling automatic seal custody. Preserve previous packets and receipts.

## Files, off-host copy, and envelope validation

| Path | Meaning |
| --- | --- |
| `/var/lib/pap-kms/operator-recovery.enc.json` | Root-owned `0600` encrypted recovery packet |
| `/etc/pap/enrollment/bootstrap-attempt.json` | Public, durable attempt journal; retain after completion |
| `/etc/pap/enrollment/bootstrap-receipt.json` | Public completion receipt and final envelope hash |
| `/etc/pap/enrollment/operator-ca.pem` | Public operator CA certificate |
| `/etc/pap/openbao-client-ca.pem` | Public listener bundle containing enrollment and operator CAs |
| `/var/lib/pap-kms/audit.jsonl` | Sensitive operational audit stream; OpenBao-owned `0600` |

After successful initialization, copy the **encrypted** packet and public completion receipt to operator-controlled storage outside the VM and its failure domain. Use an authenticated transfer, preserve restrictive destination permissions, and compare the copied packet's SHA-256 hash with `envelope_sha256` in the completion receipt. Retain a second encrypted backup under a deliberate retention policy. The host's packet is useful after a process restart; it is not an off-host disaster-recovery copy.

On the operator workstation, unwrap the copied packet using the real custody key and validate its authenticated metadata. Check the provider machine ID, local-host identity hash, operator public-key fingerprint, both CA fingerprints, final packet stage (`initialization-response-received`), and share count before relying on the backup. Verify that the recovered operator CA certificate matches its recovered private key. Perform these checks in memory without printing decrypted fields or writing a plaintext packet. Record only pass/fail, public fingerprints, and the encrypted packet's hash. A successful copy operation proves neither decryptability nor correct key custody.

The original packet supplements a protected, consistent backup of OpenBao Raft storage and PAP's durable authorization state. Shares alone do not reconstruct missing Transit keys. Authorization state retains revocation, grant and replay history. Keep data backup and recovery-packet versions associated with the same deployment.

Before changing a seal root, record how OpenBao Raft and PAP's authorization SQLite state were captured consistently. Quiesce authority writes or use a reviewed snapshot method that establishes their relationship. Bind the protected backup to the deployment, source revision and encrypted artifact hashes, copy it off host, and verify authenticated decryption through operator custody. Measure readiness restoration on that installation instead of assuming a recovery duration.

`pap-operator snapshot` captures OpenBao Raft only. Its receipt reports `authority_state_included=false`; it is not a complete PAP backup. Preserve a consistent copy of the authorization database with its revocation, grant, replay and connector-operation history. The separately encrypted static-seal successor must retain the required predecessor recovery material and pass its own in-memory decryption and deployment/key-binding checks. A successful backup or successor check establishes neither a complete isolated restore, a seal migration nor a cold boot.

The decryption contract below describes the original initialization envelope. A successor must be validated against its own authenticated schema and exact deployment/key binding; do not assume every encrypted packet is an interchangeable initialization packet.

### Standard decryption contract

The envelope is interoperable JSON, not a proprietary cryptographic format. A recovery implementation must enforce a bounded input size, reject duplicate JSON members, and reject unexpected algorithms before using it.

1. Read the envelope members `aad`, `wrapped_key`, `nonce`, and `ciphertext`. Base64 decoding uses the standard alphabet, with strict validation.
2. Require `aad.schema = "pap-openbao-operator-recovery-v1"`, `aad.cipher = "AES-256-GCM"`, and `aad.wrap = "RSA-OAEP-SHA256"`. Compare the expected deployment and public fingerprints with this metadata. These comparisons become authenticated only after GCM validation.
3. Decrypt `wrapped_key` with the operator's RSA-4096 private key using OAEP with SHA-256, MGF1-SHA256, and an **empty OAEP label** (`None` in Python cryptography). The result must be exactly 32 bytes. Schema binding belongs to GCM AAD; it is not an OAEP label.
4. Serialize the parsed `aad` as sorted-key JSON, `ensure_ascii=true`, separators `,` and `:`, with no added whitespace or newline. Those ASCII bytes are the authenticated additional data.
5. Decrypt using AES-256-GCM, the decoded 12-byte nonce, and the decoded `ciphertext`. The ciphertext includes the 16-byte GCM tag. Reject any authentication failure and release no partial plaintext.
6. Parse the authenticated plaintext as bounded, duplicate-free JSON. Validate its schema, deployment identity, CA/key pairs, and expected recovery stage. The completed initialization packet contains five distinct `unseal_shares`, threshold three, the initial root token, both CA backups, and the full initialization response.

The envelope's AAD also includes `machine_id`, `host_identity_sha256`, `operator_public_key_sha256`, `enrollment_ca_sha256`, `operator_ca_sha256`, `stage`, and `recorded_at`. The private key stays in the custody system; only the wrapped AES key needs its RSA operation. Python `cryptography` interoperability is exercised by the bootstrap tests; the selected native Keychain unwrap was separately validated. Neither result substitutes for validating each newly copied recovery packet.

## Reviewed completion of a durable checkpoint

The helper exposes an operator-integration method for one specific interrupted state: initialization material is durably encrypted, OpenBao is already initialized and unsealed, and PAP mounts, authentication, and policies have not yet been created. This is not an automatic retry mechanism or a cold-boot recovery client. The ordinary CLI remains unchanged and will refuse a partial bootstrap. There is no plaintext packet-file CLI option.

A trusted operator integration first validates/decrypts the pinned encrypted packet using the custody key, retaining its plaintext only in RAM. It supplies that authenticated dictionary and the independently reviewed encrypted-file SHA-256 to the root-only `Bootstrapper` instance. Do not serialize the plaintext packet into an argument, environment variable, log, or temporary file.

The method's public interface is:

```python
Bootstrapper.complete_checkpoint(
    packet: dict,
    expected_envelope_sha256: str,
    *,
    apply: bool = False,
    expected_plan_sha256: str | None = None,
)
```

The default call returns a public `checkpoint_plan` and `checkpoint_plan_sha256`. It holds the existing bootstrap lock, reads protected files, and performs only GET API requests. It requires all of the following:

- The encrypted file matches the exact expected hash, its AAD identifies this host/operator/CA binding, and its stage is `initialization-response-received`.
- The journal is exactly `recovery_envelope_durable`, references that envelope, and no completion receipt exists.
- The authenticated packet has five distinct, well-formed shares, threshold three, and an initialization response matching its root token and shares. Both recovered CA keys match their certificates; certificates, fingerprints, public trust files, and host identity match the deployment.
- OpenBao reports initialized, unsealed, active-node health. The existing token's lookup reports that same token ID and exactly the `root` policy.
- The declarative audit device has the required settings. `sys/mounts` and `sys/auth` show no Transit or certificate-auth backend, and both `pap-issuer` and `pap-operator` policy reads return 404.

Review and retain the **public plan only**. An apply call must provide that exact `checkpoint_plan_sha256`. It repeats the full checks under the lock and rejects any changed journal, packet, trust binding, or partial server configuration. An accepted apply journals its approval, runs the same audited configuration and actual positive/negative probes as ordinary bootstrap, revokes the initial root token, and writes the completion receipt. It does not initialize, unseal, restart OpenBao, replace trust files, or rewrite the encrypted envelope.

The receipt records `checkpoint_completion=true`, the approved plan hash, and the original attempt hash. It retains the public approval/configuration journal records with their `previous_attempt_sha256` links, allowing their hashes to be checked against the final journal. A failed completion does not authorize repeating administrative requests: preserve its journal and return to operator review. Mount, authentication, or policy creation after the reviewed checkpoint makes this narrow method refuse further work.

The local real-OpenBao checkpoint test deliberately stopped at the durable checkpoint, exercised the read-only plan, then completed it using the approved plan hash. It verified that completion made no initialization or unseal request and no service restart, kept the encrypted packet unchanged, and revoked the initial root token. This does not establish a particular live host's recovery result.

## Interrupted or uncertain initialization

Never delete the journal or encrypted packet to make a failed apply look fresh. Never rerun an uncertain initialization request, wipe raft storage, or restart a partially initialized service automatically. Inspect public status, the journal, the encrypted packet's hash/stage, and the completion receipt under operator control.

| Observed state | Required action |
| --- | --- |
| Fresh, uninitialized, no attempt artifacts | Plan, review, then run one apply |
| `prepared` or pre-initialization packet exists | Stop automatic work; review public status and partial trust changes before a deliberate recovery decision |
| `initialization_requested` or `initialization_outcome_unknown` | Treat the server outcome as unknown; do not repeat POST init |
| `recovery_envelope_durable` | Validate/decrypt the packet in operator custody; recover the initialized server using that material |
| `configured` without a complete receipt | Review root-token revocation and configuration using operator recovery credentials; do not assume success or repeat bootstrap |
| Initialized with a matching complete receipt and envelope | A helper rerun verifies the recorded binding and returns `already_complete`; it does not unseal or reinitialize |
| Initialized without a matching complete receipt | Stop for manual operator review |

There is an unavoidable boundary between OpenBao creating its first initialization response and the helper durably encrypting that response. If the response is lost or the process dies in that interval, a pre-initialization envelope cannot contain shares that were never received. The journal prevents a dangerous automatic retry; it cannot recreate lost material. A transport timeout is therefore an uncertain outcome, not proof that initialization failed. Any decision to abandon unrecoverable fresh storage must be explicit and must not destroy an existing deployment.

## Automatic pause and cold-boot recovery

A paused VM can resume with OpenBao still unsealed. The enrollment broker replaces expired issuer and listener leaves without relying on the expired certificates or an existing OpenBao token. OpenBao reloads listener material and the issuer obtains a fresh certificate-bound token. Authenticated time and network recovery can delay that process; enforce bounded retries and fail closed on identity/policy denials.

The [independent static-seal profile](cold-boot-profile.md) retrieves the externally held seal key at each guest boot. The boot helper keeps its recipient private key in RAM, verifies the response/key pin and places the seal key only in protected tmpfs for OpenBao's systemd credential. Missing custody, a proof/pin failure or the persistent incident lock prevents startup. The proof gateway starts independently of KMS readiness. Do not undo a deliberate lock or infer withdrawal of a key that has already reached trusted guest memory.

Use [the operator CLI](operator-cli.md) to prepare an encrypted successor and provision the separate custody project before any reviewed migration. Preserve predecessor recovery, the consistent encrypted backup and both seal generations. After migration, test an actual changed-boot cold start and both protected Netlify reads. A successful boot does not prove restoration from a lost disk or establish an availability SLO. Enrollment/operator CA rollover is a separate operation.

## Historical Shamir unseal and operator recovery

The earlier Shamir profile starts sealed after a cold boot or OpenBao restart and needs operator unseal. The following procedure applies to that profile. After static-seal migration, the old shares are recovery shares, and they cannot decrypt storage without the external seal key. Never treat the following share submission as a replacement for custody release or a lost static-seal key.

Historical manual unseal requires a trusted operator process with authenticated access to the loopback-only TLS listener. That process must:

1. Validate/decrypt the correct off-host recovery packet in memory. Create a short-lived `ClientAuth` leaf with common name `pap-operator` signed by the recovered operator CA; keep its private key and the CA key in protected process memory.
2. Establish authenticated TLS to the host's loopback OpenBao listener and verify its enrollment-CA server chain and identity. A remote workflow needs a separately authenticated tunnel or privileged local helper; port 8200 is not a public recovery endpoint.
3. Read seal status and submit three distinct recovered shares to `/v1/sys/unseal`, one per JSON request, while retaining them only in memory. Check the resulting seal state and configured threshold. Do not pass shares through shell arguments, environment variables, temporary files, terminal output, or command history.
4. When privileged administration is needed, log in to `/v1/auth/cert/login` with `name: "pap-operator"` over that operator mTLS connection. Keep the short-lived token only in memory and revoke it after the operation. A completed bootstrap's original root token is revoked and is not a normal recovery credential.
5. Verify signer readiness, fresh issuer enrollment/login, and preserved authorization/revocation state. Record public acceptance evidence before restoring traffic.

The supported `pap-operator unseal` command implements this RAM-only operator workflow for the historical Shamir profile. `pap-operator snapshot` encrypts an off-host Raft snapshot in operator custody. Do not substitute commands that expose shares or private keys. The independent boot client implements a separate static-seal mechanism. Root CA expiry/rollover, seal-root migration and recovery from hostile infrastructure still require deliberate procedures; automatic leaf renewal does not renew those roots.

## Audit operations and evidence limits

The file audit device records API activity with sensitive values HMAC-protected; `log_raw=false` does not make the entire audit stream public. Restrict access and transport it as sensitive operational data. Bootstrap verifies the configured device, and the isolated acceptance test verifies the newly created audit file is `0600`. Check the actual host permissions separately. The profile does **not** install an audit rotation service or off-host log collector.

Operators must monitor disk capacity, audit-write failures, log growth, CA expiry margins, and service readiness; provision retention and rotation before sustained traffic. Rotate through OpenBao's supported file-audit reopen procedure and verify logging afterward. Do not assume renaming a file moves the active descriptor, use unreviewed truncation, or disable auditing to restore capacity. An unavailable audit sink can prevent OpenBao from serving requests. Review the deployed version's [file-audit operations](https://openbao.org/docs/audit/file/) when implementing this runbook.

Keep acceptance evidence specific to the run it describes. An isolated OpenBao fixture should record its source revision, binary or image digest, temporary-state cleanup, and whether it exercised a real host clock. Actual signing, denied administrative operations, encrypted recovery validation and root-token revocation are separate results to verify. A fixture receipt does not establish a particular host's initialization, public network availability, native systemd confinement, cold-boot recovery, audit rotation or a complete deployment. A full restore must independently demonstrate continuity of PAP policy and revocation state as well as recovered KMS keys.
