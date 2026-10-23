# Independent cold-boot seal custody

This profile adds automatic cold-boot recovery to the Linux enrollment deployment. OpenBao uses its official built-in static seal. A separately deployed Netlify service retains the random 32-byte seal key and releases it only to a fresh ephemeral recipient whose exact request is published through the registered Instabox HTTPS origin. Applications receive neither this seal key nor OpenBao credentials.

This is an installable reference profile. Each deployment must test an actual memory-discarding boot and a separate pause past certificate expiry before relying on unattended recovery. Local tests do not establish an availability SLO or production acceptance. The profile adds no hardware attestation, TPM, HSM or protection against VM root, Instabox routing administrators, or administrators/trusted deployment code of the independent custody project. It does not automate seal-root or CA rotation.

## Trust and startup order

```mermaid
flowchart TD
    Mounts[Verified persistent mounts] --> Gateway[Independent Caddy gateway]
    Clock[Authenticated time synchronization] --> Boot[Root boot client]
    Gateway --> Boot
    Boot -->|Public ephemeral request only| Proof[/run/pap-boot/public]
    Custody[Independent Netlify seal custody] -->|RSA-OAEP encrypted response| Boot
    Custody -->|Fetch exact registered HTTPS proof| Gateway
    Boot -->|Raw key in protected tmpfs| Runtime[/run/pap-boot/private/current.key]
    Runtime --> Credential[systemd LoadCredential]
    Broker[Local enrollment broker] --> Bao[OpenBao static seal]
    Credential --> Bao
    Bao -->|Fresh authenticated KMS login| Authority[PAP authority]
```

The gateway must start without waiting for the PAP authority. Install the independent [pap-caddy.service](../deploy/linux/systemd/pap-caddy.service) main unit together with [boot-origin.conf](../deploy/linux/systemd/pap-caddy.service.d/boot-origin.conf). The main unit must contain no ordering or activation dependency on the authority or KMS. Empty dependency assignments in a systemd drop-in do not remove inherited dependencies; replacing the old main unit is required. Otherwise the boot client waiting for its public proof creates an ordering cycle through OpenBao and the authority. Verify the effective graph with `systemd-analyze verify` before activation.

[pap-boot.service](../deploy/linux/systemd/pap-boot.service) is a root-only oneshot with `RemainAfterExit=yes`. It waits through temporary time or custody outages with a capped backoff, then exits after preparing one key. OpenBao requires this completed unit and receives the key through [boot-static-seal.conf](../deploy/linux/systemd/pap-openbao.service.d/boot-static-seal.conf). The helper never calls an unseal API, watches a running OpenBao process, or reacts to an administrator sealing it. An explicit OpenBao restart can auto-unseal, which is the behavior of the configured seal.

The supplied authority [boot recovery drop-in](../deploy/linux/systemd/pap-authority.service.d/boot-recovery.conf) removes its previous ten-start cutoff, which can be exhausted before trusted time returns. Install the corresponding [enrollment broker drop-in](../deploy/linux/systemd/pap-enroller.service.d/boot-recovery.conf) too. A dependency readiness failure remains retryable without broadening authorization. A permanent configuration or policy denial remains visible and fails closed.

## Public configuration and files

Resolve the live IDs and group from the designated host into [boot.example.json](../deploy/linux/boot.example.json), then install it as root:root mode `0600` at `/etc/pap/boot.json`. The configuration is public policy, with exactly these members:

| Member | Constraint |
| --- | --- |
| `seal_origin` | Registered production `https://SITE.netlify.app` origin, with no preview prefix, credentials, port, path, query or fragment |
| `proof_origin` | Registered `https://8080-MACHINE.instabox.tech` origin; the custody service must independently pin the same value |
| `machine_id` | Explicit provider machine ID beginning `m_` |
| `deployment_id` | Operator-selected independent custody binding; replace `example-deployment` |
| `key_id` | Lowercase SHA-256 of the independent random 32-byte seal key |
| `proxy_gid` | Actual dedicated `pap-proxy` primary group ID |

The example's key ID is intentionally invalid until provisioned. The client does not derive a seal key from this ID or any machine identifier. A SHA-256 identifier is safe here because the underlying key has 256 bits of independent randomness.

| Path | Owner and mode | Purpose |
| --- | --- | --- |
| `/run/pap-boot` | root:root `0755` | Runtime-only parent |
| `/run/pap-boot/public` | root:pap-proxy `0750` | Only public ephemeral request records |
| `/run/pap-boot/public/UUID.json` | root:pap-proxy `0440` | Exact canonical public request, removed when the attempt finishes |
| `/run/pap-boot/private` | root:root `0700` | Private runtime directory |
| `/run/pap-boot/private/current.key` | root:root `0400` | Exactly 32 raw bytes, never persisted outside tmpfs on the VM |
| `/run/pap-boot/private/boot.lock` | root:root `0600` | Process exclusion lock |
| `/run/credentials/pap-openbao.service/seal-current` | systemd protected credential | OpenBao's read-only seal input |
| `/etc/pap/boot.locked` | root-owned persistent nonsecret latch | Any presence blocks boot retrieval, cached-key reuse and new OpenBao starts |

The helper rejects non-tmpfs runtime storage, enabled swap, symbolic links, untrusted ancestors, unexpected modes or owners, hard-linked private files, and an existing key that does not match the public SHA-256 pin. It disables core dumps and process dumpability before generating a recipient key. The systemd unit also sets `MemorySwapMax=0`, `LimitCORE=0`, a 256 MiB memory limit, and a capability bound containing only `CAP_CHOWN`, required to assign public proof records to the proxy group.

`/proc/swaps` and `/proc/sys/kernel/random/boot_id` must be visible to this specific helper. Do not add `ProcSubset=pid`; that would hide the data used by its fail-closed checks. The helper does not print requests, responses, private keys or seal bytes. Python's managed memory does not provide guaranteed secret zeroization. Root and the provider remain trusted.

## Persistent incident lock

Disabling remote custody prevents a future retrieval. It cannot erase a seal key already delivered into the running VM. Use the persistent local latch for an incident stop. The client checks `/etc/pap/boot.locked` with `lstat` before cached-key reuse, before any attempt, and immediately before writing a recovered key. Any presence, including a directory or dangling symlink, stops it with terminal `boot_locked`. The root-owned configuration directory prevents application users from creating or removing this latch.

The OpenBao drop-in separately blocks a new start when the latch exists, even if the boot oneshot remains active with a cached key. `ConditionPathExists` covers an ordinary path and a pre-start `test ! -L` guard covers a dangling symlink. No automatic path removes or ignores the latch.

As root, create the nonsecret latch without following or replacing an existing entry and fsync the directory before stopping services:

```sh
sudo python3 - <<'PY'
import os
path = "/etc/pap/boot.locked"
try:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
except FileExistsError:
    pass
else:
    try:
        os.fchmod(fd, 0o600)
        os.fsync(fd)
    finally:
        os.close(fd)
parent = os.open("/etc/pap", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    os.fsync(parent)
finally:
    os.close(parent)
PY
sudo systemctl stop pap-openbao.service pap-boot.service
```

Verify that both units are inactive and that their processes have exited. Stopping OpenBao also stops its dependent authority. Only after that verification remove `/run/pap-boot/private/current.key`; do not delete persistent Raft state, authorization state, CA material or recovery packets. A live process may retain its loaded credential even when a source file is deleted, so deletion alone is not an incident stop.

After remediation, an operator must deliberately remove the latch, fsync `/etc/pap`, reset failed units as needed, and explicitly restart the normal service chain. Do not automate that unlock. A dangling or unexpected latch entry should be investigated before removal. Remote custody policy and this persistent local lock are separate controls.

## Boot release protocol version 1

The boot client generates a new RSA-4096 recipient key with exponent 65537 for each attempt. Its private half remains in process memory. It publishes an exact canonical UTF-8 JSON record and sends those same bytes to `POST SEAL_ORIGIN/v1/boot/release`.

The request has exactly these fields:

```json
{
  "v": 1,
  "request_id": "UUIDv4",
  "deployment_id": "example-deployment",
  "machine_id": "m_PROVIDER_MACHINE_ID",
  "boot_id": "LINUX_BOOT_UUID",
  "key_id": "LOWERCASE_SHA256_OF_SEAL_KEY",
  "nonce": "BASE64URL_OF_32_RANDOM_BYTES_WITHOUT_PADDING",
  "iat": 1792706600,
  "exp": 1792706720,
  "recipient_jwk": {"kty": "RSA", "e": "AQAB", "n": "BASE64URL_OF_512_BYTE_MODULUS"}
}
```

Canonical encoding sorts object members recursively, uses compact separators, rejects duplicate members and non-finite numbers, and includes no trailing newline. All protocol string values are ASCII. Request validity is at most 120 seconds. Both ends enforce exact identity, algorithm and key bindings. The client verifies trusted time before publication and again before accepting a response.

The custody service fetches only the registered origin's exact `/.well-known/pap/boot-proof/REQUEST_UUID` route. It must verify TLS, resolve and pin public IP addresses, reject redirects and proxies, bound time and bytes, and compare the returned bytes with the canonical request. A caller-controlled URL or echo endpoint is not a valid proof.

The response has exactly `v`, `request_id`, `key_id` and `wrapped_key`. `wrapped_key` is canonical unpadded base64url of a 512-byte RSA ciphertext. Encryption uses RSA-OAEP with SHA-256 for OAEP and MGF1, and the 32-byte SHA-256 digest of the canonical request as the OAEP label. The plaintext is exactly the 32-byte seal key. The client verifies the response binding, decrypts, checks the raw key's SHA-256 pin, and atomically writes the runtime credential.

Temporary network errors and HTTP 409, 429, 500, 502, 503 or 504 trigger a fresh request, nonce and recipient key after a capped 30-second backoff. HTTP 401 is retryable only when its bounded, strict JSON body is exactly `{"error":"proof_expired"}`. Other 401 responses and every 403 denial are terminal. A backend may support safely idempotent retries of the same request, but this client does not rely on that behavior. Authorization denials, invalid responses and pin failures exit with status 78 and are not automatically restarted by the unit. An operator can correct the policy or configuration and explicitly restart the unit. Clock unavailability remains retryable and does not issue a request.

Use the [Caddy proof fragment](../deploy/linux/caddy/boot-proof.fragment.example) inside the existing origin block before its fallback. It serves only canonical UUIDv4 filenames below the public directory, with no directory browsing and `Cache-Control: no-store`. It must not serve the runtime parent or private directory. The provider terminates public HTTPS in the Instabox profile, so the provider's origin routing is part of the proof's trust model.

## Official seal configuration and migration

Append the provisioned [static seal block](../deploy/linux/openbao/static-seal.boot.example.hcl) to the existing initialized OpenBao configuration. `current_key_id` is the public pin and `current_key` is `file:///run/credentials/pap-openbao.service/seal-current`. No secret belongs in HCL or an environment variable. The official static seal is built into OpenBao 2.7, so it requires no external provider plugin. See [OpenBao static seal configuration](https://openbao.org/docs/configuration/seal/static/).

An existing Shamir-sealed instance requires an explicit seal migration. Before restarting it, take a protected consistent backup and establish a verified, independently encrypted successor recovery packet containing the static key and its deployment binding. Preserve the old packet and its hash. Use the actual existing threshold through the authenticated migration API with shares in memory. Never initialize a replacement instance to bypass a failed migration, copy plaintext shares into a service file, or remove the existing attempt journal.

After migration the old shares authorize recovery operations, but they cannot recover storage without the independent seal key. Losing the seal key can make storage unrecoverable even when recovery shares and Raft backups exist. Deleting or rotating the remote key requires deliberate retention of the historical keys still needed for existing data. This profile has a single pinned seal generation; it does not claim automatic seal-root rotation. The application and issuer credential lifecycles remain independent. See [OpenBao seal migration and recovery semantics](https://openbao.org/docs/concepts/seal/).

After the reviewed migration and restart check, persistently enable the entire stack. Starting a service does not enable it for the next boot, and the boot helper's `Before=` ordering does not activate OpenBao or the authority:

```sh
sudo systemctl enable pap-admin.socket pap-authority.service pap-enroller.service \
  pap-openbao.service pap-caddy.service pap-boot.service
sudo systemctl is-enabled pap-admin.socket pap-authority.service pap-enroller.service \
  pap-openbao.service pap-caddy.service pap-boot.service
```

Require `enabled` for every unit, verify the persistent mount dependencies, and confirm authority readiness before the memory-discarding lifecycle test. Enabling units alone does not restart them.

## Acceptance

### Acceptance requirements for each deployment

Local protocol and filesystem tests precede service installation. A native Linux root execution must cover tmpfs, file ownership, symlink rejection, protected private state and recovery through an outage longer than the old startup limit. A macOS skip does not establish those properties.

Live migration requires its own source-bound receipt and a new OpenBao process proving automatic unseal. Cold-boot acceptance must additionally record a changed Linux boot ID, correct persistent mounts, newly acquired runtime key, synchronized authenticated time, valid listener and issuer certificates, fresh KMS login, retained signing keys and retained revocations. A resumed memory snapshot or manual unseal is not a cold-boot pass. Test denial of seal release and subsequent authorized recovery without exposing the key.

A real pause past leaf expiry needs a separate provider exercise. Do not count the awake idle interval as suspension. Leave the VM suspended beyond the full one-hour certificate lifetime plus margin, then let a genuine Netlify event be its sole public waker. Record actual provider transitions, the pre-pause leaf generations and expiry, post-resume time recovery, replacement leaves, KMS state, both protected reads and persisted revocation. Controlled expired fixtures and process freezing remain separate tests.
