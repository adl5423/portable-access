# Isolated Linux authority for Netlify applications

The Netlify application runs remotely. A separate Linux host runs the PAP authority, an OpenBao Transit signing service, and Caddy. No AWS account or AWS runtime is required. A VPS, a dedicated server, or a suitable VM can host this profile.

These assets establish distinct operating-system identities and private storage. They are a single-host deployment profile, not an availability cluster or an independent security certification. Provisioning a host, initializing OpenBao, enrolling an actual Netlify site, and testing the public endpoint are separate acceptance steps.

## Execution boundaries

| Identity | Allowed private state | Network and administrative access |
| --- | --- | --- |
| `pap-issuer` | `/var/lib/pap-issuer`, including the authorization database and renewable OpenBao client certificate | Loopback API port 9480; mTLS to OpenBao; inherited administrative listening descriptor |
| `pap-kms` | `/var/lib/pap-kms`, containing encrypted OpenBao storage; enrollment profile permits read-only access to broker-owned listener key generations | HTTPS on loopback 8200 and Raft transport on loopback 8201 |
| `pap-admin` | Administrative Unix socket under `/run/pap-admin` | Can submit administrative requests; receives no issuer or KMS file access |
| `pap-proxy` | `/var/lib/pap-proxy`, including automatically managed public TLS certificates | Public TCP 80/443; proxies to 127.0.0.1:9480; private Caddy administrative socket |
| `pap-app` | No authority, KMS, proxy, or administrative files | Represents an untrusted local process in the isolation exercise. Netlify applications run on Netlify instead. |
| `pap-enroller` | Enrollment profile only: `/var/lib/pap-enroller`, runtime enrollment socket and private systemd CA credential | Unix sockets only; exact issuer UID admission; no Internet or loopback TCP access |

The application cannot authenticate to OpenBao without the issuer's client key. A process sharing the host can still establish a TCP connection to a loopback listener. Filesystem permissions do not block TCP. OpenBao requires verified client TLS and its own narrowly scoped authorization.

`pap-admin.socket` is created by systemd with mode 0600 and owner `pap-admin`. Its parent directory is mode 0700. Systemd passes the listening descriptor to the authority as descriptor 3 named `pap-admin`; the authority does not need `CAP_CHOWN` or access to the directory. The handler must also check the client's kernel peer UID against `admin_uid`.

The service units drop capabilities, disallow privilege gain, hide other UIDs' process metadata, restrict address families, and expose only their own state directory for writes. These protections depend on the installed systemd and kernel. Inspect the live unit properties after deployment. A configuration file alone is not proof that a kernel enforced every control.

## Host prerequisites

Use a maintained Linux distribution with systemd 252 or later. Configure host patching, time synchronization, a firewall, encrypted persistent disks, protected backups, and monitoring. Disable host swap for this OpenBao integrated-storage profile. The enrollment units also set `MemorySwapMax=0` for the KMS and broker and grant neither process capabilities. OpenBao 2.7 does not accept the older `disable_mlock` configuration field, so the enrollment configuration omits it. Root, the kernel, and the host administrator remain trusted.

For the generic Caddy TLS profile, only TCP 80 and 443 should be public. The reviewed Instabox variant instead publishes only guest HTTP port 8080 behind the provider's HTTPS termination. Restrict SSH to the administrative network. Never publish OpenBao ports 8200/8201, authority port 9480, or either administrative socket through a container port mapping or a reverse proxy. Generic Caddy needs outbound DNS and HTTPS for automatic public certificate management. The authority needs outbound HTTPS to fixed enrolled Netlify origins for site assertions. Enabled provider connectors additionally need HTTPS to `api.openai.com`, `api.nasa.gov` and `developer.nlr.gov`; they do not accept caller-selected destinations. The seal helper needs the separately registered custody origin.

Install reviewed releases of these programs before running the installer:

- PAP and its pinned runtime dependencies in a root-owned virtual environment at `/opt/pap/venv`. Its executable must be `/opt/pap/venv/bin/pap`. Keep the source, environment, and dependency directories unwritable by all service accounts.
- OpenBao at `/usr/local/bin/bao`.
- Caddy at `/usr/bin/caddy`.
- Python 3.12 or later for PAP. The host installer uses the Python standard library and invokes the installed PAP interpreter for schema validation.

Do not run application builds, package installation, or untrusted project code under `pap-issuer`, `pap-kms`, `pap-admin`, or `pap-proxy`. A service UID is a security boundary. An application sharing that UID has that service's permissions.

## Automatic recovery after an idle pause

The enrollment deployment profile adds `pap-enroller`, a sixth nonroot identity. It issues one-hour client certificates only to the configured issuer UID over `/run/pap-enroller/enroll.sock`. Both ends verify Linux `SO_PEERCRED`; the broker validates and signs the issuer's P-256 CSR, so the issuer's private key does not leave its process. All client issuance and renewal uses this broker. The enrollment profile requires no OpenBao PKI mount or certificate-issuance permission. An expired application certificate is not treated as proof of identity. The operating-system identity authorizes replacement, including the first certificate on a fresh installation.

The root-owned enrollment CA key lives at `/etc/pap/enrollment/ca-key.pem`, mode 0600 under a mode-0700 parent. PID 1 supplies it through `LoadCredential` to the broker's private runtime credential directory. The broker cannot read the original key path, the issuer database, or OpenBao storage. It has no network address family or Linux capability. This is a software trust boundary: host root and the host provider remain trusted, and the credential file does not claim HSM protection or independent disk encryption.

When PID 1 exposes a loaded key as root:root mode 0440 under a root:root mode-0550 directory, the runtime requires the protected systemd credential mount rather than ordinary filesystem access. An exact POSIX ACL grants only the configured broker UID access; group and other entries grant none. The credential reader accepts this fixed systemd path only after checking the read-only credential mount, both ACLs, ownership and modes. An ordinary group-readable private file remains invalid. Do not change the credential to a shared group, relax the generic key reader or copy the key into service-writable state to bypass these checks.

The broker also publishes the OpenBao listener certificate and matching key as an atomic generation under `/var/lib/pap-enroller/listener/current`. Only the broker can replace that generation. `pap-kms` can read its mode-0640 files through the KMS group and cannot write them. OpenBao 2.7 or later polls for changes every five seconds with `tls_auto_reload`; the broker never signals or restarts a privileged service. Expired listener certificates can therefore recover without first connecting through the expired TLS listener. Broker maintenance runs every 30 seconds while the VM is executing; the issuer also requests client enrollment during startup and before using an expired credential.

OpenBao starts the broker through `Wants` and orders startup after it. Its process lifetime remains independent: restarting or stopping the broker must not stop OpenBao and discard the unsealed key in memory. The authority retains a required broker dependency and denies operations if it cannot obtain valid credentials. A listener certificate that expires while the broker is unavailable still fails ordinary TLS validation.

Use the enrollment profile for deployments that can sleep. Generate the CA certificate and key through the protected operator bootstrap, then supply only their paths:

```sh
sudo python3 deploy/linux/install.py \
  --config /root/pap-bootstrap/authority.json \
  --hostname access.example.com \
  --enrollment-ca-cert /root/pap-bootstrap/enrollment-ca.pem \
  --enrollment-ca-key /root/pap-bootstrap/enrollment-ca-key.pem
```

Base the input on `authority.enrollment.example.json`. The installer resolves `enrollment_uid` and `admin_uid` to the installed nonroot accounts, then validates the complete public policy through the installed runtime's `ProductionConfig`. The isolated interpreter receives JSON on stdin, inherits no application environment and prints only a fixed success marker. Invalid site identities or policy stop installation before configuration or credential files are written. Enrollment and the six pre-provisioned certificate arguments are mutually exclusive. The installer creates no initial client certificate or signing key and does not initialize or unseal OpenBao. Start and verify `pap-enroller.service` first, confirm its listener generation, then bootstrap OpenBao and start the authority.

The issuer certificate-auth role pins only the enrollment CA and the exact issuer identity. This deployment dedicates the whole `transit/` mount to PAP. Its OpenBao 2.7 ACL allows constrained nonexportable P-256 key creation and JWS signing, and denies rotate/config/trim/delete/export and administrative operations. The ACL does not enforce a `pap-` key-name prefix; the isolated authority chooses those names. Never place another application's keys in this dedicated mount or interpret a prefix convention as an authorization boundary. Bootstrap verifies actual signing and denied operations before revoking its root token.

The HTTPS listener reads `/etc/pap/openbao-client-ca.pem`, initially containing the enrollment public CA. Before the first initialization, operator bootstrap adds a separate operator public CA to that bundle and restarts the still-uninitialized OpenBao service to load it. A successful TLS connection and a second `sys/init` check must prove the operator trust is loaded while the instance remains uninitialized. Only then may initialization proceed. The operator CA private key belongs only in RAM and the independently encrypted operator recovery packet. Administrative certificate authentication must trust only this separate operator CA; the broker's CA must never grant administrative access.

A pause that preserves process memory does not itself seal a running OpenBao instance. Provider resumption that performs a cold boot, or any OpenBao process restart, is a separate event: the Shamir-sealed profile requires operator unseal unless an independently protected auto-unseal service is configured. Do not put an unseal key beside the Raft database. No traffic generator or keepalive is required by this recovery design.

The new OpenBao profile configures audit at server startup with a declarative `audit "file" "pap"` block. It writes `/var/lib/pap-kms/audit.jsonl`, disables raw logging and HMACs accessors. OpenBao 2.7's unsafe API-audit-creation switch is not enabled. Audit write failure can fail requests closed, so production operation requires capacity alerts and reviewed rotation. Audit rotation and off-host retention are operator responsibilities; configure and test them before sustained operation.

`enrollment_boundary_probe.py` checks the actual six installed accounts without reading stored private bytes. Its negative socket probe temporarily grants an application child the issuer group, verifies the broker's kernel UID, and requires a peer-UID denial. It changes no account membership or KMS state. `exercise_expired_certificates.py` is a separate, explicitly disruptive acceptance tool. Its default checks baseline readiness; `--exercise` stops only broker and authority, publishes correctly signed expired client and listener leaves, proves rejection with TLS verification enabled, and restarts the normal units. A pass requires new valid generations, fresh authority readiness and the same unsealed KMS process. Failure restoration is reported as restoration, never automatic recovery. Run this exercise only after a live baseline.

`exercise_frozen_certificates.py` covers recovery with the existing process and cached token. It uses pidfds to freeze only issuer and broker, injects correctly signed expired leaves, proves ordinary TLS rejection, then resumes those same processes. It must not restart a service. Neither certificate exercise suspends the provider VM; actual idle pause and public wake require their own acceptance test.

Trusted time has its own resume budget. Enrollment refuses issuance while time is unsynchronized, so a long suspension may require clock reacquisition before leaf replacement and fresh authentication. The ordinary SDK readiness budget is 20 seconds; `BackgroundRecordsReader` provides a separate 300-second fixed-GET recovery budget with bounded temporary-unavailability retries. It never retries final authentication/authorization denial. Measure provider wake, clock, certificate and KMS recovery together before setting an availability objective. Controlled expiry fixtures cannot establish that result.

On Instabox, also prepare the sixth fixed persistent bind with `prepare-storage.py --with-enroller`, install the `pap-enroller.service.d/persistence.conf` pre-start check, and run `preflight.py --with-enroller --installed`. See the provider README for the exact command and acceptance scope.

## Pre-provisioned certificate bootstrap

The original profile below remains available for deployments with an existing infrastructure certificate manager. It has no local enrollment broker and does not recover an expired issuer credential by itself.

OpenBao is a software KMS. Transit keeps signing keys outside the authority process and database. This deployment does not claim a hardware-protected key boundary. A compromise of the KMS process, its administrator, or host root can compromise that boundary.

Initialize a production-mode OpenBao instance using a documented operator ceremony. Use encrypted Raft storage, an offline recovery procedure, and an appropriate seal/unseal configuration. Do not run `bao server -dev`. Do not put a root token in a shell environment, service environment, checked-in file, command argument, or deployment log. Bootstrap administrative credentials and recovery shares belong in the operator's approved protected channel.

Configure the Transit signing namespace, certificate authentication role, and constrained PKI role required by the PAP OpenBao provider. The issuer's certificate-authenticated policy must permit only its specific Transit key namespace and its own `pap-issuer` PKI certificate issuance. It must not grant root, arbitrary secret access, export of signing keys, arbitrary certificate names, or policy editing. Refer to the provider's bootstrap documentation for the full initialization procedure.

The runtime uses these OpenBao API paths. The API's `/v1/` prefix is omitted from ACL policy paths:

| Operation | API request | Required authorization |
| --- | --- | --- |
| Obtain a temporary infrastructure token | `POST /v1/auth/cert/login`, role name `pap-issuer` | Valid client certificate accepted by the TLS listener and certificate auth role |
| Read or create a nonexportable P-256 generation | `GET` or `POST /v1/transit/keys/pap-<generation UUID without dashes>` | `path "transit/keys/+"` with constrained creation parameters; all keys belong to the dedicated PAP mount |
| Reject key-management child operations | `/v1/transit/keys/<generation>/config`, `/rotate`, `/trim`, and other child endpoints | Explicit `deny` at `path "transit/keys/+/+"`; no delete or export permission |
| Sign a SHA-256 digest | `POST /v1/transit/sign/pap-<generation>/sha2-256` | `update` at `path "transit/sign/+/sha2-256"`, pinned version `"1"`, `prehashed=true`, and `marshaling_algorithm="jws"` |
| Replace the issuer's client certificate, legacy profile only | `POST /v1/pki/issue/pap-issuer` | Update permission only on this constrained issuance role; the enrollment profile does not mount or grant PKI issuance |

Use the complete-segment `+` rules and parameter restrictions from the reviewed [bootstrap policy](../../tools/bootstrap_openbao.py). A trailing `pap-*` glob is not an authorization boundary for one operation or one path segment; do not substitute it for these rules. The `pap-` name is a runtime convention, and the ACL permits constrained keys of any name inside the dedicated mount. Put unrelated application keys in separate mounts. Bootstrap verifies actual signing and denied configuration, rotation, trimming, deletion, export and administrative operations.

For the legacy profile, additionally constrain the PKI role to exactly `pap-issuer`, client authentication usage, P-256, and a maximum one-hour lifetime. The provider reacquires its temporary token through certificate authentication before its lease expires. It does not require a persistent bootstrap token or call a token-renew endpoint.

Provision the following inputs through that protected operator channel:

| Input | Requirement | Installed destination |
| --- | --- | --- |
| Issuer client certificate and private key | Valid for OpenBao TLS client authentication and the `pap-issuer` certificate auth role | `/var/lib/pap-issuer/credentials/bootstrap/client-cert.pem` and `client-key.pem`, mode 0600 |
| OpenBao listener CA | Public certificate chain that validates its HTTPS listener | `/etc/pap/openbao-ca.pem`, root-owned and readable by `pap-issuer` |
| OpenBao server certificate and private key | Server-auth certificate with IP SAN `127.0.0.1` | `/var/lib/pap-kms/credentials/server.crt` and `server.key`, mode 0600 |
| OpenBao TLS client CA | Public trust chain validating the issuer client certificate and subsequent PKI-issued replacements; direct issuing CA certificate first | `/var/lib/pap-kms/credentials/client-ca.crt`, mode 0600, and `/etc/pap/openbao-client-ca.pem`, root-owned and readable by `pap-issuer` |

`kms.ca_file` validates the OpenBao HTTPS server. `kms.client_ca_file` validates renewed issuer client certificates. These are separate trust purposes and can use different issuing authorities. The installer requires both `--openbao-ca` and `--openbao-client-ca` explicitly. The client CA chain is also installed into OpenBao's listener trust store.

The runtime renews the issuer client certificate using its constrained PKI role and atomically advances `credentials/current` to a new private generation. The issuer's directory is writable by that identity for this purpose. Do not make this directory root-owned or read-only after installing.

OpenBao's listener certificate needs a separate infrastructure certificate renewer. It must replace the server certificate and key with matching files, preserve ownership/modes, and run `systemctl reload pap-openbao.service` before expiry. The supplied assets do not implement that renewer, root CA rollover, initial OpenBao initialization, disaster recovery, or auto-unseal. Configure and verify those operations before unattended public use. PAP signing-key and access-token rotation do not replace them.

## Install on the intended host

Copy `authority.example.json` to a reviewed bootstrap input. Change `issuer` to the public HTTPS origin. Leave `sites` empty until the actual Netlify site bindings and grant expiry are approved. The example `admin_uid` is intentionally zero; the installer resolves the separate `pap-admin` account and writes its real UID. The production daemon rejects an unsafe administrative UID.

Each approved site binding supplies a canonical Netlify site UUID and production origin, subject, tenant, grant identifier, explicit absolute grant expiry, `environment: "production"`, and `trusted_site_contexts: true`. A subject must match `[A-Za-z0-9][A-Za-z0-9_-]{0,79}`; use `netlify-<site UUID>` rather than a colon-separated identity. Optional `resource_path` and `resource_action` default to `/api/pap/records` and `records.read`. This acknowledgement is required because origin control trusts every deployment context able to serve that registered production origin. It does not independently attest the running Netlify deployment or isolate untrusted code inside that site.

With the installed binaries and pre-provisioned certificate files available, run this from the reviewed source checkout on the Linux host:

```sh
sudo python3 deploy/linux/install.py \
  --config /root/pap-bootstrap/authority.json \
  --hostname access.example.com \
  --issuer-client-cert /root/pap-bootstrap/issuer-client.pem \
  --issuer-client-key /root/pap-bootstrap/issuer-client-key.pem \
  --openbao-ca /root/pap-bootstrap/openbao-ca.pem \
  --openbao-server-cert /root/pap-bootstrap/openbao-server.pem \
  --openbao-server-key /root/pap-bootstrap/openbao-server-key.pem \
  --openbao-client-ca /root/pap-bootstrap/client-ca.pem
```

`install.py` refuses non-root execution, unsafe destination parents, reused privileged identities, symlink input files, and replacement of existing files. It creates dedicated accounts without login; the enrollment broker alone uses the KMS primary group and issuer supplementary group needed for its two published resources. Other service accounts have no supplementary groups. The installer validates resolved configuration before writing policy or credentials, does not recursively change ownership and does not start services. Use it on a fresh host, with the service accounts stopped. It deliberately stops on existing credential files rather than overwriting a live renewal generation. If interrupted, inspect and complete the dedicated installation paths explicitly.

Fresh root-owned bind-mounted state directories are supported for exactly `/var/lib/pap-issuer`, `/var/lib/pap-kms`, and `/var/lib/pap-proxy`. Each must be an empty real directory with owner/group root and mode 0700, beneath root-owned parents without group/other write permission. The installer opens the directory without following symlinks, checks its inode/device and emptiness, and transfers only that directory's ownership through the verified descriptor. It never recursively changes its contents. Populated state, a permissive mode, a symlink, a changed inode, or any other path is rejected. Run the installer filesystem tests against the intended release; actual host mount mapping remains a separate acceptance check.

After completing OpenBao initialization and validating its policies:

```sh
sudo systemd-analyze verify /etc/systemd/system/pap-*.service /etc/systemd/system/pap-admin.socket
sudo -u pap-proxy /usr/bin/caddy validate --config /etc/pap/Caddyfile --adapter caddyfile
sudo systemctl enable --now pap-openbao.service
# Complete the configured OpenBao unseal procedure here if the service is sealed.
sudo systemctl enable --now pap-admin.socket pap-authority.service pap-caddy.service
sudo systemctl status pap-openbao.service pap-authority.service pap-caddy.service
sudo systemd-analyze security pap-authority.service pap-openbao.service pap-caddy.service
```

Do not expose the public endpoint until the issuer is healthy, the grants match the intended Netlify sites, and public acceptance tests pass. An empty site list denies onboarding by default.

Use the `pap-admin` identity only for the supported administrative client. Do not add the application UID to its group. Grant operators permission to execute specific administrative commands as `pap-admin` through the organization's existing privileged-access policy.

## Run and interpret isolation verification

The static deployment tests inspect the unit assets. The independent kernel exercise starts four child processes with distinct irreversible UIDs and no effective, permitted, inheritable, or ambient capabilities. It tests real reads, Unix socket connections, peer credentials, process-memory access, UID changes, a public HTTP request, and KMS mTLS authentication. All files and process state are confined to a fresh `/tmp/pap-uid-*` fixture.

Run the disposable Linux exercise from the source root:

```sh
sh deploy/linux/run-isolation.sh
```

The test container has a read-only root filesystem, no external network, a private temporary filesystem, no-new-privileges, and only the parent capabilities needed to assign fixture UIDs and ownership. Each child drops those capabilities. The parent cleans up the fixture and the container is removed after the run. Its Docker image is a test runner, not a production service image.

The equivalent pytest case skips with an explicit reason outside Linux root. A skipped kernel case is not an isolation pass. Retain the exercise output with its source commit, host/kernel version and runner configuration. This exercise does not boot systemd, execute OpenBao, run Caddy, or prove public Netlify acceptance. Those need their own deployment checks.

Validate the installed systemd units and Caddy configuration with their real parsers before activation. A systemd syntax check may use placeholder executables and does not execute services; a Caddy configuration check does not prove certificate issuance or public HTTPS. Keep those results separate from runtime containment and provider acceptance.

A second container exercise imports the actual `pap.production` source and runs `require_isolated_linux`, `activated_admin_socket`, and kernel peer identification under a non-root issuer UID. It creates `/run/pap-admin` only inside a disposable container's private `/run` filesystem. The issuer cannot traverse that directory or stat its socket node, but successfully accepts the inherited listener on descriptor 3. The exercise also verifies rejection of a wrong descriptor name, a wrong administrative UID, and root execution.

```sh
sh deploy/linux/run-runtime-activation.sh
```

Record the runtime-activation result and the hashes of the production and peer-identity source files used by that run. The corresponding pytest case requires Docker Linux root and skips elsewhere. This test exercises the runtime's real validation functions, not a copied implementation. It does not boot the complete authority, systemd PID 1, or OpenBao, and does not establish public TLS or Netlify acceptance.

## Optional provider operations

The [connector broker](../../docs/connectors.md) adds fixed OpenAI/NASA/NLR
operations for the standalone examples. The authority retains only Transit
ciphertext for their keys and never returns provider credentials to Netlify
functions. Fresh OpenBao bootstrap creates a dedicated derived AES key with
automatic version rotation and exact-path ACLs. Existing installations require
a reviewed policy/key addition before connector credential import; do not
reinitialize an existing KMS. Import keys through the Unix administrative route
using operator tooling, then enable only the connector bound to each site's
existing grant. An unavailable or replaced key fails closed, including cached
reads. See the connector runbook for the hourly at-most-one paid-attempt policy
and the limits of upstream API-key rotation.

## References

- [systemd socket ownership and descriptor activation](https://www.freedesktop.org/software/systemd/man/256/systemd.socket.html)
- [systemd execution sandbox controls](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec)
- [OpenBao server configuration](https://openbao.org/docs/configuration/)
- [OpenBao TCP TLS listener settings](https://openbao.org/docs/2.5.x/configuration/listener/tcp/)
- [Caddy administrative API protection](https://caddyserver.com/docs/api)
- [Caddy network address and Unix socket permissions](https://caddyserver.com/docs/conventions)
