# Dedicated Instabox deployment

Use a separately designated VM for the authority, OpenBao and gateway. This adapts the generic [Linux profile](../linux/README.md). Replace every example binding with your own machine and origins. Keep the current provider plan unless its resource limits require a separately approved change. No keepalive is part of this design.

## Bounded authenticated clock preparation

`prepare-clock.py` is a one-time bootstrap for a fresh, explicitly designated **Debian** PAP VM. It mutates host clock configuration and installs/enables chrony; it has no dry-run mode. Review the script and the dedicated-host designation before running:

```sh
sudo python3 deploy/instabox/prepare-clock.py
```

The helper requires root, trusted root-owned configuration parents and a private non-followed lock. It refuses an existing chrony configuration or any active chrony, ntp, ntpsec or timesyncd service instead of replacing that policy. It preserves the provider's timesyncd mask. A failed or interrupted run can leave the reviewed configuration or installed package in place; inspect host state rather than blindly rerunning. Once chrony is active, the same helper intentionally refuses a repeat bootstrap.

The fixed client policy uses `time.cloudflare.com`, `nts.netnod.se` and `gbg1.nts.netnod.se` with NTS and requires two selectable time sources. Those are three hostnames across two providers, not three independently administered clocks. It stores drift/NTS state under `/var/lib/chrony`, enables RTC synchronization, and allows a clock step exceeding one second only within the first three updates. Run this bootstrap before credential-serving PAP services. The policy sets `port 0` and `cmdport 0`, disabling the NTP server and UDP command listeners; privileged local Unix-socket monitoring remains available.

Installation uses Debian's package manager with `--no-remove` and preserves the reviewed configuration. Success requires kernel-reported time synchronization and at least two authenticated NTS source records. Retain the JSON result as an observation of that installation, not a future synchronization guarantee. Monitor the clock and repeat health checks after pause/resume and cold start:

```sh
sudo chronyc tracking
sudo chronyc -N authdata
timedatectl show -p NTPSynchronized
```

Keep normal TLS certificate validation enabled for NTS key establishment. Allow the required outbound NTS-KE/TLS and NTP traffic; do not expose an inbound public time service. The policy follows [chrony's configuration reference](https://chrony-project.org/doc/4.7/chrony.conf.html), [Cloudflare's NTS service documentation](https://developers.cloudflare.com/time-services/nts/) and [Netnod's NTS client documentation](https://tech.netnod.se/en/time-services/NTS). The use of this client does not establish an undocumented Instabox clock guarantee or change provider configuration.

## Persistent storage layout

The provider explicitly identifies `/data` as persistent. The generic Linux installer uses fixed, real directories under `/var/lib`, `/etc/pap` and `/opt/pap`, and rejects unsafe path aliases. Map those directories onto protected `/data` storage with bind mounts before installing. Do not replace them with symlinks.

| Persistent source | Installed location | Purpose |
| --- | --- | --- |
| `/data/pap/state/issuer` | `/var/lib/pap-issuer` | Authorization database, revocation/replay state and renewable issuer client credentials |
| `/data/pap/state/kms` | `/var/lib/pap-kms` | OpenBao encrypted Raft state and loopback listener credentials |
| `/data/pap/state/proxy` | `/var/lib/pap-proxy` | Private proxy administration and any gateway state |
| `/data/pap/state/enroller` | `/var/lib/pap-enroller` | Enrollment profile only: broker-owned listener certificate generations, mode 0710 with KMS traversal |
| `/data/pap/config` | `/etc/pap` | Reviewed authority, OpenBao, CA and proxy configuration |
| `/data/pap/software` | `/opt/pap` | Root-owned source and pinned Python installation |

Create `/data/pap` and `/data/pap/state` as root-owned mode-0700 directories. The installer assigns the individual state directories to the corresponding isolated service UIDs. The configuration and software directories stay root-owned and unwritable by service accounts.

Before the initial installation, the three named service state directories must be empty, real directories owned by root:root with mode 0700. The generic installer can assign exactly those directories to their dedicated service UIDs using a verified directory descriptor. It rejects populated directories, symlinks, wrong modes and unrelated paths, and never recursively changes ownership of their contents. This supports fresh bind-mounted storage without allowing an installer to adopt arbitrary existing data.

On a fresh dedicated VM, an operator can create empty source/target directories, bind each source to its target, and add these entries to the VM's existing `/etc/fstab` using the normal reviewed host-configuration workflow:

```fstab
/data/pap/state/issuer /var/lib/pap-issuer none bind,x-systemd.requires-mounts-for=/data 0 0
/data/pap/state/kms /var/lib/pap-kms none bind,x-systemd.requires-mounts-for=/data 0 0
/data/pap/state/proxy /var/lib/pap-proxy none bind,x-systemd.requires-mounts-for=/data 0 0
/data/pap/state/enroller /var/lib/pap-enroller none bind,x-systemd.requires-mounts-for=/data 0 0
/data/pap/config /etc/pap none bind,x-systemd.requires-mounts-for=/data 0 0
/data/pap/software /opt/pap none bind,x-systemd.requires-mounts-for=/data 0 0
```

Do not replace the host's fstab. Do not bind over existing data, copy live SQLite/Raft files, or initialize a new authority when a persistent mount is missing. Missing persistence must stop startup. All writes, directory creation and mounts are separate installation actions; `preflight.py` performs none of them.

`prepare-storage.py` implements this bounded preparation on an explicitly designated VM. First print its root-only read-only plan, then apply that reviewed plan:

```sh
sudo python3 deploy/instabox/prepare-storage.py --acknowledge-dedicated-vm
sudo python3 deploy/instabox/prepare-storage.py --acknowledge-dedicated-vm --apply
```

The enrollment profile adds exactly one mapping to those original five. Use `--with-enroller` for both its plan and apply commands; it preserves the existing five bindings and appends only the sixth entry when they are already configured:

```sh
sudo python3 deploy/instabox/prepare-storage.py --acknowledge-dedicated-vm --with-enroller
sudo python3 deploy/instabox/prepare-storage.py --acknowledge-dedicated-vm --with-enroller --apply
```

The new source and target must be empty real root:root directories with mode 0710 before the installer transfers their ownership to `pap-enroller:pap-kms`. Group traversal permits the KMS to read the published listener generation while denying writes and directory enumeration at the state root. The CA key stays in the separate root-only configuration directory and is supplied to the broker through a systemd runtime credential.

The preparer creates only the listed PAP source/target directories, preserves the existing fstab bytes and metadata while atomically appending missing canonical entries, and binds only the selected five or six pairs. It never runs `mount -a`, changes an existing directory's mode or ownership, starts PAP, creates credentials, or publishes a port. Existing populated storage is accepted only when the exact backing device, filesystem root and source/target inode already establish the intended bind mount. Conflicting or duplicate fstab entries, symlinks, unsafe parents, stacked/nested mounts and nonempty unmounted directories stop preparation. An interrupted apply may leave completed earlier steps; inspect its JSON result and rerun the read-only plan before retrying. A successful storage receipt does not establish clock health, cold-restart persistence, KMS bootstrap or production acceptance.

Run the storage-preparation tests and retain both their source commit and the actual-host preparation/preflight outputs. Fixture tests cover guarded filesystem operations; they do not establish the designated host's mounts, persistent storage or later boot behavior.

Install the three supplied `systemd/*/persistence.conf` drop-ins under the matching `/etc/systemd/system/*.service.d/` directories after the Linux installer has installed the base units. Include the fourth, `pap-enroller.service.d/persistence.conf`, for the enrollment profile. They add mount dependencies and a read-only pre-start check of each service's actual backing device and filesystem root. A plain `mountpoint` check would be insufficient because systemd can create other bind mounts as part of its sandbox. The `+` command prefix runs only this root-owned precheck with the privileges needed to inspect persistent mount sources. Keep the script and its entire path root-owned and unwritable by service accounts.

After installing the drop-ins, run systemd's configuration verifier and daemon reload. The cold-restart acceptance test must prove both the host configuration and these mounts survive a stopped/start cycle. Documentation that software persists does not replace that test.

## Read-only host preflight

Copy this reviewed deployment source onto the intended dedicated VM. Run:

```sh
sudo python3 deploy/instabox/preflight.py --acknowledge-dedicated-vm
```

After the Linux installation, also inspect service identities and loaded unit settings:

```sh
sudo python3 deploy/instabox/preflight.py --acknowledge-dedicated-vm --installed
```

Add `--with-enroller` when using the enrollment profile so both the sixth binding and broker account/service are inspected.

The program prints JSON and exits nonzero if a checked prerequisite fails. It creates no files, changes no units, performs no network requests and reads no environment variables or private credential contents. It checks Linux, host root, systemd PID 1 and version, manager health, cgroup v2 controllers, namespace handles, host-init capabilities, clock synchronization, swap status, available persistent capacity and the exact persistent mappings. The installed check inspects dedicated UIDs and selected loaded sandbox settings.

Its service pre-start form checks only the current service's storage view:

```sh
sudo python3 deploy/instabox/preflight.py --storage-only --role issuer
```

The role can be `issuer`, `kms`, `proxy` or `enroller`. Those checks account for systemd making the rest of the service filesystem read-only. Successful preflight means the inspected prerequisites passed. Its JSON always keeps `production_accepted` false because it cannot establish provider guarantees, actual syscall isolation, public TLS behavior or live Netlify acceptance.

## Public HTTPS gateway

Instabox documents public URLs in this form:

```text
https://PORT-MACHINE_ID_WITHOUT_m_.PROVIDER_DOMAIN/
```

Use the exact URL returned by the provider. Do not fabricate its domain or derive it from a machine ID. Configure the authority's fixed `issuer` and the Netlify public `issuerURL` to the same HTTPS origin, without a path or trailing slash.

Publish only the reviewed PAP gateway. Never publish OpenBao 8200/8201, the raw authority listener 9480, Caddy's administration socket, or the PAP administration socket. SSH administration should use the provider's certificate mechanism, without forwarding an SSH agent into this host. Provider account access and VM root remain in the trust model.

`Caddyfile.edge.example` is the template for a provider HTTPS-to-HTTP proxy topology. Verify that the provider actually supplies the documented TLS termination before selecting it. It listens on guest port 8080, adds no local public certificate issuance, and forwards only public PAP API paths to the authority's loopback listener. Install its `pap-caddy.service.d/edge-http.conf` drop-in to clear the low-port capability required by the generic 80/443 profile. Public TLS terminates at the provider in this mode. The provider-controlled hop to the VM must be acceptable to the deployment's security policy. This does not establish end-to-end TLS to the guest.

If HTTPS upstream or raw TCP passthrough is available and documented, use a reviewed end-to-end TLS alternative instead. Do not disable certificate verification, trust a forwarded client-certificate header, forward root tokens through the public proxy, or publish an OpenBao listener to make an incompatible topology work.

The edge configuration intentionally does not authenticate clients using Host or forwarded headers. The authority derives DPoP targets and token issuer values from its fixed configuration. Public requests still require valid cryptographic credentials and current policy. No shared gateway API key is added. The new cold-boot profile additionally requires the reviewed fixed public boot-proof route and gateway startup independent of authority readiness. Its filesystem must expose only public proof records, never `/run/pap-boot/private`; verify the installed Caddy main unit and effective systemd graph before activation, then test startup from that configuration with an actual changed Linux boot.

## OpenBao and unattended operation

Use the [Linux OpenBao profile](../linux/README.md) and the separate [cold-boot contract](../../docs/cold-boot-profile.md). Transit signing keys stay outside the authority process under a separate UID and verified loopback mTLS. OpenBao and independent Netlify Blobs custody are software services, with no TPM/HSM or hardware-attestation claim. VM root, the hypervisor/provider and origin routing, OpenBao administration, and the custody project's administrators/trusted deployment code remain trusted.

Bootstrap initializes OpenBao, probes restricted signing and denied operations, enrolls service certificates, encrypts operator recovery material, and revokes the initial root token. Preserve source-bound results for your deployment. The audit configuration disables raw logging and hashes accessors; off-host retention and log rotation still require an operator. A Shamir-sealed deployment requires manual unseal after a KMS process restart until an independent auto-seal profile is installed.

The [cold-boot profile](../../docs/cold-boot-profile.md) uses the built-in static seal with its key held in a separate trusted Netlify custody project. Choose your own custody project name and independently pin its deployment policy. Each guest boot generates a fresh in-memory RSA private recipient, proves the exact registered origin and retrieves the encrypted seal key. The verified key goes only into private tmpfs and OpenBao's systemd credential mount, never an environment variable or persistent plaintext guest file. The helper exits after preparing the credential and does not undo deliberate administrative sealing. A persistent root-controlled incident latch blocks retrieval, cached-key reuse and new KMS starts; remote denial alone cannot erase an already released key.

An existing Shamir instance requires a reviewed migration using its actual recovery threshold. Require an automatic unseal on a subsequent KMS restart and a separate actual cold boot. After migration, old shares authorize recovery operations but cannot decrypt storage without the external seal key. Preserve independently encrypted key generations and matched Raft/PAP backups. The pinned seal root, enrollment CAs and operator trust do not rotate automatically. Test full isolated restoration before depending on the system for recovery.

Do not store root tokens, plaintext recovery shares or Instabox API credentials in environment variables, source, command arguments or logs. The local enrollment CA is an explicit root-only host credential, supplied to the broker through systemd; the operator CA private key and recovery material belong in the independently encrypted operator packet. Disable personal Vault delivery and Org Secret selections on the dedicated VM unless a separately reviewed dependency requires them. Instabox's secret-delivery service is not a substitute for the PAP application's runtime identity protocol.

## Acceptance before real projects

1. Verify the dedicated VM, costs, actual activity classification and lifecycle settings by reading them back. Continue development and bounded live acceptance on the current plan. Test natural idle wake and its recovery budget; require continuous availability only if that is the chosen service contract. No paid upgrade is a prerequisite, and no synthetic keepalive workaround is part of this profile.
2. Pass the read-only prerequisites and Linux isolation exercise. Start the reviewed services under their own UIDs. Inspect actual sandbox settings and verify application denial of KMS files, administration and client-certificate access.
3. Verify public HTTPS behavior and the exact returned issuer hostname. Confirm the published endpoint exposes only public routes and that OpenBao and administration remain unreachable publicly.
4. Enroll a dedicated trusted Netlify site, perform a real protected operation, wait through credential renewal and signing-key rotation, then revoke the grant. Confirm both access and new enrollment fail.
5. Test a real provider suspension past both one-hour leaf lifetimes, then wake through a genuine Netlify operation. Record transitions, authenticated time, fresh leaves/KMS login, protected reads and retained revocations. Separately discard VM memory and verify a changed boot, correct mounts and a fresh tmpfs seal key. Keep denied custody and the persistent incident lock fail-closed. Measure the 300-second / 24-attempt background recovery budget; deterministic tests alone do not establish provider recovery within it.
6. Preserve a consistent encrypted off-host backup and verified successor packet. Perform full restoration onto an isolated recovery VM without exposing it or creating two active authorities. Reconcile revocation state and key-generation history before serving traffic.

The [project onboarding guide](../../docs/project-onboarding.md) defines adoption after these deployment checks. Public examples do not establish acceptance for customer workloads.

Instabox snapshots can contain saved credentials and private files. Do not clone an initialized signing authority into a developer environment or use snapshots as the only disaster-recovery mechanism. A snapshot saves files; it does not certify database consistency, independent retention or recovery.
