# Docker HTTPS workload

Run the same PAP origin proof flow on a server you control. This example has a protected `GET /api/pap/records` endpoint and a public proof callback. It uses no API key, private key file, or credential environment variable. The client creates an ephemeral proof key in memory, publishes a short-lived challenge response through the callback, and receives a short-lived credential from your PAP authority.

The example requires the Python HTTPS adapter included in this repository. Deploy the authority separately using the [operator guide](../../docs/operator-cli.md). Its public HTTPS listener must be reachable from the workload, and the workload must be reachable from the authority. The authority's administrative Unix socket stays private.

## Run it

1. Point a public DNS name such as `workload.example.com` to the Docker host. Allow inbound TCP 80 and 443. Do not publish the application's internal port 8080.
2. Copy `registration.example.json` into your authority configuration's `sites` array. Generate a new UUID and unique subject and grant for each workload. Choose the correct tenant and an explicit grant expiry for your access policy. Set `identity_adapter` to `https-origin`. Keep `trusted_site_contexts: true` only when every person and process that can deploy to this origin is trusted with this grant. Apply the authority configuration through its normal managed restart.
3. Edit `config.public.json` to match the authority registration and authority audience. The `workloadID` is the registration's `site_id`. Set `trustOriginDeployment: true` after confirming that all deployment and routing principals are trusted, then set `enabled: true` after the registration exists. These values are public configuration; do not put provider API keys here.
4. From this directory, start the containers. The hostname is public routing metadata.

   ```sh
   PAP_HOSTNAME=workload.example.com docker compose --profile https up --build -d
   ```

5. Wait for Caddy to issue the public certificate. Check readiness and perform an authorized read from the running process.

   ```sh
   curl --fail https://workload.example.com/health/ready
   docker compose exec app python /opt/pap-example/app.py --check
   docker compose exec app python /opt/pap-example/app.py --check --repeat-after 65
   ```

The last command performs two reads 65 seconds apart. With the authority's default 60-second lifetime, the second read requires renewed credentials. The command reports successful reads. Verify distinct issuance in the authority's audit records when recording a renewal acceptance test.

The check uses a permission-restricted Unix socket inside the container. It asks the already running process to issue the read with its own memory proof store. There is no public endpoint that publishes proofs or starts a check. External requests without a valid bound token and proof receive a denial.

The committed defaults start a live process but return readiness `503` and reject protected reads. The gateway requires the `https` profile, so a plain `docker compose up` does not request a certificate for the placeholder domain. Set your own hostname before enabling that profile. Readiness means the workload is configured to serve callbacks and resource checks; each protected request still checks the authority online.

## Run on an existing HTTPS server

Install the Python wheel from the verified GitHub release assets, mount the public configuration, and run this application behind your own TLS reverse proxy:

```sh
python -m pip install ./portable_access_reference-0.4.0-py3-none-any.whl
python app.py --config ./config.public.json --listen-host 127.0.0.1 \
  --control-socket ./private/control.sock
```

Keep one process and one replica. Forward the public `/.well-known/pap/site-proof/` path and the protected resource path to that same process. Preserve the original `Authorization` and `DPoP` headers. Your proxy must enforce the configured hostname and valid HTTPS. The application constructs authorization targets from `resourceOrigin` and `resourcePath`; it never trusts caller-provided `Host` or forwarding headers for the authorization URL.

`MemoryProofStore` deliberately has no shared storage. Multiple workers, rolling replicas, or a callback routed to another process can make issuance fail. Use a single process until you implement a reviewed shared proof store with expiry, bounded retention, and tenant isolation. A process restart discards the proof key and automatically reacquires a credential on the next authorized read.

## Isolation and operations

The application runs as UID 10001 with a read-only root filesystem, no Linux capabilities, no privilege escalation, a 256 MiB memory limit and 64 PID limit. Its writable locations are bounded memory mounts. The gateway runs as the same numeric UID in a separate container with a 128 MiB limit. Both containers listen on internal high ports; Docker publishes only the gateway's ports 80 and 443.

Caddy's private certificate files live in the persistent `caddy-data` volume. The gateway image sets its ownership during image construction, so a newly created volume is writable by the unprivileged process. If you attach an existing volume, verify its ownership before starting. Back up the certificate volume according to your host policy. Application proof keys are not stored there.

The Dockerfile pins official Python and Caddy image digests and installs Python dependencies from hash-checked lock files. Refresh these pins and locks during dependency maintenance. Record the final image digest and installed dependency inventory in your release process. The process does not log proofs, request headers, tokens, payloads, or provider keys.

Network access to the Docker host, DNS control, and the TLS terminator are part of the workload's trust boundary. HTTPS origin control proves permission to serve this origin; it does not attest a particular Docker image, cloud account, hardware enclave, or deployment revision. A host compromise can act as the workload. See [adapter trust boundaries](../../docs/identity-adapters.md).

For public traffic, enforce connection and request limits at your host firewall or upstream gateway. The application admits at most 32 simultaneous protected requests. Excess requests receive `503` with `Retry-After: 1` immediately, without queuing an authority call or blocking proof callbacks. The application also bounds inbound bodies, and the SDK bounds authority responses, timeouts, and issuance retries. Public protected reads use the online authority to enforce revocation; an authority outage denies access. Do not put an open forward proxy in front of this deployment.

## Tests

From the repository root:

```sh
python -m pytest examples/docker-https/tests
docker compose -f examples/docker-https/compose.yaml config --quiet
python examples/docker-https/tests/container_acceptance.py
```

The tests use a private test certificate authority and real local HTTPS connections. They do not disable certificate verification. Container acceptance is separate from that protocol test; run the documented compose commands against your own public hostname to verify DNS, ACME certificate issuance, and authority registration.

Official references: [Docker Compose service controls](https://docs.docker.com/reference/compose-file/services/), [Docker memory mounts](https://docs.docker.com/engine/storage/tmpfs/), and [Caddy reverse proxy behavior](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy).
