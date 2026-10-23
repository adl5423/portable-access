# Deploy with Docker or an HTTPS server

Use the [`examples/docker-https`](../examples/docker-https/README.md) deployment for a server outside Netlify. It includes a non-root Python process, a separate Caddy HTTPS gateway, public configuration, a private local acceptance command and an explicit authority registration example.

The authority chooses `identity_adapter: "https-origin"` for the workload. It proves control of the registered public origin by fetching a short-lived response signed by an ephemeral workload key. The proof key and issued token remain in memory. A restart creates a new key and performs fresh issuance automatically.

| Component | Where it runs | Persistent secret |
| --- | --- | --- |
| Workload client and resource | Your Docker container or Python process | None |
| Proof callback | Same workload process | None |
| HTTPS gateway | Caddy or your existing reverse proxy | Normal TLS certificate private key |
| PAP authority | Your separately operated authority | Authority signing keys under its configured key service |
| Optional provider connector | Authority-side connector broker | Centrally encrypted provider credential |

The workload still needs a valid public TLS certificate. Caddy renews that certificate automatically and keeps its private key in a separate certificate volume. Eliminating application environment secrets does not remove the TLS terminator's key or the authority's signing key.

Start with one process and one replica. The example's in-memory callback store cannot serve issuance across unrelated processes. Its read-only root filesystem and bounded writable mounts are operational controls, not protection from a compromised host administrator. Review [adapter trust boundaries](identity-adapters.md) before granting access to a shared hosting origin.

Follow the example's registration and acceptance steps before replacing your application's authentication. Test an authorized read, a read after credential expiry, and a read after operator revocation. Treat public DNS, certificate issuance, origin control, resource authorization and container isolation as separate acceptance checks.
