# Protected provider connectors

The optional connector broker lets Netlify applications use OpenAI, NASA and NLR
without receiving their provider keys. It runs inside the isolated authority
service. The authority host and its service UID are trusted with keys in memory;
an authority compromise can use configured upstream credentials. OpenBao protects
stored key material and keeps the Transit encryption key outside SQLite. This is
software isolation, not confidential computing or an HSM claim.

## Request flow

```mermaid
sequenceDiagram
  participant N as Netlify workload
  participant A as Authority actor
  participant B as Async connector broker
  participant K as OpenBao Transit
  participant P as NASA / NLR
  participant O as OpenAI Responses
  N->>B: Original DPoP headers + exact resource authorization
  B->>A: Verify proof once; enforce exact operation grant
  A->>A: Commit unique grant / operation / UTC hour claim
  A->>K: Decrypt provider-specific ciphertext using derived context
  A-->>B: Credentials in process memory
  B->>P: Fixed bounded data reads
  B->>O: Fixed model, prompt, no tools, store false
  B->>A: Recheck grant, workload and credential generations; commit result
  A-->>N: Bounded briefing and source metadata
```

The Netlify resource handler forwards its original `Authorization: DPoP ...` and
`DPoP` headers to `POST /v1/connectors/{operation}`. Its JSON contains exactly
`method`, `url`, `tenant`, `action` and `audience`, matching its registered GET
resource. It must not call `/v1/authorize` first: a proof is single use.

Callers cannot select the upstream origin, path, model, prompt, output budget or
tools. Browser origins, query parameters and unknown JSON fields are rejected.
The broker uses system TLS trust with TLS 1.2 or newer, disables redirects and
environment proxies, bounds each provider response to 512 KiB, and sets a
25-second generation deadline. NASA/NLR reads have seven-second deadlines;
OpenAI has fifteen seconds. Two generations may run concurrently. Slow provider
calls do not occupy the authority's SQLite/KMS actor thread.

## Configuration

Connectors are disabled by default. Add an entry to the root-owned authority
configuration only after its Netlify site and grant are configured:

```json
{
  "connectors": [
    {"operation":"space-briefing","grant_id":"space-project-grant","enabled":false},
    {"operation":"charging-briefing","grant_id":"charging-project-grant","enabled":false},
    {"operation":"science-digest","grant_id":"science-project-grant","enabled":false}
  ]
}
```

This is an additional top-level field; retain the rest of your authority
configuration. Each enabled entry must reference a configured site grant. Each
operation and each grant appears once. Bind each site's `resource_path`,
`resource_action`, tenant and origin to its standalone example configuration,
then enable only the intended operation. Configuration contains no provider key.

The public gateway must forward the three exact connector paths. The supplied
Instabox gateway template includes them and uses a 30-second response-header
timeout for the broker's 25-second generation budget. Retain the private-route
404 fallback; do not expose the administrative socket or OpenBao listener.

| Operation | Fixed data source | Upstream credentials |
| --- | --- | --- |
| `space-briefing` | NASA NeoWs close approaches for the current UTC day, first ten records | OpenAI, NASA |
| `charging-briefing` | Up to ten nearest public electric vehicle stations within 25 miles of Charleston, West Virginia | OpenAI, NLR |
| `science-digest` | Both fixed sources, fetched concurrently | OpenAI, NASA, NLR |

All three use `gpt-4.1-mini` through `/v1/responses`, `store:false`, a maximum of
192 output tokens, and no tools. These are example operations; add another
operation through code review and tests, rather than permitting arbitrary
caller-controlled requests. Station listings do not establish real-time charger
availability. Model text is untrusted display data: render it as text, not HTML.
Only allowlisted, bounded source fields enter the model input. Source data is
never treated as authorization or a tool instruction.

The NLR operation uses its documented Nearest Stations endpoint with fixed
latitude `38.3498`, longitude `-81.6326`, radius `25` miles, `fuel_type=ELEC`,
`status=E`, `access=public` and `limit=10`. It includes nearby municipalities;
its `records` field counts the returned sample, not every station in the radius.
The All Stations endpoint does not document a city request filter. An empty
upstream result remains valid data and must not be replaced with invented stations.

## OpenBao custody

As an OpenBao administrator, create the dedicated Transit key once:

```text
POST /v1/transit/keys/pap-provider-credentials
{"type":"aes256-gcm96","derived":true,"exportable":false,
 "allow_plaintext_backup":false,"auto_rotate_period":"86400s"}
```

The issuer certificate role needs only these extra ACL paths:

```hcl
path "transit/keys/pap-provider-credentials" {
  capabilities = ["read"]
}
path "transit/encrypt/pap-provider-credentials" {
  capabilities = ["update"]
  allowed_parameters = { "context" = [], "plaintext" = [] }
}
path "transit/decrypt/pap-provider-credentials" {
  capabilities = ["update"]
  allowed_parameters = { "context" = [], "ciphertext" = [] }
}
```

Do not grant this service key creation, deletion, configuration, export, backup,
or rotation permission. OpenBao schedules key version rotation. Old ciphertext
continues to decrypt while its version is retained; retain prior Transit
versions until a reviewed migration reencrypts and verifies every stored
credential and encrypted backup. Never advance minimum decryption version
without that migration. Before each encrypt/decrypt, the broker verifies the
dedicated key is derived AES-256-GCM, nonexportable and not plaintext-backup
enabled. Provider contexts are Base64 of
`pap-provider-credentials:v1:openai`, `...:nasa`, or `...:nlr`. A ciphertext copied
between providers cannot decrypt under the other context.

Keep OpenBao audit sensitive-field hashing enabled. Never configure plaintext
request logging, TLS interception or outbound HTTP debug logging for these
processes. The authority's application audit logs record only provider,
generation, operation, grant and period metadata.

## Credential import, replacement and revocation

The admin route exists only on the authenticated Unix listener:

```text
POST /v0/connectors/credentials
{"provider":"openai","action":"import","credential":"<read securely into memory>"}
```

Providers are exactly `openai`, `nasa` and `nlr`. The calling Unix peer must have
the configured admin UID. Use the operator tool's stdin/descriptor secret input
or encrypted custody workflow; do not paste a key into a command argument,
shell history, environment variable, source file or Netlify setting. The
response contains only `provider`, `configured` and a monotonic `generation`.
Replacing an existing credential uses the same import operation; SQLite only
receives the Transit ciphertext. The previous credential must be revoked at
its upstream provider after the new one has been tested.

To remove the broker's use of a key:

```text
POST /v0/connectors/credentials
{"provider":"openai","action":"revoke"}
```

This deletes the encrypted local credential and prevents both new generation
jobs and cached result reads that depend on that provider. It does not call the
provider's key-management API. Cached reads require the same credential
generations as the original job. Replacing a key invalidates its prior cached
results without permitting another paid attempt in the same hour. PAP's
existing grant/workload revocation events also stop cached and new access.
A replacement or revoke during generation prevents that in-flight result from
being released.

NASA and NLR document a public `DEMO_KEY` for low-volume development. Import
that value explicitly for starter use; the broker has no silent fallback.
`DEMO_KEY` is a shared public credential with restrictive quotas, not a private
issued key. Register independent free NASA/NLR keys for sustained use, then
import them centrally. OpenAI requires a separately issued key and may incur
provider charges. Sharing one OpenAI demo key across the three operations does
not share their PAP grants or Netlify identities.

## Paid requests, recovery and renewal

Before any provider work, SQLite commits a unique job for
`(grant_id, operation, UTC hour)`. A completed job returns its cached result to
freshly authorized requests. A pending, failed or abandoned job returns
`connector_period_unavailable` for that hour. A timeout, client disconnect or
reboot cannot cause the authority to retry a potentially billed request. The
next UTC hour allows a new job. This deliberately trades availability for a
strict local at-most-one-attempt boundary; it does not claim exactly-once
execution at an upstream provider. Do not clear failed jobs to force retries
unless you have independently reconciled the provider outcome. Job tombstones
are retained so clock rollback or service restart does not recreate attempts.

PAP access tokens, proof keys and host certificates renew through the existing
automated lifecycle, including expiry/pause and cold-boot recovery. OpenBao
Transit key versions rotate automatically. An OpenAI/NASA/NLR static API key
does not become automatically renewable because it is encrypted: upstream key
replacement and revocation require that provider's management support. This
release supports central replacement and immediate local revocation; it does
not claim automatic provider root-key issuance or revocation where no API is
available.

## Response

```json
{
  "operation":"space-briefing",
  "generated_at":"2026-01-01T12:34:56Z",
  "period":"2026-01-01T12:00:00Z",
  "model":"gpt-4.1-mini",
  "summary":"A bounded factual briefing.",
  "sources":[{"provider":"nasa","title":"NASA NeoWs daily close approaches",
              "url":"https://api.nasa.gov/","records":5}],
  "cached":false
}
```

Responses never include credentials, provider request URLs, raw source payloads
or raw provider errors. Upstream availability failures return a stable 503 code.
Source links are static public documentation URLs with no credential or query.

Authoritative provider references: [NASA NeoWs](https://api.nasa.gov/),
[NLR key usage](https://developer.nlr.gov/docs/api-key/),
[NLR nearest station API](https://developer.nlr.gov/docs/transportation/alt-fuel-stations-v1/nearest/),
and [OpenAI Responses](https://developers.openai.com/api/reference/resources/responses/methods/create).
