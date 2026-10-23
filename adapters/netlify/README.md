# Portable Access on Netlify

This adapter supplies a server-only TypeScript SDK, a public proof publication function, and a protected records endpoint. Applications use public configuration and short-lived proof-bound credentials. No user-managed API key, signing key, or bootstrap secret is configured in an environment variable.

The reusable adapter rejects missing configuration and requires explicit trusted-site acknowledgement. Its default configuration is disabled. Use a separate trusted site and register its exact resource binding with your own authority before enabling it. This source release provides reproducible local tests and deployment procedures; public source or a successful build does not establish live Netlify, host recovery or sustained production acceptance.

Each background records read has a 300-second budget and at most 24 attempts; the ordinary SDK retains its 20-second issuer-readiness budget. Deterministic tests exercise temporary-unavailability recovery within that deadline. Measure actual pause/clock/certificate recovery on the intended host. A provider recovery beyond the budget fails closed and requires a later authorized caller job.

## Security boundary

This is **registered HTTPS origin verification**, not a Netlify-issued workload identity token. The issuer independently retrieves a public, expiring challenge from an administrator-registered Netlify origin. The callback only reads a publication made by trusted server code. It cannot publish records, echo challenge parameters, or sign an arbitrary caller key.

All code and deployments within a Netlify site share the relevant site authority. A production deployment must use a dedicated trusted site. Disable untrusted Deploy Previews and branch deployments in Netlify's site settings, and use a separate site for previews. The build rejection in `netlify.toml` and runtime production checks reduce mistakes; code in an untrusted build can modify its own checks, so those checks are not an isolation boundary. Blobs namespaces are not permission boundaries.

The SDK keeps a non-extractable WebCrypto private key and access token in private JavaScript fields. This prevents accidental export through its public API, but it does not isolate a compromised function process. The Netlify runtime, trusted server code, site administrators, and deployment pipeline remain trusted. The Linux process-isolation profile in the main project applies to self-hosted services, not Netlify Functions. Run the issuer and protected signing service under that profile or a managed equivalent.

Official references: [Functions API](https://docs.netlify.com/build/functions/api/), [Blobs access and consistency](https://docs.netlify.com/build/data-and-storage/netlify-blobs/), [event signature scope](https://docs.netlify.com/build/functions/trigger-on-events/#signature).

## Files

```text
src/
  config.public.json        Public issuer/site/grant/resource configuration; disabled initially
  client.mts                Allowed server operations and automatic renewal
  background.mts            Bounded retries for fixed records GET jobs
  protocol.mts              ES256 proofs, schema checks, bounded HTTPS client
  proof-store.mts           Platform-authenticated public publication storage
  proof-handler.mts         Lookup-only public callback
  verifier.mts              Online authorization with original signed request
netlify/functions/
  pap-site-proof.mts        GET /.well-known/pap/site-proof/:challenge_id
  pap-records.mts           GET /api/pap/records
tests/adapter.test.mts      Deterministic conformance and adversarial cases
tools/                     Build and public-configuration utilities
```

## Set up

Use Node.js 24 and a separate trusted production Netlify site. The issuer must be reachable over publicly trusted HTTPS. Its configuration must register the exact canonical production origin, site ID, grant, tenant, environment, audience, and allowed operation. The first profile accepts canonical `https://project-name.netlify.app` origins without preview prefixes, alternate ports, or redirects.

```sh
npm ci --ignore-scripts
npm run check
npm run configure -- \
  --issuer-url https://YOUR_ISSUER_HOST \
  --site-id YOUR_NETLIFY_SITE_UUID \
  --grant-id YOUR_ISSUER_GRANT \
  --resource-origin https://YOUR_PROJECT.netlify.app \
  --tenant YOUR_TENANT \
  --audience YOUR_RESOURCE_AUDIENCE \
  --acknowledge-trusted-site
npm run build
```

Replace every uppercase placeholder with a real registered value. Configuration validation rejects placeholders. The acknowledgement confirms that every deploy context on the site is trusted; it does not configure Netlify security settings for you. `src/config.public.json` contains no secrets and may be committed. Rebuild after changing it. The issuer separately manages grants; running this configurator does not create or restore access.

Site IDs use canonical lowercase UUID text. Tenant and grant identifiers start with an ASCII letter or digit and contain at most 80 ASCII letters, digits, underscores or hyphens. The audience is limited to 200 characters. These bounds match the Python issuer. Challenge identifiers keep their separate protocol bounds and are not interpreted as tenant or grant identifiers.

The Netlify build command is `npm run build`, the publish directory is `public`, and the functions directory is `netlify/functions`. Deploy through the existing approved project workflow after reviewing the issuer registration and site settings. This package does not deploy automatically.

Netlify's runtime supplies its own Blobs credentials. The adapter neither accepts a platform token in public configuration nor reads a user-supplied secret from environment variables. Internal hosting-provider credentials still exist. No claim is made that a compromised hosting provider cannot access or impersonate a deployment.

## Use the server SDK

The installable `0.3.0` archive exports five Node-only entrypoints: `@portable-access/netlify` for `PortableAccessClient` and record validation, `/proof` for `createProofHandler`, `/verifier` for `createResourceVerifier`, `/background` for `BackgroundRecordsReader`, and `/protocol` for shared public configuration validation and classified errors. None exposes a token getter. Build the archive from source or download it from the GitHub release; registry publication is not required to deploy it independently. The [project onboarding guide](../../docs/project-onboarding.md) includes complete function files and operator registration steps.

Import this only from trusted server code. Browser package resolution is disabled, modules import Node cryptography, and the runtime guard rejects a browser context. Preserve the application's existing authentication and authorization before invoking operations on behalf of an end user.

```typescript
import { getContext } from "@netlify/functions";
import publicConfig from "./src/config.public.json" with { type: "json" };
import { PortableAccessClient } from "./src/client.mjs";

const access = new PortableAccessClient(publicConfig);

export async function readPermittedRecords() {
  return access.readRecords(getContext());
}
```

Version 0.2 permits one registered GET operation per Netlify site. The default is `records.read` at `/api/pap/records`. `getJSON(context)` calls exactly the configured target and returns its JSON; `readRecords(context)` adds the example record schema validation. There is no per-call URL, HTTP method, header, credential getter, or secret fetch argument. The current issuer registry does not accept multiple grants or GET endpoints for the same site. Supporting multiple operations requires a deliberate registry and authorization-policy extension. Write requests require a separate body-binding and idempotency policy, and this adapter rejects them.

For a real project endpoint, pass public configuration with `resourcePath: "/api/orders/current"` and `resourceAction: "orders.read"`, register the exact same mapping with the issuer, then install the verifier inside that endpoint. The configurator also accepts `--resource-path` and `--resource-action`. Authentication happens before reading project data:

```typescript
import type { Config, Context } from "@netlify/functions";
import publicConfig from "../../src/config.public.json" with { type: "json" };
import { createResourceVerifier } from "../../src/verifier.mjs";

const verify = createResourceVerifier(publicConfig);

export async function authorizeOrders(request: Request, context: Context) {
  // The caller's existing handler must await this before reading orders.
  return verify(request, context);
}

export const config: Config = { path: "/api/orders/current", method: ["GET"] };
```

The built-in `pap-records.mts` remains the complete default endpoint. When protecting an existing endpoint, incorporate the verifier into its own complete handler and preserve its established data model and response schema. Choose the single protected GET path/action when registering the site. A different operation cannot be added through a caller-supplied argument or an extra client configuration.

The records function reads an actual site-wide Blobs document at `pap-records-v1`, key `tenants/REGISTERED_TENANT/records`, after successful online authorization. Missing data returns `{ "records": [] }`. A document has the shape:

```json
{
  "records": [
    { "id": "record-1", "title": "An authorized record", "updated_at": "2026-10-22T12:00:00Z" }
  ]
}
```

Manage this data through trusted server administration. The example exposes no unauthenticated write route. Requests and responses have fixed schemas and size bounds. Add a stronger transactional data store before implementing write operations that require locking or idempotency.

## Bounded background records jobs

Use `BackgroundRecordsReader` for an already authorized server-side background job that can wait for recovery. Its only operation is `readRecords` against the configured, registered GET target. It accepts no operation callback, per-call URL, HTTP method or write payload. The package exports it through the Node-only `@portable-access/netlify/background` entry point:

```typescript
import type { Context } from "@netlify/functions";
import { BackgroundRecordsReader } from "@portable-access/netlify/background";
import publicConfig from "./src/config.public.json" with { type: "json" };

export async function runAuthorizedRecordsJob(context: Context, signal?: AbortSignal) {
  const reader = new BackgroundRecordsReader(publicConfig);
  try {
    return await reader.readRecords(context, signal ? { signal } : {});
  } finally {
    reader.close();
  }
}
```

Each read has an absolute monotonic deadline of 300 seconds, including enrollment, the resource request, proof cleanup and retry waits. It permits at most 24 attempts, with exponential jitter starting at two seconds and capped at 15 seconds. Callers may reduce `budgetMs` or `attemptLimit`; neither can exceed these limits. Only `AccessError` values with status 503 and code `issuer_unavailable` or `resource_unavailable` schedule another read. Denial, policy errors, closure, malformed data and other statuses stop immediately. The existing SDK's single resource-401 credential refresh remains unchanged; the outer helper never schedules another read after a surfaced 401/403 denial.

The reader owns one SDK client across sequential successful reads. A competing concurrent call gets `background_read_busy` without interrupting the accepted operation. An abort, deadline, exhausted retry sequence or other terminal error closes the owned client. Late fulfillment or rejection is consumed and cannot authorize another attempt or return data after termination. The deadline also bounds a hung proof-cleanup promise; already sent requests may finish safely. `close()` is idempotent. A successful read releases all helper timers and abort listeners, so keeping the reader for another operation adds no periodic traffic or keepalive.

The deploy-event check uses the same reader for both fixed reads, with independent 300-second budgets and its explicit 65-second pause between them. The maximum 300 + 65 + 300-second sequence is 665 seconds, within Netlify's 15-minute background-function limit. The ordinary `PortableAccessClient` keeps its 20-second readiness behavior.

Deterministic local fault tests exercise eventual success after simulated 129-second and 270-second outages with immediate 503 responses, and denial without retries. Those tests establish helper behavior under their injected conditions. Test a genuine provider pause past certificate expiry, clock reacquisition and a separate memory-discarding cold boot before relying on this budget for operations. Retain source-bound provider transitions and authority evidence separately from local test output.

## Wire protocol

1. The SDK generates an ephemeral P-256 key and posts `{grant_id, jwk}` to `/v1/site/challenge`.
2. The issuer responds with exactly `{challenge_id, nonce, jkt, issuer, site_id, expires_at}`. The SDK checks issuer, site, key binding and a maximum 120-second challenge lifetime.
3. The SDK publishes that public record with a conditional create through Netlify Blobs. It never publishes its private key or access credential.
4. The SDK posts `{challenge_id, jwk}` to `/v1/site/token`, with an ES256 DPoP proof bound to that endpoint and the issuer nonce. The issuer independently fetches the record at its registered canonical origin and consumes the challenge atomically. Caller-controlled URLs and redirects are forbidden at the issuer.
5. The issuer returns exactly `{access_token, token_type, expires_at, expires_in, dpop_nonce, tenant, environment}`. `token_type` must be `DPoP`. The SDK checks response scope and lifetime and deletes the public publication in `finally`.
6. Each resource call has `Authorization: DPoP TOKEN` and a fresh DPoP proof containing the resource URI, method, nonce, issue time, random `jti`, and SHA-256 token hash `ath`.
7. The resource forwards the original token and original DPoP proof as headers to `/v1/authorize`, plus the fixed JSON metadata below. It never reconstructs the target from `Host`, `Origin`, or forwarded headers.

```json
{
  "method": "GET",
  "url": "https://REGISTERED_PROJECT.netlify.app/api/pap/records",
  "tenant": "REGISTERED_TENANT",
  "action": "records.read",
  "audience": "REGISTERED_RESOURCE_AUDIENCE"
}
```

The issuer must independently match every field to registered policy, verify the access token and proof, consume replay state, and check current grant/revocation state. Merely accepting caller-supplied metadata would not authorize anything. Its successful response contains exactly `{subject, tenant, environment, grant_id, action, expires_at}`. The adapter checks those values before reading data. The authorization endpoint needs no extra shared API key because the original signed credential authorizes the operation. An unsigned request must fail.

## Renewal, rotation and revocation

Credentials renew automatically before an operation when ten seconds or less remain. Each renewal creates a new non-extractable workload key. Concurrent calls share one renewal, while every resource attempt receives a new proof and `jti`. A safe GET may retry once after a transient failure. A single 401 causes fresh enrollment once; a 403 never triggers an access-restoring retry. Token issuance itself is not automatically retried after an uncertain response.

Serverless instances can freeze when idle. The adapter does not rely on a timer continuing after a response. Expired credentials in an idle instance remain unusable; the next operation obtains fresh access first. Restarting an instance also creates a fresh identity. Grant expiry and revocation remain issuer policy and are never automatically undone.

Every resource request checks the issuer online, without a positive authorization cache. If the issuer is unreachable, access fails closed. Grant revocation must block both resource authorization and new enrollment. Previously authorized operations already in progress have their own completion boundary; implement a second check before committing future writes.

Public proof cleanup failure does not change issuer-side nonce expiry or consumption. An old publication cannot renew a credential, and credentials are bound to the private key. Expired public records may be removed by site administration; store no confidential information in them.

Response headers are set in each function's code. Netlify `_headers` and `[[headers]]` rules do not apply to function responses. Both routes disable browser/CDN caching. No cross-origin access headers are added.

## Verification and limits

`npm run check` runs strict TypeScript validation, Node's tests, and bundles all three functions. Tests use an injected in-memory publication store and network responses. They verify real WebCrypto signatures, key non-extractability, key rotation, concurrent renewal, replay-proof freshness on retry, tenant/environment binding, malformed responses, callback lookup-only behavior, and fixed-target online verification. Background-job tests cover simulated 129-second and 270-second outages with immediate 503 responses at minimum jitter, absolute deadlines including hung cleanup, late-result rejection, abort/close cleanup, independent per-read budgets and denial without retry.

These tests do not prove a real Netlify deployment, Blobs runtime authorization, public TLS callback reachability, or the live issuer/KMS configuration. Before enabling a real grant, run the full end-to-end flow on a dedicated site, then revoke it and verify both access and renewal fail. The parent project provides deployment acceptance instructions.

`ClientOptions` exists for testing transport/storage failures. Code running in the same trusted process can instrument network calls or the JavaScript runtime. Private fields and WebCrypto non-extractability do not remove that trust. Use the separate protected-agent deployment for stronger application process containment.

## Fixed deployment acceptance check

`deploy-succeeded.mts` uses Netlify's documented event-name registration and subscribes only to the typed `deploySucceeded` platform event. It exports no HTTP handler, accepts no operation/URL from callers, and returns no credential. [Netlify verifies event signatures before invocation](https://docs.netlify.com/build/functions/trigger-on-events/). The handler still requires a matching production/published runtime context from `getContext()` and the configured site binding; unavailable or invalid context fails closed. Disabled configuration skips the check without fetching or accessing Blobs.

When enabled, a successful production-deploy event delivery performs the configured records GET twice through the background reader using the same server-only SDK instance, 65 seconds apart, then closes it. Each read has its own bounded recovery window. The function sets `background: true` so the whole sequence fits within Netlify's documented 15-minute background execution limit. It logs only fixed outcome codes, phase and record count. It does not log records, headers, tokens, proof keys or upstream error bodies. Use a 60-second authority token lifetime for this bounded acceptance run and correlate the two reads with authority audit evidence before claiming renewal. Signing-key rotation and revocation remain operator-coordinated authority checks. This event is not a schedule or a VM keepalive.

`public/status.json` reports whether the adapter's public configuration was enabled at build time. It is deployment metadata, not authority readiness or production acceptance. `.netlify/` remains ignored because the CLI stores the local project link there.

After deployment, verify that a genuine production platform event completes both protected reads and correlate them with authority audit state. Verify that unsigned direct HTTP requests cannot invoke the event function, aliases are absent, and public proof endpoints remain lookup-only. Log arrival can be buffered; use authority timestamps and key thumbprints to establish renewal. A build, a function registration or an outcome-only log does not by itself establish the entire flow.

## Provider-backed standalone examples

The three [standalone projects](../../docs/use-cases.md) use the same SDK
protocol with separate Netlify sites, grants and tenants. Their resource handler
forwards the original token/proof and fixed resource metadata directly to the
[connector broker](../../docs/connectors.md). It must not call the ordinary
verifier first: consuming the same proof twice is a replay failure. The broker
performs the one current-policy verification and executes the fixed permitted
operation. Provider keys stay in central encrypted custody and never enter
Netlify configuration or application responses. The SDK bounds the resource GET
to 30 seconds; this includes the connector generation but does not extend the
separate issuer-readiness budget.

## On-demand issuer wake recovery

A healthy operation performs no readiness probe. If the first complete enrollment attempt fails with `issuer_unavailable`, the SDK waits on the configured issuer's fixed `/health` endpoint for at most 20 seconds using a monotonic deadline. It makes at most eight GET attempts with 250–2,000 ms exponential jitter; each fetch timeout is capped at eight seconds and the remaining budget. Only an exact `{"ready":true}` response permits one new enrollment attempt.

The retry generates a new non-extractable P-256 identity, challenge and DPoP proof. It never resends an uncertain issuance POST or reuses the previous challenge. Both attempts retain public-proof cleanup. HTTP 401/403 denials are not retried, and readiness denial fails closed. A second enrollment failure is returned without another recovery cycle. Closing the client aborts readiness fetching/backoff and stops further recovery. These requests follow a real failed operation; there is no timer, schedule or keepalive. Successful readiness alone does not prove successful enrollment or protected access.
