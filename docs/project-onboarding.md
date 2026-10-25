# Add Portable Access to another Netlify project

Install the release **0.4.0** SDK with a separate workload identity and least-privilege grant for each trusted project. This guide does not reuse the demonstration identity, grant or data, or deploy/migrate a customer project automatically.

The current profile protects **one registered GET path/action per Netlify site**. The complete example uses `GET /api/pap/records`, action `records.read`, and tenant-scoped records. It proves control of a registered production HTTPS origin; it is not provider-issued workload attestation or deployment/commit attestation. There is no browser SDK, credential getter, arbitrary HTTP proxy, write-operation profile or Railway/AWS/vendor-key connector. A provider that requires an API key needs a separate supported integration.

The reference deployment passed a real changed-boot recovery and subsequent Netlify renewal flow. It remains a **single-host development/pilot service**, without high-availability or critical-production availability acceptance. Consult the verification index for current evidence. Ordinary SDK enrollment has a 20-second readiness window. An authorized background records job may use the bounded 300-second helper; even that deadline can expire. Retry a failed caller job later instead of bypassing TLS, expiry or policy.

## 1. Select the project and public policy

Use a dedicated trusted production Netlify site per project. Collect its actual lowercase site UUID and canonical `https://PROJECT.netlify.app` origin. Disable untrusted Deploy Previews and branch deployments in the site settings; put untrusted previews on another site. All site deployments, administrators and build code share the relevant Blobs trust boundary. Runtime context checks and storage namespaces do not isolate hostile code in the same site.

Ask the operator for the authority's current public HTTPS origin and **existing global audience**. This authority has one audience; do not invent a different per-project value. Choose a separate tenant for a separate data boundary. Each project needs a new subject/grant, exact GET path/action and explicit approved grant expiry. Automatic credential renewal does not extend this access grant.

Applications receive public configuration only. They receive no OpenBao credential, issuer private key, seal key or recovery material. Netlify supplies its internal Blobs credentials at runtime; no application API key or bootstrap secret is added to environment variables.

## 2. Install the verified SDK archive

The package is **not published to an npm registry**. Download `portable-access-netlify-0.4.0.tgz` and `SHA256SUMS` from the same [v0.4.0 GitHub Release](https://github.com/adl5423/portable-access/releases/tag/v0.4.0). In that download directory, verify the named archive before copying it into the project's `vendor/` directory:

```sh
python3 - <<'PY'
import hashlib
from pathlib import Path

name = "portable-access-netlify-0.4.0.tgz"
entries = [line.split() for line in Path("SHA256SUMS").read_text().splitlines()]
matches = [parts[0] for parts in entries if len(parts) == 2 and parts[1] == name]
if len(matches) != 1 or hashlib.sha256(Path(name).read_bytes()).hexdigest() != matches[0]:
    raise SystemExit("SDK checksum verification failed")
print("SDK checksum verified against this release's SHA256SUMS")
PY
mkdir -p /path/to/project/vendor
cp portable-access-netlify-0.4.0.tgz /path/to/project/vendor/
```

Use the checksum file published alongside the selected version. A checksum copied from a different build or release is not a substitute. The check verifies agreement with the release metadata; it does not provide an independent signature or security audit.

The following complete files form a minimal new project. For an existing application, merge the dependencies, checks and function configuration into its existing files. Preserve its framework adapter, route ownership, end-user authentication and release process.

<!-- file: package.json -->
```json
{
  "name": "my-project-pap-integration",
  "version": "0.0.0",
  "private": true,
  "type": "module",
  "engines": {
    "node": ">=22.0.0"
  },
  "scripts": {
    "check": "tsc --noEmit",
    "build": "npm run check && node tools/build.mjs"
  },
  "dependencies": {
    "@netlify/blobs": "10.7.13",
    "@netlify/functions": "5.3.0",
    "@portable-access/netlify": "file:vendor/portable-access-netlify-0.4.0.tgz"
  },
  "devDependencies": {
    "@types/node": "24.19.2",
    "esbuild": "0.25.12",
    "typescript": "5.9.3"
  }
}
```

<!-- file: tsconfig.json -->
```json
{
  "compilerOptions": {
    "target": "ES2023",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "exactOptionalPropertyTypes": true,
    "noUnusedLocals": true,
    "noUnusedParameters": true,
    "resolveJsonModule": true,
    "skipLibCheck": true,
    "types": [
      "node"
    ]
  },
  "include": [
    "src/**/*.mts",
    "netlify/functions/**/*.mts"
  ],
  "exclude": [
    "dist",
    "node_modules",
    ".netlify"
  ]
}
```

<!-- file: netlify.toml -->
```toml
[build]
  command = "npm run build"
  publish = "public"

[build.environment]
  NODE_VERSION = "24"

[functions]
  directory = "netlify/functions"
  node_bundler = "esbuild"

[context.deploy-preview]
  command = "node -e 'process.exit(1)'"

[context.branch-deploy]
  command = "node -e 'process.exit(1)'"
```

The build rejection is a mistake guard. Site settings remain necessary because another build can change its own checks. `NODE_VERSION` is public build configuration.

```sh
npm install --ignore-scripts
mkdir -p src tools netlify/functions
```

Review and commit `package-lock.json`; subsequent builds use `npm ci --ignore-scripts`. The release builder verifies standalone examples with their vendored SDK. A new consumer's initial install resolves its own transitive lock, which requires its own review.

## 3. Prepare matching public files once

Use `pap-operator workload-init` from this checkout or its corresponding operator release. It generates a fresh subject and grant, uses the actual Netlify site UUID, validates both public files together, and creates a new owner-only output directory. It never accesses operator custody, a provider credential or a network service. The existing v0.4.0 application SDK accepts the generated Netlify configuration.

Replace the public values below with the operator-approved issuer, existing audience, site UUID, production origin and tenant. The example explicitly acknowledges the origin's administrators and prepares an enabled application configuration. Hold deployment until the operator has registered the matching grant.

```sh
mkdir -m 0700 pap-onboarding
pap-operator workload-init \
  --adapter netlify \
  --issuer https://YOUR_ISSUER_HOST \
  --audience YOUR_EXISTING_AUTHORITY_AUDIENCE \
  --origin https://YOUR_TRUSTED_SITE.netlify.app \
  --workload-id YOUR_LOWERCASE_SITE_UUID \
  --tenant YOUR_PROJECT_TENANT \
  --grant-days 7 \
  --output-directory pap-onboarding/new-workload \
  --trust-origin --enable
mkdir -p src
cp pap-onboarding/new-workload/config.public.json src/pap.public.json
cp pap-onboarding/new-workload/pap-registration.json pap-registration.json
pap-operator workload-check \
  --config src/pap.public.json \
  --registration pap-registration.json
```

Omitting both `--trust-origin` and `--enable` creates a disabled proposal with both trust acknowledgments false. `--enable` without `--trust-origin` fails. New grants default to seven days; `--grant-days` accepts 1–30. Renewal never extends this absolute expiry. A Netlify workload requires `--workload-id`; use its actual site UUID rather than a generated substitute.

The checker reports `ok: true, ready: false` for a consistent proposal whose authority registration has not been checked. It does not contact the authority, issue a credential, or change a file. It never prints untrusted JSON values or unknown member names. Use `--require-ready` with an authority configuration after operator registration to enforce the public linkage check.

Commit the reviewed `src/pap.public.json` and send `pap-registration.json` to the authority operator. Both contain public policy only. Do not run initialization during normal builds or regenerate an existing workload: exclusive output creation prevents silently replacing a grant. If interrupted, preserve and inspect the partial directory before choosing another destination. See [operator tooling](operator-cli.md#prepare-and-check-public-workload-configuration) for the Docker profile and the exact meaning of readiness.

Site UUIDs are lowercase canonical text. Subject, tenant and grant start with an ASCII letter/digit and contain at most 80 ASCII letters, digits, underscores or hyphens. Audience is at most 200 characters and the authority rejects whitespace. Origins have no custom domain, preview prefix, port, path or trailing slash. The resource request accepts no query parameters.

## 4. Operator: register the fresh grant

There is no `pap grant create` command or public registration endpoint in this release. A trusted host operator adds the binding to root-owned `/etc/pap/authority.json`. Startup provisions only its named action and persists its absolute expiry. Preserve all existing registrations and revocations.

Place the reviewed public handoff at `/root/pap-onboarding/pap-registration.json` and its paired application configuration at `/root/pap-onboarding/config.public.json` through the existing approved transfer method. On the authority host, create a separate candidate and validate it with the installed runtime:

```sh
sudo install -d -m 0700 /root/pap-onboarding
sudo cp -p /etc/pap/authority.json /root/pap-onboarding/authority.before.json
sudo /opt/pap/venv/bin/python -I - <<'PY'
import json, os, time
from pathlib import Path
from pap.configuration import parse_config_json
from pap.production import ProductionConfig, SiteConfig, load_config

current = load_config(Path("/etc/pap/authority.json"))
handoff = parse_config_json(Path("/root/pap-onboarding/pap-registration.json").read_bytes())
if set(handoff) != {"issuer", "audience", "site"}:
    raise SystemExit("invalid handoff schema")
if handoff["issuer"] != current.issuer or handoff["audience"] != current.audience:
    raise SystemExit("issuer/audience mismatch")
site = SiteConfig.model_validate(handoff["site"])
if site.grant_expires_at <= time.time():
    raise SystemExit("grant already expired")
for field in ("site_id", "origin", "subject", "grant_id"):
    if any(getattr(old, field) == getattr(site, field) for old in current.sites):
        raise SystemExit("existing binding requires a separate reviewed migration")
candidate = current.model_dump()
candidate["sites"].append(site.model_dump())
ProductionConfig.model_validate(candidate)
path = Path("/root/pap-onboarding/authority.candidate.json")
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, "w") as stream:
    json.dump(candidate, stream, indent=2)
    stream.write("\n")
    stream.flush()
    os.fsync(stream.fileno())
print("Validated new-site candidate; existing registrations preserved.")
PY
sudo diff -u /etc/pap/authority.json /root/pap-onboarding/authority.candidate.json
sudo /opt/pap/venv/bin/pap-operator workload-check \
  --config /root/pap-onboarding/config.public.json \
  --registration /root/pap-onboarding/pap-registration.json \
  --authority-config /root/pap-onboarding/authority.candidate.json \
  --require-ready
```

A nonzero `diff` status is expected for the new binding. Review the exact change and expiry, then activate the reviewed candidate atomically on the same filesystem and restart only the authority:

```sh
sudo install -o root -g pap-issuer -m 0640 /root/pap-onboarding/authority.candidate.json /etc/pap/authority.next.json
sudo mv /etc/pap/authority.next.json /etc/pap/authority.json
sudo systemctl restart pap-authority.service
sudo -u pap-admin /opt/pap/venv/bin/pap status --state /run/pap-admin
```

Require readiness before the project deploy. These commands do not initialize OpenBao, change KMS credentials or edit SQLite. Current-policy validation cannot prove absence of an older historical binding; startup independently checks immutable persisted bindings and refuses silent rebinding. Investigate startup failure. Do not restore access by editing authorization rows, rerunning a fresh-host installer or changing an existing grant expiry. The single authority restart briefly interrupts authorization for all enrolled sites; highly available registration is not implemented.

Administrative status, audit and incidents remain on the separately protected Unix socket under `pap-admin`. Public `/health` reports readiness only.

## 5. Add complete proof and protected resource functions

The proof route is lookup-only. It retrieves an internally published, expiring record, never writes a caller's challenge, echoes a caller's key or returns a credential.

<!-- file: netlify/functions/pap-site-proof.mts -->
```typescript
import type { Config, Context } from "@netlify/functions";
import publicConfig from "../../src/pap.public.json" with { type: "json" };
import { createProofHandler } from "@portable-access/netlify/proof";

const handle = createProofHandler(publicConfig);

export default async (request: Request, context: Context): Promise<Response> => handle(request, context);

export const config: Config = {
  path: "/.well-known/pap/site-proof/:challenge_id",
  method: ["GET"],
  rateLimit: { action: "rate_limit", aggregateBy: "ip", windowSize: 60, windowLimit: 120 },
};
```

<!-- file: netlify/functions/pap-records.mts -->
```typescript
import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import publicConfig from "../../src/pap.public.json" with { type: "json" };
import { AccessError, noCache } from "@portable-access/netlify/protocol";
import { parseRecords } from "@portable-access/netlify";
import { createResourceVerifier } from "@portable-access/netlify/verifier";

export default async (request: Request, context: Context): Promise<Response> => {
  try {
    const claims = await createResourceVerifier(publicConfig)(request, context);
    const records = getStore({ name: "pap-records-v1", consistency: "strong" });
    const stored = await records.get(`tenants/${claims.tenant}/records`, { type: "json", consistency: "strong" });
    const response = parseRecords(stored ?? { records: [] });
    return Response.json(response, { headers: noCache });
  } catch (error) {
    const status = error instanceof AccessError ? error.status : 503;
    // Only classifications and Netlify's generated request ID belong in logs.
    console.error(JSON.stringify({ event: "pap.records.denied", code: error instanceof AccessError ? error.code : "storage_unavailable", request_id: context.requestId }));
    return Response.json({ error: status === 503 ? "service_unavailable" : "access_denied" }, { status, headers: noCache });
  }
};

export const config: Config = {
  path: "/api/pap/records",
  method: ["GET"],
  rateLimit: { action: "rate_limit", aggregateBy: "ip", windowSize: 60, windowLimit: 60 },
};
```

The resource checks the original DPoP request online before reading data. Its canonical target comes from approved configuration, never from `Host`, `Origin` or forwarding headers. Missing data returns `{"records":[]}`. A document is `{ "records": [{ "id": "record-1", "title": "A project record", "updated_at": "2026-10-22T12:00:00Z" }] }`, stored at `pap-records-v1`, key `tenants/REGISTERED_TENANT/records`. Manage writes through trusted server administration; no seeding or public write route is provided.

For an existing endpoint, await `createResourceVerifier(publicConfig)(request, context)` before its own read and preserve its business permissions and data schema. Register the exact custom GET path/action in both configurations. `PortableAccessClient.getJSON(context)` returns that fixed target's JSON; `readRecords(context)` and `BackgroundRecordsReader` additionally enforce the records schema above. The background helper is for that records-shaped GET only. A second endpoint/grant on the same site, cross-site callers, writes and arbitrary provider APIs require a deliberate profile/registry extension.

## 6. Add a platform-only end-to-end check and build

This conventional `deploy-succeeded` function uses the public background entrypoint. Netlify verifies the platform event before invoking the typed handler. There is no HTTP handler or caller-selected target. Do not replace it with a public route trusting an event-name header.

<!-- file: netlify/functions/deploy-succeeded.mts -->
```typescript
import { getContext, type Config, type DeploySucceededEvent } from "@netlify/functions";
import { BackgroundRecordsReader } from "@portable-access/netlify/background";
import { AccessError, assertPlatform, validateConfig } from "@portable-access/netlify/protocol";
import publicConfig from "../../src/pap.public.json" with { type: "json" };

const safeCodes = new Set(["adapter_not_configured", "untrusted_deployment", "event_binding_mismatch",
  "access_denied", "issuer_unavailable", "resource_unavailable", "invalid_records_response",
  "client_closed", "background_read_aborted", "background_read_deadline"]);

export default {
  async deploySucceeded(event: DeploySucceededEvent): Promise<void> {
    let reader: BackgroundRecordsReader | undefined;
    let stage = "context";
    try {
      const config = validateConfig(publicConfig);
      const context = getContext();
      assertPlatform(config, context);
      if (event.site?.id !== config.siteID || event.deploy?.siteId !== config.siteID ||
          event.deploy?.context !== "production" || !event.deploy.publishedAt) {
        throw new AccessError("event_binding_mismatch", 403);
      }
      reader = new BackgroundRecordsReader(config);
      stage = "initial-read";
      const first = await reader.readRecords(context);
      console.log(JSON.stringify({ event: "pap.deploy-check", stage, outcome: "passed", records_count: first.records.length }));
      await new Promise<void>((resolve) => setTimeout(resolve, 65_000));
      stage = "second-read";
      const second = await reader.readRecords(context);
      console.log(JSON.stringify({ event: "pap.deploy-check", stage, outcome: "passed", records_count: second.records.length }));
    } catch (error) {
      const code = error instanceof AccessError && safeCodes.has(error.code) ? error.code : "operation_failed";
      console.log(JSON.stringify({ event: "pap.deploy-check", stage, outcome: "failed", code }));
    } finally {
      reader?.close();
    }
  }
};
export const config: Config = { background: true };
```

Each read has an absolute 300-second deadline and at most 24 attempts. Including its 65-second wait, the maximum sequence is 665 seconds, within the 15-minute background limit. Only classified issuer/resource 503s retry. Surfaced 401/403, revocation and policy errors terminate; the underlying SDK's one bounded resource-401 refresh remains unchanged. No periodic ping or keepalive is added.

Normal trusted server code imports `PortableAccessClient` from `@portable-access/netlify`, calls `getJSON(context)` or `readRecords(context)` using the actual Netlify context, and closes the client when its owning job ends. An already authorized records background job may call `BackgroundRecordsReader.readRecords(context, { signal })`. Preserve end-user authentication before any user-triggered job; workload permission does not authenticate an end user.

<!-- file: tools/build.mjs -->
```javascript
import { build } from "esbuild";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { validateConfig } from "@portable-access/netlify/protocol";

const config = validateConfig(JSON.parse(await readFile("src/pap.public.json", "utf8")));
await mkdir("public", { recursive: true });
await writeFile("public/pap.json", JSON.stringify({
  profile: "PAP-Netlify-Origin-0.2", adapter_configured: config.enabled,
  production_accepted: false, resource_requires_dpop: true
}) + "\n");
await build({
  entryPoints: ["netlify/functions/pap-site-proof.mts", "netlify/functions/pap-records.mts", "netlify/functions/deploy-succeeded.mts"],
  outdir: "dist/functions", outExtension: { ".js": ".mjs" },
  bundle: true, platform: "node", target: "node24", format: "esm", sourcemap: false
});
console.log("Validated configuration and bundled three functions; no deployment performed.");
```

```sh
npm run build
```

Typechecking and bundling validate imports and function code. They do not prove runtime Blobs access, issuer registration, public callback reachability or event delivery.

## 7. Deploy the selected project and verify access

After the operator confirms readiness and the binding, use the existing approved deployment process. With an authenticated official Netlify CLI, the explicit-target command for this standalone scaffold is:

```sh
netlify deploy --prod --site YOUR_NEW_NETLIFY_SITE_UUID --build
```

Do not omit `--site`, create a duplicate project or change billing. Check that site's function logs for the genuine event's successful `initial-read` and `second-read`. Zero records is a valid empty result. With the authority token TTL at 60 seconds, the 65-second separation requires renewal. The operator should correlate both `token.issued` / `request.authorized` audit pairs and distinct proof-key thumbprints before claiming renewal; log-arrival time can be buffered.

Unsigned terminal requests should return 401 for the resource and 404 for a nonexistent proof:

```sh
curl --silent --show-error --output /dev/null --write-out '%{http_code}\n' https://YOUR_TRUSTED_SITE.netlify.app/api/pap/records
curl --silent --show-error --output /dev/null --write-out '%{http_code}\n' https://YOUR_TRUSTED_SITE.netlify.app/.well-known/pap/site-proof/00000000-0000-4000-8000-000000000000
```

Knowing public site/grant metadata does not authorize a regular curl or browser request. Do not add a general unauthenticated route that invokes the server SDK for callers.

For a dedicated disposable acceptance identity, deliberately test revocation after the initial success. The operator confirms that exact test subject and uses a fresh event UUID:

```sh
sudo -u pap-admin /opt/pap/venv/bin/pap revoke --state /run/pap-admin \
  --subject YOUR_DISPOSABLE_REGISTERED_SUBJECT --reason operator --event-id YOUR_FRESH_EVENT_UUID
sudo -u pap-admin /opt/pap/venv/bin/pap audit --state /run/pap-admin
```

Reuse the same event UUID if a response is uncertain. A later genuine event must fail, and an authority restart must not restore access. This permanently disables the tested workload until a separate reviewed replacement procedure. Do not revoke a project's usable identity merely to complete routine onboarding. Use a separately approved fresh subject/grant for an intentional replacement; no setup/restart/expiry edit should silently restore a revoked identity.

## Repeat for other projects

Each project gets its own trusted site, new subject/grant, tenant boundary and narrow action. Issuer and global audience may be shared. Infrastructure renews short-lived credentials, replaces workload proof keys, rotates issuer signing keys and renews certificates. Grant expiry remains a deliberate access decision. An authenticated compromise event revokes future authorization; compromise detection and trusted incident delivery remain operator integrations.

Preserve existing application login, business authorization, validation and deployment controls. Every resource read checks current issuer policy online and fails closed when the authority/KMS is unavailable. Add ingress admission and hosting-provider volumetric protection; application limits alone do not establish DDoS resistance. Trusted site code can exercise its allowed operation, so separate sites/tenants and narrow GET grants matter.

Five Node-only public entrypoints are available: the root client, `/proof`, `/verifier`, `/background` and `/protocol`. They have no browser/default export condition and no credential getter. This guide provides the first working Netlify profile, not multi-provider interoperability, a managed grant-registration API, horizontal authority coordination or HA production readiness.
