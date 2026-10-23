import { writeFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";

const { values } = parseArgs({ options: {
  "issuer-url": { type: "string" }, "site-id": { type: "string" }, "grant-id": { type: "string" },
  "resource-origin": { type: "string" }, tenant: { type: "string" }, audience: { type: "string" },
  "resource-path": { type: "string", default: "/api/pap/records" }, "resource-action": { type: "string", default: "records.read" },
  "acknowledge-trusted-site": { type: "boolean", default: false },
} });
const required = ["issuer-url", "site-id", "grant-id", "resource-origin", "tenant", "audience"];
if (required.some((name) => !values[name]) || !values["acknowledge-trusted-site"]) {
  console.error("Required: --issuer-url HTTPS_ORIGIN --site-id UUID --grant-id ID --resource-origin https://PROJECT.netlify.app --tenant ID --audience AUDIENCE --acknowledge-trusted-site");
  console.error("The acknowledgement means all code and deploy contexts on this Netlify site are trusted. Use a separate site for previews.");
  process.exit(2);
}
// Validation is shared with the runtime after compilation, avoiding divergent enrollment policy.
const { validateConfig } = await import("../dist/src/protocol.mjs").catch(() => {
  console.error("Run npm run build before configuring the adapter.");
  process.exit(2);
});
let config;
try {
  config = validateConfig({
    enabled: true, issuerURL: values["issuer-url"], siteID: values["site-id"], grantID: values["grant-id"],
    resourceOrigin: values["resource-origin"], resourcePath: values["resource-path"], resourceAction: values["resource-action"], tenant: values.tenant, environment: "production", audience: values.audience,
    productionSiteIsolated: true,
  });
} catch {
  console.error("Invalid public configuration. Site ID must be a canonical lowercase UUID; tenant and grant must start with an ASCII letter or digit and contain at most 80 letters, digits, underscores or hyphens; audience is at most 200 characters. Origins must use canonical HTTPS and the resource path/action must match issuer policy.");
  process.exit(2);
}
await writeFile(fileURLToPath(new URL("../src/config.public.json", import.meta.url)), `${JSON.stringify(config, null, 2)}\n`, { mode: 0o644 });
console.log("Wrote public configuration only. Register the same site, origin, grant, tenant and audience with your issuer, then rebuild.");
