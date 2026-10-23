import { writeFile, rename, rm } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { parseArgs } from "node:util";
import { fileURLToPath } from "node:url";
import { validateConfig } from "@portable-access/netlify/protocol";

const { values } = parseArgs({ options: {
  "issuer-url": { type: "string" }, "site-id": { type: "string" }, "grant-id": { type: "string" },
  "resource-origin": { type: "string" }, tenant: { type: "string" }, audience: { type: "string" },
  "acknowledge-trusted-site": { type: "boolean", default: false }, help: { type: "boolean", default: false },
} });
if (values.help || ["issuer-url", "site-id", "grant-id", "resource-origin", "tenant", "audience"].some((name) => !values[name]) || !values["acknowledge-trusted-site"]) {
  console.error("Required: --issuer-url HTTPS_ORIGIN --site-id UUID --grant-id ID --resource-origin https://SITE.netlify.app --tenant ID --audience AUDIENCE --acknowledge-trusted-site");
  console.error("Only public identifiers are accepted. All deployments and trusted code on this production site share the identity boundary. Use a separate site for untrusted preview code.");
  process.exit(values.help ? 0 : 2);
}
const operation = "space-briefing";
let policy;
try {
  policy = validateConfig({ enabled: true, issuerURL: values["issuer-url"], siteID: values["site-id"], grantID: values["grant-id"], resourceOrigin: values["resource-origin"], resourcePath: "/api/briefing", resourceAction: `${operation}.read`, tenant: values.tenant, environment: "production", audience: values.audience, productionSiteIsolated: true });
} catch { console.error("Invalid public policy. Check canonical HTTPS origins, Netlify production origin, lowercase UUID, grant, tenant and audience."); process.exit(2); }
const destination = fileURLToPath(new URL("../src/config.public.json", import.meta.url));
const temporary = `${destination}.${randomUUID()}.tmp`;
try {
  await writeFile(temporary, `${JSON.stringify(policy, null, 2)}\n`, { flag: "wx", mode: 0o644 });
  await rename(temporary, destination);
} finally { await rm(temporary, { force: true }); }
console.log("Wrote public configuration. Register identical authority policy and fixed connector grant, then deploy. No provider keys were read or stored.");
