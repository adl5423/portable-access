import { build } from "esbuild";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
const policy = JSON.parse(await readFile("src/config.public.json", "utf8"));
await rm("dist/functions", { recursive: true, force: true });
await mkdir("dist/functions", { recursive: true });
await mkdir("public", { recursive: true });
await writeFile("public/status.json", `${JSON.stringify({ operation: "science-digest", configured: policy.enabled === true, protected_resource: "/api/briefing", cached_public_result: "/api/result", acceptance_requires_authority_audit: true })}\n`);
await build({ entryPoints: ["netlify/functions/briefing.mts", "netlify/functions/pap-site-proof.mts", "netlify/functions/deploy-succeeded.mts", "netlify/functions/result.mts"], outdir: "dist/functions", outExtension: { ".js": ".mjs" }, bundle: true, platform: "node", target: "node22", format: "esm", sourcemap: false });
