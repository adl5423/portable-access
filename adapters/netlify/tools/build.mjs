import { build } from "esbuild";
import { mkdir, readFile, writeFile, rm } from "node:fs/promises";

await rm("dist/functions", { recursive: true, force: true });
await mkdir("dist/functions", { recursive: true });
await mkdir("public", { recursive: true });
const publicConfig = JSON.parse(await readFile("src/config.public.json", "utf8"));
await writeFile("public/status.json", `${JSON.stringify({ profile: "PAP-Netlify-Origin-0.2", adapter_configured: publicConfig.enabled === true, production_accepted: false, resource_requires_dpop: true }, null, 2)}\n`);
await build({
  entryPoints: ["netlify/functions/pap-site-proof.mts", "netlify/functions/pap-records.mts", "netlify/functions/deploy-succeeded.mts"],
  outdir: "dist/functions", outExtension: { ".js": ".mjs" }, bundle: true, platform: "node", target: "node24", format: "esm", sourcemap: false,
});
console.log("Built SDK and three Netlify function bundles; no deploy was performed.");
