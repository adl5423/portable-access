import { build } from "esbuild";
import { mkdir, rm, writeFile } from "node:fs/promises";
await rm("dist/functions", { recursive: true, force: true });
await mkdir("dist/functions", { recursive: true });
await mkdir("public", { recursive: true });
await writeFile("public/status.json", '{"service":"pap-seal-custody","production_accepted":false}\n');
await build({ entryPoints: ["netlify/functions/pap-seal-release.mts", "netlify/functions/pap-seal-health.mts"], outdir: "dist/functions", outExtension: { ".js": ".mjs" }, bundle: true, platform: "node", target: "node24", format: "esm", sourcemap: false });
console.log("Built two seal custody functions; no deployment or secret provisioning performed.");
