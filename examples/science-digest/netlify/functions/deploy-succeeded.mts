import { getStore } from "@netlify/blobs";
import { getContext, type Config, type DeploySucceededEvent } from "@netlify/functions";
import policy from "../../src/config.public.json" with { type: "json" };
import { createDeployAcceptance } from "../../src/acceptance.mjs";
const check = createDeployAcceptance(policy, "science-digest", {
  context: () => getContext(),
  publish: async (briefing) => { await getStore({ name: "pap-example-results-v1", consistency: "strong" }).setJSON("latest", briefing); },
  report: (report) => console.log(JSON.stringify(report)),
});
export default { async deploySucceeded(event: DeploySucceededEvent): Promise<void> { await check(event); } };
export const config: Config = { background: true };
