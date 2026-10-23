import { getContext, type Config, type DeploySucceededEvent } from "@netlify/functions";
import publicConfig from "../../src/config.public.json" with { type: "json" };
import { createDeployCheck } from "../../src/deploy-check.mjs";

const check = createDeployCheck(publicConfig, {
  context: () => getContext(),
  report: (report) => console.log(JSON.stringify(report)),
});

// Platform-event JWS is verified by Netlify before dispatch. No HTTP fetch handler is exported.
export default {
  async deploySucceeded(event: DeploySucceededEvent): Promise<void> {
    await check(event);
  },
};

// The second fixed read waits for the acceptance issuer's 60-second credential TTL.
export const config: Config = { background: true };
