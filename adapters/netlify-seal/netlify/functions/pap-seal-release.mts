import type { Config, Context } from "@netlify/functions";
import publicConfig from "../../src/config.public.json" with { type: "json" };
import { createReleaseHandler } from "../../src/handler.mjs";
const handler = createReleaseHandler(publicConfig, { log: (event) => console.log(JSON.stringify(event)) });
export default (request: Request, context: Context) => handler(request, context);
export const config: Config = { path: "/v1/boot/release", method: "POST", rateLimit: { action: "rate_limit", aggregateBy: "domain", windowSize: 60, windowLimit: 120 } };
