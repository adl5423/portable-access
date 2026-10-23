import type { Config, Context } from "@netlify/functions";
import policy from "../../src/config.public.json" with { type: "json" };
import { createConnectorRelay } from "../../src/relay.mjs";
const handle = createConnectorRelay(policy, "science-digest");
export default async (request: Request, context: Context): Promise<Response> => handle(request, context);
export const config: Config = { path: "/api/briefing", method: ["GET"], rateLimit: { action: "rate_limit", aggregateBy: "ip", windowSize: 60, windowLimit: 30 } };
