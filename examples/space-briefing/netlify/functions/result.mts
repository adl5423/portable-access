import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import { assertPlatform, noCache, validateConfig } from "@portable-access/netlify/protocol";
import policy from "../../src/config.public.json" with { type: "json" };
import { parseBriefing } from "../../src/relay.mjs";

// This route reads an already generated public-data summary. It never calls a provider.
export default async (request: Request, context: Context): Promise<Response> => {
  try {
    assertPlatform(validateConfig(policy), context);
    if (request.method !== "GET") return new Response(null, { status: 405, headers: { ...noCache, Allow: "GET" } });
    const url = new URL(request.url);
    if (url.href !== `${policy.resourceOrigin}/api/result` || request.body !== null) return Response.json({ error: "invalid_request" }, { status: 400, headers: noCache });
    const stored = await getStore({ name: "pap-example-results-v1", consistency: "strong" }).get("latest", { type: "json", consistency: "strong" });
    if (stored === null) return Response.json({ status: "awaiting_verified_deploy_event" }, { status: 202, headers: noCache });
    return Response.json(parseBriefing(stored, "space-briefing"), { headers: noCache });
  } catch { return Response.json({ error: "result_unavailable" }, { status: 503, headers: noCache }); }
};
export const config: Config = { path: "/api/result", method: ["GET"], rateLimit: { action: "rate_limit", aggregateBy: "ip", windowSize: 60, windowLimit: 60 } };
