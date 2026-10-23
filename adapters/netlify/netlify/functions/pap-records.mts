import { getStore } from "@netlify/blobs";
import type { Config, Context } from "@netlify/functions";
import publicConfig from "../../src/config.public.json" with { type: "json" };
import { AccessError, noCache } from "../../src/protocol.mjs";
import { parseRecords } from "../../src/client.mjs";
import { createResourceVerifier } from "../../src/verifier.mjs";

export default async (request: Request, context: Context): Promise<Response> => {
  try {
    const claims = await createResourceVerifier(publicConfig)(request, context);
    const records = getStore({ name: "pap-records-v1", consistency: "strong" });
    const stored = await records.get(`tenants/${claims.tenant}/records`, { type: "json", consistency: "strong" });
    const response = parseRecords(stored ?? { records: [] });
    return Response.json(response, { headers: noCache });
  } catch (error) {
    const status = error instanceof AccessError ? error.status : 503;
    // Only classifications and Netlify's generated request ID belong in logs.
    console.error(JSON.stringify({ event: "pap.records.denied", code: error instanceof AccessError ? error.code : "storage_unavailable", request_id: context.requestId }));
    return Response.json({ error: status === 503 ? "service_unavailable" : "access_denied" }, { status, headers: noCache });
  }
};

export const config: Config = {
  path: "/api/pap/records",
  method: ["GET"],
  rateLimit: { action: "rate_limit", aggregateBy: "ip", windowSize: 60, windowLimit: 60 },
};
