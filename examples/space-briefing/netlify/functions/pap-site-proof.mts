import type { Config, Context } from "@netlify/functions";
import policy from "../../src/config.public.json" with { type: "json" };
import { createProofHandler } from "@portable-access/netlify/proof";
const handle = createProofHandler(policy);
export default async (request: Request, context: Context): Promise<Response> => handle(request, context);
export const config: Config = { path: "/.well-known/pap/site-proof/:challenge_id", method: ["GET"], rateLimit: { action: "rate_limit", aggregateBy: "ip", windowSize: 60, windowLimit: 120 } };
