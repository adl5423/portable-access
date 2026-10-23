import {
  AccessError, assertPlatform, boundedJSON, noCache, strictObject, validateConfig,
  type Fetcher, type PlatformContext, type PublicConfig,
} from "@portable-access/netlify/protocol";

export type Operation = "space-briefing" | "charging-briefing" | "science-digest";
export interface Briefing {
  operation: Operation; generated_at: string; period: string; model: "gpt-4.1-mini";
  summary: string; sources: { provider: "nasa" | "nlr"; title: string; url: string; records: number }[];
  cached: boolean;
}

const sourceURLs = new Set(["https://api.nasa.gov/", "https://developer.nlr.gov/docs/transportation/alt-fuel-stations-v1/"]);
const timestamp = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
export function parseBriefing(input: unknown, operation: Operation): Briefing {
  const value = strictObject(input, ["operation", "generated_at", "period", "model", "summary", "sources", "cached"]);
  if (value.operation !== operation || value.model !== "gpt-4.1-mini" || typeof value.generated_at !== "string" || !timestamp.test(value.generated_at) || !Number.isFinite(Date.parse(value.generated_at)) || typeof value.period !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:00:00Z$/.test(value.period) || !Number.isFinite(Date.parse(value.period)) || typeof value.summary !== "string" || value.summary.length < 1 || value.summary.length > 8192 || /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(value.summary) || typeof value.cached !== "boolean" || !Array.isArray(value.sources) || value.sources.length < 1 || value.sources.length > 2) {
    throw new AccessError("invalid_briefing", 502);
  }
  const sources = value.sources.map((item: unknown): Briefing["sources"][number] => {
    const source = strictObject(item, ["provider", "title", "url", "records"]);
    if ((source.provider !== "nasa" && source.provider !== "nlr") || typeof source.title !== "string" || source.title.length < 1 || source.title.length > 200 || typeof source.url !== "string" || !sourceURLs.has(source.url) || !Number.isInteger(source.records) || Number(source.records) < 0 || Number(source.records) > 1000000) throw new AccessError("invalid_briefing", 502);
    if ((source.provider === "nasa") !== (source.url === "https://api.nasa.gov/")) throw new AccessError("invalid_briefing", 502);
    return { provider: source.provider, title: source.title, url: source.url, records: Number(source.records) };
  });
  const providers = sources.map((source) => source.provider).sort().join(",");
  if (providers !== (operation === "science-digest" ? "nasa,nlr" : operation === "space-briefing" ? "nasa" : "nlr")) throw new AccessError("invalid_briefing", 502);
  return { operation, generated_at: value.generated_at, period: value.period, model: "gpt-4.1-mini", summary: value.summary, sources, cached: value.cached };
}

/** Preserve the original GET proof. Only the authority validates and consumes it. */
export function createConnectorRelay(publicConfig: unknown, operation: Operation, fetcher: Fetcher = fetch) {
  return async (request: Request, context: PlatformContext): Promise<Response> => {
    try {
      const policy = validateConfig(publicConfig);
      assertPlatform(policy, context);
      if (request.method !== "GET") return Response.json({ error: "method_not_allowed" }, { status: 405, headers: { ...noCache, Allow: "GET" } });
      const target = `${policy.resourceOrigin}${policy.resourcePath}`;
      const url = new URL(request.url);
      if (url.href !== target || request.body !== null || request.headers.has("content-length") && request.headers.get("content-length") !== "0") throw new AccessError("invalid_target", 400);
      const authorization = request.headers.get("authorization");
      const proof = request.headers.get("dpop");
      if (!authorization || !/^DPoP [A-Za-z0-9_.-]{16,4096}$/.test(authorization) || !proof || !/^[A-Za-z0-9_.-]{16,8192}$/.test(proof)) throw new AccessError("access_denied");
      const response = await fetcher(`${policy.issuerURL}/v1/connectors/${operation}`, {
        method: "POST", redirect: "error", cache: "no-store", signal: AbortSignal.timeout(30000),
        headers: { Authorization: authorization, DPoP: proof, "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ method: "GET", url: target, tenant: policy.tenant, action: policy.resourceAction, audience: policy.audience }),
      });
      if (!response.ok) {
        await response.body?.cancel();
        const status = [401, 403, 404, 429].includes(response.status) ? response.status : 503;
        return Response.json({ error: status === 503 ? "service_unavailable" : "access_denied" }, { status, headers: noCache });
      }
      const briefing = parseBriefing(await boundedJSON(response), operation);
      return Response.json(briefing, { headers: noCache });
    } catch (error) {
      const status = error instanceof AccessError && [400, 401, 403, 405, 503].includes(error.status) ? error.status : 503;
      return Response.json({ error: status === 503 ? "service_unavailable" : "access_denied" }, { status, headers: noCache });
    }
  };
}

export function configuredPolicy(publicConfig: unknown): PublicConfig { return validateConfig(publicConfig); }
