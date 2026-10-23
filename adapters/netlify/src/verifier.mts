import "./server-only.mjs";
import { AccessError, assertPlatform, jsonRequest, parseAuthorization, validateConfig, type Authorization, type Fetcher, type PlatformContext } from "./protocol.mjs";

export function createResourceVerifier(publicConfig: unknown, options: { fetcher?: Fetcher; now?: () => number } = {}) {
  const config = validateConfig(publicConfig);
  return async (request: Request, context: PlatformContext): Promise<Authorization> => {
    assertPlatform(config, context);
    const incoming = new URL(request.url);
    if (request.method !== "GET" || incoming.pathname !== config.resourcePath || incoming.search || request.body !== null) throw new AccessError("unsupported_operation", 400);
    const authorization = request.headers.get("authorization") ?? "";
    const proof = request.headers.get("dpop") ?? "";
    if (!/^DPoP [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(authorization) || authorization.length > 4101 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(proof) || proof.length > 4096) throw new AccessError("invalid_proof", 401);
    // Never trust Host, X-Forwarded-Host, Origin or an arbitrary client-supplied authorization target.
    const value = await jsonRequest(options.fetcher ?? fetch, `${config.issuerURL}/v1/authorize`, {
      method: "GET", url: `${config.resourceOrigin}${config.resourcePath}`, tenant: config.tenant, action: config.resourceAction, audience: config.audience,
    }, { Authorization: authorization, DPoP: proof });
    // Online authorization consumes the original proof and checks revocation. No positive-result cache exists.
    return parseAuthorization(value, config, options.now?.());
  };
}
