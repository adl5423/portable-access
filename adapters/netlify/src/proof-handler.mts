import "./server-only.mjs";
import { AccessError, PROOF_PATH, assertPlatform, identifier, noCache, parseChallenge, validateConfig, type PlatformContext } from "./protocol.mjs";
import { platformProofStore, type ProofStore } from "./proof-store.mjs";

export function createProofHandler(publicConfig: unknown, options: { store?: ProofStore; now?: () => number } = {}) {
  return async (request: Request, context: PlatformContext): Promise<Response> => {
    try {
      const config = validateConfig(publicConfig);
      assertPlatform(config, context);
      if (request.method !== "GET") return new Response(null, { status: 405, headers: { ...noCache, Allow: "GET" } });
      const url = new URL(request.url);
      const match = new RegExp(`^${PROOF_PATH}([A-Za-z0-9_-]{1,128})$`).exec(url.pathname);
      // Request metadata is never reflected. This route can only retrieve an existing internal publication.
      if (!match || url.search || request.headers.has("authorization") || request.body !== null) return new Response(null, { status: 400, headers: noCache });
      const challengeID = identifier(match[1]);
      const record = await (options.store ?? platformProofStore()).read(challengeID);
      if (record === null) return new Response(null, { status: 404, headers: noCache });
      const challenge = parseChallenge(record, config, undefined, options.now?.());
      if (challenge.challenge_id !== challengeID) throw new AccessError("challenge_binding_mismatch");
      return Response.json(challenge, { headers: noCache });
    } catch (error) {
      const status = error instanceof AccessError ? error.status : 503;
      return Response.json({ error: status === 503 ? "proof_unavailable" : "proof_not_available" }, { status: status === 502 || status === 401 ? 404 : status, headers: noCache });
    }
  };
}
