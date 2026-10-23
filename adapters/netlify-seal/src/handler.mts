import { constants, createPublicKey, publicEncrypt, timingSafeEqual } from "node:crypto";
import { MAX_BYTES, NO_CACHE, RELEASE_PATH, SealError, assertFresh, assertPlatform, canonical, decode, parseCanonical, parseConfig, parseCustody, parsePublication, parseRequest, sha256, type PlatformContext, type Publication } from "./protocol.mjs";
import { platformSealStore, type SealStore } from "./store.mjs";
import { fetchProof, untilAbort } from "./transport.mjs";

export interface HandlerOptions {
  store?: SealStore;
  proof?: (origin: string, requestID: string, signal: AbortSignal) => Promise<Buffer>;
  now?: () => number;
  budgetMS?: number;
  log?: (event: { event: "pap_seal_release"; outcome: "published" | "reused" | "denied" | "unavailable"; status: number }) => void;
}
async function requestBody(request: Request, signal: AbortSignal): Promise<Buffer> {
  const declared = request.headers.get("content-length");
  if (declared !== null && (!/^(?:0|[1-9][0-9]*)$/.test(declared) || Number(declared) > MAX_BYTES)) throw new SealError("invalid_size", 400);
  const reader = request.body?.getReader();
  if (!reader) throw new SealError("invalid_size", 400);
  const parts: Buffer[] = []; let size = 0;
  try {
    while (true) {
      const { done, value } = await untilAbort(reader.read(), signal);
      if (done) break;
      size += value.length;
      if (size > MAX_BYTES) throw new SealError("invalid_size", 400);
      parts.push(Buffer.from(value));
    }
    if (declared !== null && Number(declared) !== size) throw new SealError("invalid_size", 400);
    return Buffer.concat(parts);
  } finally { void reader.cancel().catch(() => undefined); reader.releaseLock(); }
}
function sameBytes(actual: Uint8Array, expected: Uint8Array): boolean { return actual.length === expected.length && timingSafeEqual(actual, expected); }
export function createReleaseHandler(publicConfig: unknown, options: HandlerOptions = {}) {
  let active = 0;
  const now = options.now ?? (() => Date.now() / 1000);
  return async (request: Request, context: PlatformContext): Promise<Response> => {
    let acquired = false; let timer: ReturnType<typeof setTimeout> | undefined;
    const controller = new AbortController();
    const abort = () => controller.abort();
    const emit = (outcome: "published" | "reused" | "denied" | "unavailable", status: number) => {
      // No URL, request, key, nonce, proof, ciphertext, exception or provider metadata is logged.
      try { options.log?.({ event: "pap_seal_release", outcome, status }); } catch { /* Logging cannot alter key release. */ }
    };
    try {
      const config = parseConfig(publicConfig); const url = new URL(request.url);
      assertPlatform(config, context, url);
      if (url.pathname !== RELEASE_PATH || url.search || url.hash) throw new SealError("not_found", 404);
      if (request.method !== "POST") return new Response(null, { status: 405, headers: { ...NO_CACHE, Allow: "POST" } });
      if (!/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(request.headers.get("content-type") ?? "") || request.headers.has("authorization") || request.headers.has("cookie") || (request.headers.has("content-encoding") && request.headers.get("content-encoding") !== "identity")) throw new SealError("invalid_request", 400);
      if (active >= 4) return new Response(null, { status: 429, headers: { ...NO_CACHE, "Retry-After": "2" } });
      active++; acquired = true;
      const budget = options.budgetMS ?? 12_000;
      timer = setTimeout(abort, budget);
      request.signal.addEventListener("abort", abort, { once: true });
      if (request.signal.aborted) abort();
      const signal = controller.signal;
      const raw = await requestBody(request, signal);
      const boot = parseRequest(parseCanonical(raw), config, now());
      const digest = sha256(raw);
      const proof = await untilAbort((options.proof ?? fetchProof)(config.origin, boot.request_id, signal), signal);
      if (!sameBytes(proof, raw)) throw new SealError("proof_mismatch", 403);
      assertFresh(boot, now());
      const store = options.store ?? platformSealStore();
      // Read current custody on every attempt, including idempotent retries. No policy cache.
      const custody = parseCustody(await untilAbort(store.readCustody(config.deployment_id, signal), signal), config);
      let existing = await untilAbort(store.readPublication(config.deployment_id, boot.request_id, signal), signal);
      let outcome: "published" | "reused" = "reused";
      let publication: Publication;
      if (existing !== null) publication = parsePublication(existing, boot, digest);
      else {
        const key = decode(custody.key_b64url, 32, 503);
        let ciphertext: Buffer;
        try {
          const recipient = createPublicKey({ key: { ...boot.recipient_jwk }, format: "jwk" });
          if (recipient.asymmetricKeyType !== "rsa" || recipient.asymmetricKeyDetails?.modulusLength !== 4096 || recipient.asymmetricKeyDetails.publicExponent !== 65537n) throw new SealError("invalid_recipient", 400);
          ciphertext = publicEncrypt({ key: recipient, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256", oaepLabel: Buffer.from(digest, "hex") }, key);
        } finally { key.fill(0); }
        publication = { v: 1, request_sha256: digest, expires_at: boot.exp, response: { v: 1, request_id: boot.request_id, key_id: config.key_id, wrapped_key: ciphertext.toString("base64url") } };
        signal.throwIfAborted(); assertFresh(boot, now());
        if (await untilAbort(store.publish(config.deployment_id, boot.request_id, publication, signal), signal)) outcome = "published";
        else {
          // A concurrent observer may have published first. Reuse only the same bound ciphertext.
          existing = await untilAbort(store.readPublication(config.deployment_id, boot.request_id, signal), signal);
          publication = parsePublication(existing, boot, digest);
        }
      }
      signal.throwIfAborted(); assertFresh(boot, now());
      emit(outcome, 200);
      return new Response(canonical(publication.response), { status: 200, headers: { ...NO_CACHE, "Content-Type": "application/json" } });
    } catch (error) {
      const status = error instanceof SealError ? error.status : 503;
      emit(status === 503 ? "unavailable" : "denied", status);
      const code = error instanceof SealError && [400, 401, 403, 409].includes(status) ? error.code : "temporarily_unavailable";
      return Response.json({ error: code }, { status, headers: NO_CACHE });
    } finally {
      if (timer !== undefined) clearTimeout(timer);
      controller.abort(); request.signal.removeEventListener("abort", abort);
      if (acquired) active--;
    }
  };
}
