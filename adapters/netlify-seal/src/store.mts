import { getStore } from "@netlify/blobs";
import { CUSTODY_STORE, MAX_BYTES, PUBLICATION_STORE, SealError, canonical, parseCanonical, type Publication } from "./protocol.mjs";
import { untilAbort } from "./transport.mjs";

export interface SealStore {
  readCustody(deploymentID: string, signal: AbortSignal): Promise<unknown>;
  readPublication(deploymentID: string, requestID: string, signal: AbortSignal): Promise<unknown | null>;
  publish(deploymentID: string, requestID: string, value: Publication, signal: AbortSignal): Promise<boolean>;
}
export async function readStored(stream: ReadableStream<Uint8Array> | null, signal: AbortSignal): Promise<unknown | null> {
  if (stream === null) return null;
  const reader = stream.getReader(); const chunks: Buffer[] = []; let size = 0;
  try {
    while (true) {
      const { done, value } = await untilAbort(reader.read(), signal);
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BYTES) throw new SealError("invalid_custody", 503);
      chunks.push(Buffer.from(value));
    }
    return parseCanonical(Buffer.concat(chunks), 503);
  } finally { void reader.cancel().catch(() => undefined); reader.releaseLock(); }
}
function platformStore(name: string, signal: AbortSignal) {
  return getStore({ name, consistency: "strong", fetch: (input, init = {}) => {
    const combined = init.signal ? AbortSignal.any([signal, init.signal]) : signal;
    return fetch(input, { ...init, signal: combined });
  } });
}
export function platformSealStore(): SealStore {
  // Site/token credentials come only from Netlify's function runtime, never from configuration.
  return {
    async readCustody(deploymentID, signal) {
      return readStored(await platformStore(CUSTODY_STORE, signal).get(`deployments/${deploymentID}/current`, { type: "stream", consistency: "strong" }), signal);
    },
    async readPublication(deploymentID, requestID, signal) {
      return readStored(await platformStore(PUBLICATION_STORE, signal).get(`releases/${deploymentID}/${requestID}`, { type: "stream", consistency: "strong" }), signal);
    },
    async publish(deploymentID, requestID, value, signal) {
      const result = await platformStore(PUBLICATION_STORE, signal).set(`releases/${deploymentID}/${requestID}`, canonical(value), { onlyIfNew: true, metadata: { expires_at: value.expires_at } });
      return result.modified;
    },
  };
}
