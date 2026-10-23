import "./server-only.mjs";
import { getStore } from "@netlify/blobs";
import { AccessError, PROOF_STORE, type Challenge } from "./protocol.mjs";

/** Public proof records only. No credentials or signing keys belong in this store. */
export interface ProofStore {
  publish(challenge: Challenge): Promise<void>;
  read(challengeID: string): Promise<unknown>;
  remove(challengeID: string): Promise<void>;
}

export function platformProofStore(): ProofStore {
  // No token/site override: Netlify supplies scoped platform credentials at runtime.
  const store = getStore({ name: PROOF_STORE, consistency: "strong" });
  return {
    async publish(challenge) {
      const result = await store.setJSON(challenge.challenge_id, challenge, { onlyIfNew: true });
      if (!result.modified) throw new AccessError("challenge_already_published", 409);
    },
    async read(challengeID) { return store.get(challengeID, { type: "json", consistency: "strong" }); },
    async remove(challengeID) { await store.delete(challengeID); },
  };
}
