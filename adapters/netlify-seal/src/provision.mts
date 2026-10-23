import { CUSTODY_STORE, SealError, canonical, parseConfig, parseCustody, sha256, type CustodyRecord } from "./protocol.mjs";
import { readStored } from "./store.mjs";

export interface ProvisionStore {
  getWithMetadata(key: string, options: { type: "stream"; consistency: "strong" }): Promise<{ data: ReadableStream<Uint8Array>; etag?: string } | null>;
  set(key: string, data: string, options: { onlyIfNew: true } | { onlyIfMatch: string }): Promise<{ modified: boolean }>;
}
export interface ProvisionReceipt {
  v: 1; operation: "provision" | "revoke"; store: typeof CUSTODY_STORE;
  site_id: string; deployment_id: string; key_id: string;
  state: "created" | "unchanged" | "revoked"; enabled: boolean; record_sha256: string;
}

/** Operator-only integration. No caller-controlled key name, site override or overwrite exists. */
export async function provisionCustody(publicConfig: unknown, record: unknown, revoke: boolean, store: ProvisionStore, signal: AbortSignal): Promise<ProvisionReceipt> {
  const config = parseConfig(publicConfig);
  const key = `deployments/${config.deployment_id}/current`;
  const read = async () => {
    signal.throwIfAborted();
    const entry = await store.getWithMetadata(key, { type: "stream", consistency: "strong" });
    if (entry === null) return null;
    const value = await readStored(entry.data, signal);
    if (typeof value !== "object" || value === null || Array.isArray(value) || !("enabled" in value) || typeof value.enabled !== "boolean") throw new SealError("invalid_custody", 503);
    // Validate all bindings and the key hash even when inspecting a revoked record.
    parseCustody({ ...value, enabled: true }, config);
    return { value: value as CustodyRecord, etag: entry.etag };
  };
  let desired: CustodyRecord;
  let state: ProvisionReceipt["state"];
  const current = await read();
  if (revoke) {
    if (record !== undefined) throw new SealError("unexpected_private_input", 400);
    if (current === null) throw new SealError("custody_missing", 404);
    desired = { ...current.value, enabled: false };
    if (current.value.enabled === false) state = "unchanged";
    else {
      if (!current.etag) throw new SealError("conditional_write_unavailable", 503);
      signal.throwIfAborted();
      const result = await store.set(key, canonical(desired), { onlyIfMatch: current.etag });
      if (!result.modified) throw new SealError("custody_conflict", 409);
      state = "revoked";
    }
  } else {
    desired = parseCustody(record, config);
    if (current !== null) {
      if (canonical(current.value) !== canonical(desired)) throw new SealError("custody_conflict", 409);
      state = "unchanged";
    } else {
      signal.throwIfAborted();
      const result = await store.set(key, canonical(desired), { onlyIfNew: true });
      state = result.modified ? "created" : "unchanged";
    }
  }
  const verified = await read();
  if (verified === null || canonical(verified.value) !== canonical(desired)) throw new SealError("custody_readback_mismatch", 503);
  return { v: 1, operation: revoke ? "revoke" : "provision", store: CUSTODY_STORE, site_id: config.site_id, deployment_id: config.deployment_id, key_id: config.key_id, state, enabled: desired.enabled, record_sha256: sha256(canonical(desired)) };
}
