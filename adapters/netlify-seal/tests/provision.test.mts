import { test } from "node:test";
import assert from "node:assert/strict";
import { canonical, sha256 } from "../src/protocol.mjs";
import { provisionCustody, type ProvisionStore } from "../src/provision.mjs";

const key = Buffer.alloc(32, 42);
const config = { v: 1, enabled: true, custody_site_isolated: true, site_id: "11111111-1111-4111-8111-111111111111", custody_origin: "https://independent-custody.netlify.app", deployment_id: "test-deployment", machine_id: "m_abcdefghijklmnopqrstuvwxyz", origin: "https://authority.example.com", key_id: sha256(key) };
const record = { v: 1, enabled: true, deployment_id: config.deployment_id, machine_id: config.machine_id, origin: config.origin, key_id: config.key_id, key_b64url: key.toString("base64url") };
const signal = new AbortController().signal;
function memory(initial?: unknown) {
  let value = initial, revision = 1, writes = 0;
  const store: ProvisionStore = {
    async getWithMetadata(name, options) {
      assert.equal(name, "deployments/test-deployment/current"); assert.deepEqual(options, { type: "stream", consistency: "strong" });
      return value === undefined ? null : { etag: String(revision), data: new ReadableStream({ start(controller) { controller.enqueue(Buffer.from(canonical(value))); controller.close(); } }) };
    },
    async set(name, data, options) {
      assert.equal(name, "deployments/test-deployment/current");
      if ("onlyIfNew" in options && value !== undefined || "onlyIfMatch" in options && options.onlyIfMatch !== String(revision)) return { modified: false };
      value = JSON.parse(data); revision++; writes++; return { modified: true };
    },
  };
  return { store, value: () => value, writes: () => writes };
}

test("operator provisions create-only, verifies readback and repeats idempotently", async () => {
  const state = memory();
  const receipt = await provisionCustody(config, record, false, state.store, signal);
  assert.equal(receipt.state, "created"); assert.equal(receipt.enabled, true); assert.equal(state.writes(), 1);
  assert.doesNotMatch(JSON.stringify(receipt), new RegExp(record.key_b64url));
  assert.equal((await provisionCustody(config, record, false, state.store, signal)).state, "unchanged"); assert.equal(state.writes(), 1);
});

test("operator never overwrites differing or revoked existing custody", async () => {
  for (const existing of [{ ...record, enabled: false }, { ...record, key_b64url: Buffer.alloc(32, 1).toString("base64url") }]) {
    const state = memory(existing); await assert.rejects(provisionCustody(config, record, false, state.store, signal)); assert.equal(state.writes(), 0);
  }
});

test("revoke changes only enabled using the observed ETag and readback", async () => {
  const state = memory(record);
  const receipt = await provisionCustody(config, undefined, true, state.store, signal);
  assert.equal(receipt.state, "revoked"); assert.deepEqual(state.value(), { ...record, enabled: false }); assert.equal(state.writes(), 1);
  assert.equal((await provisionCustody(config, undefined, true, state.store, signal)).state, "unchanged"); assert.equal(state.writes(), 1);
});

test("missing custody, binding mismatch and private revocation input fail closed", async () => {
  const state = memory();
  await assert.rejects(provisionCustody(config, undefined, true, state.store, signal));
  await assert.rejects(provisionCustody(config, { ...record, machine_id: "m_aaaaaaaaaaaaaaaaaaaaaaaaaa" }, false, state.store, signal));
  await assert.rejects(provisionCustody(config, record, true, memory(record).store, signal));
  assert.equal(state.writes(), 0);
});

test("conditional-write conflict and corrupt readback never report success", async () => {
  const state = memory(record);
  await assert.rejects(provisionCustody(config, undefined, true, { ...state.store, async set() { return { modified: false }; } }, signal), /custody_conflict/);
  await assert.rejects(provisionCustody(config, record, false, { ...memory().store, async set() { return { modified: true }; } }, signal), /custody_readback_mismatch/);
});

test("aborted operator request makes no provider mutation", async () => {
  const controller = new AbortController(); controller.abort(); const state = memory();
  await assert.rejects(provisionCustody(config, record, false, state.store, controller.signal)); assert.equal(state.writes(), 0);
});
