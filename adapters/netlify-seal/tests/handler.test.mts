import { test } from "node:test";
import assert from "node:assert/strict";
import { constants, generateKeyPairSync, privateDecrypt, randomUUID } from "node:crypto";
import { createReleaseHandler } from "../src/handler.mjs";
import { canonical, sha256, type BootRequest, type CustodyRecord, type Publication, type PublicConfig, type ReleaseResponse } from "../src/protocol.mjs";
import type { SealStore } from "../src/store.mjs";

const pair = generateKeyPairSync("rsa", { modulusLength: 4096, publicExponent: 65537 });
const exported = pair.publicKey.export({ format: "jwk" });
const recipient = { kty: "RSA" as const, n: exported.n!, e: "AQAB" as const };
const secret = Buffer.alloc(32, 7);
const config: PublicConfig = { v: 1, enabled: true, custody_site_isolated: true, site_id: "12345678-1234-1234-1234-123456789012", custody_origin: "https://pap-test-seal.netlify.app", deployment_id: "example-deployment", machine_id: "m_abcdefghijklmnopqrstuvwxyz", origin: "https://authority.example.com", key_id: sha256(secret) };
const context = { site: { id: config.site_id }, deploy: { context: "production", published: true } };
const clock = 1_792_700_000;
function boot(overrides: Partial<BootRequest> = {}): BootRequest { return { v: 1, request_id: randomUUID(), deployment_id: config.deployment_id, machine_id: config.machine_id, boot_id: randomUUID(), key_id: config.key_id, nonce: Buffer.alloc(32, 3).toString("base64url"), iat: clock, exp: clock + 120, recipient_jwk: recipient, ...overrides }; }
class MemoryStore implements SealStore {
  reads = 0; writes = 0; publications = new Map<string, Publication>();
  custody: CustodyRecord = { v: 1, enabled: true, deployment_id: config.deployment_id, machine_id: config.machine_id, origin: config.origin, key_id: config.key_id, key_b64url: secret.toString("base64url") };
  async readCustody() { this.reads++; return structuredClone(this.custody); }
  async readPublication(_deployment: string, id: string) { return this.publications.get(id) ?? null; }
  async publish(_deployment: string, id: string, publication: Publication) { if (this.publications.has(id)) return false; this.writes++; this.publications.set(id, structuredClone(publication)); return true; }
}
function request(value: unknown, init: RequestInit = {}) { return new Request(`${config.custody_origin}/v1/boot/release`, { method: "POST", headers: { "Content-Type": "application/json" }, body: canonical(value), ...init }); }
function setup(value = boot()) {
  const store = new MemoryStore(); let current = value; let time = clock; let callbacks = 0;
  const logs: unknown[] = [];
  const handler = createReleaseHandler(config, { store, now: () => time, proof: async (origin, id) => { callbacks++; assert.equal(origin, config.origin); assert.equal(id, current.request_id); return Buffer.from(canonical(current)); }, log: (event) => logs.push(event) });
  return { store, handler, logs, value, callbacks: () => callbacks, update: (next: BootRequest) => { current = next; }, time: (next: number) => { time = next; } };
}

test("fresh origin proof releases only recipient-encrypted 32-byte key with exact protocol label", async () => {
  const s = setup(); const response = await s.handler(request(s.value), context);
  assert.equal(response.status, 200); assert.match(response.headers.get("cache-control")!, /no-store/); assert.equal(response.headers.get("access-control-allow-origin"), null);
  const release = await response.json() as ReleaseResponse;
  assert.deepEqual(Object.keys(release).sort(), ["key_id", "request_id", "v", "wrapped_key"]);
  const plaintext = privateDecrypt({ key: pair.privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256", oaepLabel: Buffer.from(sha256(canonical(s.value)), "hex") }, Buffer.from(release.wrapped_key, "base64url"));
  assert.deepEqual(plaintext, secret); assert.equal(s.store.writes, 1);
  assert.throws(() => privateDecrypt({ key: pair.privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256", oaepLabel: Buffer.alloc(32) }, Buffer.from(release.wrapped_key, "base64url")));
  assert.deepEqual(s.logs, [{ event: "pap_seal_release", outcome: "published", status: 200 }]);
  assert.equal(JSON.stringify(s.logs).includes(secret.toString("base64url")), false);
});

test("public observer cannot burn legitimate request: exact retry returns identical ciphertext", async () => {
  const s = setup(); const observer = await s.handler(request(s.value), context); const owner = await s.handler(request(s.value), context);
  assert.equal(observer.status, 200); assert.equal(owner.status, 200); assert.equal(await observer.text(), await owner.text());
  assert.equal(s.store.writes, 1); assert.equal(s.store.reads, 2); assert.equal(s.callbacks(), 2);
});
test("concurrent identical requests atomically publish one response", async () => {
  const s = setup(); const responses = await Promise.all(Array.from({ length: 4 }, () => s.handler(request(s.value), context)));
  assert.deepEqual(responses.map((r) => r.status), [200, 200, 200, 200]);
  const bodies = await Promise.all(responses.map((r) => r.text())); assert.equal(new Set(bodies).size, 1); assert.equal(s.store.writes, 1);
});
test("same ID with changed canonical request conflicts even after new valid origin publication", async () => {
  const s = setup(); assert.equal((await s.handler(request(s.value), context)).status, 200);
  const changed = { ...s.value, nonce: Buffer.alloc(32, 4).toString("base64url") }; s.update(changed);
  assert.equal((await s.handler(request(changed), context)).status, 409); assert.equal(s.store.writes, 1);
});
test("idempotent retries revalidate current enabled policy", async () => {
  const s = setup(); assert.equal((await s.handler(request(s.value), context)).status, 200); s.store.custody.enabled = false;
  assert.equal((await s.handler(request(s.value), context)).status, 403); assert.equal(s.store.writes, 1);
});
test("idempotent retries require same origin proof and fresh expiry", async () => {
  const s = setup(); assert.equal((await s.handler(request(s.value), context)).status, 200);
  s.update({ ...s.value, nonce: Buffer.alloc(32, 5).toString("base64url") });
  assert.equal((await s.handler(request(s.value), context)).status, 403);
  s.update(s.value); s.time(s.value.exp); assert.equal((await s.handler(request(s.value), context)).status, 401);
});
test("proof mismatch never reads custody or writes a claim", async () => {
  const s = setup(); s.update({ ...s.value, boot_id: randomUUID() });
  assert.equal((await s.handler(request(s.value), context)).status, 403); assert.equal(s.store.reads, 0); assert.equal(s.store.writes, 0);
});
test("expired during callback cannot read key or publish", async () => {
  const value = boot(); const store = new MemoryStore(); let time = clock;
  const handler = createReleaseHandler(config, { store, now: () => time, proof: async () => { time = value.exp; return Buffer.from(canonical(value)); } });
  assert.equal((await handler(request(value), context)).status, 401); assert.equal(store.reads, 0); assert.equal(store.writes, 0);
});
test("expiry during custody lookup prevents publication", async () => {
  const value = boot(); const store = new MemoryStore(); let time = clock;
  store.readCustody = async () => { time = value.exp; return store.custody; };
  const handler = createReleaseHandler(config, { store, now: () => time, proof: async () => Buffer.from(canonical(value)) });
  assert.equal((await handler(request(value), context)).status, 401); assert.equal(store.writes, 0);
});
test("bad key hash and missing custody fail closed", async () => {
  const s = setup(); s.store.custody.key_b64url = Buffer.alloc(32, 99).toString("base64url");
  assert.equal((await s.handler(request(s.value), context)).status, 503); assert.equal(s.store.writes, 0);
  s.store.readCustody = async () => null as unknown as CustodyRecord;
  assert.equal((await s.handler(request(s.value), context)).status, 503);
});
test("store failure and failed publication never return ciphertext or private errors", async () => {
  const s = setup(); s.store.publish = async () => { throw new Error("sensitive provider error"); };
  const response = await s.handler(request(s.value), context); assert.equal(response.status, 503); assert.equal(await response.text(), '{"error":"temporarily_unavailable"}');
  assert.equal(JSON.stringify(s.logs).includes("sensitive"), false);
});
test("mismatched existing publication fails closed", async () => {
  const s = setup(); s.store.publications.set(s.value.request_id, { v: 1, request_sha256: sha256(canonical(s.value)), expires_at: s.value.exp, response: { v: 1, request_id: s.value.request_id, key_id: s.value.key_id, wrapped_key: "invalid" } });
  assert.equal((await s.handler(request(s.value), context)).status, 503);
});
for (const [label, patch] of [
  ["different deployment", { deployment_id: "other" }], ["different machine", { machine_id: "m_aaaaaaaaaaaaaaaaaaaaaaaaaa" }], ["different key", { key_id: "f".repeat(64) }],
  ["expired", { exp: clock }], ["future", { iat: clock + 6, exp: clock + 120 }], ["old issue", { iat: clock - 121, exp: clock + 1 }], ["too long", { exp: clock + 121 }], ["fractional issue", { iat: clock + 0.5 }],
  ["short nonce", { nonce: "AA" }], ["unknown member", { arbitrary: "value" }], ["bad recipient exponent", { recipient_jwk: { ...recipient, e: "Aw" } }], ["private recipient field", { recipient_jwk: { ...recipient, d: "private" } }],
] as const) test(`rejects ${label} before callback`, async () => {
  const s = setup(); const response = await s.handler(request({ ...s.value, ...patch }), context); assert.notEqual(response.status, 200); assert.equal(s.callbacks(), 0); assert.equal(s.store.reads, 0);
});
for (const [label, body] of [["duplicate member", '{"v":1,"v":1}'], ["noncanonical whitespace", '{ "v": 1 }'], ["invalid JSON", "{"], ["invalid UTF8", new Uint8Array([255])], ["oversize", "x".repeat(4097)]] as const) test(`rejects ${label}`, async () => {
  const s = setup(); const response = await s.handler(request(s.value, { body }), context); assert.equal(response.status, 400); assert.equal(s.callbacks(), 0);
});
test("preview aliases, unpublished functions, wrong site and disabled config never call services", async () => {
  const s = setup();
  for (const c of [{ ...context, deploy: { context: "deploy-preview", published: false } }, { ...context, site: { id: randomUUID() } }, { ...context, deploy: { context: "production", published: false } }]) assert.equal((await s.handler(request(s.value), c)).status, 403);
  assert.equal((await s.handler(new Request(`https://deploy--pap-test-seal.netlify.app/v1/boot/release`, { method: "POST" }), context)).status, 403);
  const disabled = createReleaseHandler({ ...config, enabled: false }, { store: s.store }); assert.equal((await disabled(request(s.value), context)).status, 503); assert.equal(s.callbacks(), 0);
});
test("routing and request metadata stay narrow", async () => {
  const s = setup();
  assert.equal((await s.handler(new Request(`${config.custody_origin}/v1/boot/release`), context)).status, 405);
  assert.equal((await s.handler(new Request(`${config.custody_origin}/other`, { method: "POST" }), context)).status, 404);
  assert.equal((await s.handler(new Request(`${config.custody_origin}/v1/boot/release?key=other`, { method: "POST" }), context)).status, 404);
  for (const headers of [{ "Content-Type": "text/plain" }, { "Content-Type": "application/json", Authorization: "Bearer accidental" }, { "Content-Type": "application/json", Cookie: "a=b" }, { "Content-Type": "application/json", "Content-Encoding": "gzip" }, { "Content-Type": "application/json", "Content-Length": "99999" }]) assert.equal((await s.handler(request(s.value, { headers }), context)).status, 400);
  assert.equal(s.callbacks(), 0);
});
test("whole-operation deadline aborts a stuck callback and observes late rejection", async () => {
  const value = boot(); const store = new MemoryStore(); let rejectLate: (error: Error) => void = () => undefined; let seenSignal: AbortSignal | undefined;
  const handler = createReleaseHandler(config, { store, now: () => clock, budgetMS: 10, proof: async (_origin, _id, signal) => { seenSignal = signal; return new Promise<Buffer>((_resolve, reject) => { rejectLate = reject; }); } });
  assert.equal((await handler(request(value), context)).status, 503); assert.equal(seenSignal?.aborted, true); assert.equal(store.reads, 0);
  rejectLate(new Error("late private failure")); await new Promise((resolve) => setImmediate(resolve));
});
test("aborted caller cannot cause key release", async () => {
  const s = setup(); const controller = new AbortController(); controller.abort();
  assert.equal((await s.handler(request(s.value, { signal: controller.signal }), context)).status, 503); assert.equal(s.callbacks(), 0); assert.equal(s.store.writes, 0);
});
test("bounded invocation concurrency rejects excess without adding work", async () => {
  const value = boot(); const store = new MemoryStore(); const gates: Array<() => void> = [];
  const handler = createReleaseHandler(config, { store, now: () => clock, proof: async () => new Promise<Buffer>((resolve) => { gates.push(() => resolve(Buffer.from(canonical(value)))); }) });
  const pending = Array.from({ length: 4 }, () => handler(request(value), context)); await new Promise((resolve) => setImmediate(resolve));
  assert.equal(gates.length, 4); const excess = await handler(request(value), context); assert.equal(excess.status, 429); assert.equal(gates.length, 4);
  gates.forEach((gate) => gate()); assert.deepEqual((await Promise.all(pending)).map((r) => r.status), [200, 200, 200, 200]);
});
