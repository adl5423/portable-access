import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  AccessError, PROOF_PATH, RECORDS_ACTION, RECORDS_PATH, assertPlatform,
  boundedJSON, freshIdentity, makeProof, parseAuthorization, parseChallenge,
  parseCredential, sha256, validateConfig, type Challenge, type Fetcher, type PublicConfig, type PublicJWK,
} from "../src/protocol.mjs";
import { PortableAccessClient } from "../src/client.mjs";
import { createProofHandler } from "../src/proof-handler.mjs";
import { createResourceVerifier } from "../src/verifier.mjs";
import type { ProofStore } from "../src/proof-store.mjs";

const NOW = 1_800_000_000;
const config: PublicConfig = {
  enabled: true, issuerURL: "https://issuer.security.example", siteID: "11111111-1111-4111-8111-111111111111",
  grantID: "grant-production", resourceOrigin: "https://secure-project.netlify.app", resourcePath: RECORDS_PATH, resourceAction: RECORDS_ACTION, tenant: "tenant-a", environment: "production",
  audience: "pap-resource", productionSiteIsolated: true,
};
const context = { site: { id: config.siteID }, deploy: { context: "production", published: true } };
const recordURL = `${config.resourceOrigin}${RECORDS_PATH}`;
const goodAuthorization = { subject: "project-runtime", tenant: config.tenant, environment: config.environment, grant_id: config.grantID, action: RECORDS_ACTION, expires_at: NOW + 60 };

class MemoryStore implements ProofStore {
  records = new Map<string, Challenge>();
  removed: string[] = [];
  async publish(record: Challenge): Promise<void> { assert.ok(!this.records.has(record.challenge_id)); this.records.set(record.challenge_id, record); }
  async read(id: string): Promise<unknown> { return this.records.get(id) ?? null; }
  async remove(id: string): Promise<void> { this.records.delete(id); this.removed.push(id); }
}

function challenge(overrides: Partial<Challenge> = {}): Challenge {
  return { challenge_id: "challenge_1234567890", nonce: "nonce_1234567890123456789012", jkt: "x".repeat(43), issuer: config.issuerURL, site_id: config.siteID, expires_at: NOW + 60, ...overrides };
}

function credential(now = NOW) {
  return { access_token: "abc.def.abcdefghijklmnop", token_type: "DPoP", expires_at: now + 60, expires_in: 60, dpop_nonce: "resource_12345678901234567890", tenant: config.tenant, environment: config.environment };
}

async function decodeProof(proof: string): Promise<{ header: { jwk: PublicJWK }; claims: Record<string, unknown> }> {
  const [head, body, sig] = proof.split(".");
  assert.ok(head && body && sig);
  const header = JSON.parse(Buffer.from(head, "base64url").toString()) as { jwk: PublicJWK };
  const key = await webcrypto.subtle.importKey("jwk", { ...header.jwk, ext: true }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  assert.equal(await webcrypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, Buffer.from(sig, "base64url"), Buffer.from(`${head}.${body}`)), true);
  return { header, claims: JSON.parse(Buffer.from(body, "base64url").toString()) as Record<string, unknown> };
}

test("runtime config defaults fail closed and metadata fields cannot enable it", () => {
  assert.throws(() => validateConfig({ ...config, enabled: false }), AccessError);
  assert.throws(() => validateConfig({ ...config, productionSiteIsolated: false }), AccessError);
  assert.throws(() => validateConfig({ ...config, unexpected: true }), AccessError);
  assert.throws(() => validateConfig({ ...config, environment: "deploy-preview" }), AccessError);
});

test("public configuration matches Python canonical UUID, identifier and audience bounds", () => {
  assert.equal(validateConfig({ ...config, tenant: "A".repeat(80), grantID: "9".repeat(80), audience: "a".repeat(200) }).tenant.length, 80);
  for (const changes of [
    { siteID: "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA" },
    { siteID: config.siteID.replaceAll("-", "") },
    { tenant: "_tenant" },
    { tenant: "-tenant" },
    { tenant: "a".repeat(81) },
    { grantID: "_grant" },
    { grantID: "a".repeat(81) },
    { audience: "a".repeat(201) },
  ]) assert.throws(() => validateConfig({ ...config, ...changes }), AccessError);
});

test("configuration CLI rejects incompatible UUIDs without changing the public configuration file", async () => {
  const directory = fileURLToPath(new URL("../..", import.meta.url));
  const configFile = new URL("../../src/config.public.json", import.meta.url);
  const before = await readFile(configFile, "utf8");
  const result = spawnSync(process.execPath, [
    "tools/configure.mjs", "--issuer-url", config.issuerURL,
    "--site-id", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA", "--grant-id", config.grantID,
    "--resource-origin", config.resourceOrigin, "--tenant", config.tenant, "--audience", config.audience,
    "--acknowledge-trusted-site",
  ], { cwd: directory, encoding: "utf8", timeout: 10_000 });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /canonical lowercase UUID/);
  assert.equal(await readFile(configFile, "utf8"), before);
});

for (const resourceOrigin of ["http://secure-project.netlify.app", "https://localhost", "https://127.0.0.1", "https://good.netlify.app.evil.example", "https://preview--good.netlify.app", "https://good.netlify.app/path", "https://user:pass@good.netlify.app", "https://good.netlify.app:8443", "HTTPS://good.netlify.app", "https://GOOD.netlify.app", "https://good.netlify.app\n", "https://go\tod.netlify.app", "https://good.netlify.app:443", "https://good.netlify.app/.", "https://good.netlify.app/%2e", "https://good.netlify.app\\"]) {
  test(`rejects unapproved resource origin ${JSON.stringify(resourceOrigin)}`, () => assert.throws(() => validateConfig({ ...config, resourceOrigin }), AccessError));
}

test("platform context rejects a wrong site, previews and historical production deployments", () => {
  assertPlatform(config, context);
  assert.throws(() => assertPlatform(config, { ...context, site: { id: "different" } }), AccessError);
  assert.throws(() => assertPlatform(config, { ...context, deploy: { context: "deploy-preview", published: false } }), AccessError);
  assert.throws(() => assertPlatform(config, { ...context, deploy: { context: "production", published: false } }), AccessError);
});

test("WebCrypto keys are non-extractable; DPoP is interoperable ES256 with key and token binding", async () => {
  const identity = await freshIdentity();
  await assert.rejects(webcrypto.subtle.exportKey("pkcs8", identity.key as webcrypto.CryptoKey));
  const encoded = await makeProof(identity.key, identity.jwk, "get", `${recordURL}?ignored=1#ignored`, "nonce_1234567890123456", "token", NOW);
  const proof = await decodeProof(encoded);
  assert.equal(proof.claims.htm, "GET");
  assert.equal(proof.claims.htu, recordURL);
  assert.equal(proof.claims.iat, NOW);
  assert.equal(proof.claims.ath, await sha256("token"));
  assert.deepEqual(Object.keys(proof.header.jwk).sort(), ["crv", "kty", "x", "y"]);
  assert.equal(identity.jkt, await sha256(JSON.stringify({ crv: identity.jwk.crv, kty: identity.jwk.kty, x: identity.jwk.x, y: identity.jwk.y })));
});

test("challenge schema rejects binding changes, unknown fields and stale or excessive lifetimes", () => {
  const original = challenge();
  assert.deepEqual(parseChallenge(original, config, original.jkt, NOW), original);
  for (const bad of [{ ...original, site_id: "other" }, { ...original, issuer: "https://evil.example" }, { ...original, jkt: "y".repeat(43) }, { ...original, expires_at: NOW }, { ...original, expires_at: NOW + 121 }, { ...original, token: "secret" }]) {
    assert.throws(() => parseChallenge(bad, config, original.jkt, NOW), AccessError);
  }
});

test("credentials reject tenant/environment changes and unbounded validity", () => {
  const original = credential();
  assert.equal(parseCredential(original, config, NOW).tenant, config.tenant);
  for (const bad of [{ ...original, tenant: "other" }, { ...original, environment: "preview" }, { ...original, token_type: "Bearer" }, { ...original, expires_at: NOW + 3601 }, { ...original, expires_in: 0 }, { ...original, added: 1 }]) assert.throws(() => parseCredential(bad, config, NOW), AccessError);
});

test("public proof endpoint retrieves only an internal publication and never echoes arbitrary challenge input", async () => {
  const store = new MemoryStore();
  const handler = createProofHandler(config, { store, now: () => NOW });
  assert.equal((await handler(new Request(`${config.resourceOrigin}${PROOF_PATH}not_published`), context)).status, 404);
  assert.equal((await handler(new Request(`${config.resourceOrigin}${PROOF_PATH}not_published?nonce=echo&jkt=attacker`), context)).status, 400);
  assert.equal((await handler(new Request(`${config.resourceOrigin}${PROOF_PATH}not_published`, { method: "POST", body: JSON.stringify(challenge()) }), context)).status, 405);
  assert.equal(store.records.size, 0);
  await store.publish(challenge());
  const response = await handler(new Request(`${config.resourceOrigin}${PROOF_PATH}${challenge().challenge_id}`), context);
  assert.deepEqual(await response.json(), challenge());
  assert.match(response.headers.get("cache-control")!, /no-store/);
  assert.equal(response.headers.get("access-control-allow-origin"), null);
});

test("proof endpoint rejects expired, malformed, mismatched and untrusted records", async () => {
  const store = new MemoryStore();
  const handler = createProofHandler(config, { store, now: () => NOW });
  await store.publish(challenge({ expires_at: NOW - 1 }));
  const req = new Request(`${config.resourceOrigin}${PROOF_PATH}${challenge().challenge_id}`);
  assert.equal((await handler(req, context)).status, 404);
  assert.equal((await handler(req, { ...context, site: { id: "other" } })).status, 403);
  assert.equal((await handler(req, { ...context, deploy: { context: "deploy-preview", published: false } })).status, 403);
  store.records.set(challenge().challenge_id, challenge({ challenge_id: "mismatch" }));
  assert.equal((await handler(req, context)).status, 404);
});

function network(store: MemoryStore, clock: () => number, controls: { resourceFailures?: number; issueDenied?: boolean; wrongChallenge?: boolean; wrongCredential?: boolean } = {}) {
  const observed = { enrollKeys: [] as PublicJWK[], resourceProofs: [] as Record<string, unknown>[], issueCalls: 0, challengeCalls: 0 };
  const fetcher: Fetcher = async (url, init) => {
    assert.equal(init?.redirect, "error");
    assert.ok(init?.signal);
    const headers = new Headers(init?.headers);
    if (url.endsWith("/v1/site/challenge")) {
      observed.challengeCalls++;
      const body = JSON.parse(init?.body as string) as { grant_id: string; jwk: PublicJWK };
      assert.equal(body.grant_id, config.grantID);
      observed.enrollKeys.push(body.jwk);
      const jkt = await sha256(JSON.stringify({ crv: body.jwk.crv, kty: body.jwk.kty, x: body.jwk.x, y: body.jwk.y }));
      return Response.json(challenge({ challenge_id: `challenge_${observed.challengeCalls}`, jkt, issuer: controls.wrongChallenge ? "https://evil.example" : config.issuerURL, expires_at: clock() + 60 }));
    }
    if (url.endsWith("/v1/site/token")) {
      observed.issueCalls++;
      const proof = await decodeProof(headers.get("dpop")!);
      assert.equal(proof.claims.htm, "POST");
      assert.equal(proof.claims.htu, `${config.issuerURL}/v1/site/token`);
      assert.equal("ath" in proof.claims, false);
      const body = JSON.parse(init?.body as string) as { challenge_id: string; jwk: PublicJWK };
      const published = store.records.get(body.challenge_id);
      assert.ok(published);
      assert.equal(published.nonce, proof.claims.nonce);
      assert.deepEqual(body.jwk, proof.header.jwk);
      assert.equal(JSON.stringify(published).includes("private"), false);
      if (controls.issueDenied) return Response.json({ error: "revoked" }, { status: 403 });
      return Response.json({ ...credential(clock()), tenant: controls.wrongCredential ? "other" : config.tenant });
    }
    assert.equal(url, recordURL);
    assert.match(headers.get("authorization")!, /^DPoP /);
    const proof = await decodeProof(headers.get("dpop")!);
    observed.resourceProofs.push(proof.claims);
    assert.equal(proof.claims.ath, await sha256(credential().access_token));
    assert.equal(proof.claims.htu, recordURL);
    if ((controls.resourceFailures ?? 0) > 0) { controls.resourceFailures!--; return Response.json({ error: "busy" }, { status: 503 }); }
    return Response.json({ records: [{ id: "record-1", title: "Private record", updated_at: "2026-10-22T12:00:00Z" }] });
  };
  return { fetcher, observed };
}

test("SDK enrolls with public proof, cleans it, returns records and exposes no credentials", async () => {
  const store = new MemoryStore();
  const { fetcher, observed } = network(store, () => NOW);
  const client = new PortableAccessClient(config, { store, fetcher, now: () => NOW });
  const result = await client.readRecords(context);
  assert.equal(result.records[0]?.id, "record-1");
  assert.equal(store.records.size, 0);
  assert.equal(store.removed.length, 1);
  assert.deepEqual(Object.keys(client), []);
  assert.deepEqual(Object.getOwnPropertyNames(Object.getPrototypeOf(client)).sort(), ["close", "constructor", "getJSON", "readRecords"]);
  assert.equal(observed.issueCalls, 1);
});

test("concurrent SDK calls share one enrollment but carry independent proofs", async () => {
  const store = new MemoryStore();
  const { fetcher, observed } = network(store, () => NOW);
  const client = new PortableAccessClient(config, { store, fetcher, now: () => NOW });
  await Promise.all([client.readRecords(context), client.readRecords(context), client.readRecords(context)]);
  assert.equal(observed.issueCalls, 1);
  assert.equal(new Set(observed.resourceProofs.map((proof) => proof.jti)).size, 3);
});

test("automatic renewal replaces workload proof key before expiry and on process reset", async () => {
  let now = NOW;
  const store = new MemoryStore();
  const { fetcher, observed } = network(store, () => now);
  const client = new PortableAccessClient(config, { store, fetcher, now: () => now });
  await client.readRecords(context);
  now += 51;
  await client.readRecords(context);
  client.close();
  await assert.rejects(client.readRecords(context), (error) => error instanceof AccessError && error.code === "client_closed");
  const restarted = new PortableAccessClient(config, { store, fetcher, now: () => now });
  await restarted.readRecords(context);
  assert.equal(observed.issueCalls, 3);
  assert.equal(new Set(observed.enrollKeys.map((key) => key.x)).size, 3);
  assert.equal(store.records.size, 0);
});

test("safe read retry signs a new jti for each attempt", async () => {
  const store = new MemoryStore();
  const { fetcher, observed } = network(store, () => NOW, { resourceFailures: 1 });
  const client = new PortableAccessClient(config, { store, fetcher, now: () => NOW, pause: async () => undefined });
  await client.readRecords(context);
  assert.equal(observed.resourceProofs.length, 2);
  assert.notEqual(observed.resourceProofs[0]!.jti, observed.resourceProofs[1]!.jti);
});

test("revoked enrollment fails closed, deletes public proof and does not retry issuance", async () => {
  const store = new MemoryStore();
  const { fetcher, observed } = network(store, () => NOW, { issueDenied: true });
  const client = new PortableAccessClient(config, { store, fetcher, now: () => NOW });
  await assert.rejects(client.readRecords(context), (error) => error instanceof AccessError && error.status === 403);
  assert.equal(observed.issueCalls, 1);
  assert.equal(observed.resourceProofs.length, 0);
  assert.equal(store.records.size, 0);
});

test("SDK rejects a wrong challenge before publishing and rejects wrong credential scope", async () => {
  for (const controls of [{ wrongChallenge: true }, { wrongCredential: true }]) {
    const store = new MemoryStore();
    const { fetcher, observed } = network(store, () => NOW, controls);
    const client = new PortableAccessClient(config, { store, fetcher, now: () => NOW });
    await assert.rejects(client.readRecords(context), AccessError);
    assert.equal(store.records.size, 0);
    assert.equal(observed.resourceProofs.length, 0);
    if ("wrongChallenge" in controls) assert.equal(store.removed.length, 0);
  }
});

test("resource verifier uses original proof, fixed operation and canonical configured origin", async () => {
  const calls: Array<{ url: string; init?: RequestInit }> = [];
  const identity = await freshIdentity();
  const encoded = await makeProof(identity.key, identity.jwk, "GET", recordURL, "nonce_1234567890123456", credential().access_token, NOW);
  const fetcher: Fetcher = async (url, init) => { calls.push(init === undefined ? { url } : { url, init }); return Response.json(goodAuthorization); };
  const verify = createResourceVerifier(config, { fetcher, now: () => NOW });
  const result = await verify(new Request(`https://evil-host.example${RECORDS_PATH}`, { headers: { Authorization: `DPoP ${credential().access_token}`, DPoP: encoded, "X-Forwarded-Host": "attacker.example", Origin: "https://attacker.example" } }), context);
  assert.equal(result.subject, goodAuthorization.subject);
  assert.deepEqual(JSON.parse(calls[0]!.init!.body as string), { method: "GET", url: recordURL, tenant: config.tenant, action: RECORDS_ACTION, audience: config.audience });
  assert.equal(new Headers(calls[0]!.init!.headers).get("dpop"), encoded);
  assert.equal(calls[0]!.init!.redirect, "error");
  await verify(new Request(recordURL, { headers: { Authorization: `DPoP ${credential().access_token}`, DPoP: encoded } }), context);
  assert.equal(calls.length, 2, "authorization decisions are not cached");
});

test("resource rejects invalid headers, query/path/method changes without calling issuer", async () => {
  let calls = 0;
  const verify = createResourceVerifier(config, { fetcher: async () => { calls++; return Response.json(goodAuthorization); }, now: () => NOW });
  for (const request of [new Request(recordURL), new Request(`${recordURL}?tenant=other`), new Request(`${config.resourceOrigin}/other`), new Request(recordURL, { method: "POST" }), new Request(recordURL, { headers: { Authorization: "Bearer abc.def.ghi", DPoP: "abc.def.ghi" } })]) await assert.rejects(verify(request, context), AccessError);
  assert.equal(calls, 0);
});

test("resource rejects wrong tenant, action, grant, environment, expiry and extra response fields", () => {
  for (const bad of [{ ...goodAuthorization, tenant: "other" }, { ...goodAuthorization, action: "admin" }, { ...goodAuthorization, grant_id: "other" }, { ...goodAuthorization, environment: "preview" }, { ...goodAuthorization, expires_at: NOW }, { ...goodAuthorization, token: "leak" }]) assert.throws(() => parseAuthorization(bad, config, NOW), AccessError);
});

test("bounded JSON rejects wrong content type, invalid JSON and oversized streamed responses", async () => {
  await assert.rejects(boundedJSON(new Response("hello")), AccessError);
  await assert.rejects(boundedJSON(new Response("{", { headers: { "Content-Type": "application/json" } })), AccessError);
  await assert.rejects(boundedJSON(Response.json({ large: "x".repeat(100) }), 20), AccessError);
});

test("configurable middleware binds one real project GET endpoint and rejects all other operations", async () => {
  const custom = { ...config, resourcePath: "/api/orders/current", resourceAction: "orders.read" };
  const observed: unknown[] = [];
  const verifier = createResourceVerifier(custom, { now: () => NOW, fetcher: async (_url, init) => {
    observed.push(JSON.parse(init!.body as string));
    return Response.json({ ...goodAuthorization, action: "orders.read" });
  } });
  const headers = { Authorization: `DPoP ${credential().access_token}`, DPoP: "abc.def.ghi" };
  await verifier(new Request(`${config.resourceOrigin}/api/orders/current`, { headers }), context);
  assert.deepEqual(observed, [{ method: "GET", url: `${config.resourceOrigin}/api/orders/current`, tenant: config.tenant, action: "orders.read", audience: config.audience }]);
  await assert.rejects(verifier(new Request(recordURL, { headers }), context), AccessError);
  await assert.rejects(verifier(new Request(`${config.resourceOrigin}/api/orders/current`, { method: "POST", headers }), context), AccessError);
  assert.equal(observed.length, 1);
});

test("resource policy rejects ambiguous paths, encoded segments, arbitrary methods and invalid actions", () => {
  for (const resourcePath of ["//evil.example/path", "/api/../admin", "/api/%2e%2e/admin", "/api/orders?tenant=other", "/api/orders#other", "/api//orders", "/api/v1.0/orders", "/api/~owner"]) assert.throws(() => validateConfig({ ...config, resourcePath }), AccessError);
  assert.throws(() => validateConfig({ ...config, resourceAction: "admin:all" }), AccessError);
  assert.throws(() => validateConfig({ ...config, resourceMethod: "POST" }), AccessError);
});

test("untrusted SDK context fails before any challenge or resource request", async () => {
  let calls = 0;
  const client = new PortableAccessClient(config, { fetcher: async () => { calls++; throw new Error("must not fetch"); } });
  await assert.rejects(client.getJSON({ ...context, deploy: { context: "deploy-preview", published: false } }), (error) => error instanceof AccessError && error.status === 403);
  assert.equal(calls, 0);
});

test("online denial remains denied and the resource fails closed on issuer outage", async () => {
  const request = () => new Request(recordURL, { headers: { Authorization: `DPoP ${credential().access_token}`, DPoP: "abc.def.ghi" } });
  const revoked = createResourceVerifier(config, { fetcher: async () => Response.json({ error: "revoked" }, { status: 403 }) });
  await assert.rejects(revoked(request(), context), (error) => error instanceof AccessError && error.status === 403);
  const unavailable = createResourceVerifier(config, { fetcher: async () => { throw new Error("private credential must not enter errors"); } });
  await assert.rejects(unavailable(request(), context), (error) => error instanceof AccessError && error.status === 503 && !error.message.includes("credential"));
});

test("failed public-record cleanup cannot replace a successful response or hide a denied grant", async () => {
  for (const issueDenied of [false, true]) {
    const store = new MemoryStore();
    store.remove = async () => { throw new Error("storage offline"); };
    const { fetcher } = network(store, () => NOW, { issueDenied });
    const client = new PortableAccessClient(config, { store, fetcher, now: () => NOW });
    if (issueDenied) await assert.rejects(client.readRecords(context), (error) => error instanceof AccessError && error.status === 403);
    else assert.equal((await client.readRecords(context)).records.length, 1);
    assert.equal(store.records.size, 1, "remaining record is public and expires through issuer policy");
  }
});

test("credential-free error logs and client errors never include an upstream response body", async () => {
  const store = new MemoryStore();
  const base = network(store, () => NOW);
  const fetcher: Fetcher = async (url, init) => url.endsWith("/health") ? Response.json({ ready: false }, { status: 503 }) : url.endsWith("/v1/site/token") ? Response.json({ access_token: "sensitive upstream detail" }, { status: 500 }) : base.fetcher(url, init);
  const client = new PortableAccessClient(config, { store, fetcher, now: () => NOW, pause: async () => undefined });
  await assert.rejects(client.readRecords(context), (error) => error instanceof AccessError && error.message === "issuer_unavailable" && !error.message.includes("sensitive"));
  assert.equal(store.records.size, 0);
});

test("on-demand issuer recovery uses fresh enrollment after a transient failed issuance", async () => {
  const store = new MemoryStore();
  const base = network(store, () => NOW);
  let elapsed = 0, health = 0;
  const proofs: Array<{ jwk: PublicJWK; jti: unknown; challenge: string }> = [];
  const fetcher: Fetcher = async (url, init) => {
    if (url === `${config.issuerURL}/health`) {
      health++;
      assert.equal(init?.method, "GET"); assert.equal(init?.body, undefined);
      assert.equal(new Headers(init?.headers).has("authorization"), false);
      assert.equal(init?.redirect, "error"); assert.equal(init?.cache, "no-store");
      return Response.json({ ready: health > 1 }, { status: health > 1 ? 200 : 503 });
    }
    if (url.endsWith("/v1/site/token")) {
      const proof = await decodeProof(new Headers(init?.headers).get("dpop")!);
      proofs.push({ jwk: proof.header.jwk, jti: proof.claims.jti, challenge: JSON.parse(init?.body as string).challenge_id });
      const result = await base.fetcher(url, init);
      return proofs.length === 1 ? Response.json({ error: "lifecycle_unavailable" }, { status: 503 }) : result;
    }
    return base.fetcher(url, init);
  };
  const client = new PortableAccessClient(config, { store, fetcher, now: () => NOW, monotonic: () => elapsed, pause: async (delay) => { assert.ok(delay >= 250 && delay <= 2000); elapsed += delay; } });
  assert.equal((await client.readRecords(context)).records.length, 1);
  assert.equal(health, 2); assert.equal(proofs.length, 2);
  assert.notDeepEqual(proofs[0]!.jwk, proofs[1]!.jwk);
  assert.notEqual(proofs[0]!.jti, proofs[1]!.jti);
  assert.notEqual(proofs[0]!.challenge, proofs[1]!.challenge);
  assert.equal(store.removed.length, 2); assert.equal(store.records.size, 0);
});

test("401 and 403 enrollment denial never start readiness polling or renewal retries", async () => {
  for (const status of [401, 403]) {
    const store = new MemoryStore(); const base = network(store, () => NOW);
    let health = 0, issues = 0;
    const fetcher: Fetcher = async (url, init) => {
      if (url.endsWith("/health")) { health++; return Response.json({ ready: true }); }
      if (url.endsWith("/v1/site/token")) { issues++; await base.fetcher(url, init); return Response.json({ error: "denied" }, { status }); }
      return base.fetcher(url, init);
    };
    const client = new PortableAccessClient(config, { store, fetcher, now: () => NOW });
    await assert.rejects(client.readRecords(context), (error) => error instanceof AccessError && error.status === status);
    assert.equal(health, 0); assert.equal(issues, 1); assert.equal(store.records.size, 0);
  }
});

test("not-ready issuer is polled at most eight times and does not repeat issuance", async () => {
  const store = new MemoryStore(); const base = network(store, () => NOW);
  let health = 0, issues = 0;
  const fetcher: Fetcher = async (url, init) => {
    if (url.endsWith("/health")) { health++; return Response.json({ ready: false }, { status: 503 }); }
    if (url.endsWith("/v1/site/token")) { issues++; await base.fetcher(url, init); return Response.json({ error: "unavailable" }, { status: 503 }); }
    return base.fetcher(url, init);
  };
  const client = new PortableAccessClient(config, { store, fetcher, now: () => NOW, pause: async () => undefined });
  await assert.rejects(client.readRecords(context), (error) => error instanceof AccessError && error.code === "issuer_unavailable");
  assert.equal(health, 8); assert.equal(issues, 1); assert.equal(store.records.size, 0);
});

test("readiness waiting observes an absolute 20-second monotonic budget", async () => {
  const store = new MemoryStore(); let elapsed = 0, health = 0, challenges = 0;
  const fetcher: Fetcher = async (url, init) => {
    assert.ok(init?.signal);
    if (url.endsWith("/v1/site/challenge")) { challenges++; return Response.json({ error: "unavailable" }, { status: 503 }); }
    assert.equal(url, `${config.issuerURL}/health`); health++; elapsed += Math.min(8000, 20_000 - elapsed);
    return Response.json({ ready: false }, { status: 503 });
  };
  const client = new PortableAccessClient(config, { store, fetcher, monotonic: () => elapsed, pause: async (delay) => { elapsed += delay; } });
  await assert.rejects(client.readRecords(context), (error) => error instanceof AccessError && error.code === "issuer_unavailable");
  assert.equal(challenges, 1); assert.equal(health, 3); assert.equal(elapsed, 20_000);
});

test("close during readiness backoff stops recovery before another network call", async () => {
  let health = 0, challenges = 0;
  const fetcher: Fetcher = async (url) => {
    if (url.endsWith("/v1/site/challenge")) { challenges++; return Response.json({}, { status: 503 }); }
    health++; return Response.json({ ready: false }, { status: 503 });
  };
  const client: PortableAccessClient = new PortableAccessClient(config, { fetcher, pause: async (): Promise<void> => { client.close(); } });
  await assert.rejects(client.readRecords(context), (error) => error instanceof AccessError && error.code === "client_closed");
  assert.equal(health, 1); assert.equal(challenges, 1);
});

test("close aborts an in-flight readiness fetch", async () => {
  let healthStarted!: () => void; const started = new Promise<void>((resolve) => { healthStarted = resolve; });
  let signal: AbortSignal | null | undefined;
  const fetcher: Fetcher = async (url, init) => {
    if (url.endsWith("/v1/site/challenge")) return Response.json({}, { status: 503 });
    signal = init?.signal; healthStarted();
    return new Promise<Response>((_resolve, reject) => signal?.addEventListener("abort", () => reject(new Error("private transport error")), { once: true }));
  };
  const client = new PortableAccessClient(config, { fetcher });
  const operation = client.readRecords(context); await started; client.close();
  await assert.rejects(operation, (error) => error instanceof AccessError && error.code === "client_closed");
  assert.equal(signal?.aborted, true);
});

test("recovery retries the whole enrollment once even if the second attempt is unavailable", async () => {
  const store = new MemoryStore(); const base = network(store, () => NOW);
  let health = 0, issues = 0;
  const fetcher: Fetcher = async (url, init) => {
    if (url.endsWith("/health")) { health++; return Response.json({ ready: true }); }
    if (url.endsWith("/v1/site/token")) { issues++; await base.fetcher(url, init); return Response.json({}, { status: 503 }); }
    return base.fetcher(url, init);
  };
  const client = new PortableAccessClient(config, { store, fetcher, now: () => NOW });
  await assert.rejects(client.readRecords(context), (error) => error instanceof AccessError && error.code === "issuer_unavailable");
  assert.equal(health, 1); assert.equal(issues, 2); assert.equal(store.removed.length, 2);
  assert.notDeepEqual(base.observed.enrollKeys[0], base.observed.enrollKeys[1]);
});

test("readiness endpoint denial is never retried", async () => {
  let health = 0, challenges = 0;
  const fetcher: Fetcher = async (url) => {
    if (url.endsWith("/v1/site/challenge")) { challenges++; return Response.json({}, { status: 503 }); }
    health++; return Response.json({}, { status: 403 });
  };
  const client = new PortableAccessClient(config, { fetcher });
  await assert.rejects(client.readRecords(context), (error) => error instanceof AccessError && error.status === 403);
  assert.equal(health, 1); assert.equal(challenges, 1);
});
