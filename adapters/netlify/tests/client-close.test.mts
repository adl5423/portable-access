import { test } from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { PortableAccessClient } from "../src/client.mjs";
import {
  AccessError, RECORDS_ACTION, RECORDS_PATH, sha256,
  type Challenge, type Fetcher, type PublicConfig, type PublicJWK,
} from "../src/protocol.mjs";
import type { ProofStore } from "../src/proof-store.mjs";

test("close during resource proof signing prevents the resource request from starting", { timeout: 10_000 }, async () => {
  const now = 1_800_000_000;
  const config: PublicConfig = {
    enabled: true,
    issuerURL: "https://issuer.security.example",
    siteID: "11111111-1111-4111-8111-111111111111",
    grantID: "grant-production",
    resourceOrigin: "https://secure-project.netlify.app",
    resourcePath: RECORDS_PATH,
    resourceAction: RECORDS_ACTION,
    tenant: "tenant-a",
    environment: "production",
    audience: "pap-resource",
    productionSiteIsolated: true,
  };
  const context = { site: { id: config.siteID }, deploy: { context: "production", published: true } };
  const recordURL = `${config.resourceOrigin}${RECORDS_PATH}`;
  const published = new Map<string, Challenge>();
  const removed: string[] = [];
  const store: ProofStore = {
    async publish(challenge) { published.set(challenge.challenge_id, challenge); },
    async read(id) { return published.get(id) ?? null; },
    async remove(id) { published.delete(id); removed.push(id); },
  };
  let resourceRequests = 0;
  const fetcher: Fetcher = async (url, init) => {
    if (url === `${config.issuerURL}/v1/site/challenge`) {
      const body = JSON.parse(init?.body as string) as { jwk: PublicJWK };
      const jkt = await sha256(JSON.stringify({ crv: body.jwk.crv, kty: body.jwk.kty, x: body.jwk.x, y: body.jwk.y }));
      return Response.json({
        challenge_id: "challenge_close_signing", nonce: "nonce_1234567890123456789012", jkt,
        issuer: config.issuerURL, site_id: config.siteID, expires_at: now + 60,
      });
    }
    if (url === `${config.issuerURL}/v1/site/token`) {
      const body = JSON.parse(init?.body as string) as { challenge_id: string };
      assert.ok(published.has(body.challenge_id));
      return Response.json({
        access_token: "abc.def.abcdefghijklmnop", token_type: "DPoP", expires_at: now + 60,
        expires_in: 60, dpop_nonce: "resource_12345678901234567890",
        tenant: config.tenant, environment: config.environment,
      });
    }
    assert.equal(url, recordURL);
    resourceRequests++;
    return Response.json({ records: [] });
  };
  const client = new PortableAccessClient(config, { store, fetcher, now: () => now });
  const subtle = webcrypto.subtle;
  const originalSign = subtle.sign;
  const originalDescriptor = Object.getOwnPropertyDescriptor(subtle, "sign");
  let releaseSigning!: () => void;
  const signingReleased = new Promise<void>((resolve) => { releaseSigning = resolve; });
  let signalSigningStarted!: () => void;
  const signingStarted = new Promise<void>((resolve) => { signalSigningStarted = resolve; });
  const interceptedSign = async (...args: Parameters<typeof originalSign>): Promise<ArrayBuffer> => {
    const input = Buffer.from(args[2] as Uint8Array).toString("utf8");
    const payload = input.split(".")[1];
    assert.ok(payload);
    const claims = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as { htm?: unknown; htu?: unknown };
    const signature = originalSign.apply(subtle, args);
    if (claims.htm === "GET" && claims.htu === recordURL) {
      signalSigningStarted();
      await signingReleased;
    }
    return signature;
  };
  Object.defineProperty(subtle, "sign", { configurable: true, writable: true, value: interceptedSign });
  let operation: Promise<unknown> | undefined;
  try {
    operation = client.readRecords(context);
    await Promise.race([
      signingStarted,
      operation.then(() => { throw new Error("read completed before resource proof signing"); }),
    ]);
    assert.equal(resourceRequests, 0);
    assert.equal(published.size, 0);
    assert.deepEqual(removed, ["challenge_close_signing"]);
    client.close();
    releaseSigning();
    await assert.rejects(operation, (error) => error instanceof AccessError && error.code === "client_closed");
    assert.equal(resourceRequests, 0);
  } finally {
    client.close();
    releaseSigning();
    await operation?.catch(() => undefined);
    if (originalDescriptor) Object.defineProperty(subtle, "sign", originalDescriptor);
    else Reflect.deleteProperty(subtle, "sign");
  }
});
