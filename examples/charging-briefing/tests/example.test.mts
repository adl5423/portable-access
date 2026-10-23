import { test } from "node:test";
import assert from "node:assert/strict";
import type { DeploySucceededEvent } from "@netlify/functions";
import { AccessError, type PublicConfig, validateConfig } from "@portable-access/netlify/protocol";
import { createConnectorRelay, parseBriefing, type Operation } from "../src/relay.mjs";
import { createDeployAcceptance, type AcceptanceReport } from "../src/acceptance.mjs";
import handler, { config as eventConfig } from "../netlify/functions/deploy-succeeded.mjs";
import defaults from "../src/config.public.json" with { type: "json" };

const operation = "charging-briefing" as Operation;
const policy: PublicConfig = { enabled: true, issuerURL: "https://authority.example.com", siteID: "11111111-1111-4111-8111-111111111111", grantID: "example-grant", resourceOrigin: "https://example-project.netlify.app", resourcePath: "/api/briefing", resourceAction: `${operation}.read`, tenant: "example-tenant", environment: "production", audience: "urn:pap:example", productionSiteIsolated: true };
const context = { site: { id: policy.siteID }, deploy: { context: "production", published: true } };
const event = { site: { id: policy.siteID }, deploy: { siteId: policy.siteID, context: "production", publishedAt: "2026-10-23T12:00:00Z" } } as DeploySucceededEvent;
const target = `${policy.resourceOrigin}${policy.resourcePath}`;
const authorization = `DPoP ${"a".repeat(32)}`;
const proof = "b".repeat(32);
const sources = operation === "space-briefing" ? [{ provider: "nasa", title: "Near-Earth objects", url: "https://api.nasa.gov/", records: 10 }] : operation === "charging-briefing" ? [{ provider: "nlr", title: "Charleston charging stations", url: "https://developer.nlr.gov/docs/transportation/alt-fuel-stations-v1/", records: 10 }] : [{ provider: "nasa", title: "Near-Earth objects", url: "https://api.nasa.gov/", records: 10 }, { provider: "nlr", title: "Charleston charging stations", url: "https://developer.nlr.gov/docs/transportation/alt-fuel-stations-v1/", records: 10 }];
const result = { operation, generated_at: "2026-10-23T12:00:00Z", period: "2026-10-23T12:00:00Z", model: "gpt-4.1-mini", summary: "Public science and infrastructure summary.", sources, cached: false };
const request = (url = target, headers = { Authorization: authorization, DPoP: proof }) => new Request(url, { headers });

test("configuration remains public and platform event has no HTTP entry point", () => {
  if (defaults.enabled) assert.doesNotThrow(() => validateConfig(defaults));
  else { assert.equal(defaults.enabled, false); assert.equal(defaults.productionSiteIsolated, false); }
  assert.deepEqual(Object.keys(handler), ["deploySucceeded"]); assert.deepEqual(eventConfig, { background: true });
});

test("relay preserves proof and original GET authorization target without a first verification", async () => {
  let calls = 0;
  const relay = createConnectorRelay(policy, operation, async (url, init) => {
    calls++; assert.equal(url, `${policy.issuerURL}/v1/connectors/${operation}`);
    assert.equal(init?.method, "POST"); assert.equal(init?.redirect, "error"); assert.equal(init?.cache, "no-store"); assert.ok(init?.signal);
    const headers = new Headers(init?.headers); assert.equal(headers.get("authorization"), authorization); assert.equal(headers.get("dpop"), proof);
    assert.deepEqual(JSON.parse(String(init?.body)), { method: "GET", url: target, tenant: policy.tenant, action: policy.resourceAction, audience: policy.audience });
    return Response.json(result);
  });
  const response = await relay(request(), context); assert.equal(response.status, 200); assert.deepEqual(await response.json(), result); assert.equal(calls, 1);
  assert.equal(response.headers.get("cache-control"), "no-store, private, max-age=0");
});

test("missing proof, wrong target, query, preview and wrong site never contact broker", async () => {
  let calls = 0;
  const relay = createConnectorRelay(policy, operation, async () => { calls++; throw new Error("must not contact broker"); });
  for (const [req, ctx, status] of [
    [new Request(target), context, 401], [request(`${target}?prompt=anything`), context, 400],
    [request("https://other-project.netlify.app/api/briefing"), context, 400],
    [request(), { ...context, deploy: { context: "deploy-preview", published: true } }, 403],
    [request(), { ...context, site: { id: "other" } }, 403],
    [new Request(target, { method: "POST", body: "arbitrary prompt" }), context, 405],
  ] as const) assert.equal((await relay(req, ctx)).status, status);
  assert.equal(calls, 0);
});

test("upstream denials, non-JSON, oversized output, redirects and exceptions are redacted", async () => {
  for (const response of [Response.json({ secret: "do-not-reflect" }, { status: 403 }), new Response("do-not-reflect", { status: 500 }), new Response("do-not-reflect", { headers: { "content-type": "text/plain" } }), Response.json({ ...result, summary: "do-not-reflect", extra: "private" }), new Response("{}", { headers: { "content-type": "application/json", "content-length": "99999999" } })]) {
    const relay = createConnectorRelay(policy, operation, async () => response);
    const denied = await relay(request(), context); assert.ok(denied.status >= 400); assert.doesNotMatch(await denied.text(), /do-not-reflect|private|secret/);
  }
  const denied = await createConnectorRelay(policy, operation, async () => { throw new Error("do-not-reflect"); })(request(), context);
  assert.equal(denied.status, 503); assert.doesNotMatch(await denied.text(), /do-not-reflect/);
});

test("strict briefing schema rejects provider-key URLs and operation confusion", () => {
  assert.deepEqual(parseBriefing(result, operation), result);
  for (const bad of [null, { ...result, operation: "other" }, { ...result, model: "other" }, { ...result, sources: [{ ...sources[0], url: "https://api.nasa.gov/?api_key=private" }] }, { ...result, sources: [] }, { ...result, summary: "bad\u0000text" }, { ...result, cached: "false" }]) assert.throws(() => parseBriefing(bad, operation));
});

test("disabled config performs no context lookup, credential generation or publish", async () => {
  const reports: AcceptanceReport[] = [];
  await createDeployAcceptance({ enabled: false }, operation, { context: () => { throw new Error("must not read context"); }, publish: async () => { throw new Error("must not publish"); }, report: (report) => reports.push(report) })(event);
  assert.equal(reports[0]?.outcome, "skipped");
});

test("verified deploy checks perform two reads 65 seconds apart and close one client", async () => {
  let reads = 0, closes = 0, publishes = 0;
  const pauses: number[] = [], reports: AcceptanceReport[] = [];
  await createDeployAcceptance(policy, operation, { context: () => context, client: () => ({ async getJSON(actual) { assert.deepEqual(actual, context); reads++; return result; }, close() { closes++; } }), pause: async (value) => { pauses.push(value); }, publish: async (value) => { assert.deepEqual(value, result); publishes++; }, report: (report) => reports.push(report) })(event);
  assert.equal(reads, 2); assert.equal(closes, 1); assert.equal(publishes, 2); assert.deepEqual(pauses, [65000]);
  assert.deepEqual(reports.map((report) => [report.outcome, report.stage]), [["passed", "initial-read"], ["passed", "second-read"]]);
  assert.doesNotMatch(JSON.stringify(reports), /summary|science and infrastructure/);
});

test("untrusted events fail before a client or provider operation", async () => {
  for (const bad of [{ ...event, site: { ...event.site, id: "other" } }, { ...event, deploy: { ...event.deploy, context: "deploy-preview" } }, { ...event, deploy: { ...event.deploy, publishedAt: null } }]) {
    const reports: AcceptanceReport[] = [];
    await createDeployAcceptance(policy, operation, { context: () => context, client: () => { throw new Error("must not construct client"); }, publish: async () => { throw new Error("must not publish"); }, report: (report) => reports.push(report) })(bad);
    assert.equal(reports[0]?.code, "event_binding_mismatch");
  }
});

test("second-read denial is redacted and closes cached credentials", async () => {
  let reads = 0, closes = 0; const reports: AcceptanceReport[] = [];
  await createDeployAcceptance(policy, operation, { context: () => context, client: () => ({ async getJSON() { if (++reads === 2) throw new AccessError("private-message", 403); return result; }, close() { closes++; } }), pause: async () => undefined, publish: async () => undefined, report: (report) => reports.push(report) })(event);
  assert.equal(closes, 1); assert.equal(reports[1]?.outcome, "failed"); assert.equal(reports[1]?.stage, "second-read"); assert.doesNotMatch(JSON.stringify(reports), /private-message/);
});
