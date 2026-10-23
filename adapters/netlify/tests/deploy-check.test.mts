import { test } from "node:test";
import assert from "node:assert/strict";
import type { DeploySucceededEvent } from "@netlify/functions";
import { createDeployCheck, type DeployCheckReport } from "../src/deploy-check.mjs";
import { AccessError, type PublicConfig } from "../src/protocol.mjs";
import handler, { config as deploymentCheckConfig } from "../netlify/functions/deploy-succeeded.mjs";

const config: PublicConfig = {
  enabled: true, issuerURL: "https://issuer.security.example", siteID: "11111111-1111-4111-8111-111111111111",
  grantID: "grant-production", resourceOrigin: "https://secure-project.netlify.app", resourcePath: "/api/pap/records", resourceAction: "records.read",
  tenant: "tenant-a", environment: "production", audience: "pap-resource", productionSiteIsolated: true,
};
const context = { site: { id: config.siteID }, deploy: { context: "production", published: true } };
const event = { site: { id: config.siteID }, deploy: { siteId: config.siteID, context: "production", publishedAt: "2026-10-22T00:00:00Z" } } as DeploySucceededEvent;

test("deploy check exports only a verified platform-event handler", () => {
  assert.deepEqual(Object.keys(handler), ["deploySucceeded"]);
  assert.deepEqual(deploymentCheckConfig, { background: true });
});

test("disabled deployment performs no context, SDK or network operation", async () => {
  const reports: DeployCheckReport[] = [];
  await createDeployCheck({ enabled: false }, { context: () => { throw new Error("must not execute"); }, report: (value) => reports.push(value) })(event);
  assert.deepEqual(reports, [{ event: "pap.deploy-check", outcome: "skipped", stage: "disabled", code: "adapter_not_configured" }]);
});

test("missing runtime context fails closed before constructing a client", async () => {
  const reports: DeployCheckReport[] = [];
  let created = false;
  await createDeployCheck(config, { context: () => { throw new Error("sensitive context"); }, client: () => { created = true; throw new Error("must not execute"); }, report: (value) => reports.push(value) })(event);
  assert.equal(created, false);
  assert.equal(reports[0]?.code, "context_unavailable");
  assert.doesNotMatch(JSON.stringify(reports), /sensitive context/);
});

test("wrong runtime site and unpublished context fail before a client exists", async () => {
  for (const bad of [{ ...context, site: { id: "other-site" } }, { ...context, deploy: { context: "production", published: false } }]) {
    const reports: DeployCheckReport[] = [];
    await createDeployCheck(config, { context: () => bad, client: () => { throw new Error("must not execute"); }, report: (value) => reports.push(value) })(event);
    assert.equal(reports[0]?.code, "untrusted_deployment");
  }
});

test("deploy event binding rejects other sites, previews and unpublished events", async () => {
  for (const bad of [{ ...event, site: { ...event.site, id: "other-site" } }, { ...event, deploy: { ...event.deploy, siteId: "other-site" } }, { ...event, deploy: { ...event.deploy, context: "deploy-preview" } }, { ...event, deploy: { ...event.deploy, publishedAt: null } }]) {
    const reports: DeployCheckReport[] = [];
    await createDeployCheck(config, { context: () => context, client: () => { throw new Error("must not execute"); }, report: (value) => reports.push(value) })(bad);
    assert.equal(reports[0]?.code, "event_binding_mismatch");
  }
});

test("fixed read runs twice with one client and logs only counts", async () => {
  const reports: DeployCheckReport[] = [];
  const pauses: number[] = [];
  let reads = 0, closed = false;
  await createDeployCheck(config, { context: () => context, client: () => ({
    async readRecords(actual) { assert.deepEqual(actual, context); reads++; return { records: [{ id: "record", title: "private content", updated_at: "2026-10-22T00:00:00Z" }] }; },
    close() { closed = true; },
  }), pause: async (value) => { pauses.push(value); }, report: (value) => reports.push(value) })(event);
  assert.equal(reads, 2); assert.equal(closed, true); assert.deepEqual(pauses, [65_000]);
  assert.deepEqual(reports.map((value) => value.stage), ["initial-read", "second-read"]);
  assert.equal(reports.every((value) => value.outcome === "passed" && value.records_count === 1), true);
  assert.doesNotMatch(JSON.stringify(reports), /private content/);
});

test("deploy event uses bounded background recovery for a129second fast503outage and reuses the client", async () => {
  const reports: DeployCheckReport[] = [];
  let now = 0, clients = 0, calls = 0, closes = 0, timers = 0;
  await createDeployCheck(config, {
    context: () => context,
    client: () => { clients++; return {
      async readRecords() { calls++; if (now < 129_000) throw new AccessError("resource_unavailable", 503); return { records: [] }; },
      close() { closes++; },
    }; },
    background: {
      monotonic: () => now, random: () => 0,
      pause: async (milliseconds) => { now += milliseconds; },
      schedule: () => { timers++; return () => { timers--; }; },
    },
    pause: async (milliseconds) => { assert.equal(milliseconds, 65_000); now += milliseconds; },
    report: (value) => reports.push(value),
  })(event);
  assert.deepEqual(reports.map((value) => [value.stage, value.outcome]), [["initial-read", "passed"], ["second-read", "passed"]]);
  assert.ok(calls > 2 && calls <= 17); assert.equal(clients, 1); assert.equal(closes, 1); assert.equal(timers, 0);
});

test("operation errors redact unknown codes and always close the client", async () => {
  const reports: DeployCheckReport[] = [];
  let closed = false;
  await createDeployCheck(config, { context: () => context, client: () => ({ async readRecords() { throw new AccessError("sensitive-secret-value"); }, close() { closed = true; } }), report: (value) => reports.push(value) })(event);
  assert.equal(closed, true); assert.equal(reports[0]?.code, "operation_failed");
  assert.doesNotMatch(JSON.stringify(reports), /sensitive-secret-value/);
});

test("second-read denial is reported without claiming successful renewal", async () => {
  const reports: DeployCheckReport[] = [];
  let reads = 0, closed = false;
  await createDeployCheck(config, { context: () => context, client: () => ({ async readRecords() { if (++reads === 2) throw new AccessError("access_denied", 403); return { records: [] }; }, close() { closed = true; } }), pause: async () => undefined, report: (value) => reports.push(value) })(event);
  assert.equal(closed, true); assert.equal(reports[1]?.stage, "second-read");
  assert.equal(reports[1]?.outcome, "failed"); assert.equal(reports[1]?.code, "access_denied");
});
