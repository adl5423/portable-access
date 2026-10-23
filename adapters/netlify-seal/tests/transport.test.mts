import { test } from "node:test";
import assert from "node:assert/strict";
import { getEventListeners } from "node:events";
import { fetchProof, isPublicAddress, pinnedLookup, readProofResponse, resolvePublic, untilAbort, type ProofStream } from "../src/transport.mjs";
import type { IncomingHttpHeaders } from "node:http";

for (const address of ["0.0.0.0", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.169.254", "172.16.1.1", "192.0.0.9", "192.0.2.1", "192.168.1.1", "192.88.99.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "255.255.255.255", "::", "::1", "::ffff:127.0.0.1", "fe80::1", "fc00::1", "ff02::1", "2001:db8::1", "2001::1", "2002:7f00:1::", "3fff::1", "fe80::1%lo0", "not-an-ip", "127.1"]) test(`rejects nonpublic address ${address}`, () => assert.equal(isPublicAddress(address), false));
for (const address of ["1.1.1.1", "8.8.8.8", "104.21.1.1", "2606:4700:4700::1111", "2001:4860:4860::8888", "2a00:1450:4000::1"]) test(`accepts public unicast ${address}`, () => assert.equal(isPublicAddress(address), true));
test("DNS checks every returned address and rejects empty, excessive or malformed sets", async () => {
  for (const addresses of [[], [{ address: "1.1.1.1", family: 4 }, { address: "127.0.0.1", family: 4 }], [{ address: "1.1.1.1", family: 6 }], Array.from({ length: 17 }, () => ({ address: "1.1.1.1", family: 4 }))]) await assert.rejects(resolvePublic("registered.example", new AbortController().signal, async () => addresses));
});
test("checked address is pinned; callback never accepts caller-supplied URL", async () => {
  const bytes = await fetchProof("https://registered.example", "12345678-1234-1234-1234-123456789012", new AbortController().signal, {
    resolver: async (hostname) => { assert.equal(hostname, "registered.example"); return [{ address: "1.1.1.1", family: 4 }]; },
    transport: async (url, address) => { assert.equal(url.href, "https://registered.example/.well-known/pap/boot-proof/12345678-1234-1234-1234-123456789012"); assert.deepEqual(address, { address: "1.1.1.1", family: 4 }); return Buffer.from("{}"); },
  });
  assert.equal(bytes.toString(), "{}");
  const lookup = pinnedLookup({ address: "8.8.8.8", family: 4 });
  lookup("ignored.example", {}, (error, address, family) => { assert.equal(error, null); assert.equal(address, "8.8.8.8"); assert.equal(family, 4); });
  lookup("ignored.example", { all: true }, (error, address) => { assert.equal(error, null); assert.deepEqual(address, [{ address: "8.8.8.8", family: 4 }]); });
});
test("unsafe DNS never reaches transport; DNS failure does not leak provider error", async () => {
  let calls = 0;
  await assert.rejects(fetchProof("https://registered.example", "uuid", new AbortController().signal, { resolver: async () => [{ address: "169.254.169.254", family: 4 }], transport: async () => { calls++; return Buffer.from("{}"); } })); assert.equal(calls, 0);
  await assert.rejects(resolvePublic("registered.example", new AbortController().signal, async () => { throw new Error("private resolver state"); }), /temporarily_unavailable/);
});
class Stream implements ProofStream {
  destroyed = false;
  constructor(readonly chunks: Buffer[], readonly headers: IncomingHttpHeaders = { "content-type": "application/json" }, readonly statusCode = 200) {}
  destroy() { this.destroyed = true; }
  async *[Symbol.asyncIterator]() { for (const chunk of this.chunks) yield chunk; }
}
test("proof response validates headers and exact size through EOF", async () => {
  const good = new Stream([Buffer.from("{"), Buffer.from("}")], { "content-type": "application/json; charset=utf-8", "content-length": "2" });
  assert.equal((await readProofResponse(good, new AbortController().signal)).toString(), "{}"); assert.equal(good.destroyed, true);
  for (const response of [new Stream([Buffer.from("{}")], { "content-type": "application/json", location: "https://elsewhere.example" }, 302), new Stream([Buffer.from("{}")], { "content-type": "text/html" }), new Stream([Buffer.from("{}")], { "content-type": "application/json", "content-encoding": "gzip" }), new Stream([Buffer.from("{}")], { "content-type": "application/json", "content-length": "3" }), new Stream([Buffer.from("{}")], { "content-type": "application/json", "content-length": "4097" }), new Stream([Buffer.from("{}")], { "content-type": "application/json", "content-length": "-1" }), new Stream([]), new Stream([Buffer.alloc(4096), Buffer.alloc(1)])]) { await assert.rejects(readProofResponse(response, new AbortController().signal)); assert.equal(response.destroyed, true); }
});
test("abort stops DNS before any connection and removes its listener", async () => {
  const controller = new AbortController(); let connected = false; let finish: (addresses: Array<{ address: string; family: number }>) => void = () => undefined;
  const work = fetchProof("https://registered.example", "uuid", controller.signal, { resolver: async () => new Promise((resolve) => { finish = resolve; }), transport: async () => { connected = true; return Buffer.from("{}"); } });
  assert.equal(getEventListeners(controller.signal, "abort").length, 1); controller.abort(); await assert.rejects(work); assert.equal(getEventListeners(controller.signal, "abort").length, 0);
  finish([{ address: "1.1.1.1", family: 4 }]); await new Promise((resolve) => setImmediate(resolve)); assert.equal(connected, false);
});
test("successful and failed operations remove abort listeners", async () => {
  const controller = new AbortController(); assert.equal(await untilAbort(Promise.resolve(3), controller.signal), 3); assert.equal(getEventListeners(controller.signal, "abort").length, 0);
  await assert.rejects(untilAbort(Promise.reject(new Error("failed")), controller.signal)); assert.equal(getEventListeners(controller.signal, "abort").length, 0);
});
