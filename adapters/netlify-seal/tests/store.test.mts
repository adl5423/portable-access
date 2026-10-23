import { test } from "node:test";
import assert from "node:assert/strict";
import { readStored } from "../src/store.mjs";
import { parseCanonical } from "../src/protocol.mjs";
function stream(parts: Uint8Array[], canceled?: () => void) { return new ReadableStream<Uint8Array>({ start(controller) { parts.forEach((part) => controller.enqueue(part)); controller.close(); }, cancel() { canceled?.(); } }); }
test("private store values are bounded and canonical through EOF", async () => {
  const signal = new AbortController().signal;
  assert.equal(await readStored(null, signal), null);
  assert.deepEqual(await readStored(stream([Buffer.from('{"v":'), Buffer.from('1}')]), signal), { v: 1 });
  for (const body of [Buffer.from('{ "v": 1 }'), Buffer.from('{"v":1,"v":1}'), Buffer.alloc(4097), Buffer.from([255])]) await assert.rejects(readStored(stream([body]), signal));
});
test("stuck private store stream is canceled at deadline", async () => {
  const controller = new AbortController(); let canceled = false;
  const body = new ReadableStream<Uint8Array>({ cancel() { canceled = true; } });
  const work = readStored(body, controller.signal); controller.abort(); await assert.rejects(work); assert.equal(canceled, true); assert.equal(body.locked, false);
});
test("deep or excessively branching JSON fails before recursive canonicalization", () => {
  assert.throws(() => parseCanonical(Buffer.from('['.repeat(1000) + '0' + ']'.repeat(1000))), /invalid_schema/);
  assert.throws(() => parseCanonical(Buffer.from(JSON.stringify(Array.from({ length: 65 }, () => 1)))), /invalid_schema/);
});
