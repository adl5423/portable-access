import { test } from "node:test";
import assert from "node:assert/strict";
import { getEventListeners } from "node:events";
import { BackgroundRecordsReader, type BackgroundReadClient, type BackgroundReadOptions } from "../src/background.mjs";
import { AccessError, type PublicConfig } from "../src/protocol.mjs";

const config: PublicConfig = {
  enabled: true, issuerURL: "https://issuer.security.example", siteID: "11111111-1111-4111-8111-111111111111",
  grantID: "grant-production", resourceOrigin: "https://secure-project.netlify.app", resourcePath: "/api/pap/records", resourceAction: "records.read",
  tenant: "tenant-a", environment: "production", audience: "pap-resource", productionSiteIsolated: true,
};
const context = { site: { id: config.siteID }, deploy: { context: "production", published: true } };
const records = { records: [{ id: "one", title: "record", updated_at: "2026-10-22T00:00:00Z" }] };

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

async function flush(): Promise<void> { for (let i = 0; i < 16; i++) await Promise.resolve(); }

class Clock {
  now = 0;
  next = 0;
  timers = new Map<number, { at: number; callback: () => void }>();
  delays: number[] = [];
  schedule = (callback: () => void, milliseconds: number): (() => void) => {
    const id = ++this.next;
    this.timers.set(id, { at: this.now + milliseconds, callback });
    return () => { this.timers.delete(id); };
  };
  pause = (milliseconds: number, signal: AbortSignal): Promise<void> => {
    this.delays.push(milliseconds);
    return new Promise((resolve, reject) => {
      if (signal.aborted) { reject(new AccessError("background_read_aborted", 503)); return; }
      const abort = () => { cancel(); signal.removeEventListener("abort", abort); reject(new AccessError("background_read_aborted", 503)); };
      const cancel = this.schedule(() => { signal.removeEventListener("abort", abort); resolve(); }, milliseconds);
      signal.addEventListener("abort", abort, { once: true });
    });
  };
  async advance(milliseconds: number): Promise<void> {
    const target = this.now + milliseconds;
    let turns = 0;
    while (true) {
      const entry = [...this.timers].sort((a, b) => a[1].at - b[1].at)[0];
      if (!entry || entry[1].at > target) break;
      if (++turns > 1000) throw new Error("timer loop did not terminate");
      this.now = entry[1].at;
      this.timers.delete(entry[0]);
      entry[1].callback();
      await flush();
    }
    this.now = target;
    await flush();
  }
}

function fixture(read: BackgroundReadClient["readRecords"], options: BackgroundReadOptions = {}) {
  const clock = new Clock();
  let calls = 0, closes = 0, clients = 0;
  const reader = new BackgroundRecordsReader(config, {
    monotonic: () => clock.now, random: () => 0, pause: clock.pause, schedule: clock.schedule,
    ...options,
    client: () => { clients++; return { readRecords: async (ctx) => { calls++; assert.deepEqual(ctx, context); return read(ctx); }, close() { closes++; } }; },
  });
  return { reader, clock, get calls() { return calls; }, get closes() { return closes; }, get clients() { return clients; } };
}

test("healthy background reads reuse one owned client without retry pauses or surviving timers", async () => {
  const f = fixture(async () => records);
  const signal = new AbortController().signal;
  assert.deepEqual(await f.reader.readRecords(context, { signal }), records);
  assert.deepEqual(await f.reader.readRecords(context, { signal }), records);
  assert.equal(f.clients, 1); assert.equal(f.calls, 2); assert.equal(f.closes, 0);
  assert.deepEqual(f.clock.delays, []); assert.equal(f.clock.timers.size, 0);
  assert.equal(getEventListeners(signal, "abort").length, 0);
  f.reader.close(); f.reader.close(); assert.equal(f.closes, 1);
});

test("fast availability503 responses still allow recovery after129seconds at minimum jitter", { timeout: 1000 }, async () => {
  let f: ReturnType<typeof fixture>;
  let successAt = -1;
  f = fixture(async () => {
    if (f.clock.now < 129_000) throw new AccessError(f.calls % 2 ? "issuer_unavailable" : "resource_unavailable", 503);
    successAt = f.clock.now; return records;
  });
  const reading = f.reader.readRecords(context);
  await flush();
  await f.clock.advance(129_000);
  assert.deepEqual(await reading, records);
  assert.ok(successAt >= 129_000 && successAt < 180_000);
  assert.ok(f.calls > 1 && f.calls <= 16);
  assert.ok(f.clock.delays.every((delay) => delay > 0 && delay <= 15_000));
  assert.equal(f.clock.timers.size, 0); assert.equal(f.closes, 0);
  f.reader.close();
});

test("fast503 failures do not exhaust attempts before a270second recovery at minimum jitter", { timeout: 1000 }, async () => {
  let f: ReturnType<typeof fixture>;
  let successAt = -1;
  f = fixture(async () => {
    if (f.clock.now < 270_000) throw new AccessError("issuer_unavailable", 503);
    successAt = f.clock.now;
    return records;
  });
  const reading = f.reader.readRecords(context);
  await flush();
  await f.clock.advance(285_000);
  assert.deepEqual(await reading, records);
  assert.ok(successAt >= 270_000 && successAt < 300_000);
  assert.ok(f.calls > 16 && f.calls <= 24);
  assert.equal(f.closes, 0);
  assert.equal(f.clock.timers.size, 0);
  f.reader.close();
});

test("successive reads share one client but receive independent absolute budgets", async () => {
  const first = deferred<unknown>(), second = deferred<unknown>();
  let read = 0;
  const f = fixture(() => ++read === 1 ? first.promise : second.promise, { budgetMs: 100 });
  const one = f.reader.readRecords(context);
  await f.clock.advance(99); first.resolve(records); assert.deepEqual(await one, records);
  const two = f.reader.readRecords(context);
  await f.clock.advance(99); second.resolve(records); assert.deepEqual(await two, records);
  assert.equal(f.clock.now, 198); assert.equal(f.clients, 1); assert.equal(f.calls, 2);
  assert.equal(f.closes, 0); assert.equal(f.clock.timers.size, 0); f.reader.close();
});

test("denials, policy errors, client closure and non503 errors never retry or change their identity", async () => {
  const errors = [
    new AccessError("access_denied", 401), new AccessError("access_denied", 403), new AccessError("access_denied", 503),
    new AccessError("issuer_unavailable", 401), new AccessError("issuer_unavailable", 403),
    new AccessError("resource_unavailable", 502), new AccessError("client_closed", 503),
    new AccessError("untrusted_deployment", 403), new Error("private upstream details"),
  ];
  for (const error of errors) {
    const f = fixture(async () => { throw error; });
    await assert.rejects(f.reader.readRecords(context), (actual) => actual === error);
    assert.equal(f.calls, 1); assert.equal(f.closes, 1); assert.equal(f.clock.delays.length, 0); assert.equal(f.clock.timers.size, 0);
  }
});

test("an unresolved read is bounded by the absolute deadline and its late success cannot reopen the reader", async () => {
  const pending = deferred<unknown>();
  const f = fixture(() => pending.promise, { budgetMs: 100 });
  const failure = assert.rejects(f.reader.readRecords(context), { code: "background_read_deadline" });
  await f.clock.advance(100); await failure;
  assert.equal(f.closes, 1); assert.equal(f.clock.timers.size, 0);
  pending.resolve(records); await flush();
  await assert.rejects(f.reader.readRecords(context), { code: "client_closed" });
  assert.equal(f.calls, 1); assert.equal(f.clock.timers.size, 0);
});

test("late rejection after deadline is observed without another attempt or unhandled rejection", async () => {
  const pending = deferred<unknown>();
  const unhandled: unknown[] = [];
  const listener = (error: unknown) => { unhandled.push(error); };
  process.on("unhandledRejection", listener);
  try {
    const f = fixture(() => pending.promise, { budgetMs: 100 });
    const failure = assert.rejects(f.reader.readRecords(context), { code: "background_read_deadline" });
    await f.clock.advance(100); await failure;
    pending.reject(new AccessError("issuer_unavailable", 503)); await flush();
    assert.equal(f.calls, 1); assert.equal(f.closes, 1); assert.equal(f.clock.timers.size, 0); assert.deepEqual(unhandled, []);
  } finally { process.removeListener("unhandledRejection", listener); }
});

test("the deadline includes unfinished SDK proof cleanup after the underlying operation succeeded", async () => {
  const cleanup = deferred<void>();
  let operationSucceeded = false, cleanupFinished = false;
  const f = fixture(async () => { operationSucceeded = true; await cleanup.promise; cleanupFinished = true; return records; }, { budgetMs: 100 });
  const failure = assert.rejects(f.reader.readRecords(context), { code: "background_read_deadline" });
  await flush(); assert.equal(operationSucceeded, true); assert.equal(cleanupFinished, false);
  await f.clock.advance(100); await failure;
  assert.equal(f.closes, 1); assert.equal(cleanupFinished, false);
  cleanup.resolve(); await flush(); assert.equal(cleanupFinished, true);
  assert.equal(f.calls, 1); assert.equal(f.clock.timers.size, 0);
});

test("a result at the deadline is rejected even when the timer callback has been delayed", async () => {
  const pending = deferred<unknown>();
  const f = fixture(() => pending.promise, { budgetMs: 100 });
  const failure = assert.rejects(f.reader.readRecords(context), { code: "background_read_deadline" });
  f.clock.now = 100; pending.resolve(records); await failure;
  assert.equal(f.closes, 1); assert.equal(f.clock.timers.size, 0);
});

test("setup time is deducted from the deadline timer for an unresolved operation", async () => {
  const pending = deferred<unknown>();
  const clock = new Clock(); let readings = 0, scheduled = -1;
  const f = fixture(() => pending.promise, {
    budgetMs: 100, monotonic: () => readings++ === 0 ? 0 : 25,
    schedule(callback, milliseconds) { scheduled = milliseconds; return clock.schedule(callback, milliseconds); },
  });
  const failure = assert.rejects(f.reader.readRecords(context), { code: "background_read_deadline" });
  assert.equal(scheduled, 75);
  await clock.advance(75); await failure;
  assert.equal(f.closes, 1); assert.equal(clock.timers.size, 0);
  pending.resolve(records); await flush();
});

test("a pre-aborted job performs no read and leaves no timer or abort listener", async () => {
  const abort = new AbortController(); abort.abort();
  const f = fixture(async () => records);
  await assert.rejects(f.reader.readRecords(context, { signal: abort.signal }), { code: "background_read_aborted" });
  assert.equal(f.calls, 0); assert.equal(f.closes, 1); assert.equal(f.clock.timers.size, 0);
  assert.equal(getEventListeners(abort.signal, "abort").length, 0);
});

test("abort during an in-flight read closes the owned client and discards a late success", async () => {
  const abort = new AbortController(); const pending = deferred<unknown>();
  const f = fixture(() => pending.promise);
  const failure = assert.rejects(f.reader.readRecords(context, { signal: abort.signal }), { code: "background_read_aborted" });
  abort.abort(); await failure;
  pending.resolve(records); await flush();
  assert.equal(f.calls, 1); assert.equal(f.closes, 1); assert.equal(f.clock.timers.size, 0);
  assert.equal(getEventListeners(abort.signal, "abort").length, 0);
});

test("abort during retry backoff clears deadline and pause timers and cannot start another attempt", async () => {
  const abort = new AbortController();
  const f = fixture(async () => { throw new AccessError("issuer_unavailable", 503); });
  const failure = assert.rejects(f.reader.readRecords(context, { signal: abort.signal }), { code: "background_read_aborted" });
  await flush(); assert.equal(f.clock.timers.size, 2);
  abort.abort(); await failure; await f.clock.advance(180_000);
  assert.equal(f.calls, 1); assert.equal(f.closes, 1); assert.equal(f.clock.timers.size, 0);
});

test("explicit close during a read is terminal and releases timers without waiting for the request", async () => {
  const pending = deferred<unknown>(); const f = fixture(() => pending.promise);
  const failure = assert.rejects(f.reader.readRecords(context), { code: "client_closed" });
  f.reader.close(); await failure;
  assert.equal(f.closes, 1); assert.equal(f.clock.timers.size, 0);
  pending.resolve(records); await flush();
});

test("explicit close during retry backoff clears all timers and retains client_closed", async () => {
  const f = fixture(async () => { throw new AccessError("resource_unavailable", 503); });
  const failure = assert.rejects(f.reader.readRecords(context), { code: "client_closed" });
  await flush(); assert.equal(f.clock.timers.size, 2);
  f.reader.close(); await failure; await f.clock.advance(180_000);
  assert.equal(f.calls, 1); assert.equal(f.closes, 1); assert.equal(f.clock.timers.size, 0);
});

test("a competing read is rejected without interrupting or closing the accepted read", async () => {
  const pending = deferred<unknown>(); const f = fixture(() => pending.promise);
  const accepted = f.reader.readRecords(context);
  await assert.rejects(f.reader.readRecords(context), { code: "background_read_busy" });
  assert.equal(f.closes, 0); assert.equal(f.calls, 1);
  pending.resolve(records); assert.deepEqual(await accepted, records);
  assert.equal(f.clock.timers.size, 0); assert.equal(f.closes, 0); f.reader.close();
});

test("attempt exhaustion retains the availability error and closes the reader at the configured limit", async () => {
  const error = new AccessError("resource_unavailable", 503);
  const f = fixture(async () => { throw error; }, { attemptLimit: 3 });
  const failure = assert.rejects(f.reader.readRecords(context), (actual) => actual === error);
  await flush(); await f.clock.advance(30_000); await failure;
  assert.equal(f.calls, 3); assert.equal(f.closes, 1); assert.equal(f.clock.timers.size, 0);
});

test("background bounds cannot exceed300seconds or24attempts and invalid bounds create no client", () => {
  let clients = 0;
  for (const limits of [{ budgetMs: 300_001 }, { budgetMs: 0 }, { attemptLimit: 25 }, { attemptLimit: 0 }, { budgetMs: Number.NaN }]) {
    assert.throws(() => new BackgroundRecordsReader(config, { ...limits, client: () => { clients++; throw new Error("must not construct"); } }), { code: "background_read_options_invalid" });
  }
  assert.equal(clients, 0);
});

test("a throwing clock seam fails closed during setup and cannot leave the reader busy", async () => {
  const error = new Error("clock failed");
  const f = fixture(async () => records, { monotonic: () => { throw error; } });
  await assert.rejects(f.reader.readRecords(context), (actual) => actual === error);
  await assert.rejects(f.reader.readRecords(context), { code: "client_closed" });
  assert.equal(f.calls, 0); assert.equal(f.closes, 1); assert.equal(f.clock.timers.size, 0);
});

test("malformed record data is a terminal schema error rather than a retryable outage", async () => {
  const f = fixture(async () => ({ records: [], access_token: "must not escape" }));
  await assert.rejects(f.reader.readRecords(context), { code: "invalid_records_response" });
  assert.equal(f.calls, 1); assert.equal(f.closes, 1); assert.equal(f.clock.delays.length, 0); assert.equal(f.clock.timers.size, 0);
});
