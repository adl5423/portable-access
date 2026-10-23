import "./server-only.mjs";
import { PortableAccessClient, parseRecords, type RecordItem } from "./client.mjs";
import { AccessError, assertPlatform, validateConfig, type PlatformContext, type PublicConfig } from "./protocol.mjs";

export interface BackgroundReadClient {
  readRecords(context: PlatformContext): Promise<unknown>;
  close(): void;
}

export interface BackgroundReadOptions {
  /** Bounds may be reduced by a caller; they cannot exceed this profile's limits. */
  budgetMs?: number;
  attemptLimit?: number;
  /** Test seams. Production jobs should use the platform-backed client and defaults. */
  client?: (config: PublicConfig) => BackgroundReadClient;
  monotonic?: () => number;
  random?: () => number;
  pause?: (milliseconds: number, signal: AbortSignal) => Promise<void>;
  schedule?: (callback: () => void, milliseconds: number) => () => void;
}

function pause(milliseconds: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) { reject(new AccessError("background_read_aborted", 503)); return; }
    const abort = () => {
      clearTimeout(timer);
      signal.removeEventListener("abort", abort);
      reject(new AccessError("background_read_aborted", 503));
    };
    const timer = setTimeout(() => { signal.removeEventListener("abort", abort); resolve(); }, milliseconds);
    signal.addEventListener("abort", abort, { once: true });
  });
}

function schedule(callback: () => void, milliseconds: number): () => void {
  const timer = setTimeout(callback, milliseconds);
  return () => clearTimeout(timer);
}

/** A sequential background job owning one SDK client and only its configured records GET. */
export class BackgroundRecordsReader {
  readonly #config: PublicConfig;
  readonly #client: BackgroundReadClient;
  readonly #options: BackgroundReadOptions;
  readonly #closedSignal = new AbortController();
  readonly #budget: number;
  readonly #attemptLimit: number;
  #closed = false;
  #busy = false;

  constructor(publicConfig: unknown, options: BackgroundReadOptions = {}) {
    this.#config = validateConfig(publicConfig);
    this.#budget = options.budgetMs ?? 300_000;
    this.#attemptLimit = options.attemptLimit ?? 24;
    if (!Number.isInteger(this.#budget) || this.#budget < 1 || this.#budget > 300_000 || !Number.isInteger(this.#attemptLimit) || this.#attemptLimit < 1 || this.#attemptLimit > 24) {
      throw new AccessError("background_read_options_invalid", 503);
    }
    this.#options = options;
    this.#client = options.client?.(this.#config) ?? new PortableAccessClient(this.#config);
  }

  #now(): number { return this.#options.monotonic?.() ?? performance.now(); }

  #requireOpen(): void {
    if (this.#closed) throw new AccessError("client_closed", 503);
  }

  async readRecords(context: PlatformContext, options: { signal?: AbortSignal } = {}): Promise<{ records: RecordItem[] }> {
    // Reject a competing caller without closing or interrupting the accepted read.
    if (this.#busy) throw new AccessError("background_read_busy", 503);
    this.#requireOpen();
    try { assertPlatform(this.#config, context); } catch (error) { this.close(); throw error; }
    this.#busy = true;
    const run = new AbortController();
    let started = Number.NaN;
    let deadline = Number.NaN;
    let reason: AccessError | undefined;
    let rejectStop!: (error: AccessError) => void;
    let cancelDeadline = () => {};
    const stopped = new Promise<never>((_resolve, reject) => { rejectStop = reject; });
    // A synchronous abort/clock failure can happen before the work promise exists.
    void stopped.catch(() => undefined);
    const stop = (error: AccessError) => {
      if (reason) return;
      reason = error;
      run.abort();
      rejectStop(error);
      this.close();
    };
    const onClose = () => stop(new AccessError("client_closed", 503));
    const onAbort = () => stop(new AccessError("background_read_aborted", 503));
    const check = () => {
      if (reason) throw reason;
      this.#requireOpen();
      if (options.signal?.aborted) throw new AccessError("background_read_aborted", 503);
      const now = this.#now();
      if (!Number.isFinite(started) || !Number.isFinite(now) || now < started) throw new AccessError("background_read_clock_invalid", 503);
      if (now >= deadline) throw new AccessError("background_read_deadline", 503);
    };
    this.#closedSignal.signal.addEventListener("abort", onClose, { once: true });
    options.signal?.addEventListener("abort", onAbort, { once: true });
    try {
      started = this.#now();
      deadline = started + this.#budget;
      if (options.signal?.aborted) onAbort();
      check();
      cancelDeadline = (this.#options.schedule ?? schedule)(() => stop(new AccessError("background_read_deadline", 503)), Math.max(0, deadline - this.#now()));
      check();
      const work = async (): Promise<{ records: RecordItem[] }> => {
        for (let attempt = 1; attempt <= this.#attemptLimit; attempt++) {
          check();
          try {
            // Awaiting the SDK promise includes its proof-record cleanup.
            const value = await this.#client.readRecords(context);
            check();
            const records = parseRecords(value);
            check();
            return records;
          } catch (error) {
            check();
            if (!(error instanceof AccessError) || error.status !== 503 || !["issuer_unavailable", "resource_unavailable"].includes(error.code) || attempt === this.#attemptLimit) throw error;
          }
          const random = this.#options.random?.() ?? Math.random();
          if (!Number.isFinite(random) || random < 0 || random > 1) throw new AccessError("background_read_random_invalid", 503);
          const remaining = deadline - this.#now();
          const delay = Math.min(remaining, 15_000, 2000 * 2 ** (attempt - 1) * (0.8 + random * 0.4));
          check();
          await (this.#options.pause ?? pause)(delay, run.signal);
          check();
        }
        throw new AccessError("background_read_attempts_exhausted", 503);
      };
      // The losing work promise stays observed; sent requests may finish, but their
      // outcomes cannot escape or start another attempt after this job terminates.
      const records = await Promise.race([work(), stopped]);
      check();
      return records;
    } catch (error) {
      const failure = reason ?? error;
      this.close();
      throw failure;
    } finally {
      cancelDeadline();
      this.#closedSignal.signal.removeEventListener("abort", onClose);
      options.signal?.removeEventListener("abort", onAbort);
      run.abort();
      this.#busy = false;
    }
  }

  /** End the job. Already sent requests may settle, but future reads are rejected. */
  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#closedSignal.abort();
    try { this.#client.close(); } catch { /* Cleanup cannot replace the job's result. */ }
  }
}
