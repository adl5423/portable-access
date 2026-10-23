import "./server-only.mjs";
import {
  AccessError, RECORDS_ACTION, assertPlatform, boundedJSON,
  freshIdentity, jsonRequest, makeProof, parseChallenge, parseCredential,
  validateConfig, type CredentialResponse, type Fetcher, type PlatformContext, type PublicConfig, type PublicJWK,
} from "./protocol.mjs";
import { platformProofStore, type ProofStore } from "./proof-store.mjs";

interface PrivateCredential {
  key: CryptoKey;
  jwk: PublicJWK;
  response: CredentialResponse;
}

export interface RecordItem { id: string; title: string; updated_at: string }

export function parseRecords(value: unknown): { records: RecordItem[] } {
  if (typeof value !== "object" || value === null || Array.isArray(value) || Object.keys(value).length !== 1 || !("records" in value) || !Array.isArray(value.records) || value.records.length > 100) {
    throw new AccessError("invalid_records_response", 502);
  }
  const records = value.records.map((record: unknown): RecordItem => {
    if (typeof record !== "object" || record === null || Array.isArray(record) || Object.keys(record).sort().join(",") !== "id,title,updated_at") throw new AccessError("invalid_records_response", 502);
    const item = record as Record<string, unknown>;
    if (typeof item.id !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(item.id) || typeof item.title !== "string" || item.title.length > 500 || typeof item.updated_at !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(item.updated_at) || !Number.isFinite(Date.parse(item.updated_at))) throw new AccessError("invalid_records_response", 502);
    return { id: item.id, title: item.title, updated_at: item.updated_at };
  });
  return { records };
}

export interface ClientOptions {
  /** Test seam. Production callers should use Netlify's platform-backed store. */
  store?: ProofStore;
  fetcher?: Fetcher;
  now?: () => number;
  monotonic?: () => number;
  pause?: (milliseconds: number) => Promise<void>;
}

/** Server-only SDK. It exposes allowed operations, never tokens or signing keys. */
export class PortableAccessClient {
  readonly #config: PublicConfig;
  readonly #options: ClientOptions;
  #credential: PrivateCredential | undefined;
  #renewing: Promise<PrivateCredential> | undefined;
  #closed = false;
  readonly #closedSignal = new AbortController();

  constructor(publicConfig: unknown, options: ClientOptions = {}) {
    this.#config = validateConfig(publicConfig);
    this.#options = options;
  }

  #now(): number { return this.#options.now?.() ?? Date.now() / 1000; }
  #fetcher: Fetcher = (url, init) => (this.#options.fetcher ?? fetch)(url, init);

  #requireOpen(): void {
    if (this.#closed) throw new AccessError("client_closed", 503);
  }

  async #waitForIssuer(): Promise<void> {
    const monotonic = this.#options.monotonic ?? (() => performance.now());
    const deadline = monotonic() + 20_000;
    for (let attempt = 0; attempt < 8; attempt++) {
      this.#requireOpen();
      const timeout = Math.min(8000, Math.floor(deadline - monotonic()));
      if (timeout < 1) break;
      try {
        const response = await this.#fetcher(`${this.#config.issuerURL}/health`, {
          method: "GET", redirect: "error", cache: "no-store",
          signal: AbortSignal.any([AbortSignal.timeout(timeout), this.#closedSignal.signal]),
          headers: { Accept: "application/json" },
        });
        this.#requireOpen();
        if (response.status === 401 || response.status === 403) {
          await response.body?.cancel();
          throw new AccessError("access_denied", response.status);
        }
        if (response.ok) {
          const value = await boundedJSON(response);
          this.#requireOpen();
          if (monotonic() < deadline && typeof value === "object" && value !== null && !Array.isArray(value) && Object.keys(value).length === 1 && "ready" in value && value.ready === true) return;
        } else {
          await response.body?.cancel();
        }
      } catch (error) {
        this.#requireOpen();
        if (error instanceof AccessError && error.code === "access_denied") throw error;
      }
      if (attempt === 7) break;
      const remaining = deadline - monotonic();
      if (remaining < 250) break;
      const delay = Math.min(remaining, 2000, Math.max(250, 250 * 2 ** attempt * (0.8 + Math.random() * 0.4)));
      if (this.#options.pause) {
        await this.#options.pause(delay);
      } else {
        await new Promise<void>((resolve, reject) => {
          const abort = () => { clearTimeout(timer); reject(new AccessError("client_closed", 503)); };
          const timer = setTimeout(() => { this.#closedSignal.signal.removeEventListener("abort", abort); resolve(); }, delay);
          this.#closedSignal.signal.addEventListener("abort", abort, { once: true });
          if (this.#closed) abort();
        });
      }
    }
    this.#requireOpen();
    throw new AccessError("issuer_unavailable", 503);
  }

  async #renewWithRecovery(): Promise<PrivateCredential> {
    try { return await this.#renew(); } catch (error) {
      this.#requireOpen();
      if (!(error instanceof AccessError) || error.code !== "issuer_unavailable") throw error;
      await this.#waitForIssuer();
      this.#requireOpen();
      // A fresh key/challenge/proof is mandatory after an uncertain POST result.
      return this.#renew();
    }
  }

  async #renew(): Promise<PrivateCredential> {
    this.#requireOpen();
    const identity = await freshIdentity();
    this.#requireOpen();
    const challenge = parseChallenge(await jsonRequest(this.#fetcher, `${this.#config.issuerURL}/v1/site/challenge`, { grant_id: this.#config.grantID, jwk: identity.jwk }), this.#config, identity.jkt, this.#now());
    this.#requireOpen();
    const store = this.#options.store ?? platformProofStore();
    let published = false;
    try {
      // Only a locally generated key can be published. No browser-controlled JWK input exists.
      await store.publish(challenge);
      published = true;
      this.#requireOpen();
      const target = `${this.#config.issuerURL}/v1/site/token`;
      const proof = await makeProof(identity.key, identity.jwk, "POST", target, challenge.nonce, undefined, this.#now());
      this.#requireOpen();
      const response = parseCredential(await jsonRequest(this.#fetcher, target, { challenge_id: challenge.challenge_id, jwk: identity.jwk }, { DPoP: proof }), this.#config, this.#now());
      if (this.#closed) throw new AccessError("client_closed", 503);
      const credential = { key: identity.key, jwk: identity.jwk, response };
      this.#credential = credential;
      return credential;
    } finally {
      // This is public expiring data. Cleanup failure cannot authorize access or mask an issuance error.
      if (published) await store.remove(challenge.challenge_id).catch(() => undefined);
    }
  }

  async #activeCredential(force = false): Promise<PrivateCredential> {
    this.#requireOpen();
    if (!force && this.#credential && this.#credential.response.expires_at - this.#now() > 10) return this.#credential;
    if (!this.#renewing) {
      this.#renewing = this.#renewWithRecovery().finally(() => { this.#renewing = undefined; });
    }
    return this.#renewing;
  }

  async getJSON(context: PlatformContext): Promise<unknown> {
    if (this.#closed) throw new AccessError("client_closed", 503);
    assertPlatform(this.#config, context);
    const url = `${this.#config.resourceOrigin}${this.#config.resourcePath}`;
    let renewed = false;
    let attempts = 0;
    while (true) {
      const credential = await this.#activeCredential();
      if (this.#closed) throw new AccessError("client_closed", 503);
      const proof = await makeProof(credential.key, credential.jwk, "GET", url, credential.response.dpop_nonce, credential.response.access_token, this.#now());
      this.#requireOpen();
      let response: Response;
      try {
        response = await this.#fetcher(url, {
          method: "GET", redirect: "error", cache: "no-store", signal: AbortSignal.any([AbortSignal.timeout(30_000), this.#closedSignal.signal]),
          headers: { Authorization: `DPoP ${credential.response.access_token}`, DPoP: proof, Accept: "application/json" },
        });
      } catch {
        if (++attempts >= 2) throw new AccessError("resource_unavailable", 503);
        await this.#pause();
        continue;
      }
      if (response.status === 401 && !renewed) {
        await response.body?.cancel();
        this.#credential = undefined;
        await this.#activeCredential(true);
        renewed = true;
        continue;
      }
      if (response.status === 429 || response.status >= 500) {
        await response.body?.cancel();
        if (++attempts >= 2) throw new AccessError("resource_unavailable", 503);
        await this.#pause();
        continue;
      }
      if (!response.ok) {
        await response.body?.cancel();
        throw new AccessError("access_denied", response.status === 403 ? 403 : 401);
      }
      return boundedJSON(response);
    }
  }

  async readRecords(context: PlatformContext): Promise<{ records: RecordItem[] }> {
    return parseRecords(await this.getJSON(context));
  }

  async #pause(): Promise<void> {
    const delay = 50 + Math.floor(Math.random() * 100);
    await (this.#options.pause?.(delay) ?? new Promise((resolve) => setTimeout(resolve, delay)));
  }

  /** Stop future operations and discard cached authority. Already sent requests may finish. */
  close(): void { this.#closed = true; this.#closedSignal.abort(); this.#credential = undefined; }
}

export { AccessError, RECORDS_ACTION };
