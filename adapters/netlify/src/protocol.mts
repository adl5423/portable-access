import "./server-only.mjs";
import { webcrypto } from "node:crypto";

const subtle = webcrypto.subtle;
export const RECORDS_PATH = "/api/pap/records";
export const RECORDS_ACTION = "records.read";
export const PROOF_PATH = "/.well-known/pap/site-proof/";
export const PROOF_STORE = "pap-site-proofs-v1";
export const MAX_JSON_BYTES = 16_384;

export interface PublicConfig {
  enabled: boolean;
  issuerURL: string;
  siteID: string;
  grantID: string;
  resourceOrigin: string;
  resourcePath: string;
  resourceAction: string;
  tenant: string;
  environment: string;
  audience: string;
  productionSiteIsolated: boolean;
}

export interface PlatformContext {
  site: { id?: string };
  deploy: { context?: string; published?: boolean };
}

export interface PublicJWK {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
}

export interface Challenge {
  challenge_id: string;
  nonce: string;
  jkt: string;
  issuer: string;
  site_id: string;
  expires_at: number;
}

export interface CredentialResponse {
  access_token: string;
  token_type: "DPoP";
  expires_at: number;
  expires_in: number;
  dpop_nonce: string;
  tenant: string;
  environment: string;
}

export interface Authorization {
  subject: string;
  tenant: string;
  environment: string;
  grant_id: string;
  action: string;
  expires_at: number;
}

export class AccessError extends Error {
  constructor(readonly code: string, readonly status = 401) {
    super(code);
    this.name = "AccessError";
  }
}

export type Fetcher = (input: string, init?: RequestInit) => Promise<Response>;
export const noCache = {
  "Cache-Control": "no-store, private, max-age=0",
  "Netlify-CDN-Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
};

export function strictObject(value: unknown, keys: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new AccessError("invalid_schema", 502);
  }
  const actual = Object.keys(value);
  if (keys.some((key) => !actual.includes(key)) || actual.some((key) => !keys.includes(key) && !optional.includes(key))) {
    throw new AccessError("invalid_schema", 502);
  }
  return value as Record<string, unknown>;
}

export function textValue(value: unknown, min = 1, max = 128): string {
  if (typeof value !== "string" || value.length < min || value.length > max || /[\x00-\x20\x7f]/.test(value)) {
    throw new AccessError("invalid_schema", 502);
  }
  return value;
}

export function identifier(value: unknown): string {
  const result = textValue(value);
  if (!/^[A-Za-z0-9_-]+$/.test(result)) throw new AccessError("invalid_identifier", 502);
  return result;
}

export function policyIdentifier(value: unknown): string {
  const result = textValue(value, 1, 80);
  if (!/^[A-Za-z0-9][A-Za-z0-9_-]*$/.test(result)) throw new AccessError("invalid_identifier", 502);
  return result;
}

export function httpsOrigin(value: unknown, netlify = false): string {
  const raw = textValue(value, 1, 256);
  let url: URL;
  try { url = new URL(raw); } catch { throw new AccessError("invalid_origin", 503); }
  if (url.protocol !== "https:" || url.username || url.password || url.port || url.search || url.hash || url.pathname !== "/") {
    throw new AccessError("invalid_origin", 503);
  }
  if (raw !== url.origin && raw !== `${url.origin}/`) throw new AccessError("invalid_origin", 503);
  if (url.hostname === "localhost" || url.hostname.endsWith(".localhost") || !url.hostname.includes(".") || /^[\d.]+$/.test(url.hostname) || url.hostname.includes(":")) {
    throw new AccessError("invalid_origin", 503);
  }
  if (netlify && (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.netlify\.app$/.test(url.hostname) || url.hostname.includes("--"))) {
    throw new AccessError("canonical_netlify_origin_required", 503);
  }
  return url.origin;
}

export function validateConfig(input: unknown): PublicConfig {
  const value = strictObject(input, ["enabled", "issuerURL", "siteID", "grantID", "resourceOrigin", "tenant", "environment", "audience", "productionSiteIsolated"], ["resourcePath", "resourceAction"]);
  if (value.enabled !== true || value.productionSiteIsolated !== true) throw new AccessError("adapter_not_configured", 503);
  const siteID = textValue(value.siteID);
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(siteID)) throw new AccessError("invalid_site_id", 503);
  if (value.environment !== "production") throw new AccessError("production_required", 503);
  const resourcePath = textValue(value.resourcePath ?? RECORDS_PATH, 1, 256);
  const resourceAction = textValue(value.resourceAction ?? RECORDS_ACTION, 1, 64);
  if (!/^\/(?:[A-Za-z0-9_-]+\/)*[A-Za-z0-9_-]+$/.test(resourcePath)) throw new AccessError("invalid_resource_path", 503);
  if (!/^[a-z][a-z0-9._-]*$/.test(resourceAction)) throw new AccessError("invalid_resource_action", 503);
  return Object.freeze({
    enabled: true,
    issuerURL: httpsOrigin(value.issuerURL),
    siteID,
    grantID: policyIdentifier(value.grantID),
    resourceOrigin: httpsOrigin(value.resourceOrigin, true),
    resourcePath,
    resourceAction,
    tenant: policyIdentifier(value.tenant),
    environment: "production",
    audience: textValue(value.audience, 1, 200),
    productionSiteIsolated: true,
  });
}

export function assertPlatform(config: PublicConfig, context: PlatformContext): void {
  if (!context || context.site?.id !== config.siteID || context.deploy?.context !== "production" || context.deploy.published !== true) {
    throw new AccessError("untrusted_deployment", 403);
  }
}

export function numeric(value: unknown): number {
  if (typeof value !== "number" || !Number.isFinite(value)) throw new AccessError("invalid_schema", 502);
  return value;
}

export function parseChallenge(input: unknown, config: PublicConfig, expectedJKT?: string, now = Date.now() / 1000): Challenge {
  const value = strictObject(input, ["challenge_id", "nonce", "jkt", "issuer", "site_id", "expires_at"]);
  const result: Challenge = {
    challenge_id: identifier(value.challenge_id),
    nonce: textValue(value.nonce, 16, 128),
    jkt: textValue(value.jkt, 43, 43),
    issuer: textValue(value.issuer, 1, 256),
    site_id: textValue(value.site_id),
    expires_at: numeric(value.expires_at),
  };
  if (!/^[A-Za-z0-9_-]{43}$/.test(result.jkt) || result.issuer !== config.issuerURL || result.site_id !== config.siteID || (expectedJKT !== undefined && result.jkt !== expectedJKT)) {
    throw new AccessError("challenge_binding_mismatch", 502);
  }
  if (result.expires_at <= now || result.expires_at > now + 120) throw new AccessError("challenge_expired", 401);
  return Object.freeze(result);
}

export function parseCredential(input: unknown, config: PublicConfig, now = Date.now() / 1000): CredentialResponse {
  const value = strictObject(input, ["access_token", "token_type", "expires_at", "expires_in", "dpop_nonce", "tenant", "environment"]);
  const result: CredentialResponse = {
    access_token: textValue(value.access_token, 16, 4096),
    token_type: "DPoP",
    expires_at: numeric(value.expires_at),
    expires_in: numeric(value.expires_in),
    dpop_nonce: textValue(value.dpop_nonce, 16, 128),
    tenant: textValue(value.tenant),
    environment: textValue(value.environment),
  };
  if (value.token_type !== "DPoP" || result.tenant !== config.tenant || result.environment !== config.environment || result.expires_at <= now || result.expires_at > now + 3600 || result.expires_in <= 0 || result.expires_in > 3600 || Math.abs(result.expires_at - now - result.expires_in) > 10) {
    throw new AccessError("invalid_credential_response", 502);
  }
  return Object.freeze(result);
}

export function parseAuthorization(input: unknown, config: PublicConfig, now = Date.now() / 1000): Authorization {
  const value = strictObject(input, ["subject", "tenant", "environment", "grant_id", "action", "expires_at"]);
  const result: Authorization = {
    subject: policyIdentifier(value.subject),
    tenant: policyIdentifier(value.tenant),
    environment: textValue(value.environment),
    grant_id: policyIdentifier(value.grant_id),
    action: textValue(value.action),
    expires_at: numeric(value.expires_at),
  };
  if (result.tenant !== config.tenant || result.environment !== config.environment || result.grant_id !== config.grantID || result.action !== config.resourceAction || result.expires_at <= now || result.expires_at > now + 3600) {
    throw new AccessError("authorization_binding_mismatch", 403);
  }
  return Object.freeze(result);
}

export function b64url(value: Uint8Array): string { return Buffer.from(value).toString("base64url"); }

export async function sha256(value: string): Promise<string> {
  return b64url(new Uint8Array(await subtle.digest("SHA-256", new TextEncoder().encode(value))));
}

export async function freshIdentity(): Promise<{ key: CryptoKey; jwk: PublicJWK; jkt: string }> {
  // The private key is non-extractable; only the public key is exportable in WebCrypto.
  const pair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const exported = await subtle.exportKey("jwk", pair.publicKey);
  const jwk: PublicJWK = { kty: "EC", crv: "P-256", x: exported.x!, y: exported.y! };
  const jkt = await sha256(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }));
  return { key: pair.privateKey as CryptoKey, jwk, jkt };
}

export async function makeProof(key: CryptoKey, jwk: PublicJWK, method: string, url: string, nonce: string, token?: string, now = Date.now() / 1000): Promise<string> {
  const target = new URL(url);
  target.search = "";
  target.hash = "";
  const header = { alg: "ES256", typ: "dpop+jwt", jwk };
  const claims: Record<string, string | number> = {
    jti: b64url(webcrypto.getRandomValues(new Uint8Array(24))),
    htm: method.toUpperCase(),
    htu: target.href,
    iat: Math.floor(now),
    nonce,
  };
  if (token !== undefined) claims.ath = await sha256(token);
  const content = `${b64url(new TextEncoder().encode(JSON.stringify(header)))}.${b64url(new TextEncoder().encode(JSON.stringify(claims)))}`;
  const signature = await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key as webcrypto.CryptoKey, new TextEncoder().encode(content));
  if (signature.byteLength !== 64) throw new AccessError("invalid_signature_encoding", 503);
  return `${content}.${b64url(new Uint8Array(signature))}`;
}

export async function boundedJSON(response: Response, limit = MAX_JSON_BYTES): Promise<unknown> {
  if (response.redirected || !response.headers.get("content-type")?.toLowerCase().startsWith("application/json")) throw new AccessError("invalid_upstream_response", 502);
  const length = response.headers.get("content-length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > limit)) throw new AccessError("response_too_large", 502);
  const reader = response.body?.getReader();
  if (!reader) throw new AccessError("invalid_upstream_response", 502);
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) { await reader.cancel(); throw new AccessError("response_too_large", 502); }
      chunks.push(value);
    }
    try { return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown; } catch { throw new AccessError("invalid_json", 502); }
  } finally { reader.releaseLock(); }
}

export async function jsonRequest(fetcher: Fetcher, url: string, body: unknown, headers: Record<string, string> = {}): Promise<unknown> {
  let response: Response;
  try {
    response = await fetcher(url, {
      method: "POST",
      redirect: "error",
      cache: "no-store",
      signal: AbortSignal.timeout(8000),
      headers: { "Content-Type": "application/json", Accept: "application/json", ...headers },
      body: JSON.stringify(body),
    });
  } catch { throw new AccessError("issuer_unavailable", 503); }
  if (!response.ok) {
    await response.body?.cancel();
    throw new AccessError(response.status === 401 || response.status === 403 ? "access_denied" : "issuer_unavailable", response.status === 401 || response.status === 403 ? response.status : 503);
  }
  return boundedJSON(response);
}
