import { createHash } from "node:crypto";

export const MAX_BYTES = 4096;
export const PROOF_PREFIX = "/.well-known/pap/boot-proof/";
export const RELEASE_PATH = "/v1/boot/release";
export const CUSTODY_STORE = "pap-seal-custody-v1";
export const PUBLICATION_STORE = "pap-seal-publications-v1";
export const NO_CACHE = Object.freeze({
  "Cache-Control": "no-store, private, max-age=0",
  "Netlify-CDN-Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
});
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HEX = /^[0-9a-f]{64}$/;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$/;

export class SealError extends Error {
  constructor(readonly code: string, readonly status: number) { super(code); this.name = "SealError"; }
}
export interface PublicConfig {
  v: 1; enabled: true; custody_site_isolated: true;
  site_id: string; custody_origin: string; deployment_id: string; machine_id: string; origin: string; key_id: string;
}
export interface PlatformContext { site: { id?: string }; deploy: { context?: string; published?: boolean } }
export interface RecipientJWK { kty: "RSA"; n: string; e: "AQAB" }
export interface BootRequest {
  v: 1; request_id: string; deployment_id: string; machine_id: string; boot_id: string; key_id: string;
  nonce: string; iat: number; exp: number; recipient_jwk: RecipientJWK;
}
export interface ReleaseResponse { v: 1; request_id: string; key_id: string; wrapped_key: string }
export interface CustodyRecord { v: 1; enabled: boolean; deployment_id: string; machine_id: string; origin: string; key_id: string; key_b64url: string }
export interface Publication { v: 1; request_sha256: string; expires_at: number; response: ReleaseResponse }

export function sha256(bytes: Uint8Array | string): string { return createHash("sha256").update(bytes).digest("hex"); }
export function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonical((value as Record<string, unknown>)[key])}`).join(",")}}`;
}
export function object(value: unknown, keys: readonly string[], status = 400): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length !== keys.length || keys.some((key) => !Object.hasOwn(value, key))) throw new SealError("invalid_schema", status);
  return value as Record<string, unknown>;
}
function string(value: unknown, pattern: RegExp, status = 400): string {
  if (typeof value !== "string" || !pattern.test(value)) throw new SealError("invalid_schema", status);
  return value;
}
export function decode(value: unknown, length: number, status = 400): Buffer {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) throw new SealError("invalid_encoding", status);
  const bytes = Buffer.from(value, "base64url");
  if (bytes.length !== length || bytes.toString("base64url") !== value) throw new SealError("invalid_encoding", status);
  return bytes;
}
export function parseCanonical(bytes: Uint8Array, status = 400): unknown {
  if (bytes.length === 0 || bytes.length > MAX_BYTES) throw new SealError("invalid_size", status);
  let text: string; let value: unknown;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); value = JSON.parse(text); }
  catch { throw new SealError("invalid_json", status); }
  const pending: Array<{ value: unknown; depth: number }> = [{ value, depth: 0 }]; let nodes = 0;
  while (pending.length) {
    const current = pending.pop()!;
    if (++nodes > 64 || current.depth > 6) throw new SealError("invalid_schema", status);
    if (current.value !== null && typeof current.value === "object") {
      for (const child of Object.values(current.value)) pending.push({ value: child, depth: current.depth + 1 });
    }
  }
  // Exact wire canonicalization also rejects duplicate members and ambiguous numbers/escapes.
  if (canonical(value) !== text) throw new SealError("noncanonical_json", status);
  return value;
}
export function httpsOrigin(value: unknown, netlify = false): string {
  if (typeof value !== "string" || value.length > 256) throw new SealError("invalid_configuration", 503);
  let url: URL;
  try { url = new URL(value); } catch { throw new SealError("invalid_configuration", 503); }
  if (url.protocol !== "https:" || url.origin !== value || url.pathname !== "/" || url.username || url.password || url.port || url.search || url.hash || !/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/.test(url.hostname) || !url.hostname.includes(".") || /^[0-9.]+$/.test(url.hostname)) throw new SealError("invalid_configuration", 503);
  if (netlify && (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.netlify\.app$/.test(url.hostname) || url.hostname.includes("--"))) throw new SealError("invalid_configuration", 503);
  return url.origin;
}
export function parseConfig(value: unknown): PublicConfig {
  const obj = object(value, ["v", "enabled", "custody_site_isolated", "site_id", "custody_origin", "deployment_id", "machine_id", "origin", "key_id"], 503);
  if (obj.v !== 1 || obj.enabled !== true || obj.custody_site_isolated !== true) throw new SealError("not_configured", 503);
  return Object.freeze({ v: 1, enabled: true, custody_site_isolated: true,
    site_id: string(obj.site_id, UUID, 503), custody_origin: httpsOrigin(obj.custody_origin, true),
    deployment_id: string(obj.deployment_id, IDENTIFIER, 503), machine_id: string(obj.machine_id, /^m_[a-z0-9]{26}$/, 503),
    origin: httpsOrigin(obj.origin), key_id: string(obj.key_id, HEX, 503),
  });
}
export function assertPlatform(config: PublicConfig, context: PlatformContext, url: URL): void {
  if (context?.site?.id !== config.site_id || context?.deploy?.context !== "production" || context.deploy.published !== true || url.origin !== config.custody_origin) throw new SealError("untrusted_deployment", 403);
}
export function assertFresh(request: BootRequest, now: number): void {
  if (!Number.isFinite(now) || request.iat > now + 5 || request.iat < now - 120 || request.exp <= now || request.exp - request.iat < 1 || request.exp - request.iat > 120) throw new SealError("proof_expired", 401);
}
export function parseRequest(value: unknown, config: PublicConfig, now: number): BootRequest {
  const obj = object(value, ["v", "request_id", "deployment_id", "machine_id", "boot_id", "key_id", "nonce", "iat", "exp", "recipient_jwk"]);
  const jwk = object(obj.recipient_jwk, ["kty", "n", "e"]);
  if (obj.v !== 1 || jwk.kty !== "RSA" || jwk.e !== "AQAB" || !Number.isSafeInteger(obj.iat) || !Number.isSafeInteger(obj.exp)) throw new SealError("invalid_schema", 400);
  const n = decode(jwk.n, 512);
  if ((n[0]! & 128) === 0 || (n[511]! & 1) !== 1) throw new SealError("invalid_recipient", 400);
  decode(obj.nonce, 32);
  const result: BootRequest = { v: 1, request_id: string(obj.request_id, UUID), deployment_id: string(obj.deployment_id, IDENTIFIER), machine_id: string(obj.machine_id, /^m_[a-z0-9]{26}$/), boot_id: string(obj.boot_id, UUID), key_id: string(obj.key_id, HEX), nonce: obj.nonce as string, iat: obj.iat as number, exp: obj.exp as number, recipient_jwk: { kty: "RSA", n: jwk.n as string, e: "AQAB" } };
  if (result.deployment_id !== config.deployment_id || result.machine_id !== config.machine_id || result.key_id !== config.key_id) throw new SealError("release_denied", 403);
  assertFresh(result, now);
  return Object.freeze(result);
}
export function parseCustody(value: unknown, config: PublicConfig): CustodyRecord {
  const obj = object(value, ["v", "enabled", "deployment_id", "machine_id", "origin", "key_id", "key_b64url"], 503);
  if (obj.v !== 1 || typeof obj.enabled !== "boolean" || obj.deployment_id !== config.deployment_id || obj.machine_id !== config.machine_id || obj.origin !== config.origin || obj.key_id !== config.key_id) throw new SealError("invalid_custody", 503);
  if (!obj.enabled) throw new SealError("release_denied", 403);
  const key = decode(obj.key_b64url, 32, 503);
  try { if (sha256(key) !== config.key_id) throw new SealError("invalid_custody", 503); }
  finally { key.fill(0); }
  return obj as unknown as CustodyRecord;
}
export function parsePublication(value: unknown, request: BootRequest, digest: string): Publication {
  const obj = object(value, ["v", "request_sha256", "expires_at", "response"], 503);
  if (obj.v !== 1 || obj.request_sha256 !== digest) throw new SealError("request_conflict", 409);
  if (obj.expires_at !== request.exp) throw new SealError("invalid_publication", 503);
  const response = object(obj.response, ["v", "request_id", "key_id", "wrapped_key"], 503);
  if (response.v !== 1 || response.request_id !== request.request_id || response.key_id !== request.key_id) throw new SealError("invalid_publication", 503);
  decode(response.wrapped_key, 512, 503);
  return obj as unknown as Publication;
}
