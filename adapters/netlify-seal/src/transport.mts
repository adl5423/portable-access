import { lookup } from "node:dns/promises";
import type { LookupAddress } from "node:dns";
import { request as httpsRequest } from "node:https";
import { BlockList, isIP, type LookupFunction } from "node:net";
import type { IncomingHttpHeaders } from "node:http";
import { MAX_BYTES, PROOF_PREFIX, SealError } from "./protocol.mjs";

const denied4 = new BlockList();
for (const [network, prefix] of [["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4]] as const) denied4.addSubnet(network, prefix, "ipv4");
const global6 = new BlockList(); global6.addSubnet("2000::", 3, "ipv6");
const denied6 = new BlockList();
for (const [network, prefix] of [["2001::", 23], ["2001:db8::", 32], ["2002::", 16], ["3fff::", 20]] as const) denied6.addSubnet(network, prefix, "ipv6");
export function isPublicAddress(address: string): boolean {
  if (address.includes("%")) return false;
  const family = isIP(address);
  if (family === 4) return !denied4.check(address, "ipv4");
  return family === 6 && global6.check(address, "ipv6") && !denied6.check(address, "ipv6");
}
export type Resolver = (hostname: string) => Promise<LookupAddress[]>;
const systemResolver: Resolver = (hostname) => lookup(hostname, { all: true, verbatim: true });
export async function untilAbort<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  signal.throwIfAborted();
  return new Promise<T>((resolve, reject) => {
    let settled = false;
    const cleanup = () => signal.removeEventListener("abort", aborted);
    const aborted = () => { if (!settled) { settled = true; cleanup(); reject(new SealError("temporarily_unavailable", 503)); } };
    signal.addEventListener("abort", aborted, { once: true });
    promise.then((value) => { if (!settled) { settled = true; cleanup(); resolve(value); } }, (error: unknown) => { if (!settled) { settled = true; cleanup(); reject(error); } });
  });
}
export async function resolvePublic(hostname: string, signal: AbortSignal, resolver: Resolver = systemResolver): Promise<LookupAddress> {
  let addresses: LookupAddress[];
  try { addresses = await untilAbort(resolver(hostname), signal); }
  catch { throw new SealError("temporarily_unavailable", 503); }
  if (addresses.length === 0 || addresses.length > 16 || addresses.some((entry) => ![4, 6].includes(entry.family) || isIP(entry.address) !== entry.family || !isPublicAddress(entry.address))) throw new SealError("unsafe_origin_address", 503);
  return addresses[0]!;
}
export function pinnedLookup(address: LookupAddress): LookupFunction {
  return (_hostname, options, callback) => {
    if (typeof options === "object" && options.all) callback(null, [address]);
    else callback(null, address.address, address.family);
  };
}
export interface ProofStream extends AsyncIterable<Uint8Array> {
  statusCode?: number | undefined; headers: IncomingHttpHeaders; destroy(error?: Error): void;
}
export async function readProofResponse(response: ProofStream, signal: AbortSignal): Promise<Buffer> {
  try {
    const type = response.headers["content-type"];
    const encoding = response.headers["content-encoding"];
    const length = response.headers["content-length"];
    if (response.statusCode !== 200 || typeof type !== "string" || !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(type) || (encoding !== undefined && encoding !== "identity") || (length !== undefined && (typeof length !== "string" || !/^(?:0|[1-9][0-9]*)$/.test(length) || Number(length) > MAX_BYTES))) throw new SealError("proof_unavailable", 503);
    const chunks: Buffer[] = []; let size = 0;
    const iterator = response[Symbol.asyncIterator]();
    while (true) {
      const result = await untilAbort(iterator.next(), signal);
      if (result.done) break;
      const bytes = Buffer.from(result.value); size += bytes.length;
      if (size > MAX_BYTES) throw new SealError("proof_unavailable", 503);
      chunks.push(bytes);
    }
    if (size === 0 || (length !== undefined && Number(length) !== size)) throw new SealError("proof_unavailable", 503);
    return Buffer.concat(chunks);
  } finally { response.destroy(); }
}
export type PinnedTransport = (url: URL, address: LookupAddress, signal: AbortSignal) => Promise<Buffer>;
export const pinnedTransport: PinnedTransport = async (url, address, signal) => {
  signal.throwIfAborted();
  return new Promise<Buffer>((resolve, reject) => {
    // Keep the original host for SNI/certificate verification; resolve only through the checked address.
    const req = httpsRequest(url, { method: "GET", agent: false, lookup: pinnedLookup(address), family: address.family, signal, maxHeaderSize: 8192, headers: { Accept: "application/json", "Accept-Encoding": "identity", "Cache-Control": "no-store" } }, (response) => {
      readProofResponse(response, signal).then(resolve, reject);
    });
    req.once("error", () => reject(new SealError("proof_unavailable", 503)));
    req.end();
  });
};
export interface ProofTransportOptions { resolver?: Resolver; transport?: PinnedTransport }
export async function fetchProof(origin: string, requestID: string, signal: AbortSignal, options: ProofTransportOptions = {}): Promise<Buffer> {
  const url = new URL(`${origin}${PROOF_PREFIX}${requestID}`);
  const address = await resolvePublic(url.hostname, signal, options.resolver);
  try { return await untilAbort((options.transport ?? pinnedTransport)(url, address, signal), signal); }
  catch { throw new SealError("proof_unavailable", 503); }
}
