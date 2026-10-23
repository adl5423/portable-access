#!/usr/bin/env node
import { getStore } from "@netlify/blobs";
import { readFile } from "node:fs/promises";
import { createReadStream } from "node:fs";
import { parseArgs } from "node:util";
import { CUSTODY_STORE, MAX_BYTES, SealError, parseCanonical, parseConfig } from "../dist/src/protocol.mjs";
import { provisionCustody } from "../dist/src/provision.mjs";

async function readFD(fd, limit, signal) {
  const stream = createReadStream("", { fd, autoClose: false, signal });
  const chunks = []; let size = 0;
  try {
    for await (const chunk of stream) {
      size += chunk.length;
      if (size > limit) throw new SealError("private_input_too_large", 400);
      chunks.push(chunk);
    }
    return Buffer.concat(chunks);
  } finally { stream.destroy(); }
}

try {
  const { values } = parseArgs({ options: { config: { type: "string" }, "token-fd": { type: "string" }, revoke: { type: "boolean", default: false }, help: { type: "boolean", default: false } } });
  if (values.help) {
    console.log("Usage: node tools/provision.mjs --config PUBLIC_CONFIG_PATH --token-fd INHERITED_FD [--revoke]");
    console.log("Provision reads canonical private custody JSON from stdin. --revoke reads the existing record and changes only enabled=false. Netlify authorization must arrive on a separate inherited FD>=3. No token or private record is accepted in args or environment.");
    process.exit(0);
  }
  if (!values.config || !values["token-fd"] || !/^[0-9]+$/.test(values["token-fd"])) throw new SealError("invalid_arguments", 400);
  const tokenFD = Number(values["token-fd"]);
  if (!Number.isSafeInteger(tokenFD) || tokenFD < 3 || tokenFD > 65535) throw new SealError("invalid_arguments", 400);
  const signal = AbortSignal.timeout(30000);
  const configBytes = await readFile(values.config);
  if (configBytes.length > MAX_BYTES) throw new SealError("invalid_configuration", 503);
  const config = parseConfig(JSON.parse(configBytes.toString("utf8")));
  const tokenBytes = await readFD(tokenFD, 4096, signal);
  let token;
  try {
    token = new TextDecoder("utf-8", { fatal: true }).decode(tokenBytes).trim();
    if (!/^[A-Za-z0-9_.-]{16,4096}$/.test(token)) throw new SealError("invalid_provider_authorization", 401);
  } finally { tokenBytes.fill(0); }
  let record;
  if (!values.revoke) {
    const bytes = await readFD(0, MAX_BYTES, signal);
    try { record = parseCanonical(bytes, 400); } finally { bytes.fill(0); }
  }
  const store = getStore({ name: CUSTODY_STORE, siteID: config.site_id, token, consistency: "strong", fetch: (input, init = {}) => fetch(input, { ...init, signal: init.signal ? AbortSignal.any([signal, init.signal]) : signal }) });
  const receipt = await provisionCustody(config, record, values.revoke, store, signal);
  console.log(JSON.stringify(receipt));
} catch (error) {
  const allowed = new Set(["invalid_arguments", "private_input_too_large", "invalid_provider_authorization", "invalid_configuration", "not_configured", "invalid_custody", "release_denied", "custody_missing", "custody_conflict", "custody_readback_mismatch", "conditional_write_unavailable", "invalid_schema", "invalid_json", "invalid_size", "noncanonical_json"]);
  console.error(JSON.stringify({ event: "pap.custody.operator", outcome: "failed", code: error instanceof SealError && allowed.has(error.code) ? error.code : "provider_operation_failed" }));
  process.exitCode = 1;
}
