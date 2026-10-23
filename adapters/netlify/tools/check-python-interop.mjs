import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { webcrypto } from "node:crypto";
import { freshIdentity, makeProof } from "../dist/src/protocol.mjs";

const python = process.argv[2];
if (!python || process.argv.length !== 3) {
  console.error("Usage: node tools/check-python-interop.mjs /absolute/path/to/project-venv/bin/python");
  process.exit(2);
}
const identity = await freshIdentity();
const target = "https://interop.security.example/api/pap/records";
const nonce = "interop_nonce_12345678901234567890";
const token = "synthetic_interoperability_token";
const encoded = await makeProof(identity.key, identity.jwk, "GET", target, nonce, token);
const script = `
import json, sys
from pap.crypto import verify_proof, proof, fresh_key
data = json.load(sys.stdin)
claims, jkt = verify_proof(data["proof"], "GET", data["target"], token=data["token"], expected_jkt=data["jkt"])
assert claims["nonce"] == data["nonce"]
print(json.dumps({"proof": proof(fresh_key(), "GET", data["target"], data["nonce"], data["token"])}))
`;
const result = JSON.parse(execFileSync(python, ["-c", script], {
  cwd: fileURLToPath(new URL("../../..", import.meta.url)),
  input: JSON.stringify({ proof: encoded, jkt: identity.jkt, target, token, nonce }),
  encoding: "utf8", timeout: 15_000,
}));
const [header, body, signature] = result.proof.split(".");
const jwk = JSON.parse(Buffer.from(header, "base64url").toString()).jwk;
const key = await webcrypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
const valid = await webcrypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, Buffer.from(signature, "base64url"), Buffer.from(`${header}.${body}`));
if (!valid) throw new Error("Python to Node ES256 verification failed");
const claims = JSON.parse(Buffer.from(body, "base64url").toString());
if (claims.htu !== target || claims.htm !== "GET" || claims.nonce !== nonce) throw new Error("Python DPoP claim mismatch");
console.log("Node DPoP verified by Python; Python ES256 verified by Node. No real credentials were used.");
