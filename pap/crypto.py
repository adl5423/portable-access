"""Strict ES256 JWT/DPoP profile. Cryptographic operations use maintained libraries."""

import base64
import hashlib
import json
import secrets
import time
from urllib.parse import urlsplit, urlunsplit

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec


class Denied(Exception):
    def __init__(self, code: str, status: int = 401):
        self.code, self.status = code, status
        super().__init__(code)


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def fresh_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def public_jwk(key) -> dict:
    public = key.public_key() if hasattr(key, "public_key") else key
    n = public.public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": b64(n.x.to_bytes(32, "big")), "y": b64(n.y.to_bytes(32, "big"))}


def parse_public(jwk: dict):
    if not isinstance(jwk, dict) or set(jwk) != {"kty", "crv", "x", "y"}:
        raise Denied("invalid_public_key")
    if jwk["kty"] != "EC" or jwk["crv"] != "P-256":
        raise Denied("invalid_public_key")
    try:
        for field in ("x", "y"):
            raw = jwk[field]
            if not isinstance(raw, str) or len(raw) != 43:
                raise ValueError("invalid coordinate")
            decoded = base64.urlsafe_b64decode(raw + "=")
            if len(decoded) != 32 or b64(decoded) != raw:
                raise ValueError("noncanonical coordinate")
        return jwt.PyJWK.from_dict(jwk, algorithm="ES256").key
    except (ValueError, TypeError, jwt.PyJWTError) as exc:
        raise Denied("invalid_public_key") from exc


def thumbprint(jwk: dict) -> str:
    parse_public(jwk)
    canonical = json.dumps(jwk, sort_keys=True, separators=(",", ":")).encode()
    return b64(hashlib.sha256(canonical).digest())


def private_pem(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode("ascii")


def read_private(pem: str):
    return serialization.load_pem_private_key(pem.encode("ascii"), password=None)


def external_jwt(claims: dict, kid: str, provider, reference: str) -> str:
    """Serialize a standard compact JWS; the provider performs the ES256 operation."""
    header = b64(json.dumps({"alg": "ES256", "typ": "at+jwt", "kid": kid}, separators=(",", ":")).encode())
    payload = b64(json.dumps(claims, separators=(",", ":"), allow_nan=False).encode())
    signing_input = (header + "." + payload).encode("ascii")
    signature = provider.sign(reference, signing_input)
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise Denied("signer_signature_invalid", 503)
    return signing_input.decode("ascii") + "." + b64(signature)


def target_uri(url: str) -> str:
    # RFC 9449 excludes query and fragment. Route policy must validate all other input independently.
    p = urlsplit(url)
    return urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path or "/", "", ""))


def proof(
    key,
    method: str,
    url: str,
    nonce: str,
    token: str | None = None,
    *,
    now: float | None = None,
    jti: str | None = None,
) -> str:
    claims = {
        "jti": jti or secrets.token_urlsafe(24),
        "htm": method.upper(),
        "htu": target_uri(url),
        "iat": int(time.time() if now is None else now),
        "nonce": nonce,
    }
    if token is not None:
        claims["ath"] = b64(hashlib.sha256(token.encode("ascii")).digest())
    return jwt.encode(claims, key, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": public_jwk(key)})


def verify_proof(
    encoded: str,
    method: str,
    url: str,
    *,
    token: str | None = None,
    expected_jkt: str | None = None,
    now: float | None = None,
    max_age: int = 10,
    skew: int = 2,
) -> tuple[dict, str]:
    if not isinstance(encoded, str) or len(encoded) > 4096:
        raise Denied("invalid_proof")
    try:
        header = jwt.get_unverified_header(encoded)
        if set(header) != {"alg", "typ", "jwk"} or header["alg"] != "ES256" or header["typ"] != "dpop+jwt":
            raise Denied("invalid_proof_header")
        key = parse_public(header["jwk"])
        jkt = thumbprint(header["jwk"])
        if expected_jkt is not None and not secrets.compare_digest(jkt, expected_jkt):
            raise Denied("proof_key_mismatch")
        claims = jwt.decode(
            encoded,
            key,
            algorithms=["ES256"],
            options={
                "require": ["jti", "htm", "htu", "iat", "nonce"],
                "verify_iat": False,
                "verify_exp": False,
                "verify_nbf": False,
                "verify_aud": False,
            },
        )
        allowed = {"jti", "htm", "htu", "iat", "nonce"} | ({"ath"} if token is not None else set())
        if set(claims) != allowed:
            raise Denied("invalid_proof_claims")
        current = time.time() if now is None else now
        if type(claims["iat"]) is not int or not current - max_age <= claims["iat"] <= current + skew:
            raise Denied("stale_proof")
        if claims["htm"] != method.upper() or claims["htu"] != target_uri(url):
            raise Denied("proof_target_mismatch")
        for field in ("jti", "nonce"):
            if not isinstance(claims[field], str) or not 16 <= len(claims[field]) <= 128:
                raise Denied("invalid_proof_claims")
        if token is not None:
            expected = b64(hashlib.sha256(token.encode("ascii")).digest())
            if not isinstance(claims["ath"], str) or not secrets.compare_digest(claims["ath"], expected):
                raise Denied("token_hash_mismatch")
        return claims, jkt
    except (jwt.PyJWTError, ValueError, TypeError, KeyError, UnicodeError) as exc:
        raise Denied("invalid_proof") from exc
