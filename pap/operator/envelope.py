"""Interoperable operator envelopes with authenticated deployment bindings."""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .custody import Custody, CustodyError, public_key, public_pin

SCHEMA = "pap-openbao-operator-recovery-v1"
MAX_PACKET = 16 * 1024 * 1024
SHA256 = re.compile(r"[a-f0-9]{64}\Z")


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False
    ).encode("ascii")


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CustodyError("Duplicate JSON member rejected")
        result[key] = value
    return result


def parse_json(raw: bytes, maximum: int = MAX_PACKET) -> dict:
    if not raw or len(raw) > maximum:
        raise CustodyError("JSON input exceeds its size limit")
    try:
        value = json.loads(
            raw, object_pairs_hook=_pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError())
        )
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise CustodyError("Invalid or duplicate JSON input") from exc
    if not isinstance(value, dict):
        raise CustodyError("JSON object required")
    return value


def decode(value: Any, maximum: int, *, length: int | None = None) -> bytes:
    if not isinstance(value, str) or len(value) > ((maximum + 2) // 3) * 4:
        raise CustodyError("Invalid bounded base64 field")
    try:
        result = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise CustodyError("Invalid bounded base64 field") from exc
    if len(result) > maximum or length is not None and len(result) != length:
        raise CustodyError("Invalid decoded field length")
    return result


def _envelope(raw: bytes) -> dict:
    envelope = parse_json(raw)
    if set(envelope) != {"aad", "wrapped_key", "nonce", "ciphertext"}:
        raise CustodyError("Unexpected recovery envelope members")
    aad = envelope["aad"]
    allowed = {
        "schema",
        "cipher",
        "wrap",
        "machine_id",
        "host_identity_sha256",
        "operator_public_key_sha256",
        "enrollment_ca_sha256",
        "operator_ca_sha256",
        "stage",
        "recorded_at",
        "static_seal_key_id",
        "previous_envelope_sha256",
    }
    if not isinstance(aad, dict) or set(aad) - allowed:
        raise CustodyError("Unexpected recovery metadata members")
    if (
        not isinstance(aad, dict)
        or aad.get("schema") != SCHEMA
        or aad.get("cipher") != "AES-256-GCM"
        or aad.get("wrap") != "RSA-OAEP-SHA256"
    ):
        raise CustodyError("Unsupported recovery envelope algorithm or schema")
    for field in (
        "operator_public_key_sha256",
        "host_identity_sha256",
        "enrollment_ca_sha256",
        "operator_ca_sha256",
    ):
        if not isinstance(aad.get(field), str) or not SHA256.fullmatch(aad[field]):
            raise CustodyError("Recovery envelope is missing a public fingerprint")
    if (
        not isinstance(aad.get("machine_id"), str)
        or not aad["machine_id"]
        or not isinstance(aad.get("stage"), str)
    ):
        raise CustodyError("Recovery envelope is missing its deployment binding")
    decode(envelope["wrapped_key"], 512, length=512)
    decode(envelope["nonce"], 12, length=12)
    if len(decode(envelope["ciphertext"], MAX_PACKET)) < 17:
        raise CustodyError("Recovery ciphertext is incomplete")
    return envelope


def inspect_packet(raw: bytes) -> dict:
    envelope = _envelope(raw)
    # This metadata is a claim until an authenticated decrypt succeeds.
    return {
        "authenticated": False,
        "envelope_sha256": hashlib.sha256(raw).hexdigest(),
        "aad": envelope["aad"],
    }


def encrypt_packet(packet: dict, recipient_der: bytes, metadata: dict) -> bytes:
    key = public_key(recipient_der)
    aad = {
        **metadata,
        "schema": SCHEMA,
        "cipher": "AES-256-GCM",
        "wrap": "RSA-OAEP-SHA256",
        "operator_public_key_sha256": public_pin(recipient_der),
    }
    secret = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    ciphertext = AESGCM(secret).encrypt(nonce, canonical(packet), canonical(aad))
    wrapped = key.encrypt(
        secret, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    result = (
        canonical(
            {
                "aad": aad,
                "wrapped_key": base64.b64encode(wrapped).decode(),
                "nonce": base64.b64encode(nonce).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
            }
        )
        + b"\n"
    )
    _envelope(result)
    return result


def decrypt_packet(
    raw: bytes, custody: Custody, *, expected: dict[str, str], expected_sha256: str | None = None
) -> dict:
    if expected_sha256 is not None and hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise CustodyError("Recovery envelope checksum mismatch")
    envelope = _envelope(raw)
    aad = envelope["aad"]
    # The custody pin, machine and local-host identity must all be independently
    # supplied. Inspecting an envelope is insufficient to select a deployment.
    for name in ("machine_id", "host_identity_sha256"):
        if not expected.get(name):
            raise CustodyError("Expected machine and host identity bindings are required")
    if aad["operator_public_key_sha256"] != public_pin(custody.public_der()) or any(
        aad.get(k) != v for k, v in expected.items()
    ):
        raise CustodyError("Recovery envelope deployment binding mismatch")
    secret = custody.decrypt(decode(envelope["wrapped_key"], 512, length=512))
    if len(secret) != 32:
        raise CustodyError("Invalid unwrapped AES key length")
    try:
        plaintext = AESGCM(secret).decrypt(
            decode(envelope["nonce"], 12, length=12),
            decode(envelope["ciphertext"], MAX_PACKET),
            canonical(aad),
        )
    except InvalidTag as exc:
        raise CustodyError("Recovery envelope authentication failed") from exc
    packet = parse_json(plaintext)
    if packet.get("schema") in (SCHEMA, "pap-static-seal-successor-v1"):
        material = recovery_material(packet)
        if (
            material.get("machine_id") != aad["machine_id"]
            or material.get("host_identity_sha256") != aad["host_identity_sha256"]
        ):
            raise CustodyError("Authenticated recovery content has a different host binding")
        for name in ("enrollment", "operator"):
            cert = x509.load_pem_x509_certificate(material[name + "_ca"].encode("ascii"))
            if (
                hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
                != aad[name + "_ca_sha256"]
            ):
                raise CustodyError("Authenticated recovery CA fingerprint mismatch")
        if packet.get("schema") == "pap-static-seal-successor-v1" or "static_seal" in packet:
            _, static_key = static_seal_material(packet)
            if hashlib.sha256(static_key).hexdigest() != aad.get("static_seal_key_id"):
                raise CustodyError("Authenticated static-seal key does not match its public pin")
    return packet


def static_seal_material(packet: dict) -> tuple[str, bytes]:
    """Accept the original 0.2.2 successor and the explicit public CLI schema."""
    if packet.get("schema") == "pap-static-seal-successor-v1":
        deployment_id = packet.get("deployment_id")
        secret = decode(packet.get("static_seal_key_b64"), 32, length=32)
    elif packet.get("schema") == SCHEMA and isinstance(packet.get("static_seal"), dict):
        static = packet["static_seal"]
        value = static.get("key_b64url")
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
            raise CustodyError("Invalid legacy static-seal key encoding")
        secret = base64.urlsafe_b64decode(value + "=")
        if base64.urlsafe_b64encode(secret).rstrip(b"=").decode() != value or hashlib.sha256(
            secret
        ).hexdigest() != static.get("key_id"):
            raise CustodyError("Legacy static-seal key fingerprint mismatch")
        deployment_id = static.get("deployment_id")
    else:
        raise CustodyError("Authenticated packet does not contain a supported static-seal key")
    if not isinstance(deployment_id, str) or not deployment_id or len(deployment_id) > 128:
        raise CustodyError("Static-seal deployment ID is invalid")
    return deployment_id, secret


def recovery_material(packet: dict) -> dict:
    """Validate CA custody and return the original recovery material in memory."""
    if packet.get("schema") == "pap-static-seal-successor-v1":
        packet = packet.get("predecessor_recovery")
    if not isinstance(packet, dict) or packet.get("schema") != SCHEMA:
        raise CustodyError("Unsupported authenticated recovery packet")
    try:
        for prefix in ("enrollment", "operator"):
            cert = x509.load_pem_x509_certificate(packet[prefix + "_ca"].encode("ascii"))
            key = serialization.load_pem_private_key(
                packet[prefix + "_ca_private_key"].encode("ascii"), password=None
            )
            if cert.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            ) != key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            ):
                raise CustodyError("Recovered CA and private key do not match")
            if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise CustodyError("Recovered certificate is not a CA")
    except (KeyError, ValueError, TypeError, AttributeError, UnicodeError, x509.ExtensionNotFound) as exc:
        raise CustodyError("Authenticated recovery CA material is invalid") from exc
    return packet


def prepare_successor(
    raw: bytes, custody: Custody, *, recipient_der: bytes, expected: dict[str, str], deployment_id: str
) -> tuple[bytes, dict]:
    if not deployment_id or len(deployment_id) > 128:
        raise CustodyError("A deployment ID is required")
    packet = recovery_material(decrypt_packet(raw, custody, expected=expected))
    old = _envelope(raw)["aad"]
    if old.get("stage") != "initialization-response-received":
        raise CustodyError(
            "Static-seal successor preparation requires the completed original initialization packet"
        )
    secret = os.urandom(32)
    key_id = hashlib.sha256(secret).hexdigest()
    previous = hashlib.sha256(raw).hexdigest()
    successor = {
        "schema": "pap-static-seal-successor-v1",
        "machine_id": expected["machine_id"],
        "deployment_id": deployment_id,
        "static_seal_key_b64": base64.b64encode(secret).decode(),
        "predecessor_recovery": packet,
    }
    metadata = {
        **old,
        "operator_public_key_sha256": public_pin(recipient_der),
        "stage": "static-seal-successor-pre-migration",
        "static_seal_key_id": key_id,
        "previous_envelope_sha256": previous,
        "recorded_at": datetime.now(UTC).isoformat(),
    }
    encrypted = encrypt_packet(successor, recipient_der, metadata)
    # Receipt becomes verified only after an actual unwrap using its new custody
    # key. This function does not assert custody of a recipient supplied as DER.
    receipt = {
        "schema": "pap-static-seal-successor-custody-v1",
        **expected,
        "key_id": key_id,
        "enrollment_ca_sha256": old["enrollment_ca_sha256"],
        "previous_envelope_sha256": previous,
        "successor_envelope_sha256": hashlib.sha256(encrypted).hexdigest(),
        "offhost_durable": False,
        "decryption_verified": False,
        "contains_static_key": True,
        "contains_predecessor_recovery": True,
    }
    return encrypted, receipt


def decrypt_openai_backup(
    raw: bytes, custody: Custody, *, name: str, organization_id: str, project_id: str
) -> bytes:
    backup = parse_json(raw, 1024 * 1024)
    if (
        backup.get("schema") != "pap.operator.provider-custody.v1"
        or backup.get("name") != name
        or backup.get("organization_id") != organization_id
        or backup.get("project_id") != project_id
        or backup.get("recipient_public_der_sha256") != public_pin(custody.public_der())
    ):
        raise CustodyError("OpenAI encrypted backup identity binding mismatch")
    try:
        result = backup["creation_result"]
        payload = result["structuredContent"]
        encrypted = payload["encrypted_api_key"]
        if (
            result.get("isError")
            or encrypted.get("version") != 1
            or payload["api_key_name"] != name
            or payload["organization"]["id"] != organization_id
            or payload["project"]["id"] != project_id
        ):
            raise CustodyError("Unsupported encrypted key response")
        ciphertext = encrypted["ciphertext"]
        if not isinstance(ciphertext, str) or not re.fullmatch(r"[A-Za-z0-9_-]{683}", ciphertext):
            raise CustodyError("Invalid encrypted key ciphertext encoding")
        secret = custody.decrypt(base64.urlsafe_b64decode(ciphertext + "="))
    except (KeyError, TypeError, AttributeError) as exc:
        raise CustodyError("Invalid encrypted key response") from exc
    if (
        not secret.startswith(b"sk-")
        or not 16 <= len(secret) <= 1024
        or any(c <= 32 or c >= 127 for c in secret)
    ):
        raise CustodyError("Decrypted credential format is invalid")
    return secret
