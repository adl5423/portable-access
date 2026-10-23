"""Protected signing providers. No provider accepts environment bearer credentials.

OpenBao lives in a separate trust domain. Its certificate-authentication bootstrap
must be provisioned by the host operator; it is not a Netlify workload identity.
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
import ssl
import stat
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from .crypto import public_jwk

MAX_RESPONSE = 1024 * 1024
_NAME = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_REFERENCE = re.compile(r"openbao:(pap-[0-9a-f]{32}):1\Z")


class SignerError(RuntimeError):
    """Stable, non-sensitive failure suitable for mapping to an HTTP 503."""

    status = 503

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class PreparedKey:
    reference: str
    public_jwk: dict


class SigningProvider(Protocol):
    def prepare(self, generation_id: str) -> PreparedKey: ...

    def sign(self, reference: str, signing_input: bytes) -> bytes: ...

    def retire(self, reference: str) -> None: ...

    def health(self) -> dict: ...


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _json_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON member")
        value[key] = item
    return value


@contextmanager
def _trusted_file(path: Path, *, private: bool):
    """Keep the checked inode open through TLS loading to avoid path races."""
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_RESPONSE:
            raise ValueError("invalid credential file")
        if info.st_uid not in {0, os.geteuid()}:
            raise ValueError("untrusted credential owner")
        forbidden = 0o077 if private else 0o022
        if stat.S_IMODE(info.st_mode) & forbidden:
            raise ValueError("untrusted credential permissions")
        yield descriptor
    except (OSError, ValueError):
        raise SignerError("signer_credential_file_invalid") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


# An internal injection point permits deterministic provider tests without HTTP
# downgrade options in the public configuration or live credentials in tests.
_Transport = Callable[[str, str, dict | None, dict[str, str]], tuple[int, dict]]


class OpenBaoSigner:
    """P-256 Transit signer authenticated with renewable certificate login.

    A scoped OpenBao token exists only in memory and is replaced before expiry by
    a fresh mTLS login. Every real HTTPS request reloads certificate files so an
    independently managed certificate replacement does not require a restart.

    The certificate's private key must be readable only by its service UID (or
    root). TLS certificates are bootstrap credentials; their host-level issuance,
    renewal and revocation must be configured independently.

    ``retire`` prevents reuse in this instance and discards its public-key cache.
    Durable generation revocation MUST also be enforced by the authority store.
    It does not delete a remote key or pretend that deleting private material
    would revoke tokens verified with an already distributed public key.
    """

    def __init__(
        self,
        base_url: str,
        *,
        role: str,
        client_cert: Path | str,
        client_key: Path | str,
        ca_file: Path | str | None = None,
        namespace: str | None = None,
        timeout: float = 5.0,
        _transport: _Transport | None = None,
        _clock: Callable[[], float] = time.monotonic,
    ):
        if not isinstance(base_url, str):
            raise ValueError("OpenBao requires an HTTPS origin")
        try:
            parsed = urlsplit(base_url)
            valid_url = (
                parsed.scheme == "https"
                and parsed.hostname
                and parsed.path in {"", "/"}
                and not parsed.username
                and not parsed.password
                and not parsed.query
                and not parsed.fragment
                and not any(char.isspace() for char in base_url)
            )
            _ = parsed.port  # Reject invalid ports before any requests.
        except (ValueError, TypeError):
            valid_url = False
        if not valid_url or not isinstance(role, str) or _NAME.fullmatch(role) is None:
            raise ValueError("OpenBao requires an HTTPS origin and a valid certificate role")
        if namespace is not None and (
            not isinstance(namespace, str)
            or not 1 <= len(namespace) <= 256
            or any(_NAME.fullmatch(part) is None for part in namespace.split("/"))
        ):
            raise ValueError("invalid OpenBao namespace")
        if isinstance(timeout, bool) or not isinstance(timeout, (float, int)):
            raise ValueError("invalid signer timeout")
        if not math.isfinite(timeout) or not 0 < timeout <= 30:
            raise ValueError("invalid signer timeout")
        self.base_url = base_url.rstrip("/")
        self.role, self.namespace, self.timeout = role, namespace, float(timeout)
        self.client_cert, self.client_key = Path(client_cert), Path(client_key)
        self.ca_file = Path(ca_file) if ca_file is not None else None
        for path in (self.client_cert, self.client_key, self.ca_file):
            if path is not None and not path.is_absolute():
                raise ValueError("signer credential paths must be absolute")
        self._transport, self._clock = _transport, _clock
        self._lock = threading.RLock()
        self._token: str | None = None
        self._refresh_at = 0.0
        self._public: dict[str, ec.EllipticCurvePublicKey] = {}
        self._retired: set[str] = set()

    def _ssl_context(self) -> ssl.SSLContext:
        try:
            if self.ca_file is not None:
                with _trusted_file(self.ca_file, private=False) as descriptor:
                    authority = os.read(descriptor, MAX_RESPONSE + 1)
                # Explicit CA configuration narrows trust; it must not silently
                # add every public system CA to an intended private trust root.
                context = ssl.create_default_context(cadata=authority.decode("ascii"))
            else:
                context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            certificate_path, key_path = self.client_cert, self.client_key
            if certificate_path.parent == key_path.parent:
                # The certificate manager activates a complete generation with
                # one symlink replacement. Resolve that generation only once.
                directory = certificate_path.parent.resolve(strict=True)
                info = directory.stat()
                if (
                    not stat.S_ISDIR(info.st_mode)
                    or info.st_uid not in {0, os.geteuid()}
                    or stat.S_IMODE(info.st_mode) & 0o022
                ):
                    raise SignerError("signer_credential_directory_invalid")
                certificate_path, key_path = directory / certificate_path.name, directory / key_path.name
            with (
                _trusted_file(certificate_path, private=False) as certificate,
                _trusted_file(key_path, private=True) as private_key,
            ):
                descriptor_root = "/proc/self/fd" if Path("/proc/self/fd").is_dir() else "/dev/fd"
                context.load_cert_chain(
                    certfile=f"{descriptor_root}/{certificate}",
                    keyfile=f"{descriptor_root}/{private_key}",
                    password=lambda: b"",  # Never prompt for an encrypted key on a service's stdin.
                )
            return context
        except SignerError:
            raise
        except (OSError, ValueError, UnicodeError, ssl.SSLError):
            raise SignerError("signer_tls_configuration_invalid") from None

    def _https_json(self, method: str, path: str, payload: dict | None, headers: dict) -> tuple[int, dict]:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=self._ssl_context()),
            _NoRedirects(),
        )
        request = urllib.request.Request(
            self.base_url + path,
            data=json.dumps(payload, separators=(",", ":")).encode() if payload is not None else None,
            headers={"Accept": "application/json", "Content-Type": "application/json", **headers},
            method=method,
        )
        try:
            response = opener.open(request, timeout=self.timeout)
        except urllib.error.HTTPError as error:
            # Never expose provider response bodies, URLs, headers or TLS errors.
            status_code = error.code
            error.close()
            return status_code, {}
        with response:
            data = response.read(MAX_RESPONSE + 1)
            if len(data) > MAX_RESPONSE:
                raise SignerError("signer_response_too_large")
            if not data and response.status == 204:
                return response.status, {}
            value = json.loads(data.decode("utf-8"), object_pairs_hook=_json_object)
            if not isinstance(value, dict):
                raise SignerError("signer_response_invalid")
            return response.status, value

    def _request(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
        *,
        authenticated: bool = True,
        missing_ok: bool = False,
    ) -> dict | None:
        headers = {"X-Vault-Namespace": self.namespace} if self.namespace else {}
        if authenticated:
            self._authenticate()
            headers["X-Vault-Token"] = self._token
        try:
            status_code, value = (self._transport or self._https_json)(method, path, payload, headers)
        except SignerError:
            raise
        except Exception:
            raise SignerError("signer_transport_unavailable") from None
        if status_code == 404 and missing_ok:
            return None
        if status_code in {401, 403}:
            self._token = None
            self._refresh_at = 0.0
            raise SignerError("signer_authentication_denied")
        if type(status_code) is not int or not 200 <= status_code < 300:
            raise SignerError("signer_request_failed")
        if not isinstance(value, dict):
            raise SignerError("signer_response_invalid")
        return value

    def _authenticate(self):
        now = self._clock()
        if self._token is not None and now < self._refresh_at:
            return
        self._token = None
        value = self._request("POST", "/v1/auth/cert/login", {"name": self.role}, authenticated=False)
        auth = value.get("auth")
        if not isinstance(auth, dict):
            raise SignerError("signer_login_invalid")
        token, lifetime = auth.get("client_token"), auth.get("lease_duration")
        if (
            not isinstance(token, str)
            or not 16 <= len(token) <= 4096
            or any(not 33 <= ord(char) <= 126 for char in token)
            or type(lifetime) is not int
            or not 1 <= lifetime <= 86400
        ):
            raise SignerError("signer_login_invalid")
        self._token = token
        self._refresh_at = now + lifetime - min(30.0, lifetime / 5)

    @staticmethod
    def _name(reference: str) -> str:
        if not isinstance(reference, str) or (match := _REFERENCE.fullmatch(reference)) is None:
            raise SignerError("signer_reference_invalid")
        return match[1]

    def _read(self, reference: str, *, missing_ok: bool = False):
        name = self._name(reference)
        if reference in self._retired:
            raise SignerError("signer_key_retired")
        value = self._request("GET", "/v1/transit/keys/" + name, missing_ok=missing_ok)
        if value is None:
            return None
        data = value.get("data")
        if (
            not isinstance(data, dict)
            or data.get("type") != "ecdsa-p256"
            or data.get("name") != name
            or data.get("exportable") is not False
            or data.get("allow_plaintext_backup") is not False
            or data.get("derived") is not False
            or data.get("supports_signing") is not True
            or type(data.get("latest_version")) is not int
            or data["latest_version"] != 1
            or data.get("auto_rotate_period", 0) != 0
            or type(data.get("min_encryption_version", 0)) is not int
            or data.get("min_encryption_version", 0) not in {0, 1}
            or type(data.get("min_decryption_version", 1)) is not int
            or data.get("min_decryption_version", 1) not in {0, 1}
        ):
            raise SignerError("signer_key_configuration_invalid")
        versions = data.get("keys")
        if not isinstance(versions, dict) or set(versions) != {"1"} or not isinstance(versions["1"], dict):
            raise SignerError("signer_public_key_invalid")
        pem = versions["1"].get("public_key")
        try:
            if not isinstance(pem, str) or not 1 <= len(pem) <= 8192:
                raise ValueError("invalid public PEM")
            key = serialization.load_pem_public_key(pem.encode("ascii"))
            if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
                raise ValueError("invalid public curve")
        except (ValueError, TypeError, UnicodeError):
            raise SignerError("signer_public_key_invalid") from None
        self._public[reference] = key
        return PreparedKey(reference, public_jwk(key))

    def prepare(self, generation_id: str) -> PreparedKey:
        try:
            generation = uuid.UUID(generation_id)
        except (ValueError, TypeError, AttributeError):
            raise SignerError("signer_generation_invalid") from None
        reference = "openbao:pap-" + generation.hex + ":1"
        with self._lock:
            prepared = self._read(reference, missing_ok=True)
            if prepared is not None:
                return prepared
            self._request(
                "POST",
                "/v1/transit/keys/" + self._name(reference),
                {
                    "type": "ecdsa-p256",
                    "derived": False,
                    "exportable": False,
                    "allow_plaintext_backup": False,
                    "auto_rotate_period": "0",
                },
            )
            return self._read(reference)

    def sign(self, reference: str, signing_input: bytes) -> bytes:
        if not isinstance(signing_input, bytes) or not 1 <= len(signing_input) <= MAX_RESPONSE:
            raise SignerError("signer_input_invalid")
        with self._lock:
            name = self._name(reference)
            if reference in self._retired:
                raise SignerError("signer_key_retired")
            if reference not in self._public:
                self._read(reference)
            digest = hashlib.sha256(signing_input).digest()
            value = self._request(
                "POST",
                "/v1/transit/sign/" + name + "/sha2-256",
                {
                    "input": base64.b64encode(digest).decode("ascii"),
                    "prehashed": True,
                    # OpenBao ACL parameter equality distinguishes JSON numbers
                    # from HCL integers; its TypeInt field accepts this strict
                    # decimal string, matching the configured ACL value.
                    "key_version": "1",
                    "marshaling_algorithm": "jws",
                },
            )
            data = value.get("data")
            signature = data.get("signature") if isinstance(data, dict) else None
            try:
                if not isinstance(signature, str) or not signature.startswith("vault:v1:"):
                    raise ValueError("invalid signature version")
                encoded = signature[len("vault:v1:") :]
                if re.fullmatch(r"[A-Za-z0-9_-]{86}(?:==)?", encoded) is None:
                    raise ValueError("invalid signature encoding")
                raw = base64.urlsafe_b64decode(encoded.rstrip("=") + "==")
                if len(raw) != 64 or base64.urlsafe_b64encode(raw).decode().rstrip("=") != encoded.rstrip(
                    "="
                ):
                    raise ValueError("noncanonical signature")
                der = utils.encode_dss_signature(
                    int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
                )
                self._public[reference].verify(der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
                return raw
            except (ValueError, TypeError, InvalidSignature):
                raise SignerError("signer_signature_invalid") from None

    def retire(self, reference: str) -> None:
        self._name(reference)
        with self._lock:
            self._retired.add(reference)
            self._public.pop(reference, None)

    def reset_authentication(self) -> None:
        """A new mTLS identity must obtain its own certificate-bound login."""
        with self._lock:
            self._token = None
            self._refresh_at = 0.0

    def _credential_context(self, provider: str) -> str:
        if provider not in {"openai", "nasa", "nlr"}:
            raise SignerError("provider_credential_invalid")
        return base64.b64encode(("pap-provider-credentials:v1:" + provider).encode("ascii")).decode("ascii")

    def _credential_key(self):
        value = self._request("GET", "/v1/transit/keys/pap-provider-credentials")
        data = value.get("data")
        if (
            not isinstance(data, dict)
            or data.get("name") != "pap-provider-credentials"
            or data.get("type") != "aes256-gcm96"
            or data.get("derived") is not True
            or data.get("exportable") is not False
            or data.get("allow_plaintext_backup") is not False
            or data.get("supports_encryption") is not True
            or data.get("supports_decryption") is not True
            or type(data.get("latest_version")) is not int
            or data["latest_version"] < 1
            or type(data.get("auto_rotate_period")) is not int
            or not 3600 <= data["auto_rotate_period"] <= 31536000
        ):
            raise SignerError("provider_key_configuration_invalid")

    def encrypt_provider_credential(self, provider: str, credential: str) -> str:
        """Dedicated derived Transit key; never create or export key material here."""
        context = self._credential_context(provider)
        if (
            not isinstance(credential, str)
            or not 8 <= len(credential) <= 4096
            or any(not 33 <= ord(c) <= 126 for c in credential)
        ):
            raise SignerError("provider_credential_invalid")
        with self._lock:
            self._credential_key()
            value = self._request(
                "POST",
                "/v1/transit/encrypt/pap-provider-credentials",
                {
                    "context": context,
                    "plaintext": base64.b64encode(credential.encode("ascii")).decode("ascii"),
                },
            )
        data = value.get("data")
        ciphertext = data.get("ciphertext") if isinstance(data, dict) else None
        if (
            not isinstance(ciphertext, str)
            or re.fullmatch(r"vault:v[1-9][0-9]*:[A-Za-z0-9+/=]{20,8192}", ciphertext) is None
        ):
            raise SignerError("provider_ciphertext_invalid")
        return ciphertext

    def decrypt_provider_credential(self, provider: str, ciphertext: str) -> str:
        context = self._credential_context(provider)
        if (
            not isinstance(ciphertext, str)
            or re.fullmatch(r"vault:v[1-9][0-9]*:[A-Za-z0-9+/=]{20,8192}", ciphertext) is None
        ):
            raise SignerError("provider_ciphertext_invalid")
        with self._lock:
            self._credential_key()
            value = self._request(
                "POST",
                "/v1/transit/decrypt/pap-provider-credentials",
                {
                    "context": context,
                    "ciphertext": ciphertext,
                },
            )
        data = value.get("data")
        try:
            raw = data.get("plaintext") if isinstance(data, dict) else None
            if not isinstance(raw, str) or not 1 <= len(raw) <= 5500:
                raise ValueError("invalid plaintext")
            credential = base64.b64decode(raw, validate=True).decode("ascii")
            if not 8 <= len(credential) <= 4096 or any(not 33 <= ord(c) <= 126 for c in credential):
                raise ValueError("invalid credential")
            return credential
        except (ValueError, TypeError, UnicodeError):
            raise SignerError("provider_credential_invalid") from None

    def health(self) -> dict:
        with self._lock:
            self._authenticate()
            return {"provider": "openbao-transit", "authenticated": True, "cached_keys": len(self._public)}

    def issue_client_certificate(self, pki_role: str, common_name: str, *, ttl_seconds: int = 3600) -> dict:
        """Operator-only certificate-manager API; never expose to application IPC.

        The PKI role must constrain the exact service name, ClientAuth usage and
        maximum TTL server-side. The caller must validate the complete returned
        certificate/key/chain and activate a complete filesystem generation.
        """
        if (
            not isinstance(pki_role, str)
            or _NAME.fullmatch(pki_role) is None
            or not isinstance(common_name, str)
            or not 1 <= len(common_name) <= 253
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.-]*", common_name) is None
            or type(ttl_seconds) is not int
            or not 60 <= ttl_seconds <= 3600
        ):
            raise SignerError("signer_certificate_request_invalid")
        with self._lock:
            value = self._request(
                "POST",
                "/v1/pki/issue/" + pki_role,
                {"common_name": common_name, "ttl": f"{ttl_seconds}s"},
            )
            if not isinstance(value.get("data"), dict):
                raise SignerError("signer_certificate_response_invalid")
            return value["data"]
