#!/usr/bin/env python3
"""One-time local OpenBao initialization with operator-encrypted recovery.

No unseal share, bearer token, client key, or operator CA key is emitted or
written in plaintext. The initial Shamir response cannot be recovered if the
process dies before encrypting it; an attempt journal forbids automatic retries.
Cold boot requires either reviewed independent seal custody or operator recovery.

API sources:
https://openbao.org/docs/api/system/init/
https://openbao.org/docs/api/system/unseal/
https://openbao.org/docs/api/auth/cert/
https://openbao.org/docs/concepts/policies/
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import fcntl
import hashlib
import json
import os
import re
import resource
import ssl
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ORIGIN = "https://127.0.0.1:8200"
MAX_FILE = 1024 * 1024
SCHEMA = "pap-openbao-operator-recovery-v1"
# Native macOS SecKey RSA-OAEP-SHA256 uses the empty label. Schema and
# machine binding remain authenticated by the canonical AES-GCM AAD.
OAEP_LABEL = None
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")

# This fresh mount is exclusively for PAP issuer signing. Single-segment rules
# prevent prefix globs from accidentally granting config/rotate/import routes.
ISSUER_POLICY = """path "transit/keys/+" {
  capabilities = ["create", "read", "update"]
  allowed_parameters = {
    "type" = ["ecdsa-p256"]
    "derived" = [false]
    "exportable" = [false]
    "allow_plaintext_backup" = [false]
    "auto_rotate_period" = ["0"]
  }
}
path "transit/keys/+/+" {
  capabilities = ["deny"]
}
path "transit/keys/pap-provider-credentials" {
  capabilities = ["read"]
}
path "transit/encrypt/pap-provider-credentials" {
  capabilities = ["update"]
  allowed_parameters = {
    "context" = []
    "plaintext" = []
  }
}
path "transit/decrypt/pap-provider-credentials" {
  capabilities = ["update"]
  allowed_parameters = {
    "context" = []
    "ciphertext" = []
  }
}
path "transit/sign/+/sha2-256" {
  capabilities = ["update"]
  allowed_parameters = {
    "input" = []
    "prehashed" = [true]
    "key_version" = ["1"]
    "marshaling_algorithm" = ["jws"]
  }
}
"""
OPERATOR_POLICY = """path "*" {
  capabilities = ["create", "read", "update", "patch", "delete", "list", "scan", "sudo"]
}
"""


class BootstrapError(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class BootstrapPaths:
    enrollment_ca: Path = Path("/etc/pap/enrollment-ca.pem")
    enrollment_key: Path = Path("/etc/pap/enrollment/ca-key.pem")
    operator_ca: Path = Path("/etc/pap/enrollment/operator-ca.pem")
    client_ca_bundle: Path = Path("/etc/pap/openbao-client-ca.pem")
    envelope: Path = Path("/var/lib/pap-kms/operator-recovery.enc.json")
    attempt: Path = Path("/etc/pap/enrollment/bootstrap-attempt.json")
    receipt: Path = Path("/etc/pap/enrollment/bootstrap-receipt.json")
    lock: Path = Path("/run/pap-openbao-bootstrap.lock")
    machine_id: Path = Path("/etc/machine-id")
    audit: Path = Path("/var/lib/pap-kms/audit.jsonl")


DEFAULT_PATHS = BootstrapPaths()


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _object(pairs):
    value = {}
    for name, item in pairs:
        if name in value:
            raise ValueError("duplicate JSON member")
        value[name] = item
    return value


def _json(data: bytes) -> dict:
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_object)
        if not isinstance(value, dict):
            raise ValueError("object required")
        return value
    except (ValueError, UnicodeError):
        raise BootstrapError("bootstrap_json_invalid") from None


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def encrypt_recovery(packet: dict, public_key: rsa.RSAPublicKey, metadata: dict) -> bytes:
    """Standard RSA-OAEP-SHA256 key wrapping and AES-256-GCM payload encryption."""
    if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size != 4096:
        raise BootstrapError("operator_rsa4096_required")
    key, nonce = AESGCM.generate_key(bit_length=256), os.urandom(12)
    aad = {"schema": SCHEMA, "cipher": "AES-256-GCM", "wrap": "RSA-OAEP-SHA256", **metadata}
    if aad["schema"] != SCHEMA or aad["cipher"] != "AES-256-GCM" or aad["wrap"] != "RSA-OAEP-SHA256":
        raise BootstrapError("recovery_metadata_invalid")
    ciphertext = AESGCM(key).encrypt(nonce, _canonical(packet), _canonical(aad))
    wrapped = public_key.encrypt(
        key, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=OAEP_LABEL)
    )
    return (
        _canonical(
            {"aad": aad, "wrapped_key": _b64(wrapped), "nonce": _b64(nonce), "ciphertext": _b64(ciphertext)}
        )
        + b"\n"
    )


def _protected_parent(path: Path, owners: set[int]):
    if not path.is_absolute() or ".." in path.parts:
        raise BootstrapError("bootstrap_path_invalid")
    for directory in [path.parent, *path.parent.parents]:
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in owners:
            raise BootstrapError("bootstrap_directory_untrusted")
        if stat.S_IMODE(info.st_mode) & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
            raise BootstrapError("bootstrap_directory_untrusted")


def _read(path: Path, *, owner: int, private: bool, parent_owners: set[int] | None = None) -> bytes:
    _protected_parent(path, parent_owners or {0, owner})
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != owner
            or not 0 < info.st_size <= MAX_FILE
            or stat.S_IMODE(info.st_mode) & (0o077 if private else 0o022)
        ):
            raise BootstrapError("bootstrap_file_untrusted")
        return os.read(fd, MAX_FILE + 1)
    finally:
        os.close(fd)


def _write(
    path: Path,
    data: bytes,
    *,
    owner: int,
    parent_owners: set[int],
    private: bool,
    previous_sha256: str | None = None,
):
    _protected_parent(path, parent_owners)
    if len(data) > MAX_FILE:
        raise BootstrapError("bootstrap_file_too_large")
    mode = 0o600 if private else 0o644
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    temporary = ".pap-bootstrap-" + uuid.uuid4().hex
    descriptor = None
    try:
        descriptor = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=directory
        )
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(data)
            output.flush()
            os.fsync(descriptor)
        if previous_sha256 is None:
            os.link(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory, follow_symlinks=False)
            os.unlink(temporary, dir_fd=directory)
        else:
            if (
                _sha(_read(path, owner=owner, private=private, parent_owners=parent_owners))
                != previous_sha256
            ):
                raise BootstrapError("bootstrap_file_changed")
            os.replace(temporary, path.name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
        actual = _read(path, owner=owner, private=private, parent_owners=parent_owners)
        if actual != data:
            raise BootstrapError("bootstrap_durable_write_mismatch")
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)


def _private_pem(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode("ascii")


def _certificate_pem(certificate) -> str:
    return certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _new_operator_ca(now: datetime):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PAP independent operator CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(True, 0), True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def _client_leaf(ca, key, common_name: str, now: datetime):
    client_key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca.subject)
        .public_key(client_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(seconds=30))
        .not_valid_after(now + timedelta(minutes=5))
        .add_extension(x509.BasicConstraints(False, None), True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(client_key.public_key()), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
        .sign(key, hashes.SHA256())
    )
    return cert, client_key


def _tls_context(server_ca, client_ca, client_ca_key, common_name: str, now: datetime):
    if not hasattr(os, "memfd_create") or not Path("/proc/self/fd").is_dir():
        raise BootstrapError("linux_memfd_required")
    leaf, key = _client_leaf(client_ca, client_ca_key, common_name, now)
    context = ssl.create_default_context(cadata=_certificate_pem(server_ca))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    descriptors = []
    try:
        for name, value in (
            ("pap-bootstrap-public", _certificate_pem(leaf)),
            ("pap-bootstrap-private", _private_pem(key)),
        ):
            fd = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            descriptors.append(fd)
            os.fchmod(fd, 0o600)
            data = value.encode("ascii")
            with os.fdopen(fd, "wb", closefd=False) as output:
                output.write(data)
                output.flush()
            fcntl.fcntl(
                fd,
                fcntl.F_ADD_SEALS,
                fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL,
            )
        context.load_cert_chain(
            f"/proc/self/fd/{descriptors[0]}", f"/proc/self/fd/{descriptors[1]}", password=lambda: b""
        )
        return context
    except BootstrapError:
        raise
    except Exception:
        raise BootstrapError("bootstrap_tls_invalid") from None
    finally:
        for fd in descriptors:
            os.close(fd)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _HTTPS:
    def __init__(self, context):
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context), _NoRedirect()
        )

    def __call__(
        self,
        method: str,
        path: str,
        payload: dict | None = None,
        token: str | None = None,
        *,
        timeout: float | None = None,
    ):
        if not re.fullmatch(r"/v1/[A-Za-z0-9_/-]+", path):
            raise BootstrapError("bootstrap_api_path_invalid")
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if token is not None:
            headers["X-Vault-Token"] = token
        request = urllib.request.Request(
            ORIGIN + path,
            method=method,
            headers=headers,
            data=None if payload is None else _canonical(payload),
        )
        try:
            with self.opener.open(
                request,
                timeout=min(
                    60 if method == "POST" and path == "/v1/sys/init" else 10,
                    timeout if timeout is not None else 60,
                ),
            ) as response:
                data = response.read(MAX_FILE + 1)
                if len(data) > MAX_FILE:
                    raise BootstrapError("bootstrap_response_too_large")
                return response.status, _json(data) if data else {}
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
            return status, {}
        except BootstrapError:
            raise
        except Exception:
            raise BootstrapError("bootstrap_transport_unavailable") from None


def _harden():
    if sys.platform != "linux":
        raise BootstrapError("bootstrap_linux_required")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    if ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0) != 0:  # PR_SET_DUMPABLE
        raise BootstrapError("bootstrap_memory_protection_failed")
    try:
        result = subprocess.run(
            ["/usr/bin/timedatectl", "show", "--property=NTPSynchronized", "--value"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=3,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        if result.returncode != 0 or result.stdout.strip() != b"yes":
            raise BootstrapError("bootstrap_clock_untrusted")
    except (OSError, subprocess.TimeoutExpired):
        raise BootstrapError("bootstrap_clock_untrusted") from None


def _restart():
    try:
        result = subprocess.run(
            ["/usr/bin/systemctl", "restart", "pap-openbao.service"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=45,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        if result.returncode != 0:
            raise BootstrapError("bootstrap_preinit_restart_failed")
    except (OSError, subprocess.TimeoutExpired):
        raise BootstrapError("bootstrap_preinit_restart_failed") from None


class Bootstrapper:
    """One-shot state machine. Underscored injections are solely for isolated tests."""

    def __init__(
        self,
        operator_public_key: Path,
        operator_public_key_sha256: str,
        machine_id: str,
        *,
        _paths: BootstrapPaths = DEFAULT_PATHS,
        _owner_uid: int = 0,
        _kms_uid: int | None = None,
        _transport_factory: Callable | None = None,
        _context_factory: Callable = _tls_context,
        _restart_service: Callable = _restart,
        _harden_process: Callable = _harden,
        _clock: Callable = lambda: datetime.now(UTC),
        _sleep: Callable = time.sleep,
        _monotonic: Callable = time.monotonic,
    ):
        if not _SHA256.fullmatch(operator_public_key_sha256) or not re.fullmatch(
            r"[A-Za-z0-9_-]{1,128}", machine_id
        ):
            raise BootstrapError("bootstrap_public_arguments_invalid")
        self.paths, self.owner = _paths, _owner_uid
        self.kms_uid = _owner_uid if _kms_uid is None else _kms_uid
        self.public_path, self.public_pin, self.machine_id = (
            Path(operator_public_key),
            operator_public_key_sha256,
            machine_id,
        )
        self.transport_factory = _transport_factory or (lambda context, identity: _HTTPS(context))
        self.context_factory, self.restart_service = _context_factory, _restart_service
        self.harden_process, self.clock, self.sleep = _harden_process, _clock, _sleep
        self.monotonic = _monotonic
        self.checkpoint_plan = None
        self.checkpoint_journal_chain = []
        self.envelope_sha = self.attempt_sha = None
        self.initialization_requested = False
        self._ca = self._ca_key = self._operator_ca = self._operator_key = None

    def _request(self, transport, method, path, payload=None, token=None, *, expected=(200, 204)):
        try:
            status, value = transport(method, path, payload, token)
            if type(status) is not int or status not in expected or not isinstance(value, dict):
                raise BootstrapError("bootstrap_api_request_failed")
            return value
        except BootstrapError:
            raise
        except Exception:
            raise BootstrapError("bootstrap_transport_unavailable") from None

    def _identity(self, name: str):
        ca, key, cn = (self._ca, self._ca_key, "pap-bootstrap")
        if name == "operator":
            ca, key, cn = self._operator_ca, self._operator_key, "pap-operator"
        elif name == "issuer":
            cn = "pap-issuer"
        context = self.context_factory(self._ca, ca, key, cn, self.clock())
        return self.transport_factory(context, name)

    def _load(self):
        if os.geteuid() != self.owner:
            raise BootstrapError("bootstrap_root_required")
        self.harden_process()
        der = _read(self.public_path, owner=self.owner, private=False)
        if _sha(der) != self.public_pin:
            raise BootstrapError("operator_public_key_pin_mismatch")
        try:
            self.public_key = serialization.load_der_public_key(der)
            if (
                not isinstance(self.public_key, rsa.RSAPublicKey)
                or self.public_key.key_size != 4096
                or self.public_key.public_numbers().e != 65537
            ):
                raise ValueError("RSA-4096 with exponent 65537 required")
        except Exception:
            raise BootstrapError("operator_rsa4096_required") from None
        try:
            parent = self.paths.enrollment_key.parent.lstat()
            if parent.st_uid != self.owner or stat.S_IMODE(parent.st_mode) != 0o700:
                raise ValueError("private infrastructure store required")
            self._ca = x509.load_pem_x509_certificate(
                _read(self.paths.enrollment_ca, owner=self.owner, private=False)
            )
            self._ca_key = serialization.load_pem_private_key(
                _read(self.paths.enrollment_key, owner=self.owner, private=True), password=None
            )
            if (
                not isinstance(self._ca_key, ec.EllipticCurvePrivateKey)
                or not isinstance(self._ca_key.curve, ec.SECP256R1)
                or self._ca.public_key().public_numbers() != self._ca_key.public_key().public_numbers()
                or not self._ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                or not self._ca.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
                or self._ca.not_valid_before_utc > self.clock() - timedelta(seconds=30)
                or self._ca.not_valid_after_utc <= self.clock() + timedelta(hours=1)
            ):
                raise ValueError("invalid infrastructure CA")
        except Exception:
            raise BootstrapError("bootstrap_enrollment_ca_invalid") from None
        host_id = _read(self.paths.machine_id, owner=self.owner, private=False).strip()
        if re.fullmatch(rb"[0-9a-f]{32}", host_id) is None:
            raise BootstrapError("bootstrap_machine_identity_invalid")
        self.host_identity_sha256 = _sha(host_id)
        self.ca_sha256 = _sha(self._ca.public_bytes(serialization.Encoding.DER))

    def _completed(self):
        receipt = _json(_read(self.paths.receipt, owner=self.owner, private=False))
        envelope = _read(
            self.paths.envelope, owner=self.owner, private=True, parent_owners={0, self.owner, self.kms_uid}
        )
        if (
            receipt.get("schema") != "pap-openbao-bootstrap-receipt-v1"
            or receipt.get("state") != "complete"
            or receipt.get("machine_id") != self.machine_id
            or receipt.get("host_identity_sha256") != self.host_identity_sha256
            or receipt.get("operator_public_key_sha256") != self.public_pin
            or receipt.get("enrollment_ca_sha256") != self.ca_sha256
            or receipt.get("envelope_sha256") != _sha(envelope)
            or receipt.get("initial_root_token_revoked") is not True
        ):
            raise BootstrapError("bootstrap_existing_state_requires_operator_review")
        return {
            "outcome": "already_complete",
            "initialized": True,
            "envelope_sha256": _sha(envelope),
            "envelope_path": str(self.paths.envelope),
        }

    def _journal(self, state: str):
        value = {
            "schema": "pap-openbao-bootstrap-attempt-v1",
            "state": state,
            "machine_id": self.machine_id,
            "host_identity_sha256": self.host_identity_sha256,
            "operator_public_key_sha256": self.public_pin,
            "enrollment_ca_sha256": self.ca_sha256,
            "recorded_at": self.clock().isoformat(),
        }
        if self.envelope_sha:
            value["envelope_sha256"] = self.envelope_sha
        if self.attempt_sha:
            value["previous_attempt_sha256"] = self.attempt_sha
        if self.checkpoint_plan:
            value["checkpoint_plan_sha256"] = self.checkpoint_plan["checkpoint_plan_sha256"]
        data = _canonical(value) + b"\n"
        _write(
            self.paths.attempt,
            data,
            owner=self.owner,
            parent_owners={0, self.owner},
            private=False,
            previous_sha256=self.attempt_sha,
        )
        self.attempt_sha = _sha(data)
        if self.checkpoint_plan:
            self.checkpoint_journal_chain.append(value)

    def _envelope(self, packet: dict, stage: str):
        metadata = {
            "machine_id": self.machine_id,
            "host_identity_sha256": self.host_identity_sha256,
            "operator_public_key_sha256": self.public_pin,
            "enrollment_ca_sha256": self.ca_sha256,
            "operator_ca_sha256": _sha(self._operator_ca.public_bytes(serialization.Encoding.DER)),
            "stage": stage,
            "recorded_at": self.clock().isoformat(),
        }
        data = encrypt_recovery(packet, self.public_key, metadata)
        _write(
            self.paths.envelope,
            data,
            owner=self.owner,
            parent_owners={0, self.owner, self.kms_uid},
            private=True,
            previous_sha256=self.envelope_sha,
        )
        self.envelope_sha = _sha(data)

    def _publish_operator_trust(self):
        if self.initialization_requested:
            raise BootstrapError("bootstrap_restart_after_initialization_forbidden")
        _write(
            self.paths.operator_ca,
            _certificate_pem(self._operator_ca).encode(),
            owner=self.owner,
            parent_owners={0, self.owner},
            private=False,
        )
        before = _read(self.paths.client_ca_bundle, owner=self.owner, private=False)
        certificates = x509.load_pem_x509_certificates(before)
        if len(certificates) != 1 or certificates[0] != self._ca:
            raise BootstrapError("bootstrap_initial_client_trust_unexpected")
        _write(
            self.paths.client_ca_bundle,
            (_certificate_pem(self._ca) + _certificate_pem(self._operator_ca)).encode(),
            owner=self.owner,
            parent_owners={0, self.owner},
            private=False,
            previous_sha256=_sha(before),
        )

    def _restart_uninitialized(self, bootstrap):
        if (
            self.initialization_requested
            or self._request(bootstrap, "GET", "/v1/sys/init").get("initialized") is not False
        ):
            raise BootstrapError("bootstrap_restart_after_initialization_forbidden")
        self.restart_service()
        operator = self._identity("operator")
        deadline = time.monotonic() + 30
        for attempt in range(40):
            try:
                value = self._request(operator, "GET", "/v1/sys/init")
                if value.get("initialized") is not False:
                    raise BootstrapError("bootstrap_existing_state_requires_operator_review")
                return operator
            except BootstrapError as error:
                if (
                    error.code != "bootstrap_transport_unavailable"
                    or attempt == 39
                    or time.monotonic() >= deadline
                ):
                    raise
                self.sleep(0.25)
        raise BootstrapError("bootstrap_preinit_restart_failed")

    @staticmethod
    def _role(certificate, policy: str, common_name: str):
        return {
            "certificate": _certificate_pem(certificate),
            "allowed_common_names": [common_name],
            "token_policies": [policy],
            "token_ttl": 300,
            "token_max_ttl": 300,
            "token_explicit_max_ttl": 300,
            "token_no_default_policy": True,
            "token_bound_cidrs": ["127.0.0.1/32"],
            "token_type": "service",
        }

    def _verify_audit(self, bootstrap, root_token: str):
        audit = self._request(bootstrap, "GET", "/v1/sys/audit", token=root_token)
        devices = audit.get("data", audit)
        device = devices.get("pap/") if isinstance(devices, dict) else None
        if (
            not isinstance(devices, dict)
            or set(devices) != {"pap/"}
            or not isinstance(device, dict)
            or device.get("type") != "file"
            or not isinstance(device.get("options"), dict)
            or device["options"].get("file_path") != str(self.paths.audit)
            or device["options"].get("log_raw") != "false"
            or device["options"].get("hmac_accessor") != "true"
        ):
            raise BootstrapError("bootstrap_declarative_audit_verification_failed")

    def _configure(self, bootstrap, operator, root_token: str):
        self._verify_audit(bootstrap, root_token)
        requests = [
            (
                "/v1/sys/mounts/transit",
                {"type": "transit", "description": "Dedicated PAP issuer signing keys"},
            ),
            ("/v1/sys/auth/cert", {"type": "cert"}),
            ("/v1/transit/keys/pap-provider-credentials", {
                "type": "aes256-gcm96", "derived": True, "exportable": False,
                "allow_plaintext_backup": False, "auto_rotate_period": "86400s",
            }),
            ("/v1/sys/policies/acl/pap-issuer", {"policy": ISSUER_POLICY}),
            ("/v1/sys/policies/acl/pap-operator", {"policy": OPERATOR_POLICY}),
            ("/v1/auth/cert/config", {"disable_binding": False}),
            ("/v1/auth/cert/certs/pap-issuer", self._role(self._ca, "pap-issuer", "pap-issuer")),
            (
                "/v1/auth/cert/certs/pap-operator",
                self._role(self._operator_ca, "pap-operator", "pap-operator"),
            ),
        ]
        for path, payload in requests:
            self._request(bootstrap, "POST", path, payload, root_token)
        operator_token = self._login(operator, "pap-operator")
        issuer = self._identity("issuer")
        issuer_token = self._login(issuer, "pap-issuer")
        name = "pap-" + "0" * 32
        paths = {
            f"transit/keys/{name}": {"create", "read", "update"},
            f"transit/sign/{name}/sha2-256": {"update"},
            f"transit/export/signing-key/{name}": {"deny"},
            "sys/policies/acl/pap-operator": {"deny"},
            "auth/cert/certs/pap-operator": {"deny"},
            f"transit/keys/{name}/rotate": {"deny"},
            f"transit/keys/{name}/config": {"deny"},
            "other-mount/keys/not-a-pap-key": {"deny"},
        }
        value = self._request(
            operator,
            "POST",
            "/v1/sys/capabilities",
            {"token": issuer_token, "paths": list(paths)},
            operator_token,
        )
        caps = value.get("data", value)
        if not isinstance(caps, dict) or any(
            set(caps.get(path, [])) != allowed for path, allowed in paths.items()
        ):
            raise BootstrapError("bootstrap_issuer_policy_verification_failed")
        self.probe_key = self._signing_probe(issuer, issuer_token)
        spoof_context = self.context_factory(self._ca, self._ca, self._ca_key, "pap-operator", self.clock())
        spoof = self.transport_factory(spoof_context, "spoof_operator")
        self._request(spoof, "POST", "/v1/auth/cert/login", {"name": "pap-operator"}, expected=(400, 403))
        for token in (issuer_token, operator_token):
            self._request(bootstrap, "POST", "/v1/auth/token/revoke", {"token": token}, root_token)

    def _signing_probe(self, issuer, token):
        name = "pap-" + uuid.uuid4().hex
        creation = {
            "type": "ecdsa-p256",
            "derived": False,
            "exportable": False,
            "allow_plaintext_backup": False,
            "auto_rotate_period": "0",
        }
        self._request(issuer, "POST", "/v1/transit/keys/" + name, creation, token)
        data = self._request(issuer, "GET", "/v1/transit/keys/" + name, token=token).get("data")
        try:
            if (
                not isinstance(data, dict)
                or data.get("type") != "ecdsa-p256"
                or data.get("exportable") is not False
                or data.get("allow_plaintext_backup") is not False
                or data.get("latest_version") != 1
                or set(data.get("keys", {})) != {"1"}
            ):
                raise ValueError("unexpected probe key")
            public = serialization.load_pem_public_key(data["keys"]["1"]["public_key"].encode("ascii"))
            if not isinstance(public, ec.EllipticCurvePublicKey) or not isinstance(
                public.curve, ec.SECP256R1
            ):
                raise ValueError("unexpected probe curve")
            digest = hashlib.sha256(b"PAP bootstrap signing policy probe v1").digest()
            result = self._request(
                issuer,
                "POST",
                "/v1/transit/sign/" + name + "/sha2-256",
                {"input": _b64(digest), "prehashed": True, "key_version": "1", "marshaling_algorithm": "jws"},
                token,
            ).get("data")
            signature = result.get("signature") if isinstance(result, dict) else None
            if not isinstance(signature, str) or not signature.startswith("vault:v1:"):
                raise ValueError("unexpected signature")
            encoded = signature[len("vault:v1:") :]
            if re.fullmatch(r"[A-Za-z0-9_-]{86}(?:==)?", encoded) is None:
                raise ValueError("unexpected signature encoding")
            raw = base64.urlsafe_b64decode(encoded.rstrip("=") + "==")
            if len(raw) != 64 or base64.urlsafe_b64encode(raw).decode().rstrip("=") != encoded.rstrip("="):
                raise ValueError("unexpected signature length")
            der = utils.encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
            public.verify(der, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        except (ValueError, TypeError, KeyError, InvalidSignature):
            raise BootstrapError("bootstrap_signing_probe_failed") from None
        for method, path, payload in [
            ("POST", f"/v1/transit/keys/{name}/rotate", {}),
            ("POST", f"/v1/transit/keys/{name}/config", {"exportable": True}),
            ("POST", f"/v1/transit/keys/{name}/trim", {"min_available_version": 1}),
            ("DELETE", f"/v1/transit/keys/{name}", None),
            ("GET", f"/v1/transit/export/signing-key/{name}", None),
            ("POST", "/v1/sys/policies/acl/pap-operator", {"policy": OPERATOR_POLICY}),
        ]:
            self._request(issuer, method, path, payload, token, expected=(403,))
        return name

    def _login(self, transport, role):
        auth = self._request(transport, "POST", "/v1/auth/cert/login", {"name": role}).get("auth")
        if (
            not isinstance(auth, dict)
            or not isinstance(auth.get("client_token"), str)
            or not 16 <= len(auth["client_token"]) <= 4096
            or any(not 33 <= ord(char) <= 126 for char in auth["client_token"])
            or auth.get("policies") != [role]
            or type(auth.get("lease_duration")) is not int
            or not 1 <= auth["lease_duration"] <= 300
        ):
            raise BootstrapError("bootstrap_role_verification_failed")
        return auth["client_token"]

    def run(self, *, apply: bool = False) -> dict:
        self._load()
        bootstrap = self._identity("bootstrap")
        initialized = self._request(bootstrap, "GET", "/v1/sys/init").get("initialized")
        if type(initialized) is not bool:
            raise BootstrapError("bootstrap_initialization_status_invalid")
        if initialized:
            try:
                return self._completed()
            except (OSError, BootstrapError):
                raise BootstrapError("bootstrap_existing_state_requires_operator_review") from None
        for path in (
            self.paths.attempt,
            self.paths.receipt,
            self.paths.envelope,
            self.paths.operator_ca,
        ):
            if path.exists() or path.is_symlink():
                raise BootstrapError("bootstrap_existing_state_requires_operator_review")
        try:
            bundle = x509.load_pem_x509_certificates(
                _read(self.paths.client_ca_bundle, owner=self.owner, private=False)
            )
            if len(bundle) != 1 or bundle[0] != self._ca:
                raise ValueError("unexpected initial listener trust")
            _protected_parent(self.paths.envelope, {0, self.owner, self.kms_uid})
            parent = self.paths.envelope.parent.lstat()
            if parent.st_uid not in {self.owner, self.kms_uid} or stat.S_IMODE(parent.st_mode) != 0o700:
                raise ValueError("private KMS state required")
            space = os.statvfs(self.paths.envelope.parent)
            if space.f_bavail * space.f_frsize < MAX_FILE * 3:
                raise ValueError("recovery storage capacity required")
        except Exception:
            raise BootstrapError("bootstrap_storage_or_initial_trust_invalid") from None
        if not apply:
            return {
                "outcome": "plan",
                "initialized": False,
                "operator_public_key_sha256": self.public_pin,
                "secret_shares": 5,
                "secret_threshold": 3,
                "root_token_will_be_revoked": True,
                "automatic_cold_boot_unseal": False,
                "envelope_path": str(self.paths.envelope),
            }
        return self._apply(bootstrap)

    @contextmanager
    def _locked(self, *, create: bool = True):
        _protected_parent(self.paths.lock, {0, self.owner})
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(self.paths.lock, flags | (os.O_CREAT if create else 0), 0o600)
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != self.owner
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise BootstrapError("bootstrap_lock_untrusted")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        except BootstrapError:
            raise
        except Exception:
            raise BootstrapError("bootstrap_stopped_operator_review_required") from None
        finally:
            os.close(fd)

    def _apply(self, bootstrap):
        with self._locked():
            if self._request(bootstrap, "GET", "/v1/sys/init").get("initialized") is not False:
                raise BootstrapError("bootstrap_existing_state_requires_operator_review")
            return self._initialize(bootstrap)

    def _wait_active(self, bootstrap):
        deadline = self.monotonic() + 30
        for _ in range(120):
            remaining = deadline - self.monotonic()
            if remaining <= 0:
                break
            try:
                status, value = bootstrap("GET", "/v1/sys/health", None, None, timeout=min(10.0, remaining))
                if type(status) is not int or not isinstance(value, dict):
                    raise BootstrapError("bootstrap_health_response_invalid")
                if status == 200:
                    if (
                        value.get("initialized") is True
                        and value.get("sealed") is False
                        and value.get("standby") is False
                    ):
                        return
                    raise BootstrapError("bootstrap_health_response_invalid")
                if status not in {429, 472, 473, 503}:
                    raise BootstrapError("bootstrap_health_response_invalid")
            except BootstrapError as error:
                if error.code != "bootstrap_transport_unavailable":
                    raise
            except Exception:
                raise BootstrapError("bootstrap_transport_unavailable") from None
            remaining = deadline - self.monotonic()
            if remaining <= 0:
                break
            self.sleep(min(0.25, remaining))
        raise BootstrapError("bootstrap_active_readiness_timeout")

    def _checkpoint(self, packet: dict, expected_envelope_sha256: str):
        try:
            if (
                not _SHA256.fullmatch(expected_envelope_sha256)
                or not isinstance(packet, dict)
                or len(_canonical(packet)) > MAX_FILE
                or self.paths.receipt.exists()
                or self.paths.receipt.is_symlink()
            ):
                raise ValueError("invalid checkpoint")
            raw_envelope = _read(
                self.paths.envelope,
                owner=self.owner,
                private=True,
                parent_owners={0, self.owner, self.kms_uid},
            )
            if _sha(raw_envelope) != expected_envelope_sha256:
                raise ValueError("envelope changed")
            envelope = _json(raw_envelope)
            if set(envelope) != {"aad", "wrapped_key", "nonce", "ciphertext"}:
                raise ValueError("unexpected envelope")
            aad = envelope["aad"]
            journal_bytes = _read(self.paths.attempt, owner=self.owner, private=False)
            journal = _json(journal_bytes)
            bindings = {
                "machine_id": self.machine_id,
                "host_identity_sha256": self.host_identity_sha256,
                "operator_public_key_sha256": self.public_pin,
                "enrollment_ca_sha256": self.ca_sha256,
            }
            if (
                not isinstance(aad, dict)
                or aad.get("schema") != SCHEMA
                or aad.get("cipher") != "AES-256-GCM"
                or aad.get("wrap") != "RSA-OAEP-SHA256"
                or aad.get("stage") != "initialization-response-received"
                or any(aad.get(k) != v or journal.get(k) != v for k, v in bindings.items())
                or journal.get("schema") != "pap-openbao-bootstrap-attempt-v1"
                or journal.get("state") != "recovery_envelope_durable"
                or journal.get("envelope_sha256") != expected_envelope_sha256
                or packet.get("schema") != SCHEMA
                or packet.get("machine_id") != self.machine_id
                or packet.get("host_identity_sha256") != self.host_identity_sha256
                or packet.get("secret_shares") != 5
                or packet.get("secret_threshold") != 3
            ):
                raise ValueError("checkpoint binding mismatch")
            shares, root_token = packet.get("unseal_shares"), packet.get("initial_root_token")
            initial = packet.get("initialization_response")
            if (
                not isinstance(shares, list)
                or len(shares) != 5
                or any(not isinstance(x, str) or not 32 <= len(x) <= 512 for x in shares)
                or len(set(shares)) != 5
                or not isinstance(root_token, str)
                or not 16 <= len(root_token) <= 4096
                or not isinstance(initial, dict)
                or initial.get("keys_base64") != shares
                or initial.get("root_token") != root_token
            ):
                raise ValueError("initialization material mismatch")
            for share in shares:
                if not 16 <= len(base64.b64decode(share, validate=True)) <= 128:
                    raise ValueError("invalid share")
            enrollment_ca = x509.load_pem_x509_certificate(packet["enrollment_ca"].encode("ascii"))
            enrollment_key = serialization.load_pem_private_key(
                packet["enrollment_ca_private_key"].encode("ascii"), None
            )
            self._operator_ca = x509.load_pem_x509_certificate(packet["operator_ca"].encode("ascii"))
            self._operator_key = serialization.load_pem_private_key(
                packet["operator_ca_private_key"].encode("ascii"), None
            )
            for ca, key in [(enrollment_ca, enrollment_key), (self._operator_ca, self._operator_key)]:
                if (
                    not isinstance(key, ec.EllipticCurvePrivateKey)
                    or not isinstance(key.curve, ec.SECP256R1)
                    or ca.public_key().public_numbers() != key.public_key().public_numbers()
                    or not ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                    or not ca.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
                    or ca.not_valid_before_utc > self.clock()
                    or ca.not_valid_after_utc <= self.clock() + timedelta(hours=1)
                ):
                    raise ValueError("invalid recovery CA")
                ca.verify_directly_issued_by(ca)
            if (
                enrollment_ca != self._ca
                or self._operator_ca == self._ca
                or self._operator_ca.public_key().public_numbers() == self._ca.public_key().public_numbers()
                or x509.load_pem_x509_certificate(
                    _read(self.paths.operator_ca, owner=self.owner, private=False)
                )
                != self._operator_ca
                or x509.load_pem_x509_certificates(
                    _read(self.paths.client_ca_bundle, owner=self.owner, private=False)
                )
                != [self._ca, self._operator_ca]
            ):
                raise ValueError("deployed CA mismatch")
            operator_sha = _sha(self._operator_ca.public_bytes(serialization.Encoding.DER))
            if aad.get("operator_ca_sha256") != operator_sha:
                raise ValueError("operator CA mismatch")
        except Exception:
            raise BootstrapError("bootstrap_checkpoint_verification_failed") from None
        self.envelope_sha = expected_envelope_sha256
        self.attempt_sha = _sha(journal_bytes)
        self.initialization_requested = True
        bootstrap = self._identity("bootstrap")
        if self._request(bootstrap, "GET", "/v1/sys/init").get("initialized") is not True:
            raise BootstrapError("bootstrap_checkpoint_server_state_invalid")
        self._wait_active(bootstrap)
        lookup = self._request(bootstrap, "GET", "/v1/auth/token/lookup-self", token=root_token).get("data")
        if (
            not isinstance(lookup, dict)
            or lookup.get("policies") != ["root"]
            or lookup.get("id") != root_token
        ):
            raise BootstrapError("bootstrap_checkpoint_root_token_invalid")
        self._verify_audit(bootstrap, root_token)
        for route, forbidden, backend in [
            ("/v1/sys/mounts", "transit/", "transit"),
            ("/v1/sys/auth", "cert/", "cert"),
        ]:
            response = self._request(bootstrap, "GET", route, token=root_token)
            values = response.get("data", response)
            if (
                not isinstance(values, dict)
                or forbidden in values
                or any(
                    not isinstance(value, dict) or value.get("type") == backend for value in values.values()
                )
            ):
                raise BootstrapError("bootstrap_checkpoint_partial_configuration")
        for policy in ("pap-issuer", "pap-operator"):
            self._request(
                bootstrap, "GET", "/v1/sys/policies/acl/" + policy, token=root_token, expected=(404,)
            )
        plan = {
            "schema": "pap-openbao-checkpoint-plan-v1",
            **bindings,
            "envelope_sha256": self.envelope_sha,
            "previous_attempt_sha256": self.attempt_sha,
            "operator_ca_sha256": operator_sha,
            "packet_sha256": _sha(_canonical(packet)),
            "initialized": True,
            "sealed": False,
            "standby": False,
            "root_token_policy_verified": True,
            "pap_configuration_absent": True,
            "declarative_audit_verified": True,
        }
        plan["checkpoint_plan_sha256"] = _sha(_canonical(plan))
        return plan, bootstrap, self._identity("operator"), root_token

    def complete_checkpoint(
        self,
        packet: dict,
        expected_envelope_sha256: str,
        *,
        apply: bool = False,
        expected_plan_sha256: str | None = None,
    ):
        """Finish only an operator-reviewed, durable pre-configuration checkpoint.

        The trusted operator supplies authenticated decrypted packet data in RAM.
        This method never initializes, unseals, restarts, or rewrites the envelope.
        """
        self._load()
        with self._locked(create=False):
            plan, bootstrap, operator, root_token = self._checkpoint(packet, expected_envelope_sha256)
            if not apply:
                return {"outcome": "checkpoint_plan", **plan}
            if (
                not isinstance(expected_plan_sha256, str)
                or not _SHA256.fullmatch(expected_plan_sha256)
                or expected_plan_sha256 != plan["checkpoint_plan_sha256"]
            ):
                raise BootstrapError("bootstrap_checkpoint_plan_not_approved")
            self.checkpoint_plan = plan
            self._journal("checkpoint_completion_approved")
            return self._finish(bootstrap, operator, root_token, outcome="checkpoint_completed")

    def _initialize(self, bootstrap):
        self._operator_ca, self._operator_key = _new_operator_ca(self.clock())
        if self._operator_ca.public_key().public_numbers() == self._ca.public_key().public_numbers():
            raise BootstrapError("bootstrap_operator_ca_not_independent")
        packet = {
            "schema": SCHEMA,
            "machine_id": self.machine_id,
            "host_identity_sha256": self.host_identity_sha256,
            "enrollment_ca": _certificate_pem(self._ca),
            "enrollment_ca_private_key": _private_pem(self._ca_key),
            "operator_ca": _certificate_pem(self._operator_ca),
            "operator_ca_private_key": _private_pem(self._operator_key),
            "secret_shares": 5,
            "secret_threshold": 3,
            "unseal_shares": [],
            "initial_root_token": None,
        }
        self._journal("prepared")
        self._envelope(packet, "pre-initialization")
        self._publish_operator_trust()
        operator = self._restart_uninitialized(bootstrap)
        self._journal("initialization_requested")
        self.initialization_requested = True
        try:
            initial = self._request(
                bootstrap, "POST", "/v1/sys/init", {"secret_shares": 5, "secret_threshold": 3}
            )
        except Exception:
            self._journal("initialization_outcome_unknown")
            raise BootstrapError(
                "bootstrap_initialization_outcome_unknown_operator_review_required"
            ) from None
        # Encrypt the full response before even validating its expected schema.
        # An unexpected response must never discard potentially useful material.
        packet["initialization_response"] = initial
        shares, root_token = initial.get("keys_base64"), initial.get("root_token")
        packet["unseal_shares"], packet["initial_root_token"] = shares, root_token
        self._envelope(packet, "initialization-response-received")
        self._journal("recovery_envelope_durable")
        if (
            not isinstance(shares, list)
            or len(shares) != 5
            or any(not isinstance(share, str) or not 32 <= len(share) <= 512 for share in shares)
            or len(set(shares)) != 5
            or not isinstance(root_token, str)
            or not 16 <= len(root_token) <= 4096
        ):
            raise BootstrapError("bootstrap_initialization_response_requires_operator_review")
        for index, share in enumerate(shares[:3]):
            value = self._request(bootstrap, "POST", "/v1/sys/unseal", {"key": share})
            if value.get("sealed") is not (index != 2) or value.get("t") != 3 or value.get("n") != 5:
                raise BootstrapError("bootstrap_unseal_outcome_requires_operator_review")
        self._wait_active(bootstrap)
        return self._finish(bootstrap, operator, root_token, outcome="initialized")

    def _finish(self, bootstrap, operator, root_token: str, *, outcome: str):
        self._configure(bootstrap, operator, root_token)
        self._journal("configured")
        self._request(bootstrap, "POST", "/v1/auth/token/revoke-self", {}, root_token)
        self._request(bootstrap, "GET", "/v1/auth/token/lookup-self", token=root_token, expected=(401, 403))
        receipt = {
            "schema": "pap-openbao-bootstrap-receipt-v1",
            "state": "complete",
            "machine_id": self.machine_id,
            "host_identity_sha256": self.host_identity_sha256,
            "operator_public_key_sha256": self.public_pin,
            "enrollment_ca_sha256": self.ca_sha256,
            "operator_ca_sha256": _sha(self._operator_ca.public_bytes(serialization.Encoding.DER)),
            "envelope_sha256": self.envelope_sha,
            "initial_root_token_revoked": True,
            "checkpoint_completion": self.checkpoint_plan is not None,
            "secret_shares": 5,
            "secret_threshold": 3,
            "issuer_policy_verified": True,
            "issuer_real_signing_and_denials_verified": True,
            "broker_ca_operator_authentication_denied": True,
            "dedicated_pap_transit_mount": True,
            "key_name_prefix_enforced_by_acl": False,
            "bootstrap_probe_key": self.probe_key,
            "bootstrap_probe_key_scope": "nonexportable key retained after signing a public bootstrap marker",
            "audit_file_device_enabled": True,
            "audit_raw_logging": False,
            "audit_accessor_hmac": True,
            "audit_log_rotation_automated": False,
            "audit_log_capacity_monitoring_required": True,
            "automatic_cold_boot_unseal": False,
            "recorded_at": self.clock().isoformat(),
        }
        if self.checkpoint_plan:
            receipt["checkpoint_plan_sha256"] = self.checkpoint_plan["checkpoint_plan_sha256"]
            receipt["checkpoint_previous_attempt_sha256"] = self.checkpoint_plan["previous_attempt_sha256"]
            receipt["configured_attempt_sha256"] = self.attempt_sha
            receipt["checkpoint_journal_chain"] = list(self.checkpoint_journal_chain)
        _write(
            self.paths.receipt,
            _canonical(receipt) + b"\n",
            owner=self.owner,
            parent_owners={0, self.owner},
            private=False,
        )
        self._journal("complete")
        return {
            "outcome": outcome,
            "initialized": True,
            "root_token_revoked": True,
            "secret_shares": 5,
            "secret_threshold": 3,
            "envelope_sha256": self.envelope_sha,
            "envelope_path": str(self.paths.envelope),
            "receipt_path": str(self.paths.receipt),
            "automatic_cold_boot_unseal": False,
        }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Root-only one-shot OpenBao bootstrap; default is read-only plan"
    )
    parser.add_argument("--operator-public-key", type=Path, required=True)
    parser.add_argument("--operator-public-key-sha256", required=True)
    parser.add_argument("--machine-id", required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--plan", action="store_true")
    mode.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        import pwd

        kms_uid = pwd.getpwnam("pap-kms").pw_uid
        result = Bootstrapper(
            args.operator_public_key, args.operator_public_key_sha256, args.machine_id, _kms_uid=kms_uid
        ).run(apply=args.apply)
        print(json.dumps(result, sort_keys=True))
        return 0
    except BaseException as error:
        code = (
            error.code if isinstance(error, BootstrapError) else "bootstrap_stopped_operator_review_required"
        )
        print(json.dumps({"outcome": "stopped", "code": code}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
