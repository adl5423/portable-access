"""Local UID-attested certificate enrollment, independent of OpenBao authentication.

The infrastructure CA is delivered to a dedicated service by systemd credentials.
It is never a JWT signing key. Only the enrolled process creates its client key.
The broker issues fixed identities and never accepts filesystem paths or names
from its caller. Linux SO_PEERCRED is mandatory outside explicit test injection.
"""

from __future__ import annotations

import base64
import fcntl
import ipaddress
import json
import logging
import math
import os
import re
import select
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, SignatureAlgorithmOID

from .signers import SignerError, _json_object, _trusted_file

MAX_MESSAGE = 16384
MAX_CSR = 4096
_GENERATION = re.compile(r"generation-[0-9a-f]{32}\Z")
_NAME = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_LOG = logging.getLogger(__name__)
_SYSTEMD_CA_KEY = Path("/run/credentials/pap-enroller.service/enrollment-ca-key")


def _event(event: str, code: str, uid: int | None = None):
    fields = {"event": event, "code": code}
    if uid is not None:
        fields["uid"] = uid
    _LOG.info(json.dumps(fields, separators=(",", ":"), sort_keys=True))


def _peer_uid(connection: socket.socket) -> int:
    if not hasattr(socket, "SO_PEERCRED"):
        raise SignerError("enrollment_kernel_identity_unavailable")
    value = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    return struct.unpack("3i", value)[1]


def _clock_ready() -> bool:
    try:
        result = subprocess.run(
            ["/usr/bin/timedatectl", "show", "--property=NTPSynchronized", "--value"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=3,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        return result.returncode == 0 and result.stdout.strip() == b"yes"
    except (OSError, subprocess.TimeoutExpired):
        return False


def _absolute(path: Path | str) -> Path:
    value = Path(path)
    if not value.is_absolute() or ".." in value.parts or "\x00" in str(value):
        raise ValueError("absolute canonical enrollment paths required")
    return value


def _trusted_ancestors(path: Path, owners: set[int]):
    for directory in [path, *path.parents]:
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in owners:
            raise SignerError("enrollment_directory_untrusted")
        # Root's sticky temporary directory permits isolated local tests; the
        # broker's immediate parent is checked separately and cannot be writable.
        if stat.S_IMODE(info.st_mode) & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
            raise SignerError("enrollment_directory_untrusted")


def _directory(path: Path, *, uid: int, gid: int | None = None):
    _trusted_ancestors(path, {0, uid})
    info = path.lstat()
    if info.st_uid != uid or (gid is not None and info.st_gid != gid) or stat.S_IMODE(info.st_mode) & 0o027:
        raise SignerError("enrollment_directory_untrusted")


def _receive_exact(connection: socket.socket, length: int, deadline: float) -> bytes:
    pieces = bytearray()
    while len(pieces) < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise SignerError("enrollment_message_timeout")
        connection.settimeout(remaining)
        chunk = connection.recv(length - len(pieces))
        if not chunk:
            raise SignerError("enrollment_message_invalid")
        pieces.extend(chunk)
    return bytes(pieces)


def _receive(connection: socket.socket) -> dict:
    # Header and body share one deadline; a byte-dripping peer cannot indefinitely
    # postpone independent listener certificate maintenance.
    deadline = time.monotonic() + min(connection.gettimeout() or 5.0, 5.0)
    length = struct.unpack("!I", _receive_exact(connection, 4, deadline))[0]
    if not 1 <= length <= MAX_MESSAGE:
        raise SignerError("enrollment_message_invalid")
    try:
        value = json.loads(
            _receive_exact(connection, length, deadline).decode("utf-8"), object_pairs_hook=_json_object
        )
    except (ValueError, UnicodeError):
        raise SignerError("enrollment_message_invalid") from None
    if not isinstance(value, dict):
        raise SignerError("enrollment_message_invalid")
    return value


def _send(connection: socket.socket, value: dict):
    body = json.dumps(value, separators=(",", ":")).encode("utf-8")
    if len(body) > MAX_MESSAGE:
        raise SignerError("enrollment_message_invalid")
    connection.sendall(struct.pack("!I", len(body)) + body)


def _spki(key) -> bytes:
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _p256(key) -> bool:
    return isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1)


def _leaf_usage() -> x509.KeyUsage:
    return x509.KeyUsage(True, False, False, False, False, False, False, False, False)


def _credential_acl_valid(raw: bytes, uid: int, permission: int) -> bool:
    # Linux POSIX ACL v2. The mode's group bits represent the ACL mask, not
    # GROUP_OBJ permissions, when systemd grants a single service UID access.
    expected = [
        (1, permission, 0xFFFFFFFF),
        (2, permission, uid),
        (4, 0, 0xFFFFFFFF),
        (16, permission, 0xFFFFFFFF),
        (32, 0, 0xFFFFFFFF),
    ]
    if len(raw) != 44 or struct.unpack_from("<I", raw)[0] != 2:
        return False
    return [struct.unpack_from("<HHI", raw, offset) for offset in range(4, 44, 8)] == expected


def _read_ca_key(path: Path) -> bytes:
    if path != _SYSTEMD_CA_KEY:
        with _trusted_file(path, private=True) as fd:
            return os.read(fd, MAX_MESSAGE + 1)
    descriptors = []
    try:
        if sys.platform != "linux" or os.geteuid() == 0:
            raise ValueError("unprivileged Linux credential consumer required")
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        descriptors.append(parent)
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        descriptors.append(fd)
        for descriptor, mode, permission, regular in [(parent, 0o550, 5, False), (fd, 0o440, 4, True)]:
            info = os.fstat(descriptor)
            kind = stat.S_ISREG(info.st_mode) if regular else stat.S_ISDIR(info.st_mode)
            if (
                not kind
                or info.st_uid != 0
                or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != mode
                or not os.fstatvfs(descriptor).f_flag & os.ST_RDONLY
                or not _credential_acl_valid(
                    os.getxattr(descriptor, "system.posix_acl_access"), os.geteuid(), permission
                )
            ):
                raise ValueError("untrusted systemd credential")
        if not 0 < os.fstat(fd).st_size <= MAX_MESSAGE:
            raise ValueError("invalid credential size")
        return os.read(fd, MAX_MESSAGE + 1)
    except (OSError, ValueError):
        raise SignerError("enrollment_systemd_credential_invalid") from None
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


class _CertificateAuthority:
    def __init__(
        self,
        certificate_file: Path,
        key_file: Path,
        *,
        clock: Callable[[], datetime],
        clock_ready: Callable[[], bool],
    ):
        for path in (certificate_file, key_file):
            _trusted_ancestors(path.parent, {0, os.geteuid()})
        with _trusted_file(certificate_file, private=False) as fd:
            certificate = os.read(fd, MAX_MESSAGE + 1)
        private_key = _read_ca_key(key_file)
        try:
            self.certificate = x509.load_pem_x509_certificate(certificate)
            self.key = serialization.load_pem_private_key(private_key, password=None)
            if not isinstance(self.key, ec.EllipticCurvePrivateKey) or not _p256(self.key.public_key()):
                raise ValueError("P-256 CA key required")
            if _spki(self.certificate.public_key()) != _spki(self.key.public_key()):
                raise ValueError("CA key mismatch")
            if not self.certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise ValueError("CA certificate required")
            if not self.certificate.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
                raise ValueError("CA certificate signing usage required")
        except Exception:
            raise SignerError("enrollment_ca_invalid") from None
        self.pem = self.certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
        self.clock, self.clock_ready = clock, clock_ready
        self._last_now: datetime | None = None

    def now(self, ttl_seconds: int) -> datetime:
        now = self.clock()
        if (
            not isinstance(now, datetime)
            or now.tzinfo is None
            or not self.clock_ready()
            or (self._last_now is not None and now < self._last_now - timedelta(seconds=5))
        ):
            raise SignerError("enrollment_clock_untrusted")
        now = now.astimezone(UTC)
        if not (
            self.certificate.not_valid_before_utc <= now - timedelta(seconds=30)
            and now + timedelta(seconds=ttl_seconds) < self.certificate.not_valid_after_utc
        ):
            raise SignerError("enrollment_ca_expired_or_not_ready")
        self._last_now = now
        return now

    def issue(self, public_key, *, common_name: str, usage, sans: list, ttl_seconds: int) -> x509.Certificate:
        now = self.now(ttl_seconds)
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
            .issuer_name(self.certificate.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(seconds=30))
            .not_valid_after(now + timedelta(seconds=ttl_seconds - 30))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_leaf_usage(), critical=True)
            .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(self.key.public_key()), critical=False
            )
        )
        if sans:
            builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
        return builder.sign(self.key, hashes.SHA256())


@dataclass(frozen=True)
class EnrollmentConfig:
    ca_cert: Path
    ca_key: Path
    socket: Path
    issuer_uid: int
    issuer_gid: int
    broker_uid: int
    listener_dir: Path
    listener_gid: int
    client_common_name: str = "pap-issuer"
    client_uri_san: str | None = None
    ttl_seconds: int = 3600
    server_dns_names: tuple[str, ...] = ("localhost",)
    server_ip_addresses: tuple[str, ...] = ("127.0.0.1",)
    maintenance_interval: int = 30
    rate_per_minute: int = 30

    def __post_init__(self):
        for name in ("ca_cert", "ca_key", "socket", "listener_dir"):
            object.__setattr__(self, name, _absolute(getattr(self, name)))
        for name in ("issuer_uid", "issuer_gid", "broker_uid", "listener_gid"):
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value < 2**31:
                raise ValueError("invalid enrollment identity")
        if self.broker_uid == 0:
            raise ValueError("enrollment broker must be unprivileged")
        if self.issuer_uid == 0 or self.issuer_uid == self.broker_uid:
            raise ValueError("issuer and broker require distinct unprivileged UIDs")
        if not isinstance(self.client_common_name, str) or not _NAME.fullmatch(self.client_common_name):
            raise ValueError("invalid fixed client identity")
        if self.client_uri_san is not None and (
            not isinstance(self.client_uri_san, str)
            or not 1 <= len(self.client_uri_san) <= 256
            or any(c.isspace() for c in self.client_uri_san)
            or not urlsplit(self.client_uri_san).scheme
        ):
            raise ValueError("invalid fixed client URI")
        if type(self.ttl_seconds) is not int or self.ttl_seconds != 3600:
            raise ValueError("enrollment certificate lifetime must be one hour")
        for name in ("maintenance_interval", "rate_per_minute"):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= 60:
                raise ValueError("invalid enrollment maintenance or rate limit")
        if not self.server_dns_names and not self.server_ip_addresses:
            raise ValueError("fixed listener SANs required")
        for name in self.server_dns_names:
            if name != "localhost":
                raise ValueError("local listener DNS SAN must be localhost")
        for address in self.server_ip_addresses:
            if not ipaddress.ip_address(address).is_loopback:
                raise ValueError("local listener IP SAN must be loopback")
        if len(str(self.socket).encode()) > 103:
            raise ValueError("enrollment socket path too long")


def load_enrollment_config(path: Path | str) -> EnrollmentConfig:
    path = _absolute(path)
    _trusted_ancestors(path.parent, {0})
    with _trusted_file(path, private=False) as fd:
        if os.fstat(fd).st_uid != 0:
            raise ValueError("enrollment configuration must be owned by root")
        data = os.read(fd, MAX_MESSAGE + 1)
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_json_object)
        if not isinstance(value, dict):
            raise ValueError("object required")
        for name in ("server_dns_names", "server_ip_addresses"):
            if name in value:
                if not isinstance(value[name], list):
                    raise ValueError("SAN array required")
                value[name] = tuple(value[name])
        return EnrollmentConfig(**value)
    except (ValueError, TypeError, UnicodeError):
        raise ValueError("invalid enrollment configuration") from None


class ListenerCertificateManager:
    """Publish a complete listener key/certificate generation for OpenBao reload."""

    def __init__(
        self,
        ca_cert_file: Path | str,
        ca_key_file: Path | str,
        directory: Path | str,
        *,
        listener_gid: int,
        server_dns_names: tuple[str, ...] = ("localhost",),
        server_ip_addresses: tuple[str, ...] = ("127.0.0.1",),
        ttl_seconds: int = 3600,
        _clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        _clock_ready: Callable[[], bool] = _clock_ready,
        _authority: _CertificateAuthority | None = None,
    ):
        self.directory = _absolute(directory)
        self.gid, self.ttl_seconds = listener_gid, ttl_seconds
        self.sans = [x509.DNSName(name) for name in server_dns_names] + [
            x509.IPAddress(ipaddress.ip_address(address)) for address in server_ip_addresses
        ]
        if (
            ttl_seconds != 3600
            or not self.sans
            or type(listener_gid) is not int
            or listener_gid < 0
            or any(name != "localhost" for name in server_dns_names)
            or any(not ipaddress.ip_address(address).is_loopback for address in server_ip_addresses)
        ):
            raise ValueError("one-hour listener lifetime and fixed SANs required")
        if not self.directory.exists():
            self.directory.mkdir(mode=0o710)
            # The service UMask is 0077; restore the fixed KMS traversal bit
            # explicitly after mkdir rather than inheriting a private 0700.
            os.chmod(self.directory, 0o710, follow_symlinks=False)
            os.chown(self.directory, -1, listener_gid)
        _directory(self.directory, uid=os.geteuid(), gid=listener_gid)
        if stat.S_IMODE(self.directory.lstat().st_mode) != 0o710:
            raise SignerError("enrollment_directory_untrusted")
        self.authority = _authority or _CertificateAuthority(
            _absolute(ca_cert_file), _absolute(ca_key_file), clock=_clock, clock_ready=_clock_ready
        )
        self._lock = threading.RLock()

    @staticmethod
    def _fsync(directory: Path):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def _read(self, path: Path) -> bytes:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_gid != self.gid
                or stat.S_IMODE(info.st_mode) != 0o640
                or not 0 < info.st_size <= MAX_MESSAGE
            ):
                raise SignerError("enrollment_listener_file_untrusted")
            return os.read(fd, MAX_MESSAGE + 1)
        finally:
            os.close(fd)

    def _current(self) -> tuple[Path, x509.Certificate]:
        pointer = self.directory / "current"
        info = pointer.lstat()
        name = os.readlink(pointer)
        if not stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid() or not _GENERATION.fullmatch(name):
            raise SignerError("enrollment_listener_generation_untrusted")
        directory = self.directory / name
        _directory(directory, uid=os.geteuid(), gid=self.gid)
        certificate = x509.load_pem_x509_certificate(self._read(directory / "server.crt"))
        key = serialization.load_pem_private_key(self._read(directory / "server.key"), password=None)
        if not isinstance(key, ec.EllipticCurvePrivateKey) or not _p256(key.public_key()):
            raise SignerError("enrollment_listener_certificate_invalid")
        if _spki(key.public_key()) != _spki(certificate.public_key()):
            raise SignerError("enrollment_listener_certificate_invalid")
        certificate.verify_directly_issued_by(self.authority.certificate)
        if (
            set(certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
            != {ExtendedKeyUsageOID.SERVER_AUTH}
            or set(certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName).value)
            != set(self.sans)
            or certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            or certificate.extensions.get_extension_for_class(x509.KeyUsage).value != _leaf_usage()
        ):
            raise SignerError("enrollment_listener_certificate_invalid")
        return directory, certificate

    def maintain(self, *, force: bool = False) -> dict:
        with self._lock:
            try:
                now = self.authority.now(self.ttl_seconds)
                try:
                    _, current = self._current()
                except FileNotFoundError:
                    if (self.directory / "current").is_symlink():
                        raise SignerError("enrollment_listener_generation_untrusted") from None
                    current = None
                if (
                    current is not None
                    and not force
                    and (
                        current.not_valid_before_utc <= now
                        and current.not_valid_after_utc - now > timedelta(minutes=5)
                    )
                ):
                    return {"renewed": False, "expires_at": current.not_valid_after_utc.timestamp()}
                key = ec.generate_private_key(ec.SECP256R1())
                certificate = self.authority.issue(
                    key.public_key(),
                    common_name="localhost",
                    usage=ExtendedKeyUsageOID.SERVER_AUTH,
                    sans=self.sans,
                    ttl_seconds=self.ttl_seconds,
                )
                directory = self.directory / ("generation-" + uuid.uuid4().hex)
                directory.mkdir(mode=0o750)
                os.chmod(directory, 0o750)
                os.chown(directory, -1, self.gid)
                values = {
                    "server.crt": certificate.public_bytes(serialization.Encoding.PEM),
                    "server.key": key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.PKCS8,
                        serialization.NoEncryption(),
                    ),
                }
                for name, value in values.items():
                    fd = os.open(
                        directory / name, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, 0o640
                    )
                    with os.fdopen(fd, "wb") as output:
                        os.fchmod(output.fileno(), 0o640)
                        os.fchown(output.fileno(), -1, self.gid)
                        output.write(value)
                        output.flush()
                        os.fsync(output.fileno())
                self._fsync(directory)
                pointer = self.directory / ("next-" + uuid.uuid4().hex)
                os.symlink(directory.name, pointer)
                os.replace(pointer, self.directory / "current")
                self._fsync(self.directory)
                self.cleanup(now)
                _event("listener_certificate_renewed", "ok")
                return {"renewed": True, "expires_at": certificate.not_valid_after_utc.timestamp()}
            except SignerError:
                raise
            except Exception:
                raise SignerError("enrollment_listener_renewal_failed") from None

    def cleanup(self, now: datetime):
        current, _ = self._current()
        for directory in self.directory.iterdir():
            if not _GENERATION.fullmatch(directory.name) or directory == current or directory.is_symlink():
                continue
            try:
                _directory(directory, uid=os.geteuid(), gid=self.gid)
                if {p.name for p in directory.iterdir()} != {"server.crt", "server.key"}:
                    continue
                cert = x509.load_pem_x509_certificate(self._read(directory / "server.crt"))
                if cert.not_valid_after_utc >= now - timedelta(minutes=5):
                    continue
                (directory / "server.key").unlink()
                (directory / "server.crt").unlink()
                directory.rmdir()
            except (OSError, ValueError, SignerError):
                continue


class EnrollmentServer:
    def __init__(
        self,
        config: EnrollmentConfig,
        *,
        _clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        _clock_ready: Callable[[], bool] = _clock_ready,
        _peer_reader: Callable[[socket.socket], int] = _peer_uid,
        _monotonic: Callable[[], float] = time.monotonic,
    ):
        if os.geteuid() != config.broker_uid:
            raise ValueError("enrollment broker UID does not match configuration")
        self.config, self._peer_reader, self._monotonic = config, _peer_reader, _monotonic
        self.authority = _CertificateAuthority(
            config.ca_cert, config.ca_key, clock=_clock, clock_ready=_clock_ready
        )
        self.listener = ListenerCertificateManager(
            config.ca_cert,
            config.ca_key,
            config.listener_dir,
            listener_gid=config.listener_gid,
            server_dns_names=config.server_dns_names,
            server_ip_addresses=config.server_ip_addresses,
            ttl_seconds=config.ttl_seconds,
            _authority=self.authority,
        )
        self._socket: socket.socket | None = None
        self._inode: tuple[int, int] | None = None
        self._requests: deque[float] = deque()
        self._closed = False
        self._lock_descriptor: int | None = None

    def start(self):
        if self._socket is not None:
            return
        _directory(self.config.socket.parent, uid=self.config.broker_uid, gid=self.config.issuer_gid)
        lock = os.open(
            self.config.socket.with_name(self.config.socket.name + ".lock"),
            os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            info = os.fstat(lock)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != self.config.broker_uid
                or (stat.S_IMODE(info.st_mode) != 0o600)
            ):
                raise SignerError("enrollment_lock_untrusted")
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self._lock_descriptor = lock
        except BaseException:
            os.close(lock)
            raise
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            # The process-lifetime lock permits safe removal after a crash and
            # prevents a second broker from stealing a live socket.
            if self.config.socket.exists() or self.config.socket.is_symlink():
                stale = self.config.socket.lstat()
                if not stat.S_ISSOCK(stale.st_mode) or stale.st_uid != self.config.broker_uid:
                    raise SignerError("enrollment_socket_untrusted")
                self.config.socket.unlink()
            connection.bind(str(self.config.socket))
            info = self.config.socket.lstat()
            self._inode = (info.st_dev, info.st_ino)
            os.chmod(self.config.socket, 0o660)
            os.chown(self.config.socket, -1, self.config.issuer_gid)
            connection.listen(16)
            self._socket = connection
        except BaseException:
            connection.close()
            self.close()
            raise
        try:
            self.listener.maintain()
        except SignerError as error:
            # Keep the local recovery endpoint available while clock sync starts.
            _event("listener_certificate_unavailable", error.code)

    def _admit(self, connection: socket.socket) -> int:
        uid = self._peer_reader(connection)
        if uid != self.config.issuer_uid:
            raise SignerError("enrollment_peer_denied")
        now = self._monotonic()
        while self._requests and self._requests[0] <= now - 60:
            self._requests.popleft()
        if len(self._requests) >= self.config.rate_per_minute:
            raise SignerError("enrollment_rate_limited")
        self._requests.append(now)
        return uid

    def _enroll(self, value: dict) -> dict:
        if set(value) != {"csr"} or not isinstance(value["csr"], str) or len(value["csr"]) > MAX_CSR * 2:
            raise SignerError("enrollment_request_invalid")
        try:
            der = base64.b64decode(value["csr"], validate=True)
            if not 1 <= len(der) <= MAX_CSR:
                raise ValueError("CSR too large")
            csr = x509.load_der_x509_csr(der)
            public_key = csr.public_key()
            if (
                csr.public_bytes(serialization.Encoding.DER) != der
                or not _p256(public_key)
                or csr.signature_algorithm_oid != SignatureAlgorithmOID.ECDSA_WITH_SHA256
                or not csr.is_signature_valid
            ):
                raise ValueError("invalid CSR key or signature")
        except Exception:
            raise SignerError("enrollment_csr_invalid") from None
        # Refresh even an expired listener without contacting its TLS endpoint.
        self.listener.maintain()
        sans = (
            [x509.UniformResourceIdentifier(self.config.client_uri_san)] if self.config.client_uri_san else []
        )
        certificate = self.authority.issue(
            public_key,
            common_name=self.config.client_common_name,
            usage=ExtendedKeyUsageOID.CLIENT_AUTH,
            sans=sans,
            ttl_seconds=self.config.ttl_seconds,
        )
        return {
            "certificate": certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),
            "issuing_ca": self.authority.pem,
        }

    def handle_connection(self, connection: socket.socket):
        uid = None
        connection.settimeout(3)
        try:
            uid = self._admit(connection)
            response = self._enroll(_receive(connection))
            _send(connection, response)
            _event("client_certificate_enrolled", "ok", uid)
        except Exception as error:
            code = error.code if isinstance(error, SignerError) else "enrollment_request_failed"
            _event("client_certificate_denied", code, uid)
            try:
                _send(connection, {"error": code})
            except (OSError, SignerError):
                pass

    def serve_forever(self, stop_event: threading.Event | None = None):
        self.start()
        next_maintenance = self._monotonic() + self.config.maintenance_interval
        while not self._closed and not (stop_event is not None and stop_event.is_set()):
            try:
                readable, _, _ = select.select([self._socket], [], [], 0.25)
                if readable:
                    connection, _ = self._socket.accept()
                    with connection:
                        self.handle_connection(connection)
            except (OSError, ValueError):
                if self._closed:
                    break
                raise
            if self._monotonic() >= next_maintenance:
                try:
                    self.listener.maintain()
                except SignerError as error:
                    _event("listener_certificate_unavailable", error.code)
                next_maintenance = self._monotonic() + self.config.maintenance_interval

    def close(self):
        self._closed = True
        if self._socket is not None:
            self._socket.close()
        try:
            info = self.config.socket.lstat()
            if self._inode == (info.st_dev, info.st_ino) and stat.S_ISSOCK(info.st_mode):
                self.config.socket.unlink()
        except FileNotFoundError:
            pass
        finally:
            if self._lock_descriptor is not None:
                os.close(self._lock_descriptor)
                self._lock_descriptor = None


class UnixEnrollmentClient:
    def __init__(
        self,
        socket_path: Path | str,
        ca_file: Path | str,
        expected_uid: int,
        *,
        common_name: str = "pap-issuer",
        uri_san: str | None = None,
        issuer_uid: int | None = None,
        timeout: float = 5.0,
        _peer_reader: Callable[[socket.socket], int] = _peer_uid,
        _clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ):
        self.socket_path, self.ca_file = _absolute(socket_path), _absolute(ca_file)
        if type(expected_uid) is not int or expected_uid <= 0:
            raise ValueError("unprivileged broker UID required")
        if issuer_uid is not None and issuer_uid != os.geteuid():
            raise ValueError("issuer UID does not match caller")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (float, int))
            or not math.isfinite(timeout)
            or not 0 < timeout <= 10
            or not isinstance(common_name, str)
            or not _NAME.fullmatch(common_name)
        ):
            raise ValueError("invalid enrollment client configuration")
        self.expected_uid, self.common_name, self.uri_san = expected_uid, common_name, uri_san
        self.timeout, self._peer_reader, self._clock = timeout, _peer_reader, _clock

    def _validate_response(self, value: dict, key, now: datetime) -> dict:
        try:
            if set(value) != {"certificate", "issuing_ca"} or any(
                not isinstance(item, str) or len(item) > MAX_MESSAGE for item in value.values()
            ):
                raise ValueError("invalid response shape")
            with _trusted_file(self.ca_file, private=False) as fd:
                pinned = x509.load_pem_x509_certificate(os.read(fd, MAX_MESSAGE + 1))
            supplied = x509.load_pem_x509_certificate(value["issuing_ca"].encode("ascii"))
            cert = x509.load_pem_x509_certificate(value["certificate"].encode("ascii"))
            if supplied.public_bytes(serialization.Encoding.DER) != pinned.public_bytes(
                serialization.Encoding.DER
            ):
                raise ValueError("foreign CA")
            if (
                not pinned.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                or not pinned.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
                or pinned.not_valid_before_utc > now
                or pinned.not_valid_after_utc <= cert.not_valid_after_utc
            ):
                raise ValueError("unusable pinned CA")
            cert.verify_directly_issued_by(pinned)
            if (
                _spki(cert.public_key()) != _spki(key.public_key())
                or [item.value for item in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
                != [self.common_name]
                or set(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value)
                != {ExtendedKeyUsageOID.CLIENT_AUTH}
                or cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                or cert.extensions.get_extension_for_class(x509.KeyUsage).value != _leaf_usage()
                or cert.not_valid_before_utc > now + timedelta(seconds=5)
                or not now + timedelta(minutes=10) < cert.not_valid_after_utc <= now + timedelta(hours=1)
                or cert.not_valid_after_utc - cert.not_valid_before_utc > timedelta(hours=1)
            ):
                raise ValueError("invalid client leaf")
            if self.uri_san is not None and list(
                cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            ) != [x509.UniformResourceIdentifier(self.uri_san)]:
                raise ValueError("fixed client URI mismatch")
            return {
                "certificate": value["certificate"],
                "private_key": key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ).decode("ascii"),
                "issuing_ca": value["issuing_ca"],
            }
        except Exception:
            raise SignerError("enrollment_certificate_invalid") from None

    def issue_client_certificate(self, role: str, common_name: str, *, ttl_seconds: int = 3600) -> dict:
        if (
            not isinstance(role, str)
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", role)
            or common_name != self.common_name
            or type(ttl_seconds) is not int
            or ttl_seconds != 3600
        ):
            raise SignerError("enrollment_request_invalid")
        try:
            _directory(self.socket_path.parent, uid=self.expected_uid)
            before = self.socket_path.lstat()
            if (
                not stat.S_ISSOCK(before.st_mode)
                or before.st_uid != self.expected_uid
                or stat.S_IMODE(before.st_mode) != 0o660
            ):
                raise SignerError("enrollment_socket_untrusted")
            key = ec.generate_private_key(ec.SECP256R1())
            csr = (
                x509.CertificateSigningRequestBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.common_name)]))
                .sign(key, hashes.SHA256())
            )
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout)
                connection.connect(str(self.socket_path))
                after = self.socket_path.lstat()
                if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) or self._peer_reader(
                    connection
                ) != self.expected_uid:
                    raise SignerError("enrollment_peer_denied")
                _send(
                    connection,
                    {"csr": base64.b64encode(csr.public_bytes(serialization.Encoding.DER)).decode()},
                )
                value = _receive(connection)
            if "error" in value:
                raise SignerError("enrollment_unavailable")
            return self._validate_response(value, key, self._clock())
        except SignerError:
            raise
        except Exception:
            raise SignerError("enrollment_unavailable") from None
