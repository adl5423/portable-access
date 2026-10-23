"""Root-only retrieval of an independently held OpenBao static seal key.

Only an ephemeral public request is exposed by the independent HTTPS gateway.
The recipient private key stays in this process; the recovered seal key exists
only in protected tmpfs and systemd's OpenBao credential. No unseal API is used.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import ctypes
import fcntl
import hashlib
import json
import logging
import math
import os
import re
import resource
import secrets
import ssl
import stat
import sys
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import aiohttp
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .cloud import PublicResolver, netlify_origin
from .enrollment import _clock_ready

LOG = logging.getLogger(__name__)
MAX_REQUEST = 4096
MAX_RESPONSE = 4096
REQUEST_TTL = 120
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}\Z")
_REQUEST_FIELDS = {
    "v",
    "request_id",
    "deployment_id",
    "machine_id",
    "boot_id",
    "key_id",
    "nonce",
    "iat",
    "exp",
    "recipient_jwk",
}


class BootError(RuntimeError):
    """A stable error code that never contains request or credential bytes."""

    def __init__(self, code: str, *, retryable: bool = False):
        self.code, self.retryable = code, retryable
        super().__init__(code)


def canonical(value) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode()


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _json(raw: bytes, limit: int) -> dict:
    try:
        if not 0 < len(raw) <= limit:
            raise ValueError("bounded JSON required")

        def constant(_):
            raise ValueError("non-finite JSON number")

        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object, parse_constant=constant)
        if not isinstance(value, dict):
            raise ValueError("object required")
        return value
    except (ValueError, UnicodeError):
        raise BootError("boot_json_invalid") from None


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value, length: int) -> bytes:
    try:
        if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9_-]+", value) is None:
            raise ValueError("base64url required")
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        if len(decoded) != length or _b64(decoded) != value:
            raise ValueError("canonical base64url required")
        return decoded
    except (ValueError, TypeError):
        raise BootError("boot_encoding_invalid") from None


def _uuid(value, *, version: int | None = None) -> str:
    try:
        parsed = uuid.UUID(value)
        if str(parsed) != value or (version is not None and parsed.version != version):
            raise ValueError("canonical UUID required")
        return value
    except (ValueError, TypeError, AttributeError):
        raise BootError("boot_identity_invalid") from None


def _proof_origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
        host = parsed.hostname or ""
        if (
            value != "https://" + host
            or not re.fullmatch(r"8080-[a-z0-9]{16,64}\.instabox\.tech", host)
            or not host.isascii()
        ):
            raise ValueError("registered Instabox HTTPS origin required")
        return value
    except (ValueError, TypeError):
        raise BootError("boot_origin_invalid") from None


@dataclass(frozen=True)
class BootConfig:
    seal_origin: str
    proof_origin: str
    machine_id: str
    deployment_id: str
    key_id: str
    proxy_gid: int

    def __post_init__(self):
        try:
            netlify_origin(self.seal_origin)
            _proof_origin(self.proof_origin)
            if (
                not _ID.fullmatch(self.machine_id)
                or not self.machine_id.startswith("m_")
                or not _ID.fullmatch(self.deployment_id)
                or not _HEX.fullmatch(self.key_id)
                or type(self.proxy_gid) is not int
                or self.proxy_gid <= 0
            ):
                raise ValueError("invalid boot binding")
        except (ValueError, TypeError):
            raise BootError("boot_configuration_invalid") from None


def _ancestors(path: Path):
    if not path.is_absolute() or ".." in path.parts:
        raise BootError("boot_path_untrusted")
    for part in (path, *path.parents):
        info = part.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise BootError("boot_directory_untrusted")


def _read_file(path: Path, *, mode: int, gid: int, limit: int) -> bytes:
    _ancestors(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_gid != gid
            or stat.S_IMODE(info.st_mode) != mode
            or not 0 < info.st_size <= limit
            or info.st_nlink != 1
        ):
            raise BootError("boot_file_untrusted")
        raw = os.read(fd, limit + 1)
        if len(raw) != info.st_size:
            raise BootError("boot_file_untrusted")
        return raw
    finally:
        os.close(fd)


def load_config(path: Path) -> BootConfig:
    try:
        raw = _read_file(path, mode=0o600, gid=0, limit=MAX_REQUEST)
        return BootConfig(**_json(raw, MAX_REQUEST))
    except BootError:
        raise
    except (OSError, TypeError, ValueError):
        raise BootError("boot_configuration_invalid") from None


def _tmpfs(path: Path, raw: str) -> bool:
    def unescape(value):
        return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m[1], 8)), value)

    selected = None
    for line in raw.splitlines():
        before, marker, after = line.partition(" - ")
        fields, filesystem = before.split(), after.split()
        if not marker or len(fields) < 6 or len(filesystem) < 3:
            raise BootError("boot_mount_inventory_invalid")
        mount = Path(unescape(fields[4]))
        if path == mount or mount in path.parents:
            if selected is None or len(mount.parts) > selected[0]:
                selected = len(mount.parts), filesystem[0], fields[5].split(",")
    return selected is not None and selected[1] == "tmpfs" and "rw" in selected[2]


def harden(runtime: Path):
    try:
        if sys.platform != "linux" or os.geteuid() != 0:
            raise BootError("boot_root_linux_required")
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0) != 0:
            raise BootError("boot_memory_protection_failed")
        if len(Path("/proc/swaps").read_text().splitlines()) != 1:
            raise BootError("boot_swap_enabled")
        if not _tmpfs(runtime, Path("/proc/self/mountinfo").read_text()):
            raise BootError("boot_tmpfs_required")
    except BootError:
        raise
    except (OSError, ValueError):
        raise BootError("boot_memory_protection_failed") from None


def request(config: BootConfig, boot_id: str, key: rsa.RSAPrivateKey, now: int) -> dict:
    if (
        not isinstance(key, rsa.RSAPrivateKey)
        or key.key_size != 4096
        or key.public_key().public_numbers().e != 65537
        or type(now) is not int
        or not 0 < now < 4102444680
    ):
        raise BootError("boot_request_invalid")
    numbers = key.public_key().public_numbers()
    value = {
        "v": 1,
        "request_id": str(uuid.uuid4()),
        "deployment_id": config.deployment_id,
        "machine_id": config.machine_id,
        "boot_id": _uuid(boot_id),
        "key_id": config.key_id,
        "nonce": _b64(secrets.token_bytes(32)),
        "iat": now,
        "exp": now + REQUEST_TTL,
        "recipient_jwk": {"kty": "RSA", "e": "AQAB", "n": _b64(numbers.n.to_bytes(512, "big"))},
    }
    if set(value) != _REQUEST_FIELDS or len(canonical(value)) > MAX_REQUEST:
        raise BootError("boot_request_invalid")
    return value


def unwrap(config: BootConfig, value: dict, response: dict, key: rsa.RSAPrivateKey, now: float) -> bytes:
    try:
        if (
            set(response) != {"v", "request_id", "key_id", "wrapped_key"}
            or type(response["v"]) is not int
            or response["v"] != 1
            or response["request_id"] != value["request_id"]
            or response["key_id"] != config.key_id
            or not math.isfinite(now)
            or not value["iat"] <= now < value["exp"]
        ):
            raise ValueError("response binding mismatch")
        ciphertext = _decode(response["wrapped_key"], 512)
        plain = key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=hashlib.sha256(canonical(value)).digest(),
            ),
        )
        if len(plain) != 32 or not secrets.compare_digest(hashlib.sha256(plain).hexdigest(), config.key_id):
            raise ValueError("key pin mismatch")
        return plain
    except Exception:
        raise BootError("boot_release_invalid") from None


class ReleaseTransport:
    def __init__(self, config: BootConfig):
        self.config = config

    @staticmethod
    async def _read(response) -> dict:
        if (
            response.content_type != "application/json"
            or response.headers.get("Content-Encoding", "identity") != "identity"
        ):
            raise BootError("boot_release_invalid")
        raw = bytearray()
        while True:
            chunk = await response.content.read(MAX_RESPONSE + 1 - len(raw))
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > MAX_RESPONSE:
                raise BootError("boot_release_invalid")
        return _json(bytes(raw), MAX_RESPONSE)

    async def __call__(self, value: dict) -> dict:
        connector = aiohttp.TCPConnector(
            resolver=PublicResolver(urlsplit(self.config.seal_origin).hostname),
            ssl=ssl.create_default_context(),
            use_dns_cache=False,
            limit=1,
        )
        try:
            async with aiohttp.ClientSession(
                connector=connector,
                trust_env=False,
                auto_decompress=False,
                timeout=aiohttp.ClientTimeout(total=15, connect=5, sock_read=10),
            ) as session:
                async with session.post(
                    self.config.seal_origin + "/v1/boot/release",
                    data=canonical(value),
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                        "Accept-Encoding": "identity",
                    },
                    allow_redirects=False,
                ) as response:
                    if response.status == 401:
                        try:
                            expired = await self._read(response) == {"error": "proof_expired"}
                        except Exception:
                            expired = False
                        if expired:
                            raise BootError("boot_request_expired", retryable=True)
                        raise BootError("boot_release_denied")
                    if response.status != 200:
                        raise BootError(
                            "boot_release_unavailable"
                            if response.status in {409, 429, 500, 502, 503, 504}
                            else "boot_release_denied",
                            retryable=response.status in {409, 429, 500, 502, 503, 504},
                        )
                    return await self._read(response)
        except BootError:
            raise
        except (OSError, ValueError, aiohttp.ClientError, TimeoutError):
            raise BootError("boot_release_unavailable", retryable=True) from None


class BootClient:
    def __init__(
        self,
        config: BootConfig,
        *,
        _runtime: Path = Path("/run/pap-boot"),
        _incident_lock: Path = Path("/etc/pap/boot.locked"),
        _boot_id: Callable[[], str] = lambda: Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        _clock: Callable[[], float] = time.time,
        _clock_ready: Callable[[], bool] = _clock_ready,
        _harden: Callable[[Path], None] = harden,
        _key_factory: Callable[[], rsa.RSAPrivateKey] = lambda: rsa.generate_private_key(
            public_exponent=65537, key_size=4096
        ),
        _transport=None,
        _sleep=asyncio.sleep,
        _jitter: Callable[[], float] = lambda: secrets.randbelow(1001) / 1000,
    ):
        self.config, self.runtime = config, _runtime
        self.incident_lock = _incident_lock
        self.public, self.private = _runtime / "public", _runtime / "private"
        self.key_path, self.lock_path = self.private / "current.key", self.private / "boot.lock"
        self.clock, self.clock_ready, self.harden = _clock, _clock_ready, _harden
        self.boot_id, self.key_factory = _boot_id, _key_factory
        self.transport, self.sleep, self.jitter = _transport or ReleaseTransport(config), _sleep, _jitter

    def _directory(self, path: Path, mode: int, gid: int):
        if not path.exists():
            path.mkdir(mode=mode)
            os.chmod(path, mode, follow_symlinks=False)
            os.chown(path, 0, gid, follow_symlinks=False)
        _ancestors(path)
        info = path.lstat()
        if info.st_gid != gid or stat.S_IMODE(info.st_mode) != mode:
            raise BootError("boot_directory_untrusted")

    def prepare(self):
        self.harden(self.runtime)
        self._directory(self.runtime, 0o755, 0)
        self._directory(self.public, 0o750, self.config.proxy_gid)
        self._directory(self.private, 0o700, 0)
        _ancestors(self.incident_lock.parent)

    def _require_unlocked(self):
        try:
            self.incident_lock.lstat()
        except FileNotFoundError:
            return
        except OSError:
            raise BootError("boot_lock_status_unavailable") from None
        # Presence is the entire signal. Never follow links or read latch contents.
        raise BootError("boot_locked")

    def _atomic(self, path: Path, raw: bytes, mode: int, gid: int):
        _ancestors(path.parent)
        temporary = path.parent / (".next-" + uuid.uuid4().hex)
        fd = None
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
            os.fchmod(fd, mode)
            os.fchown(fd, 0, gid)
            with os.fdopen(fd, "wb") as stream:
                fd = None
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if fd is not None:
                os.close(fd)
            with contextlib.suppress(FileNotFoundError):
                temporary.unlink()

    def existing(self) -> bool:
        self._require_unlocked()
        if not self.key_path.exists() and not self.key_path.is_symlink():
            return False
        raw = _read_file(self.key_path, mode=0o400, gid=0, limit=32)
        if len(raw) != 32 or not secrets.compare_digest(hashlib.sha256(raw).hexdigest(), self.config.key_id):
            raise BootError("boot_existing_key_untrusted")
        self._require_unlocked()
        return True

    async def attempt(self):
        self._require_unlocked()
        if not self.clock_ready():
            raise BootError("boot_clock_untrusted", retryable=True)
        key = self.key_factory()
        value = request(self.config, self.boot_id(), key, int(self.clock()))
        path = self.public / (value["request_id"] + ".json")
        self._atomic(path, canonical(value), 0o440, self.config.proxy_gid)
        try:
            response = await self.transport(value)
            if not self.clock_ready():
                raise BootError("boot_clock_untrusted", retryable=True)
            plain = unwrap(self.config, value, response, key, self.clock())
            self._require_unlocked()
            self._atomic(self.key_path, plain, 0o400, 0)
            del plain
        finally:
            path.unlink()

    async def run(self) -> dict:
        self.prepare()
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != 0
                or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
            ):
                raise BootError("boot_lock_untrusted")
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise BootError("boot_already_running") from None
            self._require_unlocked()
            if self.existing():
                self._require_unlocked()
                return {"ready": True, "key_id": self.config.key_id, "runtime_key_reused": True}
            count = 0
            while True:
                try:
                    await self.attempt()
                    return {"ready": True, "key_id": self.config.key_id, "runtime_key_reused": False}
                except BootError as error:
                    if not error.retryable:
                        raise
                    LOG.warning(json.dumps({"event": "boot_waiting", "code": error.code}, sort_keys=True))
                    count = min(count + 1, 5)
                    delay = min(30.0, 2.0**count) * (0.75 + min(max(self.jitter(), 0), 1) * 0.25)
                    await self.sleep(delay)
        finally:
            os.close(fd)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Retrieve one independently held OpenBao static seal key")
    parser.add_argument("--config", type=Path, default=Path("/etc/pap/boot.json"))
    args = parser.parse_args(argv)
    try:
        result = asyncio.run(BootClient(load_config(args.config)).run())
        print(json.dumps(result, sort_keys=True))
        return 0
    except BaseException as error:
        code = error.code if isinstance(error, BootError) else "boot_stopped"
        print(json.dumps({"ready": False, "code": code}, sort_keys=True))
        return 78


if __name__ == "__main__":
    raise SystemExit(main())
