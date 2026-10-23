"""Bounded SSH and local UNIX/mTLS transports, with no secret files."""

from __future__ import annotations

import http.client
import ipaddress
import os
import re
import selectors
import shlex
import socket
import ssl
import stat
import subprocess
import time
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .custody import CustodyError
from .envelope import MAX_PACKET, canonical, parse_json, recovery_material


def ssh_command(
    target: str, *, executable: str, arguments: list[str], port: int = 22, known_hosts: Path | None = None
) -> list[str]:
    if not re.fullmatch(r"(?:[A-Za-z_][A-Za-z0-9_.-]*@)?[A-Za-z0-9][A-Za-z0-9_.-]{0,252}", target):
        raise CustodyError("SSH target must be a host or user@host, without options")
    if (
        not 1 <= port <= 65535
        or not executable.startswith("/")
        or not re.fullmatch(r"/[A-Za-z0-9_./-]+", executable)
        or ".." in Path(executable).parts
    ):
        raise CustodyError("Invalid SSH port or absolute remote executable")
    command = [
        "ssh",
        "-T",
        "-p",
        str(port),
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=2",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ForwardX11=no",
        "-o",
        "ClearAllForwardings=yes",
    ]
    if known_hosts is not None:
        command.extend(["-o", "UserKnownHostsFile=" + str(known_hosts.resolve())])
    command.extend(["--", target, shlex.join(["sudo", "-n", executable, *arguments])])
    return command


def ssh_send(command: list[str], payload: dict, *, timeout: float = 90, maximum: int = 1024 * 1024) -> bytes:
    """No retries. A timeout or disconnect may follow a successful mutation."""
    raw = canonical(payload)
    if len(raw) > MAX_PACKET:
        raise CustodyError("SSH secret input exceeds its size limit")
    # No shell and no inherited credential-bearing environment variables.
    env = {
        name: value
        for name, value in os.environ.items()
        if name in {"PATH", "HOME", "USER", "LOGNAME", "SSH_AUTH_SOCK", "LANG", "LC_ALL"}
    }
    output = bytearray()
    try:
        with subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env
        ) as process:
            assert process.stdin is not None and process.stdout is not None
            deadline = time.monotonic() + timeout
            pending = memoryview(raw)
            try:
                with selectors.DefaultSelector() as ready:
                    os.set_blocking(process.stdin.fileno(), False)
                    os.set_blocking(process.stdout.fileno(), False)
                    ready.register(process.stdin, selectors.EVENT_WRITE)
                    ready.register(process.stdout, selectors.EVENT_READ)
                    while ready.get_map():
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise CustodyError(
                                "SSH operation outcome unknown; inspect host state before retrying"
                            )
                        for event, _ in ready.select(remaining):
                            if event.fileobj is process.stdin:
                                count = os.write(process.stdin.fileno(), pending[:65536])
                                pending = pending[count:]
                                if not pending:
                                    ready.unregister(process.stdin)
                                    process.stdin.close()
                            else:
                                chunk = os.read(
                                    process.stdout.fileno(), min(65536, maximum - len(output) + 1)
                                )
                                if not chunk:
                                    ready.unregister(process.stdout)
                                    process.stdout.close()
                                else:
                                    output.extend(chunk)
                                    if len(output) > maximum:
                                        raise CustodyError(
                                            "SSH response exceeds its size limit; inspect host state before retrying"
                                        )
                process.wait(timeout=max(0.001, deadline - time.monotonic()))
            except BaseException:
                process.kill()
                process.wait()
                raise
            if process.returncode != 0:
                raise CustodyError(
                    "SSH operation failed or outcome unknown; inspect host state before retrying"
                )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CustodyError(
            "SSH transport failed or outcome unknown; inspect host state before retrying"
        ) from exc
    return bytes(output)


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: Path, *, expected_peer_uid: int, expected_socket_uid: int):
        super().__init__("localhost", timeout=15)
        self.path = path
        self.expected_peer_uid = expected_peer_uid
        self.expected_socket_uid = expected_socket_uid

    def connect(self):
        info = self.path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_mode & 0o007 or info.st_uid != self.expected_socket_uid:
            raise CustodyError("Administrative UNIX socket is not protected")
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(str(self.path))
        if hasattr(socket, "SO_PEERCRED"):
            import struct

            _, peer_uid, _ = struct.unpack(
                "3i", self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            if peer_uid != self.expected_peer_uid:
                self.close()
                raise CustodyError("Administrative UNIX socket peer changed")


def import_credential(
    socket_path: Path, credential: dict, *, expected_peer_uid: int, expected_socket_uid: int
) -> dict:
    connection = _UnixHTTPConnection(
        socket_path, expected_peer_uid=expected_peer_uid, expected_socket_uid=expected_socket_uid
    )
    try:
        connection.request(
            "POST",
            "/v0/connectors/credentials",
            body=canonical(credential),
            headers={"Content-Type": "application/json", "Connection": "close"},
        )
        response = connection.getresponse()
        raw = response.read(65537)
        if response.status not in (200, 201) or len(raw) > 65536:
            raise CustodyError(
                "Credential import rejected or outcome unknown; inspect broker metadata before retrying"
            )
        result = parse_json(raw, 65536)
        generation = result.get("generation")
        revoked = credential.get("action") == "revoke"
        if (
            set(result) != {"provider", "configured", "generation"}
            or result.get("provider") != credential.get("provider")
            or result.get("configured") is not (not revoked)
            or type(generation) is not int
            or generation < (0 if revoked else 1)
        ):
            raise CustodyError(
                "Credential response verification failed; inspect broker metadata before retrying"
            )
        # Only public success metadata crosses back to the operator terminal.
        return {
            "revoked" if revoked else "imported": True,
            "provider": result["provider"],
            "generation": generation,
        }
    except (OSError, http.client.HTTPException) as exc:
        raise CustodyError(
            "Credential import outcome unknown; inspect broker metadata before retrying"
        ) from exc
    finally:
        connection.close()


@contextmanager
def memfd_mtls(packet: dict):
    """Issue a five-minute operator leaf and load its private key from memfd."""
    if not hasattr(os, "memfd_create") or not Path("/proc/self/fd").is_dir():
        raise CustodyError("Operator OpenBao access requires a Linux memfd receiver")
    material = recovery_material(packet)
    descriptors = []
    try:
        ca = x509.load_pem_x509_certificate(material["operator_ca"].encode("ascii"))
        ca_key = serialization.load_pem_private_key(material["operator_ca_private_key"].encode("ascii"), None)
        server_ca = x509.load_pem_x509_certificate(material["enrollment_ca"].encode("ascii"))
        now = datetime.now(UTC)
        if (
            ca.not_valid_before_utc > now
            or ca.not_valid_after_utc <= now + timedelta(minutes=5)
            or server_ca.not_valid_after_utc <= now
        ):
            raise CustodyError("Recovered CA is expired or cannot issue a complete operator leaf")
        key = ec.generate_private_key(ec.SECP256R1())
        leaf = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pap-operator")]))
            .issuer_name(ca.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(seconds=30))
            .not_valid_after(now + timedelta(minutes=5))
            .add_extension(x509.BasicConstraints(False, None), True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
            .sign(ca_key, hashes.SHA256())
        )
        context = ssl.create_default_context(cadata=material["enrollment_ca"])
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        import fcntl

        for name, value in (
            ("pap-operator-cert", leaf.public_bytes(serialization.Encoding.PEM)),
            (
                "pap-operator-key",
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ),
            ),
        ):
            fd = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            descriptors.append(fd)
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=False) as output:
                output.write(value)
                output.flush()
            fcntl.fcntl(
                fd,
                fcntl.F_ADD_SEALS,
                fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL,
            )
        context.load_cert_chain(f"/proc/self/fd/{descriptors[0]}", f"/proc/self/fd/{descriptors[1]}")
        yield context
    except CustodyError:
        raise
    except (ValueError, OSError, KeyError, TypeError, ssl.SSLError) as exc:
        raise CustodyError("Cannot establish authenticated operator TLS") from exc
    finally:
        for fd in descriptors:
            os.close(fd)


class OpenBaoOperator:
    def __init__(self, context: ssl.SSLContext, origin: str = "https://127.0.0.1:8200"):
        parsed = urlsplit(origin)
        try:
            loopback = ipaddress.ip_address(parsed.hostname or "").is_loopback
        except ValueError:
            loopback = False
        if (
            parsed.scheme != "https"
            or not loopback
            or parsed.username
            or parsed.password
            or parsed.path
            or parsed.query
            or parsed.fragment
        ):
            raise CustodyError("OpenBao operator origin must be loopback HTTPS")
        self.connection = http.client.HTTPSConnection(
            parsed.hostname, parsed.port or 443, context=context, timeout=15
        )
        self.token = None

    def request(
        self,
        method: str,
        path: str,
        value: dict | None = None,
        *,
        maximum: int = 1024 * 1024,
        binary: bool = False,
        allow_missing: bool = False,
    ):
        headers = {"Connection": "close"}
        if self.token:
            headers["X-Vault-Token"] = self.token
        if value is not None:
            headers["Content-Type"] = "application/json"
        try:
            self.connection.request(method, path, canonical(value) if value is not None else None, headers)
            response = self.connection.getresponse()
            data = response.read(maximum + 1)
            if allow_missing and response.status == 404 and len(data) <= maximum:
                return None
            if response.status not in (200, 204) or len(data) > maximum:
                raise CustodyError(
                    "OpenBao operation rejected or outcome unknown; inspect server state before retrying"
                )
            return data if binary else parse_json(data, maximum) if data else {}
        except (OSError, http.client.HTTPException) as exc:
            raise CustodyError(
                "OpenBao operation outcome unknown; inspect server state before retrying"
            ) from exc
        finally:
            self.connection.close()

    def login(self):
        data = self.request("POST", "/v1/auth/cert/login", {"name": "pap-operator"})
        token = data.get("auth", {}).get("client_token")
        if not isinstance(token, str) or not token or len(token) > 4096:
            raise CustodyError("OpenBao operator login did not return a valid token")
        self.token = token

    def revoke(self):
        if self.token:
            try:
                self.request("POST", "/v1/auth/token/revoke-self", {})
            finally:
                self.token = None

    def unseal(self, packet: dict) -> dict:
        material = recovery_material(packet)
        status = self.request("GET", "/v1/sys/seal-status")
        if status.get("type") != "shamir":
            raise CustodyError("Share unseal is only valid for the historical Shamir profile")
        if status.get("sealed") is False:
            return {"sealed": False, "shares_submitted": 0}
        threshold = material.get("secret_threshold")
        shares = material.get("unseal_shares")
        if (
            type(threshold) is not int
            or threshold < 1
            or not isinstance(shares, list)
            or len(set(shares)) != len(shares)
            or threshold > len(shares)
            or status.get("t") != threshold
        ):
            raise CustodyError("Recovery share threshold or distinctness check failed")
        if status.get("progress") != 0:
            raise CustodyError("Unseal is already in progress; review partial operation before continuing")
        for count, share in enumerate(shares[:threshold], 1):
            if not isinstance(share, str) or not 16 <= len(share) <= 256:
                raise CustodyError("Invalid recovery share")
            status = self.request("POST", "/v1/sys/unseal", {"key": share})
            if status.get("sealed") is False:
                return {"sealed": False, "shares_submitted": count}
        raise CustodyError("Unseal did not finish; inspect server state before retrying")

    def snapshot(self) -> bytes:
        self.login()
        try:
            return self.request(
                "GET", "/v1/sys/storage/raft/snapshot", maximum=256 * 1024 * 1024, binary=True
            )
        finally:
            self.revoke()
