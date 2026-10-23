#!/usr/bin/env python3
"""Run real, disposable Linux UID boundaries without touching system accounts.

This exercises kernel file/socket/peer-credential enforcement. It does not boot
systemd, run OpenBao, or certify the unit sandbox directives. Root is needed only
in the disposable runner to start children with different irreversible UIDs.
"""

import argparse
import ctypes
import errno
import json
import os
import select
import shutil
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

UIDS = {"issuer": 60001, "kms": 60002, "admin": 60003, "app": 60004}


def _security_state():
    state = {}
    for line in Path("/proc/self/status").read_text().splitlines():
        name, _, value = line.partition(":")
        if name in {"CapInh", "CapPrm", "CapEff", "CapAmb", "NoNewPrivs"}:
            state[name] = value.strip()
    return state


def _drop(uid):
    libc = ctypes.CDLL(None, use_errno=True)
    # PR_SET_NO_NEW_PRIVS and PR_SET_DUMPABLE precede every unprivileged exec.
    if libc.prctl(38, 1, 0, 0, 0) or libc.prctl(4, 0, 0, 0, 0):
        raise OSError(ctypes.get_errno(), "prctl failed")
    os.setgroups([])
    os.setresgid(uid, uid, uid)
    os.setresuid(uid, uid, uid)
    os.umask(0o077)


def _denied(operation):
    try:
        result = operation()
        if isinstance(result, int):
            os.close(result)
        return False
    except OSError as error:
        return error.errno in {errno.EACCES, errno.EPERM}


def _socket_call(path):
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(3)
        client.connect(str(path))
        client.sendall(b"status")
        return json.loads(client.recv(4096))


def _kms_call(base, port, *, with_identity):
    context = ssl.create_default_context(cafile=str(base / "public-ca.pem"))
    if with_identity:
        context.load_cert_chain(base / "issuer/client.crt", base / "issuer/client.key")
    with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
        with context.wrap_socket(raw, server_hostname="localhost") as secure:
            secure.sendall(b"sign")
            return secure.recv(128) == b"permitted"


def _kms_worker(base):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(base / "kms/server.crt", base / "kms/server.key")
    context.load_verify_locations(base / "public-ca.pem")
    context.verify_mode = ssl.CERT_REQUIRED
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(8)
        print(json.dumps({"port": listener.getsockname()[1], "uid": os.getuid()}), flush=True)
        while True:
            raw, _ = listener.accept()
            raw.settimeout(3)
            try:
                with context.wrap_socket(raw, server_side=True) as secure:
                    if secure.recv(128) == b"sign":
                        secure.sendall(b"permitted")
            except (OSError, ssl.SSLError):
                raw.close()


def _issuer_worker(base, admin_fd, kms_port):
    checks = {
        "issuer_reads_own_database": (base / "issuer/authority.sqlite3").read_bytes() == b"fixture",
        "issuer_authenticates_to_kms": _kms_call(base, kms_port, with_identity=True),
        "issuer_cannot_read_kms_storage": _denied(lambda: os.open(base / "kms/storage.key", os.O_RDONLY)),
        "issuer_cannot_chown_admin_socket": _denied(
            lambda: os.chown(base / "admin/admin.sock", os.getuid(), -1)
        ),
    }
    admin = socket.socket(fileno=admin_fd)

    def administrative_listener():
        while True:
            client, _ = admin.accept()
            with client:
                _, uid, _ = struct.unpack("3i", client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                client.recv(128)
                client.sendall(json.dumps({"authorized": uid == UIDS["admin"], "peer_uid": uid}).encode())

    threading.Thread(target=administrative_listener, daemon=True).start()
    with socket.socket() as public:
        public.bind(("127.0.0.1", 0))
        public.listen(8)
        print(json.dumps({"port": public.getsockname()[1], "uid": os.getuid(), "checks": checks}), flush=True)
        while True:
            client, _ = public.accept()
            with client:
                client.settimeout(3)
                client.recv(4096)
                body = b'{"public":true}'
                client.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\n" + body)


def _app_worker(base, public_port, kms_port, issuer_pid):
    checks = {}
    for name, path in {
        "issuer_database": "issuer/authority.sqlite3",
        "issuer_client_private_key": "issuer/client.key",
        "issuer_configuration": "authority.json",
        "kms_private_key": "kms/storage.key",
        "kms_tls_private_key": "kms/server.key",
    }.items():
        checks[f"app_cannot_read_{name}"] = _denied(lambda path=path: os.open(base / path, os.O_RDONLY))
    checks["app_cannot_connect_admin_socket"] = _denied(lambda: _socket_call(base / "admin/admin.sock"))
    checks["app_cannot_remove_admin_socket"] = _denied(lambda: os.unlink(base / "admin/admin.sock"))
    checks["app_cannot_read_issuer_process_memory"] = _denied(
        lambda: os.open(f"/proc/{issuer_pid}/mem", os.O_RDONLY)
    )
    checks["app_cannot_signal_issuer"] = _denied(lambda: os.kill(issuer_pid, 0))
    checks["app_cannot_regain_root_uid"] = _denied(lambda: os.setuid(0))
    checks["app_cannot_assume_issuer_uid"] = _denied(lambda: os.setuid(UIDS["issuer"]))
    checks["app_has_no_supplementary_groups"] = os.getgroups() == []
    status = _security_state()
    for capability in ("CapInh", "CapPrm", "CapEff", "CapAmb"):
        checks[f"app_{capability}_zero"] = int(status[capability], 16) == 0
    checks["app_no_new_privileges"] = status["NoNewPrivs"] == "1"
    try:
        checks["app_cannot_authenticate_to_kms"] = not _kms_call(base, kms_port, with_identity=False)
    except (OSError, ssl.SSLError):
        checks["app_cannot_authenticate_to_kms"] = True
    with socket.create_connection(("127.0.0.1", public_port), timeout=3) as public:
        public.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        response = public.recv(4096)
        checks["app_can_reach_public_api"] = b"200 OK" in response and b'{"public":true}' in response
    print(json.dumps({"uid": os.getuid(), "checks": checks}), flush=True)


def _certificates(base):
    # The fixture CA exists only in the root parent memory and is never written.
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "disposable-isolation-ca")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    (base / "public-ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (base / "public-ca.pem").chmod(0o444)
    for role, name, usage in (
        ("kms", "server", ExtendedKeyUsageOID.SERVER_AUTH),
        ("issuer", "client", ExtendedKeyUsageOID.CLIENT_AUTH),
    ):
        key = ec.generate_private_key(ec.SECP256R1())
        certificate = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, role)]))
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=None,
                    decipher_only=None,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
            )
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
            .sign(ca_key, hashes.SHA256())
        )
        key_path = base / role / f"{name}.key"
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        certificate_path = base / role / f"{name}.crt"
        certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        for path in (key_path, certificate_path):
            path.chmod(0o600)
            os.chown(path, UIDS[role], UIDS[role])


def _ready(process):
    ready, _, _ = select.select([process.stdout], [], [], 10)
    if not ready:
        raise RuntimeError("isolation fixture child did not become ready")
    line = process.stdout.readline()
    if not line:
        raise RuntimeError(f"isolation fixture failed: {process.stderr.read()[:300]}")
    return json.loads(line)


def run_probe():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("real UID isolation requires Linux and root in a disposable runner")
    base = Path(tempfile.mkdtemp(prefix="pap-uid-", dir="/tmp"))
    processes = []
    listener = None
    try:
        base.chmod(0o711)
        for role in UIDS:
            directory = base / role
            directory.mkdir(mode=0o700)
            os.chown(directory, UIDS[role], UIDS[role])
        for path, content, role in (
            (base / "issuer/authority.sqlite3", b"fixture", "issuer"),
            (base / "kms/storage.key", b"fixture-storage-material", "kms"),
        ):
            path.write_bytes(content)
            path.chmod(0o600)
            os.chown(path, UIDS[role], UIDS[role])
        configuration = base / "authority.json"
        configuration.write_text("{}")
        configuration.chmod(0o640)
        os.chown(configuration, 0, UIDS["issuer"])
        _certificates(base)
        script = base / "probe.py"
        shutil.copyfile(__file__, script)
        script.chmod(0o555)
        interpreter = sys.executable

        def start(role, *arguments, pass_fds=()):
            process = subprocess.Popen(
                [interpreter, str(script), "--worker", role, "--base", str(base), *map(str, arguments)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                close_fds=True,
                pass_fds=pass_fds,
                env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1"},
                preexec_fn=lambda: _drop(UIDS[role]),
            )
            processes.append(process)
            return process

        kms = start("kms")
        kms_ready = _ready(kms)
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(str(base / "admin/admin.sock"))
        listener.listen(8)
        (base / "admin/admin.sock").chmod(0o600)
        os.chown(base / "admin/admin.sock", UIDS["admin"], UIDS["admin"])
        issuer = start(
            "issuer",
            "--admin-fd",
            listener.fileno(),
            "--kms-port",
            kms_ready["port"],
            pass_fds=(listener.fileno(),),
        )
        issuer_ready = _ready(issuer)
        admin = start("admin")
        administrative = _ready(admin)
        admin.wait(timeout=5)
        app = start(
            "app",
            "--public-port",
            issuer_ready["port"],
            "--kms-port",
            kms_ready["port"],
            "--issuer-pid",
            issuer.pid,
        )
        app_ready = _ready(app)
        app.wait(timeout=5)
        checks = {
            **issuer_ready["checks"],
            **app_ready["checks"],
            "admin_peer_uid_verified_by_kernel": administrative
            == {"authorized": True, "peer_uid": UIDS["admin"]},
            "four_distinct_nonroot_uids": len(set(UIDS.values())) == 4
            and all(uid != 0 for uid in UIDS.values()),
            "admin_socket_mode_0600": stat.S_IMODE((base / "admin/admin.sock").stat().st_mode) == 0o600,
        }
        return {
            "passed": all(checks.values()),
            "checks": checks,
            "uids": UIDS,
            "scope": "Linux DAC, mTLS, peer UID, privilege drop",
        }
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
        if listener:
            listener.close()
        shutil.rmtree(base)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", choices=UIDS)
    parser.add_argument("--base", type=Path)
    parser.add_argument("--kms-port", type=int)
    parser.add_argument("--public-port", type=int)
    parser.add_argument("--admin-fd", type=int)
    parser.add_argument("--issuer-pid", type=int)
    arguments = parser.parse_args()
    if not arguments.worker:
        result = run_probe()
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result["passed"] else 1)
    if arguments.worker == "kms":
        _kms_worker(arguments.base)
    elif arguments.worker == "issuer":
        _issuer_worker(arguments.base, arguments.admin_fd, arguments.kms_port)
    elif arguments.worker == "admin":
        print(json.dumps(_socket_call(arguments.base / "admin/admin.sock")), flush=True)
    else:
        _app_worker(arguments.base, arguments.public_port, arguments.kms_port, arguments.issuer_pid)


if __name__ == "__main__":
    main()
