#!/usr/bin/env python3
"""Exercise actual production activation code in a disposable Linux container.

The fixture uses the daemon's fixed /run pathname, so it refuses execution
outside a root Docker container or when that pathname already exists. It never
boots the daemon, initializes KMS, or claims full deployment acceptance.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import select
import socket
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

ADMIN_DIRECTORY = Path("/run/pap-admin")
ADMIN_SOCKET = ADMIN_DIRECTORY / "admin.sock"


def helpers():
    specification = importlib.util.spec_from_file_location(
        "pap_isolation_fixture", Path(__file__).with_name("isolation_probe.py")
    )
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def issuer_worker(source_root, admin_fd):
    from pap import production

    fixture = helpers()
    if admin_fd != 3:
        os.dup2(admin_fd, 3)
        os.close(admin_fd)
    os.environ.update(LISTEN_PID=str(os.getpid()), LISTEN_FDS="1", LISTEN_FDNAMES="pap-admin")
    checks = {
        "actual_production_module_loaded": Path(production.__file__).resolve()
        == source_root / "pap/production.py",
        "issuer_uid_is_distinct_nonroot": os.getuid() == fixture.UIDS["issuer"] != 0,
        "issuer_uid_triplet_is_irreversible": os.getresuid() == (fixture.UIDS["issuer"],) * 3,
        "issuer_gid_triplet_is_irreversible": os.getresgid() == (fixture.UIDS["issuer"],) * 3,
        "issuer_has_no_supplementary_groups": os.getgroups() == [],
        "issuer_cannot_traverse_admin_directory": fixture._denied(lambda: os.listdir(ADMIN_DIRECTORY)),
        "issuer_cannot_lstat_admin_socket": fixture._denied(lambda: os.lstat(ADMIN_SOCKET)),
    }
    production.require_isolated_linux()
    checks["actual_runtime_isolation_validator_accepts_issuer"] = True
    os.environ["LISTEN_FDNAMES"] = "incorrect-name"
    try:
        production.activated_admin_socket(fixture.UIDS["admin"])
    except ValueError:
        checks["actual_activation_rejects_wrong_descriptor_name"] = True
    else:
        checks["actual_activation_rejects_wrong_descriptor_name"] = False
    os.environ["LISTEN_FDNAMES"] = "pap-admin"
    try:
        production.activated_admin_socket(fixture.UIDS["app"])
    except ValueError:
        checks["actual_activation_rejects_wrong_admin_uid"] = True
    else:
        checks["actual_activation_rejects_wrong_admin_uid"] = False
    with production.activated_admin_socket(fixture.UIDS["admin"]) as listener:
        checks["actual_activation_accepts_private_admin_listener"] = True
        checks["actual_activation_returns_nonblocking_listener"] = listener.getblocking() is False
        print(json.dumps({"ready": True}), flush=True)
        readable, _, _ = select.select([listener], [], [], 10)
        if not readable:
            raise RuntimeError("administrative fixture client did not connect")
        client, _ = listener.accept()
        with client:
            client.settimeout(5)
            request = SimpleNamespace(
                transport=SimpleNamespace(get_extra_info=lambda name: client if name == "socket" else None)
            )
            peer = production.peer_uid(request)
            checks["actual_peer_uid_reads_admin_identity_from_kernel"] = peer == fixture.UIDS["admin"]
            client.recv(128)
            client.sendall(json.dumps({"authorized": peer == fixture.UIDS["admin"]}).encode())
    print(json.dumps({"checks": checks}), flush=True)


def admin_worker():
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(5)
        client.connect(str(ADMIN_SOCKET))
        client.sendall(b"status")
        print(
            json.dumps({"admin_received_authorization": json.loads(client.recv(128))["authorized"]}),
            flush=True,
        )


def run_probe(source_root):
    if sys.platform != "linux" or os.geteuid() != 0 or not Path("/.dockerenv").is_file():
        raise RuntimeError(
            "fixed runtime pathname probe requires root in a disposable Docker Linux container"
        )
    if ADMIN_DIRECTORY.exists() or ADMIN_DIRECTORY.is_symlink():
        raise RuntimeError("refusing to replace an existing administrative runtime directory")
    source_root = source_root.resolve(strict=True)
    sys.path.insert(0, str(source_root))
    from pap import production

    fixture = helpers()
    processes = []
    listener = None
    created = False
    try:
        try:
            production.require_isolated_linux()
        except ValueError:
            root_rejected = True
        else:
            root_rejected = False
        ADMIN_DIRECTORY.mkdir(mode=0o700)
        created = True
        os.chown(ADMIN_DIRECTORY, fixture.UIDS["admin"], fixture.UIDS["admin"])
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(str(ADMIN_SOCKET))
        listener.listen(8)
        ADMIN_SOCKET.chmod(0o600)
        os.chown(ADMIN_SOCKET, fixture.UIDS["admin"], fixture.UIDS["admin"])

        def start(role, *arguments, pass_fds=()):
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--worker",
                    role,
                    "--source-root",
                    str(source_root),
                    *map(str, arguments),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                close_fds=True,
                pass_fds=pass_fds,
                env={"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1", "PYTHONPATH": str(source_root)},
                preexec_fn=lambda: fixture._drop(fixture.UIDS[role]),
            )
            processes.append(process)
            return process

        issuer = start("issuer", "--admin-fd", listener.fileno(), pass_fds=(listener.fileno(),))
        if fixture._ready(issuer) != {"ready": True}:
            raise RuntimeError("actual runtime activation did not become ready")
        admin = start("admin")
        result = fixture._ready(issuer)
        result["checks"].update(fixture._ready(admin))
        for process in (issuer, admin):
            process.wait(timeout=5)
            if process.returncode != 0:
                raise RuntimeError("actual runtime activation child failed")
        result["checks"]["actual_runtime_isolation_validator_rejects_root"] = root_rejected
        result["passed"] = all(result["checks"].values())
        result["source_sha256"] = {
            str(path.relative_to(source_root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (source_root / "pap/production.py", source_root / "pap/local.py")
        }
        result["probe_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        result["scope"] = "Actual PAP runtime activation/isolation validators and kernel admin peer identity"
        result["not_verified"] = [
            "full daemon boot",
            "systemd PID1 execution",
            "OpenBao",
            "public TLS",
            "Netlify",
        ]
        return result
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
        if created:
            ADMIN_SOCKET.unlink(missing_ok=True)
            ADMIN_DIRECTORY.rmdir()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path("/source"))
    parser.add_argument("--worker", choices=("issuer", "admin"))
    parser.add_argument("--admin-fd", type=int)
    arguments = parser.parse_args()
    if arguments.worker == "issuer":
        issuer_worker(arguments.source_root, arguments.admin_fd)
    elif arguments.worker == "admin":
        admin_worker()
    else:
        result = run_probe(arguments.source_root)
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
