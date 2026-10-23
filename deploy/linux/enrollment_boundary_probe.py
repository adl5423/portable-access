#!/usr/bin/env python3
"""Exercise the installed Linux UID boundary without reading stored private key values.

Requires an already running broker. Mints one short-lived issuer certificate in
memory, performs no KMS writes, and creates no accounts or persistent state.
"""

import ctypes
import json
import os
import pwd
import socket
import stat
import struct
import subprocess
import sys
import time
from pathlib import Path

ROLES = {
    "pap-issuer": [
        ("/var/lib/pap-issuer", True, True),
        ("/var/lib/pap-kms", True, False),
        ("/var/lib/pap-enroller", True, False),
        ("/etc/pap/enrollment/ca-key.pem", False, False),
    ],
    "pap-kms": [
        ("/var/lib/pap-kms", True, True),
        ("/var/lib/pap-issuer", True, False),
        ("/var/lib/pap-enroller/listener/current/server.key", False, True),
        ("/etc/pap/enrollment/ca-key.pem", False, False),
    ],
    "pap-enroller": [
        ("/var/lib/pap-enroller", True, True),
        ("/var/lib/pap-issuer", True, False),
        ("/var/lib/pap-kms", True, False),
        ("/etc/pap/enrollment/ca-key.pem", False, False),
    ],
    "pap-admin": [
        ("/run/pap-admin", True, True),
        ("/var/lib/pap-issuer", True, False),
        ("/var/lib/pap-kms", True, False),
        ("/var/lib/pap-enroller", True, False),
    ],
    "pap-app": [
        ("/var/lib/pap-issuer", True, False),
        ("/var/lib/pap-kms", True, False),
        ("/var/lib/pap-enroller", True, False),
        ("/run/pap-admin", True, False),
        ("/etc/pap/enrollment/ca-key.pem", False, False),
    ],
    "pap-proxy": [
        ("/var/lib/pap-proxy", True, True),
        ("/etc/pap/Caddyfile", False, True),
        ("/var/lib/pap-issuer", True, False),
        ("/var/lib/pap-kms", True, False),
        ("/var/lib/pap-enroller", True, False),
    ],
}


def child(role):
    if ctypes.CDLL(None, use_errno=True).prctl(38, 1, 0, 0, 0):
        raise OSError("cannot set no-new-privileges")
    status = dict(
        line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line
    )
    result = {
        "uid": os.geteuid(),
        "gid": os.getegid(),
        "no_new_privileges": status["NoNewPrivs"].strip() == "1",
        "zero_effective_capabilities": int(status["CapEff"].strip(), 16) == 0,
        "checks": [],
    }
    if role in ROLES:
        for name, directory, expected in ROLES[role]:
            try:
                if directory:
                    with os.scandir(name):
                        pass
                else:
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW)
                    os.close(fd)
                allowed = True
            except PermissionError:
                allowed = False
            result["checks"].append(
                {
                    "path": name,
                    "expected_open": expected,
                    "actual_open": allowed,
                    "passed": allowed == expected,
                }
            )
    elif role == "app-with-issuer-group":
        # The production client intentionally hides all broker error details.
        # A disallowed UID is rejected before the broker reads any request, so
        # receive its framed denial directly without sending a CSR or a key.
        broker_uid = pwd.getpwnam("pap-enroller").pw_uid
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(3)
            connection.connect("/run/pap-enroller/enroll.sock")
            _, actual_uid, _ = struct.unpack(
                "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
            )
            frame = b""
            while len(frame) < 4:
                value = connection.recv(4 - len(frame))
                if not value:
                    raise RuntimeError("broker denial frame missing")
                frame += value
            length = struct.unpack("!I", frame)[0]
            if not 0 < length <= 1024:
                raise RuntimeError("broker denial frame invalid")
            payload = b""
            while len(payload) < length:
                value = connection.recv(length - len(payload))
                if not value:
                    raise RuntimeError("broker denial payload missing")
                payload += value
            response = json.loads(payload)
        result["error_code"] = response.get("error")
        result["checks"].append(
            {
                "check": "wrong_uid_rejected_after_filesystem_access",
                "passed": actual_uid == broker_uid and response == {"error": "enrollment_peer_denied"},
            }
        )
    else:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        from pap.enrollment import UnixEnrollmentClient
        from pap.signers import SignerError

        cfg = {"broker_uid": pwd.getpwnam("pap-enroller").pw_uid}
        client = UnixEnrollmentClient(
            "/run/pap-enroller/enroll.sock", "/etc/pap/enrollment-ca.pem", cfg["broker_uid"], timeout=3.0
        )
        try:
            material = client.issue_client_certificate("pap-issuer", "pap-issuer")
        except SignerError as error:
            result["error_code"] = error.code
            result["checks"].append(
                {
                    "check": "wrong_uid_rejected_after_filesystem_access",
                    "passed": False,
                }
            )
        else:
            cert = x509.load_pem_x509_certificate(material["certificate"].encode())
            key = serialization.load_pem_private_key(material["private_key"].encode(), password=None)
            result["checks"].append(
                {
                    "check": "issuer_native_uid_enrollment_and_key_match",
                    "passed": role == "issuer-enrollment"
                    and cert.public_key().public_numbers() == key.public_key().public_numbers(),
                }
            )
    result["passed"] = (
        result["no_new_privileges"]
        and result["zero_effective_capabilities"]
        and all(item["passed"] for item in result["checks"])
    )
    print(json.dumps(result))
    return 0 if result["passed"] else 1


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--child":
        return child(sys.argv[2])
    if sys.platform != "linux" or os.geteuid() != 0:
        raise SystemExit("requires root on the installed Linux PAP host")
    filename = Path(__file__).resolve()
    if filename.stat().st_uid != 0 or stat.S_IMODE(filename.stat().st_mode) & 0o022:
        raise SystemExit("probe must be a root-owned public source file")
    results = {}
    for role in [*ROLES, "issuer-enrollment", "app-with-issuer-group"]:
        user = (
            "pap-issuer"
            if role == "issuer-enrollment"
            else "pap-app"
            if role == "app-with-issuer-group"
            else role
        )
        command = ["/usr/sbin/runuser", "--user", user]
        if role == "app-with-issuer-group":
            command += ["--group", "pap-app", "--supp-group", "pap-issuer"]
        command += ["--", "/opt/pap/venv/bin/python", str(filename), "--child", role]
        completed = subprocess.run(command, capture_output=True, text=True, timeout=10)
        try:
            result = json.loads(completed.stdout)
        except ValueError:
            result = {"passed": False, "error": "child_failed_without_public_result"}
        results[role] = result
    output = {
        "observed_unix_time": int(time.time()),
        "scope": "actual installed six UID DAC and native Unix credential checks; no stored private key bytes read and no private values returned",
        "passed": all(item["passed"] for item in results.values()),
        "results": results,
    }
    print(json.dumps(output))
    return 0 if output["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
