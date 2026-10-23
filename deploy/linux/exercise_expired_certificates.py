#!/usr/bin/env python3
"""Run an explicitly requested certificate-expiry recovery exercise on one PAP host.

Default mode only checks prerequisites. --exercise briefly stops the issuer and
enroller, publishes already expired test leaves, proves TLS rejection, then starts
the normal units and observes recovery. OpenBao is never stopped or restarted.
No clock changes, TLS verification bypasses, KMS writes, or private output occur.
"""

import argparse
import ctypes
import hashlib
import http.client
import ipaddress
import json
import os
import pwd
import re
import resource
import ssl
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ISSUER_ROOT = Path("/var/lib/pap-issuer/credentials")
LISTENER_ROOT = Path("/var/lib/pap-enroller/listener")
CA_FILE = Path("/etc/pap/enrollment-ca.pem")
CA_KEY = Path("/etc/pap/enrollment/ca-key.pem")
SYSTEMCTL = "/usr/bin/systemctl"
GENERATION = re.compile(r"generation-[0-9a-f]{32}")
UNITS = ("pap-enroller.service", "pap-openbao.service", "pap-authority.service", "pap-caddy.service")


class ExerciseError(Exception):
    pass


def require(condition, code):
    if not condition:
        raise ExerciseError(code)


def service(action, unit):
    completed = subprocess.run([SYSTEMCTL, action, unit], capture_output=True, timeout=35, check=False)
    require(completed.returncode == 0, "unit_operation_failed_" + action)


def properties(unit):
    completed = subprocess.run(
        [SYSTEMCTL, "show", unit, "--property=ActiveState,MainPID,Requires,Wants"],
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )
    require(completed.returncode == 0, "unit_metadata_unavailable")
    return dict(line.split("=", 1) for line in completed.stdout.splitlines() if "=" in line)


def check_pid(pid):
    current = properties("pap-openbao.service")
    require(current["ActiveState"] == "active", "kms_process_not_active")
    require(int(current["MainPID"]) == pid, "kms_process_changed")


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def trusted_file(path, *, uid, mode):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(descriptor)
        require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == uid
            and stat.S_IMODE(info.st_mode) == mode
            and 0 < info.st_size < 65536,
            "fixture_input_untrusted",
        )
        return os.read(descriptor, 65536)
    finally:
        os.close(descriptor)


def current(root, uid, gid, mode):
    info = root.lstat()
    require(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == uid
        and info.st_gid == gid
        and stat.S_IMODE(info.st_mode) == mode,
        "fixture_directory_untrusted",
    )
    pointer = root / "current"
    info = pointer.lstat()
    name = os.readlink(pointer)
    require(
        stat.S_ISLNK(info.st_mode) and info.st_uid == uid and GENERATION.fullmatch(name),
        "fixture_generation_untrusted",
    )
    generation = root / name
    info = generation.lstat()
    require(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == uid
        and info.st_gid == gid
        and stat.S_IMODE(info.st_mode) == (0o700 if root == ISSUER_ROOT else 0o750),
        "fixture_generation_untrusted",
    )
    return generation


def tls_request(cert_bytes, key_bytes):
    # Private temporary files are root-only, never passed as command arguments,
    # and removed after SSLContext loads them. All HTTPS checks use pinned CA.
    with tempfile.TemporaryDirectory(prefix="pap-expiry-tls-", dir="/run") as temporary:
        directory = Path(temporary)
        for name, value in (("client.pem", cert_bytes), ("client.key", key_bytes)):
            descriptor = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(value)
        context = ssl.create_default_context(cafile=str(CA_FILE))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(directory / "client.pem"), str(directory / "client.key"))
    connection = http.client.HTTPSConnection("127.0.0.1", 8200, context=context, timeout=3)
    try:
        connection.request("GET", "/v1/sys/health")
        response = connection.getresponse()
        data = response.read(16385)
        require(len(data) <= 16384, "kms_health_response_too_large")
        return response.status, json.loads(data)
    finally:
        connection.close()


def authority_health():
    connection = http.client.HTTPConnection("127.0.0.1", 9480, timeout=2)
    try:
        connection.request("GET", "/health")
        response = connection.getresponse()
        data = response.read(1025)
        return response.status == 200 and len(data) <= 1024 and json.loads(data) == {"ready": True}
    except (OSError, ValueError, http.client.HTTPException):
        return False
    finally:
        connection.close()


def admin_active_key():
    completed = subprocess.run(
        [
            "/usr/sbin/runuser",
            "--user",
            "pap-admin",
            "--",
            "/opt/pap/venv/bin/pap",
            "status",
            "--state",
            "/run/pap-admin",
        ],
        capture_output=True,
        timeout=7,
        check=False,
    )
    require(completed.returncode == 0, "private_administration_unavailable")
    value = json.loads(completed.stdout)
    keys = [key["kid"] for key in value["signing_keys"] if key["state"] == "active"]
    require(value.get("ready") and len(keys) == 1, "private_administration_not_ready")
    return keys[0]


def valid_leaf(cert, ca, *, now):
    cert.verify_directly_issued_by(ca)
    require(
        cert.not_valid_before_utc <= now and cert.not_valid_after_utc > now + timedelta(minutes=10),
        "baseline_leaf_lifetime_insufficient",
    )
    require(not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca, "leaf_is_ca")


def expired_leaf(ca, ca_key, *, server, config):
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    name = "localhost" if server else config.get("client_common_name", "pap-issuer")
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(hours=2))
        .not_valid_after(now - timedelta(hours=1))
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
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca.public_key()), critical=False)
    )
    if server:
        sans = [x509.DNSName(name) for name in config.get("server_dns_names", ["localhost"])]
        sans += [
            x509.IPAddress(ipaddress.ip_address(value))
            for value in config.get("server_ip_addresses", ["127.0.0.1"])
        ]
    else:
        uri = config.get("client_uri_san")
        sans = [x509.UniformResourceIdentifier(uri)] if uri else []
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    cert = builder.sign(ca_key, hashes.SHA256())
    cert.verify_directly_issued_by(ca)
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
    )


def switch(root, generation, uid, gid):
    require(GENERATION.fullmatch(generation), "fixture_pointer_target_invalid")
    pointer = root / ("next-" + uuid.uuid4().hex)
    os.symlink(generation, pointer)
    os.lchown(pointer, uid, gid)
    os.replace(pointer, root / "current")
    fsync_directory(root)


def publish(root, cert, key, *, uid, gid, server):
    name = "generation-" + uuid.uuid4().hex
    directory = root / name
    directory.mkdir(mode=0o700)
    os.chown(directory, uid, gid)
    os.chmod(directory, 0o750 if server else 0o700)
    cert_name, key_name = ("server.crt", "server.key") if server else ("client-cert.pem", "client-key.pem")
    for filename, value in ((cert_name, cert), (key_name, key)):
        descriptor = os.open(
            directory / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "wb") as output:
            os.fchown(output.fileno(), uid, gid)
            os.fchmod(output.fileno(), 0o640 if server else 0o600)
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
    fsync_directory(directory)
    switch(root, name, uid, gid)
    return name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exercise", action="store_true")
    parser.add_argument("--expected-issuer", required=True)
    arguments = parser.parse_args()
    receipt = {
        "recorded_at": datetime.now(UTC).isoformat(),
        "exercise_requested": arguments.exercise,
        "passed": False,
        "scope": "real leaf expiry and service restart recovery; VM suspend and cached-token renewal are separate exercises",
    }
    stopped = False
    old_client = old_listener = None
    issuer = enroller = None
    try:
        require(sys.platform == "linux" and os.geteuid() == 0, "requires_installed_linux_root")
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        libc = ctypes.CDLL(None, use_errno=True)
        require(libc.prctl(4, 0, 0, 0, 0) == 0, "process_dump_protection_failed")
        require(libc.prctl(38, 1, 0, 0, 0) == 0, "process_privilege_lock_failed")
        info = Path(__file__).resolve().stat()
        require(info.st_uid == 0 and not info.st_mode & 0o022, "exercise_source_untrusted")
        config = json.loads(trusted_file(Path("/etc/pap/authority.json"), uid=0, mode=0o640))
        require(config["issuer"] == arguments.expected_issuer, "unexpected_authority")
        require(config["state_dir"] == "/var/lib/pap-issuer", "unexpected_state_path")
        require(config["kms"]["base_url"] == "https://127.0.0.1:8200", "unexpected_kms_endpoint")
        enrollment = json.loads(trusted_file(Path("/etc/pap/enrollment.json"), uid=0, mode=0o640))
        issuer, enroller, kms = (pwd.getpwnam(name) for name in ("pap-issuer", "pap-enroller", "pap-kms"))
        require(enrollment["issuer_uid"] == issuer.pw_uid, "unexpected_issuer_uid")
        require(enrollment["broker_uid"] == enroller.pw_uid, "unexpected_broker_uid")
        expected_kms = {
            "client_cert": str(ISSUER_ROOT / "current/client-cert.pem"),
            "client_key": str(ISSUER_ROOT / "current/client-key.pem"),
            "ca_file": str(CA_FILE),
            "client_ca_file": str(CA_FILE),
            "enrollment_socket": "/run/pap-enroller/enroll.sock",
            "enrollment_uid": enroller.pw_uid,
        }
        require(
            all(config["kms"].get(name) == value for name, value in expected_kms.items()),
            "unexpected_authority_credential_binding",
        )
        for unit in UNITS:
            require(properties(unit)["ActiveState"] == "active", "baseline_unit_not_active")
        props = properties("pap-openbao.service")
        require("pap-enroller.service" not in props.get("Requires", "").split(), "unsafe_kms_dependency")
        pid = int(props["MainPID"])
        require(pid > 1, "kms_pid_invalid")
        old_client = current(ISSUER_ROOT, issuer.pw_uid, issuer.pw_gid, 0o700)
        old_listener = current(LISTENER_ROOT, enroller.pw_uid, kms.pw_gid, 0o710)
        client = trusted_file(old_client / "client-cert.pem", uid=issuer.pw_uid, mode=0o600)
        key = trusted_file(old_client / "client-key.pem", uid=issuer.pw_uid, mode=0o600)
        ca = x509.load_pem_x509_certificate(trusted_file(CA_FILE, uid=0, mode=0o644))
        now = datetime.now(UTC)
        valid_leaf(x509.load_pem_x509_certificate(client), ca, now=now)
        valid_leaf(
            x509.load_pem_x509_certificate(
                trusted_file(old_listener / "server.crt", uid=enroller.pw_uid, mode=0o640)
            ),
            ca,
            now=now,
        )
        status, health = tls_request(client, key)
        require(
            status == 200 and health.get("initialized") and not health.get("sealed"), "kms_baseline_not_ready"
        )
        require(authority_health(), "authority_baseline_not_ready")
        active_key = admin_active_key()
        receipt.update({"kms_pid_before": pid, "baseline_verified": True, "active_key_before": active_key})
        if not arguments.exercise:
            receipt.update({"passed": True, "mutation_performed": False})
            return receipt
        ca_key = serialization.load_pem_private_key(trusted_file(CA_KEY, uid=0, mode=0o600), password=None)
        require(ca_key.public_key().public_numbers() == ca.public_key().public_numbers(), "ca_key_mismatch")
        expired_client, expired_client_key = expired_leaf(ca, ca_key, server=False, config=enrollment)
        expired_server, expired_server_key = expired_leaf(ca, ca_key, server=True, config=enrollment)
        del ca_key
        stopped = True
        service("stop", "pap-authority.service")
        service("stop", "pap-enroller.service")
        check_pid(pid)
        for unit in ("pap-authority.service", "pap-enroller.service"):
            require(properties(unit)["ActiveState"] == "inactive", "fixture_units_not_stopped")
        expired_client_name = publish(
            ISSUER_ROOT,
            expired_client,
            expired_client_key,
            uid=issuer.pw_uid,
            gid=issuer.pw_gid,
            server=False,
        )
        try:
            tls_request(expired_client, expired_client_key)
        except ssl.SSLCertVerificationError:
            raise ExerciseError("server_failed_before_expired_client_check") from None
        except ssl.SSLError as error:
            require(
                error.reason in {"SSLV3_ALERT_CERTIFICATE_EXPIRED", "SSLV3_ALERT_BAD_CERTIFICATE"},
                "expired_client_rejected_for_unexpected_reason",
            )
            receipt["expired_client_rejected"] = error.reason
        else:
            raise ExerciseError("expired_client_was_accepted")
        for unit in ("pap-authority.service", "pap-enroller.service"):
            require(properties(unit)["ActiveState"] == "inactive", "unexpected_unit_reactivation")
        expired_listener_name = publish(
            LISTENER_ROOT,
            expired_server,
            expired_server_key,
            uid=enroller.pw_uid,
            gid=kms.pw_gid,
            server=True,
        )
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            check_pid(pid)
            try:
                tls_request(client, key)
            except ssl.SSLCertVerificationError as error:
                require(error.verify_code == 10, "server_rejected_for_unexpected_reason")
                receipt["expired_listener_rejected"] = {"verify_code": 10, "verification_enabled": True}
                break
            time.sleep(0.3)
        else:
            raise ExerciseError("expired_listener_not_loaded_within_deadline")
        started_at = time.monotonic()
        service("start", "pap-enroller.service")
        service("start", "pap-authority.service")
        deadline = started_at + 45
        while time.monotonic() < deadline:
            check_pid(pid)
            new_client = current(ISSUER_ROOT, issuer.pw_uid, issuer.pw_gid, 0o700)
            new_listener = current(LISTENER_ROOT, enroller.pw_uid, kms.pw_gid, 0o710)
            if new_client.name not in {expired_client_name, old_client.name} and new_listener.name not in {
                expired_listener_name,
                old_listener.name,
            }:
                fresh_client = trusted_file(new_client / "client-cert.pem", uid=issuer.pw_uid, mode=0o600)
                fresh_key = trusted_file(new_client / "client-key.pem", uid=issuer.pw_uid, mode=0o600)
                fresh_listener = trusted_file(new_listener / "server.crt", uid=enroller.pw_uid, mode=0o640)
                valid_leaf(x509.load_pem_x509_certificate(fresh_client), ca, now=datetime.now(UTC))
                valid_leaf(x509.load_pem_x509_certificate(fresh_listener), ca, now=datetime.now(UTC))
                try:
                    status, health = tls_request(fresh_client, fresh_key)
                except (ssl.SSLError, OSError, http.client.HTTPException):
                    pass
                else:
                    if status == 200 and not health.get("sealed") and authority_health():
                        recovered_active_key = admin_active_key()
                        require(recovered_active_key == active_key, "unexpected_signing_key_change")
                        stopped = False
                        receipt.update(
                            {
                                "passed": True,
                                "mutation_performed": True,
                                "automatic_recovery_seconds": round(time.monotonic() - started_at, 3),
                                "kms_pid_after": pid,
                                "kms_process_unchanged": True,
                                "kms_unsealed": True,
                                "authority_ready_after_fresh_authentication": True,
                                "active_key_after": recovered_active_key,
                                "client_certificate_sha256": hashlib.sha256(fresh_client).hexdigest(),
                                "listener_certificate_sha256": hashlib.sha256(fresh_listener).hexdigest(),
                            }
                        )
                        return receipt
            time.sleep(0.3)
        raise ExerciseError("automatic_recovery_deadline_exceeded")
    except Exception as error:
        receipt["error_code"] = str(error) if isinstance(error, ExerciseError) else type(error).__name__
        if stopped and old_client and old_listener and issuer and enroller:
            try:
                # Availability recovery on test failure is explicitly manual
                # restoration and can never turn a failed exercise into PASS.
                service("stop", "pap-authority.service")
                service("stop", "pap-enroller.service")
                for directory, filename, owner, mode in (
                    (old_client, "client-cert.pem", issuer.pw_uid, 0o600),
                    (old_listener, "server.crt", enroller.pw_uid, 0o640),
                ):
                    certificate = x509.load_pem_x509_certificate(
                        trusted_file(directory / filename, uid=owner, mode=mode)
                    )
                    require(certificate.not_valid_after_utc > datetime.now(UTC), "restoration_leaf_expired")
                switch(ISSUER_ROOT, old_client.name, issuer.pw_uid, issuer.pw_gid)
                switch(LISTENER_ROOT, old_listener.name, enroller.pw_uid, enroller.pw_gid)
                service("start", "pap-enroller.service")
                service("start", "pap-authority.service")
                receipt["failure_restoration"] = "original_valid_pointers_restored_using_normal_units"
            except Exception:
                receipt["failure_restoration"] = "operator_attention_required"
        return receipt


if __name__ == "__main__":
    result = main()
    print(json.dumps(result))
    raise SystemExit(0 if result["passed"] else 1)
