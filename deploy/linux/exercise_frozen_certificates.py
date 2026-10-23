#!/usr/bin/env python3
"""Probe cached-login recovery after freezing existing issuer and broker processes.

The default is read-only planning. --exercise uses pinned pidfds, replaces leaves
with expired test certificates, resumes the same processes and requires new KMS
login evidence. It never restarts services, changes the clock or bypasses TLS.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import pwd
import resource
import select
import signal
import ssl
import stat
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

if __package__:
    from . import exercise_expired_certificates as b
else:
    import exercise_expired_certificates as b

AUDIT = Path("/var/lib/pap-kms/audit.jsonl")
MAX_AUDIT = 32 * 1024 * 1024
MAX_LINE = 64 * 1024
TRACKED = ("pap-authority.service", "pap-enroller.service", "pap-openbao.service")


def hardened_root():
    b.require(sys.platform == "linux" and os.geteuid() == 0, "requires_installed_linux_root")
    b.require(hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal"), "native_pidfd_required")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    libc = ctypes.CDLL(None, use_errno=True)
    b.require(libc.prctl(4, 0, 0, 0, 0) == 0, "process_dump_protection_failed")
    b.require(libc.prctl(38, 1, 0, 0, 0) == 0, "process_privilege_lock_failed")
    for source in (Path(__file__), Path(b.__file__)):
        info = source.lstat()
        b.require(
            stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
            "exercise_source_untrusted",
        )
        for directory in source.absolute().parents:
            info = directory.lstat()
            b.require(
                stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022,
                "exercise_source_directory_untrusted",
            )


def process_status(pid):
    value = Path(f"/proc/{pid}/status").read_text()
    return dict(line.split(":", 1) for line in value.splitlines() if ":" in line)


def process_started_at(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(") ", 1)[1].split()
    ticks = int(fields[19])
    boot = next(
        int(line.split()[1])
        for line in Path("/proc/stat").read_text().splitlines()
        if line.startswith("btime ")
    )
    return boot + ticks / os.sysconf("SC_CLK_TCK")


class PinnedProcess:
    def __init__(self, unit, pid, uid, gid):
        self.unit, self.pid, self.uid, self.gid = unit, pid, uid, gid
        self.fd = os.pidfd_open(pid, 0)
        self.resume_required = False
        try:
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        poller = select.poll()
        poller.register(self.fd, select.POLLIN)
        b.require(not poller.poll(0), "pinned_process_exited")
        info = process_status(self.pid)
        b.require(
            info.get("Uid", "").split() == [str(self.uid)] * 4
            and info.get("Gid", "").split() == [str(self.gid)] * 4,
            "pinned_process_identity_changed",
        )
        b.require(
            info.get("NoNewPrivs", "").strip() == "1"
            and all(
                int(info.get(name, "1").strip(), 16) == 0 for name in ("CapEff", "CapPrm", "CapInh", "CapAmb")
            ),
            "pinned_process_privileges_invalid",
        )
        return info["State"].strip().split()[0]

    def stop(self):
        self.check()
        self.resume_required = True
        signal.pidfd_send_signal(self.fd, signal.SIGSTOP, None, 0)

    def resume(self):
        if self.resume_required:
            signal.pidfd_send_signal(self.fd, signal.SIGCONT, None, 0)
            self.resume_required = False

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


@dataclass(frozen=True)
class LoginCounts:
    identity: tuple[int, int]
    requests: int
    responses: int
    recent_requests: int
    recent_responses: int


def login_counts(kms_uid, since):
    """Inspect only audit event kind/path/time; never return bodies or credentials."""
    descriptor = os.open(AUDIT, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        b.require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid == kms_uid
            and stat.S_IMODE(info.st_mode) == 0o600
            and 0 < info.st_size <= MAX_AUDIT,
            "audit_file_untrusted_or_too_large",
        )
        total = {"request": 0, "response": 0}
        recent = {"request": 0, "response": 0}
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            remaining = info.st_size
            while remaining:
                line = stream.readline(min(MAX_LINE + 1, remaining))
                if not line:
                    break
                remaining -= len(line)
                b.require(len(line) <= MAX_LINE, "audit_record_too_large")
                if not line.endswith(b"\n"):
                    b.require(remaining == 0, "audit_record_incomplete")
                    break
                record = json.loads(line)
                kind = record.get("type")
                request = record.get("request")
                if (
                    kind not in total
                    or not isinstance(request, dict)
                    or request.get("path") != "auth/cert/login"
                ):
                    continue
                if kind == "response" and record.get("error"):
                    continue
                total[kind] += 1
                timestamp = datetime.fromisoformat(record["time"].replace("Z", "+00:00")).timestamp()
                if timestamp >= since:
                    recent[kind] += 1
        return LoginCounts(
            (info.st_dev, info.st_ino),
            total["request"],
            total["response"],
            recent["request"],
            recent["response"],
        )
    finally:
        os.close(descriptor)


@dataclass
class Baseline:
    enrollment: dict
    issuer: object
    broker: object
    kms: object
    processes: dict
    old_client: Path
    old_listener: Path
    client: bytes
    key: bytes
    ca: x509.Certificate
    active_key: str
    logins: LoginCounts


class FrozenProbe:
    def __init__(self, expected_issuer):
        self.expected_issuer = expected_issuer
        self.processes = {}
        self.baseline = None
        self.mutated = False
        self.cleaning_up = False

    def identities_unchanged(self):
        for unit, process in self.processes.items():
            process.check()
            props = b.properties(unit)
            b.require(
                props.get("ActiveState") == "active" and int(props.get("MainPID", "0")) == process.pid,
                "service_process_changed",
            )

    def baseline_checks(self):
        hardened_root()
        config = json.loads(b.trusted_file(Path("/etc/pap/authority.json"), uid=0, mode=0o640))
        enrollment = json.loads(b.trusted_file(Path("/etc/pap/enrollment.json"), uid=0, mode=0o640))
        issuer, broker, kms = (pwd.getpwnam(name) for name in ("pap-issuer", "pap-enroller", "pap-kms"))
        b.require(
            len({issuer.pw_uid, broker.pw_uid, kms.pw_uid}) == 3, "distinct_process_identities_required"
        )
        b.require(
            config.get("issuer") == self.expected_issuer and config.get("state_dir") == "/var/lib/pap-issuer",
            "unexpected_authority",
        )
        expected = {
            "provider": "openbao",
            "base_url": "https://127.0.0.1:8200",
            "role": "pap-issuer",
            "client_cert": str(b.ISSUER_ROOT / "current/client-cert.pem"),
            "client_key": str(b.ISSUER_ROOT / "current/client-key.pem"),
            "ca_file": str(b.CA_FILE),
            "client_ca_file": str(b.CA_FILE),
            "enrollment_socket": "/run/pap-enroller/enroll.sock",
            "enrollment_uid": broker.pw_uid,
        }
        b.require(
            all(config.get("kms", {}).get(k) == v for k, v in expected.items()),
            "unexpected_authority_credential_binding",
        )
        b.require(
            enrollment.get("issuer_uid") == issuer.pw_uid and enrollment.get("broker_uid") == broker.pw_uid,
            "unexpected_enrollment_identity",
        )
        for unit, account in zip(TRACKED, (issuer, broker, kms), strict=True):
            props = b.properties(unit)
            b.require(props.get("ActiveState") == "active", "baseline_unit_not_active")
            pid = int(props.get("MainPID", "0"))
            b.require(pid > 1, "baseline_pid_invalid")
            self.processes[unit] = PinnedProcess(unit, pid, account.pw_uid, account.pw_gid)
            b.require(self.processes[unit].check() not in {"T", "t"}, "baseline_process_already_frozen")
        b.require(len({p.pid for p in self.processes.values()}) == 3, "distinct_process_pids_required")
        old_client = b.current(b.ISSUER_ROOT, issuer.pw_uid, issuer.pw_gid, 0o700)
        old_listener = b.current(b.LISTENER_ROOT, broker.pw_uid, kms.pw_gid, 0o710)
        client = b.trusted_file(old_client / "client-cert.pem", uid=issuer.pw_uid, mode=0o600)
        key = b.trusted_file(old_client / "client-key.pem", uid=issuer.pw_uid, mode=0o600)
        ca = x509.load_pem_x509_certificate(b.trusted_file(b.CA_FILE, uid=0, mode=0o644))
        b.valid_leaf(x509.load_pem_x509_certificate(client), ca, now=datetime.now(UTC))
        b.valid_leaf(
            x509.load_pem_x509_certificate(
                b.trusted_file(old_listener / "server.crt", uid=broker.pw_uid, mode=0o640)
            ),
            ca,
            now=datetime.now(UTC),
        )
        status, health = b.tls_request(client, key)
        b.require(
            status == 200
            and health.get("initialized") is True
            and health.get("sealed") is False
            and health.get("standby") is False,
            "kms_baseline_not_ready",
        )
        b.require(b.authority_health(), "authority_baseline_not_ready")
        active_key = b.admin_active_key()
        counts = login_counts(kms.pw_uid, process_started_at(self.processes[TRACKED[0]].pid))
        b.require(
            counts.recent_requests > 0 and counts.recent_responses > 0, "authority_startup_login_not_observed"
        )
        self.identities_unchanged()
        return Baseline(
            enrollment,
            issuer,
            broker,
            kms,
            self.processes,
            old_client,
            old_listener,
            client,
            key,
            ca,
            active_key,
            counts,
        )

    def freeze(self):
        for unit in TRACKED[:2]:
            self.processes[unit].stop()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            self.identities_unchanged()
            if all(self.processes[unit].check() == "T" for unit in TRACKED[:2]):
                return
            time.sleep(0.05)
        raise b.ExerciseError("process_freeze_deadline_exceeded")

    def resume(self):
        failures = []
        for unit in reversed(TRACKED[:2]):
            process = self.processes.get(unit)
            if process is not None:
                try:
                    process.resume()
                except BaseException:
                    failures.append(unit)
        b.require(not failures, "process_resume_failed")

    def rollback(self):
        baseline = self.baseline
        self.freeze()
        for directory, cert_name, key_name, account, mode in (
            (baseline.old_client, "client-cert.pem", "client-key.pem", baseline.issuer, 0o600),
            (baseline.old_listener, "server.crt", "server.key", baseline.broker, 0o640),
        ):
            cert = x509.load_pem_x509_certificate(
                b.trusted_file(directory / cert_name, uid=account.pw_uid, mode=mode)
            )
            key = serialization.load_pem_private_key(
                b.trusted_file(directory / key_name, uid=account.pw_uid, mode=mode), None
            )
            b.valid_leaf(cert, baseline.ca, now=datetime.now(UTC))
            b.require(
                cert.public_key().public_numbers() == key.public_key().public_numbers(),
                "rollback_key_mismatch",
            )
        b.switch(b.ISSUER_ROOT, baseline.old_client.name, baseline.issuer.pw_uid, baseline.issuer.pw_gid)
        b.switch(b.LISTENER_ROOT, baseline.old_listener.name, baseline.broker.pw_uid, baseline.kms.pw_gid)

    def exercise(self, receipt):
        baseline = self.baseline
        ca_key = serialization.load_pem_private_key(b.trusted_file(b.CA_KEY, uid=0, mode=0o600), None)
        b.require(
            ca_key.public_key().public_numbers() == baseline.ca.public_key().public_numbers(),
            "ca_key_mismatch",
        )
        expired_client, expired_key = b.expired_leaf(
            baseline.ca, ca_key, server=False, config=baseline.enrollment
        )
        expired_server, expired_server_key = b.expired_leaf(
            baseline.ca, ca_key, server=True, config=baseline.enrollment
        )
        del ca_key
        self.freeze()
        self.mutated = True
        expired_client_name = b.publish(
            b.ISSUER_ROOT,
            expired_client,
            expired_key,
            uid=baseline.issuer.pw_uid,
            gid=baseline.issuer.pw_gid,
            server=False,
        )
        try:
            b.tls_request(expired_client, expired_key)
        except ssl.SSLCertVerificationError:
            raise b.ExerciseError("server_failed_before_expired_client_check") from None
        except ssl.SSLError as error:
            b.require(
                error.reason in {"SSLV3_ALERT_CERTIFICATE_EXPIRED", "SSLV3_ALERT_BAD_CERTIFICATE"},
                "expired_client_rejected_for_unexpected_reason",
            )
            receipt["expired_client_rejected"] = error.reason
        else:
            raise b.ExerciseError("expired_client_was_accepted")
        self.identities_unchanged()
        expired_listener_name = b.publish(
            b.LISTENER_ROOT,
            expired_server,
            expired_server_key,
            uid=baseline.broker.pw_uid,
            gid=baseline.kms.pw_gid,
            server=True,
        )
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            self.identities_unchanged()
            try:
                b.tls_request(baseline.client, baseline.key)
            except ssl.SSLCertVerificationError as error:
                b.require(error.verify_code == 10, "server_rejected_for_unexpected_reason")
                receipt["expired_listener_rejected"] = {"verify_code": 10, "verification_enabled": True}
                break
            time.sleep(0.2)
        else:
            raise b.ExerciseError("expired_listener_not_loaded_within_deadline")
        resumed_at = datetime.now(UTC).timestamp()
        started = time.monotonic()
        self.resume()
        deadline = started + 30
        while time.monotonic() < deadline:
            self.identities_unchanged()
            client_dir = b.current(b.ISSUER_ROOT, baseline.issuer.pw_uid, baseline.issuer.pw_gid, 0o700)
            server_dir = b.current(b.LISTENER_ROOT, baseline.broker.pw_uid, baseline.kms.pw_gid, 0o710)
            if client_dir.name not in {
                expired_client_name,
                baseline.old_client.name,
            } and server_dir.name not in {expired_listener_name, baseline.old_listener.name}:
                client = b.trusted_file(
                    client_dir / "client-cert.pem", uid=baseline.issuer.pw_uid, mode=0o600
                )
                key = b.trusted_file(client_dir / "client-key.pem", uid=baseline.issuer.pw_uid, mode=0o600)
                server = b.trusted_file(server_dir / "server.crt", uid=baseline.broker.pw_uid, mode=0o640)
                b.valid_leaf(x509.load_pem_x509_certificate(client), baseline.ca, now=datetime.now(UTC))
                b.valid_leaf(x509.load_pem_x509_certificate(server), baseline.ca, now=datetime.now(UTC))
                try:
                    status, health = b.tls_request(client, key)
                except (ssl.SSLError, OSError):
                    pass
                else:
                    counts = login_counts(baseline.kms.pw_uid, resumed_at)
                    b.require(counts.identity == baseline.logins.identity, "audit_rotated_during_exercise")
                    if (
                        status == 200
                        and health.get("initialized") is True
                        and health.get("sealed") is False
                        and health.get("standby") is False
                        and b.authority_health()
                        and counts.requests > baseline.logins.requests
                        and counts.responses > baseline.logins.responses
                        and counts.recent_requests > 0
                        and counts.recent_responses > 0
                    ):
                        b.require(
                            b.admin_active_key() == baseline.active_key, "unexpected_signing_key_change"
                        )
                        self.identities_unchanged()
                        b.require(time.monotonic() <= deadline, "frozen_process_recovery_deadline_exceeded")
                        return {
                            "automatic_recovery_seconds": round(time.monotonic() - started, 3),
                            "all_three_processes_unchanged": True,
                            "kms_unsealed": True,
                            "authority_ready_after_fresh_authentication": True,
                            "certificate_auth_requests_before": baseline.logins.requests,
                            "certificate_auth_requests_after": counts.requests,
                            "successful_login_responses_before": baseline.logins.responses,
                            "successful_login_responses_after": counts.responses,
                            "active_key_unchanged": True,
                            "client_certificate_sha256": hashlib.sha256(client).hexdigest(),
                            "listener_certificate_sha256": hashlib.sha256(server).hexdigest(),
                        }
            time.sleep(0.2)
        raise b.ExerciseError("frozen_process_recovery_deadline_exceeded")

    def run(self, *, exercise=False):
        receipt = {
            "schema": "pap-frozen-process-certificate-recovery-v1",
            "recorded_at": datetime.now(UTC).isoformat(),
            "exercise_requested": exercise,
            "scope": "existing-process freeze, expired leaves and cached-login revalidation; not provider VM suspend",
            "passed": False,
            "mutation_performed": False,
            "production_accepted": False,
        }
        previous_handlers = {}

        def interrupted(signum, frame):
            if not self.cleaning_up:
                raise b.ExerciseError("exercise_interrupted")

        try:
            self.baseline = self.baseline_checks()
            receipt.update(
                {
                    "baseline_verified": True,
                    "processes_before": {u: p.pid for u, p in self.processes.items()},
                    "authority_startup_login_observed": True,
                }
            )
            if not exercise:
                receipt["passed"] = True
                return receipt
            for signum in (signal.SIGTERM, signal.SIGINT):
                previous_handlers[signum] = signal.signal(signum, interrupted)
            receipt.update(self.exercise(receipt))
            receipt.update(
                {
                    "passed": True,
                    "mutation_performed": True,
                    "processes_after": {u: p.pid for u, p in self.processes.items()},
                }
            )
        except BaseException as error:
            receipt["error_code"] = str(error) if isinstance(error, b.ExerciseError) else type(error).__name__
            receipt["mutation_performed"] = self.mutated
            if self.mutated and self.baseline is not None:
                self.cleaning_up = True
                try:
                    self.rollback()
                    receipt["failure_restoration"] = "original_valid_pointers_restored"
                except BaseException:
                    receipt["failure_restoration"] = "operator_attention_required"
        finally:
            self.cleaning_up = True
            try:
                self.resume()
                receipt["all_stopped_processes_resumed"] = True
            except BaseException:
                receipt["all_stopped_processes_resumed"] = False
                receipt["passed"] = False
                receipt["error_code"] = "process_resume_failed_operator_attention_required"
            for process in self.processes.values():
                process.close()
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)
        return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-issuer", required=True)
    parser.add_argument("--exercise", action="store_true")
    args = parser.parse_args()
    receipt = FrozenProbe(args.expected_issuer).run(exercise=args.exercise)
    print(json.dumps(receipt, sort_keys=True))
    return 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
