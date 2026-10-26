"""State-machine and native-process checks for the opt-in frozen-leaf probe."""

import json
import os
import ssl
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from deploy.linux import exercise_frozen_certificates as f


def ca_and_leaf(*, server=False, ca=None, ca_key=None):
    now = datetime.now(UTC)
    if ca is None:
        ca_key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic fixture CA")])
        ca = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(True, 0), True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
            .sign(ca_key, hashes.SHA256())
        )
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost" if server else "pap-issuer")])
        )
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(False, None), True)
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    return (
        ca,
        ca_key,
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
    )


@pytest.fixture
def fixture(tmp_path, monkeypatch):
    tmp_path.chmod(0o700)
    os.chown(tmp_path, -1, os.getegid())
    issuer_root, listener_root = tmp_path / "issuer", tmp_path / "listener"
    issuer_root.mkdir(mode=0o700)
    listener_root.mkdir(mode=0o710)
    monkeypatch.setattr(f.b, "ISSUER_ROOT", issuer_root)
    monkeypatch.setattr(f.b, "LISTENER_ROOT", listener_root)
    ca, ca_key, client, key = ca_and_leaf()
    _, _, server, server_key = ca_and_leaf(server=True, ca=ca, ca_key=ca_key)
    ca_key_path = tmp_path / "fixture-ca-key.pem"
    ca_key_path.write_bytes(
        ca_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    ca_key_path.chmod(0o600)
    monkeypatch.setattr(f.b, "CA_KEY", ca_key_path)
    original_read = f.b.trusted_file

    def read(path, *, uid, mode):
        return original_read(path, uid=os.getuid() if path == ca_key_path else uid, mode=mode)

    monkeypatch.setattr(f.b, "trusted_file", read)
    account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
    old_client = f.b.publish(issuer_root, client, key, uid=account.pw_uid, gid=account.pw_gid, server=False)
    old_listener = f.b.publish(
        listener_root, server, server_key, uid=account.pw_uid, gid=account.pw_gid, server=True
    )
    events = []
    processes = {}
    state = {
        "recover": True,
        "login": True,
        "client_rejected": True,
        "server_rejected": True,
        "changed_pid": False,
        "resumed": False,
        "fresh_published": False,
        "monotonic": 0.0,
        "identity": (1, 2),
    }

    class Process:
        def __init__(self, unit, pid):
            self.unit, self.pid, self.resume_required, self.closed = unit, pid, False, False
            self.frozen = False

        def check(self):
            return "T" if self.frozen else "S"

        def stop(self):
            events.append(("stop", self.unit))
            self.resume_required = True
            self.frozen = True

        def resume(self):
            if self.resume_required:
                events.append(("resume", self.unit))
                self.frozen = False
                self.resume_required = False
                if all(not p.frozen for p in processes.values()):
                    state["resumed"] = True

        def close(self):
            self.closed = True

    for i, unit in enumerate(f.TRACKED):
        processes[unit] = Process(unit, 100 + i)
    counts = f.LoginCounts((1, 2), 2, 2, 1, 1)
    baseline = f.Baseline(
        {},
        account,
        account,
        account,
        processes,
        issuer_root / old_client,
        listener_root / old_listener,
        client,
        key,
        ca,
        "stable-key",
        counts,
    )

    def properties(unit):
        return {
            "ActiveState": "active",
            "MainPID": str(processes[unit].pid + (1 if state["changed_pid"] else 0)),
        }

    monkeypatch.setattr(f.b, "properties", properties)
    monkeypatch.setattr(
        f.b, "service", lambda *args: pytest.fail("freeze probe must not mutate systemd services")
    )
    monkeypatch.setattr(f.b, "authority_health", lambda: True)
    monkeypatch.setattr(f.b, "admin_active_key", lambda: "stable-key")
    monkeypatch.setattr(
        f,
        "login_counts",
        lambda uid, since: f.LoginCounts(
            state["identity"],
            3 if state["login"] and state["fresh_published"] else 2,
            3 if state["login"] and state["fresh_published"] else 2,
            1 if state["login"] and state["fresh_published"] else 0,
            1 if state["login"] and state["fresh_published"] else 0,
        ),
    )

    def tls(cert, private):
        used = x509.load_pem_x509_certificate(cert)
        current_server = listener_root / os.readlink(listener_root / "current") / "server.crt"
        published = x509.load_pem_x509_certificate(current_server.read_bytes())
        if published.not_valid_after_utc < datetime.now(UTC) and state["server_rejected"]:
            error = ssl.SSLCertVerificationError("synthetic expired listener")
            error.verify_code = 10
            raise error
        if used.not_valid_after_utc < datetime.now(UTC) and state["client_rejected"]:
            error = ssl.SSLError("synthetic expired client")
            error.reason = "SSLV3_ALERT_CERTIFICATE_EXPIRED"
            raise error
        return 200, {"initialized": True, "sealed": False, "standby": False}

    monkeypatch.setattr(f.b, "tls_request", tls)

    def sleep(duration):
        state["monotonic"] += duration
        if state["resumed"] and state["recover"] and not state["fresh_published"]:
            _, _, cert, private = ca_and_leaf(ca=ca, ca_key=ca_key)
            _, _, listener, listener_key = ca_and_leaf(server=True, ca=ca, ca_key=ca_key)
            f.b.publish(issuer_root, cert, private, uid=account.pw_uid, gid=account.pw_gid, server=False)
            f.b.publish(
                listener_root, listener, listener_key, uid=account.pw_uid, gid=account.pw_gid, server=True
            )
            state["fresh_published"] = True

    monkeypatch.setattr(f.time, "monotonic", lambda: state["monotonic"])
    monkeypatch.setattr(f.time, "sleep", sleep)
    probe = f.FrozenProbe("https://fixture.example.test")

    def baseline_checks():
        probe.processes = processes
        return baseline

    monkeypatch.setattr(probe, "baseline_checks", baseline_checks)
    return SimpleNamespace(
        probe=probe,
        state=state,
        processes=processes,
        events=events,
        baseline=baseline,
        issuer_root=issuer_root,
        listener_root=listener_root,
        ca=ca,
        ca_key=ca_key,
        tmp=tmp_path,
    )


def test_default_plan_neither_freezes_nor_changes_credentials(fixture):
    pointers = [os.readlink(root / "current") for root in (fixture.issuer_root, fixture.listener_root)]
    result = fixture.probe.run()
    assert result["passed"] and not result["mutation_performed"]
    assert fixture.events == []
    assert [
        os.readlink(root / "current") for root in (fixture.issuer_root, fixture.listener_root)
    ] == pointers
    assert all(p.closed for p in fixture.processes.values())


def test_existing_process_freeze_requires_tls_rejection_fresh_auth_and_same_pids(fixture, capsys):
    result = fixture.probe.run(exercise=True)
    assert result["passed"] and result["all_three_processes_unchanged"]
    assert result["authority_ready_after_fresh_authentication"]
    assert result["certificate_auth_requests_before"] == 2
    assert result["certificate_auth_requests_after"] == 3
    assert result["successful_login_responses_after"] == 3
    assert result["expired_listener_rejected"]["verify_code"] == 10
    assert result["processes_before"] == result["processes_after"]
    assert result["all_stopped_processes_resumed"]
    assert all(unit != f.TRACKED[2] for _, unit in fixture.events)
    assert all(not p.frozen and p.closed for p in fixture.processes.values())
    assert capsys.readouterr().out == ""
    serialized = json.dumps(result)
    assert "PRIVATE KEY" not in serialized and fixture.baseline.key.decode() not in serialized


@pytest.mark.parametrize(
    "defect,code",
    [
        ("client_rejected", "expired_client_was_accepted"),
        ("server_rejected", "expired_listener_not_loaded_within_deadline"),
        ("login", "frozen_process_recovery_deadline_exceeded"),
        ("recover", "frozen_process_recovery_deadline_exceeded"),
    ],
)
def test_recovery_failure_restores_valid_pointers_and_resumes_every_process(fixture, defect, code):
    fixture.state[defect] = False
    result = fixture.probe.run(exercise=True)
    assert not result["passed"] and result["error_code"] == code
    assert result["failure_restoration"] == "original_valid_pointers_restored"
    assert result["all_stopped_processes_resumed"]
    assert os.readlink(fixture.issuer_root / "current") == fixture.baseline.old_client.name
    assert os.readlink(fixture.listener_root / "current") == fixture.baseline.old_listener.name
    assert all(not p.frozen and p.closed for p in fixture.processes.values())


def test_partial_stop_failure_always_resumes_the_first_process(fixture, monkeypatch):
    def fail():
        raise f.b.ExerciseError("synthetic_second_stop_failed")

    monkeypatch.setattr(fixture.processes[f.TRACKED[1]], "stop", fail)
    result = fixture.probe.run(exercise=True)
    assert not result["passed"] and result["error_code"] == "synthetic_second_stop_failed"
    assert not result["mutation_performed"]
    assert ("resume", f.TRACKED[0]) in fixture.events
    assert all(not p.frozen and p.closed for p in fixture.processes.values())


def test_pid_change_is_failure_and_never_signals_a_replacement_process(fixture, monkeypatch):
    original = fixture.processes[f.TRACKED[0]].stop

    def changed():
        original()
        fixture.state["changed_pid"] = True

    monkeypatch.setattr(fixture.processes[f.TRACKED[0]], "stop", changed)
    result = fixture.probe.run(exercise=True)
    assert not result["passed"] and result["error_code"] == "service_process_changed"
    assert not result["mutation_performed"]
    assert all(not p.frozen for p in fixture.processes.values())


def test_audit_inode_change_cannot_satisfy_reauthentication(fixture):
    fixture.state["identity"] = (9, 9)
    result = fixture.probe.run(exercise=True)
    assert not result["passed"] and result["error_code"] == "audit_rotated_during_exercise"
    assert result["failure_restoration"] == "original_valid_pointers_restored"


def test_interrupt_after_publication_rolls_back_and_resumes(fixture, monkeypatch):
    original = f.b.publish
    calls = [0]

    def interrupted(*args, **kwargs):
        value = original(*args, **kwargs)
        calls[0] += 1
        if calls[0] == 1:
            raise KeyboardInterrupt()
        return value

    monkeypatch.setattr(f.b, "publish", interrupted)
    result = fixture.probe.run(exercise=True)
    assert not result["passed"] and result["error_code"] == "KeyboardInterrupt"
    assert result["failure_restoration"] == "original_valid_pointers_restored"
    assert result["all_stopped_processes_resumed"]


def test_path_only_audit_counter_bounds_input_and_excludes_failed_login_responses(
    tmp_path, monkeypatch, capsys
):
    audit = tmp_path / "audit.jsonl"
    monkeypatch.setattr(f, "AUDIT", audit)
    now = datetime.now(UTC)

    def row(kind, path="auth/cert/login", **extra):
        return (
            json.dumps(
                {
                    "type": kind,
                    "request": {"path": path, "data": {"secret": "synthetic-never-output"}},
                    "time": now.isoformat(),
                    **extra,
                }
            )
            + "\n"
        )

    audit.write_text(
        row("request")
        + row("response")
        + row("request", "other")
        + row("response", error="denied")
        + '{"partial":'
    )
    audit.chmod(0o600)
    result = f.login_counts(os.getuid(), now.timestamp() - 1)
    assert (result.requests, result.responses, result.recent_requests, result.recent_responses) == (
        1,
        1,
        1,
        1,
    )
    assert capsys.readouterr().out == ""
    audit.chmod(0o644)
    with pytest.raises(f.b.ExerciseError, match="audit_file_untrusted"):
        f.login_counts(os.getuid(), 0)
    audit.chmod(0o600)
    audit.write_bytes(b"x" * (f.MAX_LINE + 2))
    with pytest.raises(f.b.ExerciseError, match="audit_record_too_large"):
        f.login_counts(os.getuid(), 0)


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "pidfd_open"), reason="native Linux pidfd required"
)
def test_native_pidfd_stop_resume_targets_only_the_pinned_child():
    child_code = """import ctypes, os, time
libc=ctypes.CDLL(None)
class Header(ctypes.Structure): _fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
class Data(ctypes.Structure): _fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
h=Header(0x20080522,0); d=(Data*2)()
assert libc.capset(ctypes.byref(h),ctypes.byref(d))==0
assert libc.prctl(38,1,0,0,0)==0
print('ready',flush=True)
time.sleep(20)
"""
    child = subprocess.Popen(
        [sys.executable, "-c", child_code], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    )
    process = None
    try:
        assert child.stdout.readline() == b"ready\n"
        process = f.PinnedProcess("synthetic-child", child.pid, os.getuid(), os.getgid())
        process.stop()
        deadline = time.monotonic() + 2
        while process.check() != "T" and time.monotonic() < deadline:
            time.sleep(0.02)
        assert process.check() == "T" and child.poll() is None
        process.resume()
        deadline = time.monotonic() + 2
        while process.check() == "T" and time.monotonic() < deadline:
            time.sleep(0.02)
        assert process.check() != "T" and child.poll() is None
    finally:
        if process is not None:
            process.resume()
            process.close()
        child.terminate()
        child.wait(timeout=3)
        if child.stdout is not None:
            child.stdout.close()


def test_slow_final_readiness_check_cannot_pass_beyond_recovery_budget(fixture, monkeypatch):
    def delayed_key():
        fixture.state["monotonic"] += 31
        return "stable-key"

    monkeypatch.setattr(f.b, "admin_active_key", delayed_key)
    result = fixture.probe.run(exercise=True)
    assert not result["passed"]
    assert result["error_code"] == "frozen_process_recovery_deadline_exceeded"
    assert result["all_stopped_processes_resumed"]
    assert result["failure_restoration"] == "original_valid_pointers_restored"
