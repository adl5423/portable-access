import base64
import json
import os
import socket
import stat
import struct
import tempfile
import threading
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from pap import enrollment as e
from pap.signers import SignerError


def test_slow_frame_has_one_absolute_deadline_for_header_and_body(monkeypatch):
    now = [0.0]

    def monotonic():
        value = now[0]
        now[0] += 0.3
        return value

    class SlowPeer:
        reads = 0
        timeouts = []

        def gettimeout(self):
            return 1.0

        def settimeout(self, value):
            self.timeouts.append(value)

        def recv(self, length):
            self.reads += 1
            return struct.pack("!I", 100) if self.reads == 1 else b" "

    peer = SlowPeer()
    monkeypatch.setattr(e.time, "monotonic", monotonic)
    with pytest.raises(SignerError, match="enrollment_message_timeout"):
        e._receive(peer)
    assert peer.reads == 3
    assert peer.timeouts == sorted(peer.timeouts, reverse=True)


def make_ca(directory, now, *, before=None, after=None, ca=True, signing=True):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Fixture infrastructure CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(before or now - timedelta(days=1))
        .not_valid_after(after or now + timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, signing, signing, None, None), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .sign(key, hashes.SHA256())
    )
    cp, kp = directory / "ca.pem", directory / "ca.key"
    cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    kp.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    cp.chmod(0o644)
    kp.chmod(0o600)
    return cp, kp, cert, key


def csr_value(key=None, *, elevated=False):
    key = key or ec.generate_private_key(ec.SECP256R1())
    builder = x509.CertificateSigningRequestBuilder().subject_name(
        x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "attacker.example")])
    )
    if elevated:
        builder = (
            builder.add_extension(x509.BasicConstraints(True, 3), True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("attacker.example")]), False)
        )
    csr = builder.sign(key, hashes.SHA256())
    return {"csr": base64.b64encode(csr.public_bytes(serialization.Encoding.DER)).decode()}, key


@pytest.fixture
def fixture():
    # Linux UNIX paths are limited to 108 bytes, independent of pytest's tmp root.
    with tempfile.TemporaryDirectory(
        prefix="pap-enroll-", dir="/private/tmp" if Path("/private/tmp").exists() else "/tmp"
    ) as name:
        root = Path(name)
        root.chmod(0o700)
        now = [datetime.now(UTC).replace(microsecond=0)]
        ready = [True]
        cp, kp, ca, ca_key = make_ca(root, now[0])
        runtime = root / "run"
        runtime.mkdir(mode=0o750)
        uid, gid = os.geteuid(), os.getegid()
        os.chown(runtime, -1, gid)
        if uid == 0:
            pytest.skip("unit fixtures require an unprivileged test runner")
        config = e.EnrollmentConfig(
            ca_cert=cp,
            ca_key=kp,
            socket=runtime / "enroll.sock",
            issuer_uid=uid + 1000,
            issuer_gid=gid,
            broker_uid=uid,
            listener_dir=root / "listener",
            listener_gid=gid,
            client_uri_san="spiffe://pap.local/issuer",
        )
        servers = []

        def server(**kwargs):
            value = e.EnrollmentServer(
                kwargs.pop("config", config),
                _clock=lambda: now[0],
                _clock_ready=lambda: ready[0],
                _peer_reader=kwargs.pop("_peer_reader", lambda connection: config.issuer_uid),
                **kwargs,
            )
            servers.append(value)
            return value

        yield {
            "root": root,
            "now": now,
            "ready": ready,
            "config": config,
            "server": server,
            "ca": ca,
            "ca_key": ca_key,
        }
        for value in servers:
            value.close()


def start_client(fixture):
    server = fixture["server"]()
    server.start()
    stop = threading.Event()
    thread = threading.Thread(target=server.serve_forever, args=(stop,), daemon=True)
    thread.start()
    config = fixture["config"]
    client = e.UnixEnrollmentClient(
        config.socket,
        config.ca_cert,
        config.broker_uid,
        uri_san=config.client_uri_san,
        _peer_reader=lambda connection: config.broker_uid,
        _clock=lambda: fixture["now"][0],
    )
    return server, client, stop, thread


def finish(server, stop, thread):
    stop.set()
    thread.join(timeout=2)
    server.close()
    assert not thread.is_alive()


def test_live_client_keeps_private_key_local_and_issues_fixed_identity(fixture, monkeypatch):
    server, client, stop, thread = start_client(fixture)
    sent = []
    original = e._send

    def record(connection, value):
        sent.append(value)
        return original(connection, value)

    monkeypatch.setattr(e, "_send", record)
    monkeypatch.setenv("BAO_TOKEN", "never-read-this-bearer-value")
    monkeypatch.setenv("HTTPS_PROXY", "https://not-used.invalid")
    try:
        result = client.issue_client_certificate("issuer", "pap-issuer")
        assert set(result) == {"certificate", "private_key", "issuing_ca"}
        cert = x509.load_pem_x509_certificate(result["certificate"].encode())
        key = serialization.load_pem_private_key(result["private_key"].encode(), None)
        assert e._spki(cert.public_key()) == e._spki(key.public_key())
        cert.verify_directly_issued_by(fixture["ca"])
        assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "pap-issuer"
        assert set(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == {
            ExtendedKeyUsageOID.CLIENT_AUTH
        }
        assert cert.not_valid_after_utc - cert.not_valid_before_utc == timedelta(hours=1)
        assert all("private_key" not in value for value in sent)
        assert set(sent[0]) == {"csr"}
        assert fixture["config"].socket.stat().st_mode & 0o777 == 0o660
    finally:
        finish(server, stop, thread)


def test_expired_listener_and_client_recover_without_old_authentication(fixture):
    server, client, stop, thread = start_client(fixture)
    try:
        first = client.issue_client_certificate("issuer", "pap-issuer")
        old_client = x509.load_pem_x509_certificate(first["certificate"].encode())
        old_generation = (fixture["config"].listener_dir / "current").resolve()
        fixture["now"][0] += timedelta(hours=2)
        assert old_client.not_valid_after_utc < fixture["now"][0]
        second = client.issue_client_certificate("issuer", "pap-issuer")
        cert = x509.load_pem_x509_certificate(second["certificate"].encode())
        assert cert.not_valid_after_utc > fixture["now"][0] + timedelta(minutes=50)
        assert second["private_key"] != first["private_key"]
        assert (fixture["config"].listener_dir / "current").resolve() != old_generation
        assert not old_generation.exists()
    finally:
        finish(server, stop, thread)


def test_requested_identity_and_capabilities_are_ignored(fixture):
    value, key = csr_value(elevated=True)
    result = fixture["server"]()._enroll(value)
    cert = x509.load_pem_x509_certificate(result["certificate"].encode())
    assert e._spki(cert.public_key()) == e._spki(key.public_key())
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "pap-issuer"
    assert not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert cert.extensions.get_extension_for_class(x509.KeyUsage).value == e._leaf_usage()
    assert set(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == {
        ExtendedKeyUsageOID.CLIENT_AUTH
    }
    assert list(cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value) == [
        x509.UniformResourceIdentifier("spiffe://pap.local/issuer")
    ]


@pytest.mark.parametrize(
    "value",
    [
        {},
        {"csr": 2},
        {"csr": "!"},
        {"csr": "A" * 9000},
        {"csr": "YQ==", "common_name": "root"},
        {"csr": "YQ==", "path": "/etc/passwd"},
    ],
)
def test_request_schema_and_malformed_csr_fail_closed(fixture, value):
    with pytest.raises(SignerError):
        fixture["server"]()._enroll(value)


@pytest.mark.parametrize(
    "key",
    [
        lambda: ec.generate_private_key(ec.SECP384R1()),
        lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
    ],
)
def test_wrong_key_algorithm_rejected(fixture, key):
    value, _ = csr_value(key())
    with pytest.raises(SignerError, match="enrollment_csr_invalid"):
        fixture["server"]()._enroll(value)


def test_invalid_csr_signature_rejected(fixture):
    value, _ = csr_value()
    raw = bytearray(base64.b64decode(value["csr"]))
    raw[-1] ^= 1
    value["csr"] = base64.b64encode(raw).decode()
    with pytest.raises(SignerError, match="enrollment_csr_invalid"):
        fixture["server"]()._enroll(value)


def test_wrong_uid_denied_before_request_is_read(fixture, monkeypatch):
    server = fixture["server"](_peer_reader=lambda connection: fixture["config"].issuer_uid + 1)
    monkeypatch.setattr(e, "_receive", lambda connection: pytest.fail("unauthorized request was read"))
    left, right = socket.socketpair()
    with left, right:
        server.handle_connection(left)
        length = struct.unpack("!I", right.recv(4))[0]
        assert json.loads(right.recv(length)) == {"error": "enrollment_peer_denied"}


def test_authorized_requests_are_rate_limited_and_window_recovers(fixture):
    now = [100.0]
    server = fixture["server"](
        config=replace(fixture["config"], rate_per_minute=2), _monotonic=lambda: now[0]
    )
    assert server._admit(None) == fixture["config"].issuer_uid
    server._admit(None)
    with pytest.raises(SignerError, match="enrollment_rate_limited"):
        server._admit(None)
    now[0] += 60
    server._admit(None)


def test_client_rejects_wrong_broker_uid(fixture):
    server, client, stop, thread = start_client(fixture)
    client._peer_reader = lambda connection: client.expected_uid + 1
    try:
        with pytest.raises(SignerError, match="enrollment_peer_denied"):
            client.issue_client_certificate("issuer", "pap-issuer")
    finally:
        finish(server, stop, thread)


@pytest.mark.parametrize("body", [b'{"csr":"a","csr":"b"}', b"[]", b"\xff", b'{"csr":'])
def test_duplicate_and_invalid_json_rejected(body):
    left, right = socket.socketpair()
    with left, right:
        left.sendall(struct.pack("!I", len(body)) + body)
        with pytest.raises(SignerError, match="enrollment_message_invalid"):
            e._receive(right)


@pytest.mark.parametrize("length", [0, e.MAX_MESSAGE + 1, 2**32 - 1])
def test_unbounded_frame_rejected_without_reading_body(length):
    left, right = socket.socketpair()
    with left, right:
        left.sendall(struct.pack("!I", length))
        with pytest.raises(SignerError, match="enrollment_message_invalid"):
            e._receive(right)


def test_incomplete_frame_fails_closed():
    left, right = socket.socketpair()
    with left, right:
        left.sendall(b"\x00\x00")
        left.shutdown(socket.SHUT_WR)
        with pytest.raises(SignerError, match="enrollment_message_invalid"):
            e._receive(right)


@pytest.mark.parametrize("offset", [timedelta(days=500), -timedelta(days=5)])
def test_expired_or_not_yet_valid_ca_denied(fixture, offset):
    fixture["now"][0] += offset
    with pytest.raises(SignerError, match="enrollment_ca_expired_or_not_ready"):
        fixture["server"]()._enroll(csr_value()[0])


def test_clock_gate_and_clock_rollback_fail_closed(fixture):
    server = fixture["server"]()
    fixture["ready"][0] = False
    with pytest.raises(SignerError, match="enrollment_clock_untrusted"):
        server._enroll(csr_value()[0])
    fixture["ready"][0] = True
    server._enroll(csr_value()[0])
    fixture["now"][0] -= timedelta(seconds=6)
    with pytest.raises(SignerError, match="enrollment_clock_untrusted"):
        server._enroll(csr_value()[0])


def test_world_readable_ca_private_key_is_rejected(fixture):
    fixture["config"].ca_key.chmod(0o644)
    with pytest.raises(SignerError, match="signer_credential_file_invalid"):
        fixture["server"]()


def test_symlinked_ca_key_rejected(fixture):
    path = fixture["config"].ca_key
    original = path.with_suffix(".original")
    path.rename(original)
    path.symlink_to(original.name)
    with pytest.raises(SignerError, match="signer_credential_file_invalid"):
        fixture["server"]()


@pytest.mark.parametrize("kwargs", [{"ca": False}, {"signing": False}])
def test_invalid_ca_permissions_rejected(fixture, kwargs):
    make_ca(fixture["root"], fixture["now"][0], **kwargs)
    with pytest.raises(SignerError, match="enrollment_ca_invalid"):
        fixture["server"]()


def test_ca_private_key_mismatch_rejected(fixture):
    other = ec.generate_private_key(ec.SECP256R1())
    fixture["config"].ca_key.write_bytes(
        other.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    with pytest.raises(SignerError, match="enrollment_ca_invalid"):
        fixture["server"]()


def test_listener_publication_remains_kms_traversable_under_service_umask(fixture):
    previous = os.umask(0o077)
    try:
        server = fixture["server"]()
        server.listener.maintain()
    finally:
        os.umask(previous)
    directory = fixture["config"].listener_dir
    assert stat.S_IMODE(directory.stat().st_mode) == 0o710
    generation = (directory / "current").resolve()
    assert stat.S_IMODE(generation.stat().st_mode) == 0o750
    assert stat.S_IMODE((generation / "server.key").stat().st_mode) == 0o640


def test_existing_untraversable_listener_directory_is_rejected(fixture):
    directory = fixture["config"].listener_dir
    directory.mkdir(mode=0o700)
    with pytest.raises(SignerError, match="enrollment_directory_untrusted"):
        fixture["server"]()


def test_listener_modes_and_atomic_failure_preserve_previous_pair(fixture, monkeypatch):
    server = fixture["server"]()
    server.listener.maintain()
    current = fixture["config"].listener_dir / "current"
    generation = current.resolve()
    for name in ("server.crt", "server.key"):
        assert stat.S_IMODE((generation / name).stat().st_mode) == 0o640
    assert stat.S_IMODE(generation.stat().st_mode) == 0o750
    original = e.os.replace

    def fail_replace(source, target):
        if target == current:
            raise OSError("private material must not appear in error")
        return original(source, target)

    monkeypatch.setattr(e.os, "replace", fail_replace)
    with pytest.raises(SignerError, match="^enrollment_listener_renewal_failed$"):
        server.listener.maintain(force=True)
    assert current.resolve() == generation
    server.listener._current()


def test_listener_writable_directory_and_symlink_generation_rejected(fixture):
    server = fixture["server"]()
    server.listener.maintain()
    generation = (fixture["config"].listener_dir / "current").resolve()
    generation.chmod(0o770)
    with pytest.raises(SignerError, match="enrollment_directory_untrusted"):
        server.listener.maintain()


def test_duplicate_server_cannot_steal_socket_and_stale_socket_recovers(fixture):
    first = fixture["server"]()
    first.start()
    inode = fixture["config"].socket.stat().st_ino
    second = fixture["server"]()
    with pytest.raises(BlockingIOError):
        second.start()
    second.close()
    assert fixture["config"].socket.stat().st_ino == inode
    first.close()
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(str(fixture["config"].socket))
    stale.close()
    third = fixture["server"]()
    third.start()
    assert fixture["config"].socket.exists()


def test_symlink_or_regular_socket_path_never_unlinked(fixture):
    path = fixture["config"].socket
    path.write_text("preserve me")
    with pytest.raises(SignerError, match="enrollment_socket_untrusted"):
        fixture["server"]().start()
    assert path.read_text() == "preserve me"


def test_client_rejects_unsafe_socket_mode_before_connecting(fixture):
    server, client, stop, thread = start_client(fixture)
    fixture["config"].socket.chmod(0o666)
    try:
        with pytest.raises(SignerError, match="enrollment_socket_untrusted"):
            client.issue_client_certificate("issuer", "pap-issuer")
    finally:
        finish(server, stop, thread)


def test_client_rejects_foreign_ca_and_mismatched_key(fixture):
    server = fixture["server"]()
    value, key = csr_value()
    response = server._enroll(value)
    config = fixture["config"]
    client = e.UnixEnrollmentClient(
        config.socket, config.ca_cert, config.broker_uid, _clock=lambda: fixture["now"][0]
    )
    with pytest.raises(SignerError, match="enrollment_certificate_invalid"):
        client._validate_response(response, ec.generate_private_key(ec.SECP256R1()), fixture["now"][0])
    foreign = fixture["root"] / "foreign"
    foreign.mkdir(mode=0o700)
    _, _, foreign_ca, _ = make_ca(foreign, fixture["now"][0])
    response["issuing_ca"] = foreign_ca.public_bytes(serialization.Encoding.PEM).decode()
    with pytest.raises(SignerError, match="enrollment_certificate_invalid"):
        client._validate_response(response, key, fixture["now"][0])


@pytest.mark.parametrize(
    "defect", ["name", "server_eku", "ca", "key_usage", "expired", "not_yet_valid", "overlong", "wrong_uri"]
)
def test_client_rejects_signed_but_invalid_certificate(fixture, defect):
    config, now = fixture["config"], fixture["now"][0]
    key = ec.generate_private_key(ec.SECP256R1())
    common_name = "other-issuer" if defect == "name" else "pap-issuer"
    before = now + timedelta(minutes=2) if defect == "not_yet_valid" else now - timedelta(seconds=30)
    after = now - timedelta(seconds=1) if defect == "expired" else now + timedelta(minutes=59)
    if defect == "overlong":
        after = now + timedelta(hours=2)
    builder = (
        x509.CertificateBuilder()
        .issuer_name(fixture["ca"].subject)
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(before)
        .not_valid_after(after)
        .add_extension(x509.BasicConstraints(defect == "ca", None), True)
        .add_extension(
            x509.ExtendedKeyUsage(
                [
                    ExtendedKeyUsageOID.SERVER_AUTH
                    if defect == "server_eku"
                    else ExtendedKeyUsageOID.CLIENT_AUTH
                ]
            ),
            False,
        )
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, defect == "key_usage", False, False, False), True
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.UniformResourceIdentifier(
                        "spiffe://pap.local/other" if defect == "wrong_uri" else config.client_uri_san
                    )
                ]
            ),
            False,
        )
    )
    cert = builder.sign(fixture["ca_key"], hashes.SHA256())
    response = {
        "certificate": cert.public_bytes(serialization.Encoding.PEM).decode(),
        "issuing_ca": fixture["ca"].public_bytes(serialization.Encoding.PEM).decode(),
    }
    client = e.UnixEnrollmentClient(
        config.socket, config.ca_cert, config.broker_uid, uri_san=config.client_uri_san
    )
    with pytest.raises(SignerError, match="enrollment_certificate_invalid"):
        client._validate_response(response, key, now)


def test_missing_kernel_credential_api_has_no_fallback(monkeypatch):
    monkeypatch.delattr(socket, "SO_PEERCRED", raising=False)
    left, right = socket.socketpair()
    with left, right:
        with pytest.raises(SignerError, match="enrollment_kernel_identity_unavailable"):
            e._peer_uid(left)


def test_clock_command_failure_is_closed_and_does_not_use_caller_environment(monkeypatch):
    calls = []

    def failed(command, **kwargs):
        calls.append((command, kwargs))
        raise e.subprocess.TimeoutExpired(command, 3)

    monkeypatch.setattr(e.subprocess, "run", failed)
    assert e._clock_ready() is False
    assert calls[0][0] == ["/usr/bin/timedatectl", "show", "--property=NTPSynchronized", "--value"]
    assert calls[0][1]["env"] == {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}


@pytest.mark.parametrize(
    "kwargs",
    [
        {"issuer_uid": 0},
        {"broker_uid": 0},
        {"issuer_uid": os.geteuid()},
        {"ttl_seconds": 86400},
        {"server_ip_addresses": ("8.8.8.8",)},
        {"server_dns_names": ("external.example",)},
        {"maintenance_interval": 0},
        {"rate_per_minute": True},
        {"socket": Path("relative")},
        {"client_uri_san": "broken URI"},
    ],
)
def test_invalid_config_rejected(fixture, kwargs):
    with pytest.raises(ValueError):
        replace(fixture["config"], **kwargs)


def test_nonroot_configuration_file_rejected(fixture):
    config = fixture["root"] / "config.json"
    config.write_text("{}")
    with pytest.raises((ValueError, SignerError)):
        e.load_enrollment_config(config)


def test_redacted_errors_do_not_log_csr_or_key(fixture, caplog):
    caplog.set_level("INFO", logger="pap.enrollment")
    server = fixture["server"]()
    left, right = socket.socketpair()
    with left, right:
        e._send(right, {"csr": "SENSITIVE_BAD_CSR"})
        server.handle_connection(left)
        assert e._receive(right) == {"error": "enrollment_csr_invalid"}
    assert "SENSITIVE_BAD_CSR" not in caplog.text
    assert "PRIVATE KEY" not in caplog.text
    assert '"code":"enrollment_csr_invalid"' in caplog.text


@pytest.mark.skipif(not hasattr(socket, "SO_PEERCRED"), reason="Linux SO_PEERCRED required")
def test_native_kernel_peer_uid():
    left, right = socket.socketpair()
    with left, right:
        assert e._peer_uid(left) == os.geteuid()


def _systemd_acl(uid, permission=4):
    return struct.pack("<I", 2) + b"".join(
        struct.pack("<HHI", *entry)
        for entry in [
            (1, permission, 0xFFFFFFFF),
            (2, permission, uid),
            (4, 0, 0xFFFFFFFF),
            (16, permission, 0xFFFFFFFF),
            (32, 0, 0xFFFFFFFF),
        ]
    )


@pytest.mark.parametrize("permission", [4, 5])
def test_systemd_credential_acl_only_authorizes_service_uid(permission):
    raw = _systemd_acl(985, permission)
    assert e._credential_acl_valid(raw, 985, permission)
    assert not e._credential_acl_valid(raw, 986, permission)
    assert not e._credential_acl_valid(raw + struct.pack("<HHI", 2, 4, 986), 985, permission)
    for offset in [6, 14, 22, 30, 38]:
        changed = bytearray(raw)
        changed[offset] ^= 2  # Adding write access to any ACL entry is forbidden.
        assert not e._credential_acl_valid(bytes(changed), 985, permission)


def test_arbitrary_group_readable_ca_key_stays_rejected(fixture):
    fixture["config"].ca_key.chmod(0o440)
    with pytest.raises(SignerError, match="signer_credential_file_invalid"):
        e._read_ca_key(fixture["config"].ca_key)


@pytest.mark.parametrize(
    "readonly,uid,extra_acl", [(True, 985, False), (False, 985, False), (True, 986, False), (True, 985, True)]
)
def test_systemd_credential_reader_checks_mount_and_acl(fixture, monkeypatch, readonly, uid, extra_acl):
    from types import SimpleNamespace

    key = fixture["config"].ca_key
    monkeypatch.setattr(e, "_SYSTEMD_CA_KEY", key)
    monkeypatch.setattr(e.sys, "platform", "linux")
    monkeypatch.setattr(e.os, "geteuid", lambda: uid)
    original_stat = e.os.fstat

    def metadata(fd):
        info = original_stat(fd)
        directory = stat.S_ISDIR(info.st_mode)
        return SimpleNamespace(
            st_mode=(stat.S_IFDIR | 0o550) if directory else (stat.S_IFREG | 0o440),
            st_uid=0,
            st_gid=0,
            st_size=info.st_size,
        )

    monkeypatch.setattr(e.os, "fstat", metadata)
    monkeypatch.setattr(e.os, "ST_RDONLY", 1, raising=False)
    monkeypatch.setattr(e.os, "fstatvfs", lambda fd: SimpleNamespace(f_flag=1 if readonly else 0))

    def acl(fd, name):
        raw = _systemd_acl(985, 5 if stat.S_ISDIR(original_stat(fd).st_mode) else 4)
        return raw + struct.pack("<HHI", 2, 4, 986) if extra_acl else raw

    monkeypatch.setattr(e.os, "getxattr", acl, raising=False)
    if readonly and uid == 985 and not extra_acl:
        assert e._read_ca_key(key) == key.read_bytes()
    else:
        with pytest.raises(SignerError, match="enrollment_systemd_credential_invalid"):
            e._read_ca_key(key)
