import base64
import hashlib
import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

from pap.operator import cli, transport
from pap.operator import process as operator_process
from pap.operator.custody import (
    CustodyError,
    EncryptedPEMCustody,
    MacOSKeychainCustody,
    private_read,
    public_der,
    public_jwk,
    public_pin,
    write_new_private,
)
from pap.operator.envelope import (
    SCHEMA,
    canonical,
    decrypt_openai_backup,
    decrypt_packet,
    encrypt_packet,
    inspect_packet,
    parse_json,
    prepare_successor,
    recovery_material,
    static_seal_material,
)
from pap.operator.kms import CREDENTIAL_POLICY_BLOCKS, provision_kms
from pap.operator.transport import OpenBaoOperator, memfd_mtls, ssh_command


class MemoryCustody:
    def __init__(self, key):
        self.key = key

    def public_der(self):
        return public_der(self.key.public_key())

    def decrypt(self, value):
        return self.key.decrypt(
            value, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )


@pytest.fixture(scope="module")
def custody():
    return MemoryCustody(rsa.generate_private_key(public_exponent=65537, key_size=4096))


@pytest.fixture
def recovery(custody):
    now = datetime.now(UTC)
    packet = {
        "schema": SCHEMA,
        "machine_id": "host-example",
        "host_identity_sha256": "a" * 64,
        "secret_threshold": 3,
        "secret_shares": 5,
        "unseal_shares": ["share-value-0000" + str(i) for i in range(5)],
    }
    aad = {
        "machine_id": packet["machine_id"],
        "host_identity_sha256": packet["host_identity_sha256"],
        "stage": "initialization-response-received",
        "recorded_at": now.isoformat(),
    }
    for name in ("enrollment", "operator"):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name + " CA")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(True, 0), True)
            .sign(key, hashes.SHA256())
        )
        packet[name + "_ca"] = cert.public_bytes(serialization.Encoding.PEM).decode()
        packet[name + "_ca_private_key"] = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode()
        aad[name + "_ca_sha256"] = hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()
    raw = encrypt_packet(packet, custody.public_der(), aad)
    expected = {"machine_id": packet["machine_id"], "host_identity_sha256": packet["host_identity_sha256"]}
    return raw, packet, expected


def test_recovery_roundtrip_original_contract_and_pins(custody, recovery):
    raw, packet, expected = recovery
    assert inspect_packet(raw)["authenticated"] is False
    result = decrypt_packet(raw, custody, expected=expected, expected_sha256=hashlib.sha256(raw).hexdigest())
    assert recovery_material(result) == packet
    for wrong in ({**expected, "machine_id": "wrong"}, {"machine_id": expected["machine_id"]}):
        with pytest.raises(CustodyError):
            decrypt_packet(raw, custody, expected=wrong)
    with pytest.raises(CustodyError, match="checksum"):
        decrypt_packet(raw, custody, expected=expected, expected_sha256="b" * 64)


@pytest.mark.parametrize("field", ["ciphertext", "nonce", "wrapped_key"])
def test_recovery_rejects_corruption_without_plaintext(custody, recovery, field):
    raw, _, expected = recovery
    value = json.loads(raw)
    data = bytearray(base64.b64decode(value[field]))
    data[0] ^= 1
    value[field] = base64.b64encode(data).decode()
    with pytest.raises((CustodyError, ValueError)):
        decrypt_packet(canonical(value), custody, expected=expected)


def test_recovery_rejects_duplicate_and_algorithm_confusion(custody, recovery):
    raw, _, expected = recovery
    with pytest.raises(CustodyError, match="JSON"):
        parse_json(b'{"x":1,"x":2}')
    value = json.loads(raw)
    value["aad"]["wrap"] = "RSA-PKCS1"
    with pytest.raises(CustodyError, match="algorithm"):
        decrypt_packet(canonical(value), custody, expected=expected)
    with pytest.raises(CustodyError):
        parse_json(b'{"x":NaN}')


def test_static_successor_keeps_previous_packet_and_authenticates_key(custody, recovery):
    raw, original, expected = recovery
    old_hash = hashlib.sha256(raw).hexdigest()
    encrypted, receipt = prepare_successor(
        raw,
        custody,
        recipient_der=custody.public_der(),
        expected=expected,
        deployment_id="deployment-example",
    )
    successor = decrypt_packet(encrypted, custody, expected=expected)
    assert successor["predecessor_recovery"] == original
    assert hashlib.sha256(base64.b64decode(successor["static_seal_key_b64"])).hexdigest() == receipt["key_id"]
    assert receipt["previous_envelope_sha256"] == old_hash
    assert receipt["decryption_verified"] is False
    assert hashlib.sha256(raw).hexdigest() == old_hash
    with pytest.raises(CustodyError, match="original initialization"):
        prepare_successor(
            encrypted, custody, recipient_der=custody.public_der(), expected=expected, deployment_id="another"
        )


def test_legacy_static_successor_022_is_accepted_without_rewriting(custody, recovery):
    raw, original, expected = recovery
    secret = os.urandom(32)
    key_id = hashlib.sha256(secret).hexdigest()
    packet = {
        **original,
        "static_seal": {
            "custody": "independent",
            "deployment_id": "legacy-deployment",
            "key_b64url": base64.urlsafe_b64encode(secret).rstrip(b"=").decode(),
            "key_id": key_id,
            "prepared_at": datetime.now(UTC).isoformat(),
            "seal_type": "static",
        },
    }
    aad = inspect_packet(raw)["aad"]
    aad.update(
        {
            "stage": "static-seal-successor-pre-migration",
            "static_seal_key_id": key_id,
            "previous_envelope_sha256": hashlib.sha256(raw).hexdigest(),
        }
    )
    encrypted = encrypt_packet(packet, custody.public_der(), aad)
    decrypted = decrypt_packet(encrypted, custody, expected=expected)
    assert static_seal_material(decrypted) == ("legacy-deployment", secret)
    assert recovery_material(decrypted)["operator_ca"] == original["operator_ca"]


def test_public_der_formats_and_jwk(custody):
    spki = custody.key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert public_jwk(spki) == public_jwk(custody.public_der())
    assert public_jwk(spki)["e"] == "AQAB"
    assert public_pin(spki) != public_pin(custody.public_der())


def test_private_files_no_overwrite_no_symlink_no_group_access(tmp_path):
    destination = tmp_path / "operator" / "backup.json"
    write_new_private(destination, b"encrypted")
    assert private_read(destination) == b"encrypted"
    assert destination.stat().st_mode & 0o777 == 0o600
    with pytest.raises(CustodyError, match="already exists"):
        write_new_private(destination, b"replacement")
    link = destination.parent / "link"
    link.symlink_to(destination)
    with pytest.raises(CustodyError):
        private_read(link)
    destination.chmod(0o640)
    with pytest.raises(CustodyError, match="owner-only"):
        private_read(destination)


def test_encrypted_pem_contains_no_plaintext_key(tmp_path):
    path = tmp_path / "custody" / "private.pem"
    custody = EncryptedPEMCustody.create(path, b"a long independent test passphrase")
    assert b"BEGIN ENCRYPTED PRIVATE KEY" in path.read_bytes()
    wrapped = custody.key.public_key() if hasattr(custody, "key") else None
    assert wrapped is None
    with pytest.raises(CustodyError, match="unlock"):
        EncryptedPEMCustody(path, b"wrong passphrase")
    assert len(custody.public_der()) > 500


def openai_backup(custody):
    secret = b"sk-proj-synthetic-operator-test-value"
    ciphertext = custody.key.public_key().encrypt(
        secret, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    encrypted = base64.urlsafe_b64encode(ciphertext).rstrip(b"=").decode()
    wrapper = {
        "schema": "pap.operator.provider-custody.v1",
        "name": "example-key",
        "organization_id": "org-example",
        "project_id": "proj-example",
        "recipient_public_der_sha256": public_pin(custody.public_der()),
        "creation_result": {
            "isError": False,
            "structuredContent": {
                "encrypted_api_key": {"version": 1, "ciphertext": encrypted},
                "api_key_name": "example-key",
                "organization": {"id": "org-example"},
                "project": {"id": "proj-example"},
            },
        },
    }
    return canonical(wrapper), secret


def test_openai_connector_ciphertext_interop_and_binding(custody):
    raw, secret = openai_backup(custody)
    assert (
        decrypt_openai_backup(
            raw, custody, name="example-key", organization_id="org-example", project_id="proj-example"
        )
        == secret
    )
    with pytest.raises(CustodyError, match="binding"):
        decrypt_openai_backup(
            raw, custody, name="wrong", organization_id="org-example", project_id="proj-example"
        )


def test_cli_credential_import_receipt_never_prints_secret(custody, tmp_path, monkeypatch, capsys):
    raw, secret = openai_backup(custody)
    packet = tmp_path / "private" / "key.enc.json"
    write_new_private(packet, raw)
    monkeypatch.setattr(cli, "load_custody", lambda *args: custody)
    captured = []

    def capture(args, value):
        captured.append(value)
        return {"imported": True, "provider": "openai"}

    monkeypatch.setattr(cli, "_import_as_admin", capture)
    assert (
        cli.main(
            [
                "credential-import",
                "--custody",
                "unused",
                "--provider",
                "openai",
                "--encrypted-openai-backup",
                str(packet),
                "--name",
                "example-key",
                "--organization-id",
                "org-example",
                "--project-id",
                "proj-example",
            ]
        )
        == 0
    )
    out = capsys.readouterr()
    assert secret.decode() not in out.out + out.err
    assert captured == [{"provider": "openai", "action": "import", "credential": secret.decode()}]


@pytest.mark.parametrize(
    "target", ["-oProxyCommand=evil", "host;touch-x", "user@host extra", "$(anything)", "host\ncommand"]
)
def test_ssh_target_rejects_shell_and_option_injection(target):
    with pytest.raises(CustodyError):
        ssh_command(target, executable="/opt/pap/venv/bin/pap-operator", arguments=["receive-unseal"])


def test_ssh_uses_known_host_verification_and_no_shell():
    result = ssh_command(
        "operator@example.invalid",
        executable="/opt/pap/venv/bin/pap-operator",
        arguments=["receive-credential", "--socket", "/run/pap-admin/admin.sock"],
    )
    assert "StrictHostKeyChecking=yes" in result
    assert "BatchMode=yes" in result
    assert "ForwardAgent=no" in result
    assert "ForwardX11=no" in result
    assert "ClearAllForwardings=yes" in result
    assert result[-2] == "operator@example.invalid"
    assert result[-1].startswith("sudo -n /opt/pap/venv/bin/pap-operator receive-credential")


def test_ssh_response_is_bounded_before_accumulating():
    command = [sys.executable, "-c", "import sys;sys.stdin.buffer.read();sys.stdout.write('x'*1000000)"]
    with pytest.raises(CustodyError, match="size limit"):
        transport.ssh_send(command, {"test": "value"}, maximum=1024)


def test_ssh_stream_roundtrip_and_timeout():
    echo = [sys.executable, "-c", "import sys;sys.stdout.buffer.write(sys.stdin.buffer.read())"]
    assert transport.ssh_send(echo, {"test": "value"}) == canonical({"test": "value"})
    timeout = [sys.executable, "-c", "import time;time.sleep(5)"]
    with pytest.raises(CustodyError, match="outcome unknown"):
        transport.ssh_send(timeout, {}, timeout=0.02)


@pytest.mark.parametrize(
    "result",
    [
        {},
        {"provider": "nasa", "configured": True, "generation": 1},
        {"provider": "openai", "configured": False, "generation": 1},
        {"provider": "openai", "configured": True, "generation": True},
        {"provider": "openai", "configured": True, "generation": 0},
        {"provider": "openai", "configured": True, "generation": 1, "credential": "forbidden"},
    ],
)
def test_import_rejects_unverified_success_json(monkeypatch, result):
    class Response:
        status = 200

        def read(self, count):
            return canonical(result)

    class Connection:
        def __init__(self, *args, **kwargs):
            pass

        def request(self, *args, **kwargs):
            pass

        def getresponse(self):
            return Response()

        def close(self):
            pass

    monkeypatch.setattr(transport, "_UnixHTTPConnection", Connection)
    with pytest.raises(CustodyError, match="verification"):
        transport.import_credential(
            Path("unused"),
            {"provider": "openai", "action": "import", "credential": "synthetic"},
            expected_peer_uid=123,
            expected_socket_uid=456,
        )


def test_custody_provision_verifies_exact_receipt(custody, recovery, tmp_path, monkeypatch, capsys):
    from types import SimpleNamespace

    raw, _, expected = recovery
    encrypted, _ = prepare_successor(
        raw,
        custody,
        recipient_der=custody.public_der(),
        expected=expected,
        deployment_id="deployment-example",
    )
    packet = tmp_path / "operator" / "successor.enc.json"
    write_new_private(packet, encrypted)
    key_id = inspect_packet(encrypted)["aad"]["static_seal_key_id"]
    config = tmp_path / "operator" / "public.json"
    public = {
        "site_id": "00000000-0000-4000-8000-000000000001",
        "deployment_id": "deployment-example",
        "machine_id": "host-example",
        "origin": "https://authority.example",
        "key_id": key_id,
    }
    write_new_private(config, canonical(public))
    helper = tmp_path / "operator" / "helper.mjs"
    write_new_private(helper, b"// trusted test helper")
    monkeypatch.setattr(cli, "load_custody", lambda *args: custody)
    monkeypatch.setattr(cli.shutil, "which", lambda _: sys.executable)
    seen = []

    def run(argv, **kwargs):
        seen.append(kwargs)
        record = parse_json(kwargs["input"])
        result = {
            "v": 1,
            "operation": "provision",
            "store": "pap-seal-custody-v1",
            "site_id": public["site_id"],
            "deployment_id": public["deployment_id"],
            "key_id": key_id,
            "state": "created",
            "enabled": True,
            "record_sha256": hashlib.sha256(canonical(record)).hexdigest(),
        }
        return SimpleNamespace(returncode=0, stdout=canonical(result))

    monkeypatch.setattr(cli.subprocess, "run", run)
    args = [
        "custody-provision",
        "--custody",
        "unused",
        "--packet",
        str(packet),
        "--machine-id",
        expected["machine_id"],
        "--host-identity-sha256",
        expected["host_identity_sha256"],
        "--envelope-sha256",
        hashlib.sha256(encrypted).hexdigest(),
        "--config",
        str(config),
        "--helper",
        str(helper),
        "--netlify-token-fd",
        "3",
    ]
    assert cli.main(args) == 0
    assert seen[0]["pass_fds"] == (3,)
    secret = parse_json(seen[0]["input"])["key_b64url"]
    out = capsys.readouterr()
    assert secret not in out.out + out.err
    helper.unlink()
    helper.symlink_to(config)
    assert cli.main(args) == 2
    assert len(seen) == 1


def test_hardening_happens_before_secret_dispatch(monkeypatch):
    calls = []
    monkeypatch.setattr(cli, "harden_process", lambda: calls.append("harden"))
    monkeypatch.setattr(cli, "execute", lambda args: calls.append("execute"))
    assert cli.main(["inspect", "--packet", "unused"]) == 0
    assert calls == ["harden", "execute"]


def test_core_dump_protection_failure_is_closed(monkeypatch):
    def fail(*args):
        raise OSError("synthetic failure")

    monkeypatch.setattr(operator_process.resource, "setrlimit", fail)
    with pytest.raises(CustodyError, match="dump protection"):
        operator_process.harden_process()


class FakeKMS:
    def __init__(self):
        self.key = None
        self.policy = 'path "transit/sign/+/sha2-256" { capabilities = ["update"] }\n'
        self.calls = []
        self.revoked = False

    def login(self):
        self.calls.append(("POST", "login"))

    def revoke(self):
        self.revoked = True

    def request(self, method, path, value=None, **kwargs):
        self.calls.append((method, path))
        if "policies" in path:
            if method == "POST":
                self.policy = value["policy"]
            return {"data": {"policy": self.policy}}
        if method == "POST":
            self.key = {
                "name": "pap-provider-credentials",
                **value,
                "auto_rotate_period": 86400,
                "supports_encryption": True,
                "supports_decryption": True,
            }
        return {"data": self.key} if self.key is not None else None


def test_kms_provision_read_plan_binds_apply_and_is_idempotent():
    kms = FakeKMS()
    plan = provision_kms(kms)
    assert not plan["applied"] and plan["plan"]["create_key"]
    assert kms.revoked and kms.key is None
    with pytest.raises(CustodyError, match="plan"):
        provision_kms(kms, apply=True, expected_plan_sha256="a" * 64)
    assert kms.key is None
    result = provision_kms(kms, apply=True, expected_plan_sha256=plan["plan_sha256"])
    assert result["applied"] and kms.key["derived"]
    assert all(block in kms.policy for block in CREDENTIAL_POLICY_BLOCKS)
    again = provision_kms(kms)
    assert again["plan"]["create_key"] is False
    assert again["plan"]["update_policy"] is False


def test_kms_provision_rejects_incompatible_policy_without_write():
    kms = FakeKMS()
    kms.policy += 'path "transit/decrypt/pap-provider-credentials" { capabilities = ["sudo"] }'
    with pytest.raises(CustodyError, match="incompatible"):
        provision_kms(kms)
    assert all(method != "POST" or path == "login" for method, path in kms.calls)


@pytest.mark.skipif(
    sys.platform == "darwin", reason="Do not read or write an operator's actual Keychain in tests"
)
def test_keychain_backend_fails_closed_outside_macos():
    with pytest.raises(CustodyError, match="macOS"):
        MacOSKeychainCustody("org.example.test")


@pytest.mark.skipif(hasattr(os, "memfd_create"), reason="Linux integration runs separately")
def test_memfd_transport_fails_closed_on_non_linux(recovery):
    with pytest.raises(CustodyError, match="Linux memfd"):
        with memfd_mtls(recovery[1]):
            pytest.fail("Non-Linux transport must not create private-key files")


@pytest.mark.skipif(not hasattr(os, "memfd_create"), reason="Linux sealed memfd required")
def test_native_memfd_context_loads_real_operator_certificate_and_closes_fds(recovery):
    import ssl

    before = set(Path("/proc/self/fd").iterdir())
    with memfd_mtls(recovery[1]) as context:
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True
        assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert set(Path("/proc/self/fd").iterdir()) == before


def test_openbao_transport_rejects_non_loopback_origins():
    import ssl

    with pytest.raises(CustodyError, match="loopback"):
        OpenBaoOperator(ssl.create_default_context(), "https://remote.example:8200")
