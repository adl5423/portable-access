import base64
import json
import os
import stat
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import NameOID

from tools import bootstrap_openbao as b


@pytest.fixture(scope="module")
def operator_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


def decrypt(data, key):
    envelope = json.loads(data)
    aes_key = key.decrypt(
        base64.b64decode(envelope["wrapped_key"]),
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return json.loads(
        AESGCM(aes_key).decrypt(
            base64.b64decode(envelope["nonce"]),
            base64.b64decode(envelope["ciphertext"]),
            b._canonical(envelope["aad"]),
        )
    )


class FakeAPI:
    def __init__(self, paths, operator_key):
        self.paths, self.operator_key = paths, operator_key
        self.initialized = self.revoked = False
        self.calls, self.unsealed, self.configurations = [], [], {}
        self.init_calls = self.restart_calls = 0
        self.fail_init = self.fail_path = self.bad_response = False
        self.bad_capabilities = self.bad_login = False
        self.bad_signature = self.bad_denials = False
        self.bad_audit = False
        self.probe_keys = {}
        self.health_statuses = []
        self.health_default = 200
        self.after_restart_initialized = False
        self.envelope_before_unseal = False
        self.initial = {
            "keys_base64": [base64.b64encode(bytes([n]) * 33).decode() for n in range(1, 6)],
            "keys": [bytes([n]).hex() * 33 for n in range(1, 6)],
            "root_token": "s.synthetic-initial-root-token-never-print",
        }

    def context(self, server_ca, client_ca, key, name, now):
        return {"server_ca": server_ca, "client_ca": client_ca, "name": name}

    def factory(self, context, identity):
        if identity == "operator":
            assert context["client_ca"] != context["server_ca"]
            assert context["name"] == "pap-operator"
        else:
            assert context["client_ca"] == context["server_ca"]
        return lambda method, path, payload=None, token=None, **kwargs: self.request(
            identity, method, path, payload, token
        )

    def restart(self):
        assert not self.initialized
        bundle = x509.load_pem_x509_certificates(self.paths.client_ca_bundle.read_bytes())
        assert len(bundle) == 2 and bundle[0] != bundle[1]
        prepared = decrypt(self.paths.envelope.read_bytes(), self.operator_key)
        assert prepared["unseal_shares"] == []
        assert prepared["operator_ca"] == self.paths.operator_ca.read_text()
        self.restart_calls += 1
        self.initialized = self.after_restart_initialized

    def request(self, identity, method, path, payload, token):
        self.calls.append((identity, method, path, payload, token))
        if path == self.fail_path:
            return 500, {"error": self.initial["root_token"]}
        if method == "GET" and path == "/v1/sys/init":
            return 200, {"initialized": self.initialized}
        if method == "GET" and path == "/v1/sys/health":
            status = self.health_statuses.pop(0) if self.health_statuses else self.health_default
            return status, {
                "initialized": self.initialized,
                "sealed": len(self.unsealed) < 3,
                "standby": status == 429,
            }
        if method == "GET" and path == "/v1/sys/mounts":
            return 200, {"data": {"sys/": {"type": "system"}}}
        if method == "GET" and path == "/v1/sys/auth":
            return 200, {"data": {"token/": {"type": "token"}}}
        if method == "GET" and path.startswith("/v1/sys/policies/acl/"):
            return 404, {}
        if method == "GET" and path == "/v1/sys/audit":
            return 200, {
                "data": {
                    "pap/": {
                        "type": "file",
                        "options": {
                            "file_path": str(self.paths.audit),
                            "log_raw": "true" if self.bad_audit else "false",
                            "hmac_accessor": "true",
                        },
                    }
                }
            }
        if method == "POST" and path == "/v1/sys/init":
            self.init_calls += 1
            assert self.init_calls == 1
            assert payload == {"secret_shares": 5, "secret_threshold": 3}
            assert not self.initialized
            self.initialized = True
            if self.fail_init:
                raise OSError("unknown outcome; " + self.initial["root_token"])
            return 200, {"unexpected": self.initial["root_token"]} if self.bad_response else self.initial
        if path == "/v1/sys/unseal":
            packet = decrypt(self.paths.envelope.read_bytes(), self.operator_key)
            assert packet["unseal_shares"] == self.initial["keys_base64"]
            assert packet["initial_root_token"] == self.initial["root_token"]
            self.envelope_before_unseal = True
            self.unsealed.append(payload["key"])
            return 200, {"sealed": len(self.unsealed) < 3, "t": 3, "n": 5}
        if path == "/v1/auth/cert/login":
            role = payload["name"]
            if identity == "spoof_operator":
                return 403, {}
            assert identity == ("operator" if role == "pap-operator" else "issuer")
            return 200, {
                "auth": {
                    "client_token": "s.synthetic-" + role + "-memory-token",
                    "policies": ["root"] if self.bad_login else [role],
                    "lease_duration": 300,
                }
            }
        if path == "/v1/sys/capabilities":
            capabilities = {}
            for item in payload["paths"]:
                if item.startswith("transit/keys/") and item.count("/") == 2:
                    capabilities[item] = ["create", "read", "update"]
                elif item.startswith("transit/sign/pap-"):
                    capabilities[item] = ["update"]
                else:
                    capabilities[item] = ["sudo"] if self.bad_capabilities else ["deny"]
            # The official API documents top-level fields, not an obligatory data wrapper.
            return 200, capabilities
        if identity == "issuer":
            if path.startswith("/v1/transit/keys/") and path.count("/") == 4:
                name = path.rsplit("/", 1)[1]
                if method == "POST":
                    assert payload == {
                        "type": "ecdsa-p256",
                        "derived": False,
                        "exportable": False,
                        "allow_plaintext_backup": False,
                        "auto_rotate_period": "0",
                    }
                    self.probe_keys[name] = ec.generate_private_key(ec.SECP256R1())
                    return 204, {}
                if method == "GET":
                    return 200, {
                        "data": {
                            "type": "ecdsa-p256",
                            "exportable": False,
                            "allow_plaintext_backup": False,
                            "latest_version": 1,
                            "keys": {
                                "1": {
                                    "public_key": self.probe_keys[name]
                                    .public_key()
                                    .public_bytes(
                                        serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo,
                                    )
                                    .decode()
                                }
                            },
                        }
                    }
            if path.startswith("/v1/transit/sign/"):
                assert payload["key_version"] == "1"
                name = path.split("/")[-2]
                signature = self.probe_keys[name].sign(
                    base64.b64decode(payload["input"]), ec.ECDSA(utils.Prehashed(hashes.SHA256()))
                )
                r, s = utils.decode_dss_signature(signature)
                raw = bytearray(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
                if self.bad_signature:
                    raw[0] ^= 1
                return 200, {
                    "data": {"signature": "vault:v1:" + base64.urlsafe_b64encode(raw).decode().rstrip("=")}
                }
            return (204, {}) if self.bad_denials else (403, {})
        if path == "/v1/auth/token/revoke-self":
            assert token == self.initial["root_token"]
            self.revoked = True
            return 204, {}
        if path == "/v1/auth/token/lookup-self":
            return (403, {}) if self.revoked else (200, {"data": {"id": token, "policies": ["root"]}})
        self.configurations[path] = payload
        return 204, {}


@pytest.fixture
def fixture(tmp_path, operator_key):
    root = tmp_path
    root.chmod(0o700)
    public = root / "operator-public.der"
    public.write_bytes(
        operator_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    public.chmod(0o644)
    now = datetime.now(UTC).replace(microsecond=0)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Enrollment fixture")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(True, 0), True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
        .sign(ca_key, hashes.SHA256())
    )
    paths = b.BootstrapPaths(
        **{name: root / (name + ".file") for name in b.BootstrapPaths.__dataclass_fields__}
    )
    paths.enrollment_ca.write_text(b._certificate_pem(ca))
    paths.enrollment_key.write_text(b._private_pem(ca_key))
    paths.enrollment_key.chmod(0o600)
    paths.client_ca_bundle.write_text(b._certificate_pem(ca))
    paths.machine_id.write_text("a" * 32 + "\n")
    api = FakeAPI(paths, operator_key)

    def create(**kwargs):
        return b.Bootstrapper(
            public,
            kwargs.pop("pin", b._sha(public.read_bytes())),
            "m_fixture",
            _paths=paths,
            _owner_uid=os.geteuid(),
            _kms_uid=os.geteuid(),
            _transport_factory=api.factory,
            _context_factory=api.context,
            _restart_service=api.restart,
            _harden_process=lambda: None,
            _clock=lambda: now,
            _sleep=kwargs.pop("_sleep", lambda duration: None),
            **kwargs,
        )

    return {
        "root": root,
        "paths": paths,
        "api": api,
        "create": create,
        "public": public,
        "operator_key": operator_key,
        "ca": ca,
        "now": now,
    }


def test_complete_bootstrap_encrypts_before_unseal_and_revokes_root(fixture, capsys):
    result = fixture["create"]().run(apply=True)
    api, paths = fixture["api"], fixture["paths"]
    assert result["outcome"] == "initialized"
    assert api.init_calls == api.restart_calls == 1
    assert len(api.unsealed) == 3 and api.revoked and api.envelope_before_unseal
    assert stat.S_IMODE(paths.envelope.stat().st_mode) == 0o600
    assert json.loads(paths.receipt.read_text())["initial_root_token_revoked"] is True
    assert json.loads(paths.attempt.read_text())["state"] == "complete"
    packet = decrypt(paths.envelope.read_bytes(), fixture["operator_key"])
    assert packet["unseal_shares"] == api.initial["keys_base64"]
    assert packet["initial_root_token"] == api.initial["root_token"]
    operator_key = serialization.load_pem_private_key(packet["operator_ca_private_key"].encode(), None)
    operator_ca = x509.load_pem_x509_certificate(packet["operator_ca"].encode())
    assert operator_key.public_key().public_numbers() == operator_ca.public_key().public_numbers()
    assert operator_ca != fixture["ca"]
    for path in fixture["root"].iterdir():
        if path == paths.enrollment_key:
            continue
        data = path.read_bytes()
        assert api.initial["root_token"].encode() not in data
        assert packet["operator_ca_private_key"].encode() not in data
        assert all(share.encode() not in data for share in api.initial["keys_base64"])
    assert capsys.readouterr().out == ""
    assert not any(path.name.startswith(".pap-bootstrap-") for path in fixture["root"].iterdir())


def test_default_plan_has_no_mutations_or_private_outputs(fixture):
    result = fixture["create"]().run()
    assert result["outcome"] == "plan"
    assert all(method == "GET" for _, method, _, _, _ in fixture["api"].calls)
    assert not fixture["paths"].attempt.exists()
    assert not fixture["paths"].operator_ca.exists()
    assert not fixture["paths"].envelope.exists()


def test_completed_second_run_is_read_only_and_bound_to_exact_envelope(fixture):
    fixture["create"]().run(apply=True)
    assert fixture["create"]().run(apply=True)["outcome"] == "already_complete"
    assert fixture["api"].init_calls == fixture["api"].restart_calls == 1
    path = fixture["paths"].envelope
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(b.BootstrapError, match="bootstrap_existing_state_requires_operator_review"):
        fixture["create"]().run(apply=True)


def test_existing_initialized_without_complete_receipt_never_mutates(fixture):
    fixture["api"].initialized = True
    with pytest.raises(b.BootstrapError, match="bootstrap_existing_state_requires_operator_review"):
        fixture["create"]().run(apply=True)
    assert fixture["api"].init_calls == fixture["api"].restart_calls == 0


@pytest.mark.parametrize("field", ["attempt", "receipt", "envelope", "operator_ca"])
def test_any_existing_partial_state_requires_review(fixture, field):
    getattr(fixture["paths"], field).write_text("existing")
    with pytest.raises(b.BootstrapError, match="bootstrap_existing_state_requires_operator_review"):
        fixture["create"]().run(apply=True)
    assert fixture["api"].init_calls == 0


def test_uncertain_init_has_no_retry_unseal_or_acl(fixture):
    api = fixture["api"]
    api.fail_init = True
    with pytest.raises(
        b.BootstrapError, match="bootstrap_initialization_outcome_unknown_operator_review_required"
    ):
        fixture["create"]().run(apply=True)
    assert api.init_calls == 1 and not api.unsealed and not api.configurations
    assert json.loads(fixture["paths"].attempt.read_text())["state"] == "initialization_outcome_unknown"
    with pytest.raises(b.BootstrapError, match="bootstrap_existing_state_requires_operator_review"):
        fixture["create"]().run(apply=True)
    assert api.init_calls == 1


def test_unexpected_response_is_encrypted_before_refusal(fixture):
    fixture["api"].bad_response = True
    with pytest.raises(b.BootstrapError, match="bootstrap_initialization_response_requires_operator_review"):
        fixture["create"]().run(apply=True)
    packet = decrypt(fixture["paths"].envelope.read_bytes(), fixture["operator_key"])
    assert packet["initialization_response"]["unexpected"] == fixture["api"].initial["root_token"]
    assert not fixture["api"].unsealed


def test_envelope_write_failure_never_unseals_or_configures(fixture, monkeypatch):
    original = b._write

    def fail(path, data, **kwargs):
        if path == fixture["paths"].envelope and fixture["api"].initialized:
            raise OSError("write failed")
        return original(path, data, **kwargs)

    monkeypatch.setattr(b, "_write", fail)
    with pytest.raises(b.BootstrapError, match="bootstrap_stopped_operator_review_required"):
        fixture["create"]().run(apply=True)
    assert not fixture["api"].unsealed and not fixture["api"].configurations


def test_no_restart_after_initialization_even_if_it_happens_externally(fixture):
    fixture["api"].after_restart_initialized = True
    with pytest.raises(b.BootstrapError, match="bootstrap_existing_state_requires_operator_review"):
        fixture["create"]().run(apply=True)
    assert fixture["api"].restart_calls == 1 and fixture["api"].init_calls == 0


def test_state_machine_explicitly_forbids_post_init_restart(fixture):
    helper = fixture["create"]()
    helper.initialization_requested = True
    with pytest.raises(b.BootstrapError, match="bootstrap_restart_after_initialization_forbidden"):
        helper._restart_uninitialized(None)
    assert fixture["api"].restart_calls == 0


def test_separate_ca_roles_and_least_privilege_policy_payloads(fixture):
    fixture["create"]().run(apply=True)
    configurations = fixture["api"].configurations
    assert "/v1/sys/audit/pap" not in configurations
    assert any(method == "GET" and path == "/v1/sys/audit" for _, method, path, _, _ in fixture["api"].calls)
    issuer = configurations["/v1/auth/cert/certs/pap-issuer"]
    operator = configurations["/v1/auth/cert/certs/pap-operator"]
    assert issuer["certificate"] != operator["certificate"]
    for role, name in [(issuer, "pap-issuer"), (operator, "pap-operator")]:
        assert role["allowed_common_names"] == [name]
        assert role["token_policies"] == [name]
        assert role["token_ttl"] == role["token_max_ttl"] == role["token_explicit_max_ttl"] == 300
        assert role["token_no_default_policy"] is True
    assert configurations["/v1/auth/cert/config"] == {"disable_binding": False}
    assert 'path "*"' not in b.ISSUER_POLICY
    assert "export/" not in b.ISSUER_POLICY and '"exportable" = [false]' in b.ISSUER_POLICY
    assert 'path "transit/keys/+"' in b.ISSUER_POLICY
    assert 'path "transit/keys/+/+"' in b.ISSUER_POLICY
    assert 'path "transit/sign/+/sha2-256"' in b.ISSUER_POLICY
    assert '"key_version" = ["1"]' in b.ISSUER_POLICY
    assert "pap-*" not in b.ISSUER_POLICY
    assert '"sudo"' not in b.ISSUER_POLICY
    assert '"sudo"' in b.OPERATOR_POLICY
    assert not any("pki" in path for _, _, path, _, _ in fixture["api"].calls)


@pytest.mark.parametrize(
    "defect", ["bad_capabilities", "bad_login", "bad_signature", "bad_denials", "bad_audit"]
)
def test_incorrect_policy_or_role_verification_stops_before_root_revocation(fixture, defect):
    setattr(fixture["api"], defect, True)
    with pytest.raises(b.BootstrapError):
        fixture["create"]().run(apply=True)
    assert not fixture["api"].revoked
    assert not fixture["paths"].receipt.exists()
    assert fixture["paths"].envelope.exists()


def test_pin_mismatch_prevents_all_api_calls(fixture):
    with pytest.raises(b.BootstrapError, match="operator_public_key_pin_mismatch"):
        fixture["create"](pin="0" * 64).run(apply=True)
    assert not fixture["api"].calls


def test_small_operator_rsa_is_rejected_before_init(fixture):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    fixture["public"].write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    with pytest.raises(b.BootstrapError, match="operator_rsa4096_required"):
        fixture["create"]().run(apply=True)
    assert not fixture["api"].calls


def test_aad_ciphertext_and_wrapped_key_tampering_fails(operator_key):
    data = b.encrypt_recovery(
        {"synthetic-secret": "secret"}, operator_key.public_key(), {"machine_id": "m_one"}
    )
    assert decrypt(data, operator_key) == {"synthetic-secret": "secret"}
    envelope = json.loads(data)
    envelope["aad"]["machine_id"] = "m_other"
    with pytest.raises(InvalidTag):
        decrypt(json.dumps(envelope), operator_key)
    for name in ["ciphertext", "wrapped_key"]:
        envelope = json.loads(data)
        raw = bytearray(base64.b64decode(envelope[name]))
        raw[-1] ^= 1
        envelope[name] = base64.b64encode(raw).decode()
        with pytest.raises((InvalidTag, ValueError)):
            decrypt(json.dumps(envelope), operator_key)


@pytest.mark.parametrize("defect", ["symlink", "world_readable"])
def test_unsafe_private_ca_paths_rejected_before_network(fixture, defect):
    path = fixture["paths"].enrollment_key
    if defect == "symlink":
        real = path.with_suffix(".real")
        path.rename(real)
        path.symlink_to(real.name)
    else:
        path.chmod(0o644)
    with pytest.raises(b.BootstrapError):
        fixture["create"]().run(apply=True)
    assert not fixture["api"].calls


def test_root_guard_is_not_disabled_by_public_arguments(fixture):
    if os.geteuid() == 0:
        pytest.skip("requires an unprivileged runner")
    helper = b.Bootstrapper(fixture["public"], b._sha(fixture["public"].read_bytes()), "m_fixture")
    with pytest.raises(b.BootstrapError, match="bootstrap_root_required"):
        helper.run(apply=True)


def test_json_duplicate_members_rejected():
    with pytest.raises(b.BootstrapError, match="bootstrap_json_invalid"):
        b._json(b'{"initialized":false,"initialized":true}')


def test_cli_failure_prints_only_stable_code(fixture, monkeypatch, capsys):
    class Failure:
        def __init__(self, *args, **kwargs):
            pass

        def run(self, **kwargs):
            raise RuntimeError("RAW-SECRET-MUST-NOT-PRINT")

    monkeypatch.setattr(b, "Bootstrapper", Failure)
    import pwd

    monkeypatch.setattr(pwd, "getpwnam", lambda name: type("Account", (), {"pw_uid": os.geteuid()})())
    status = b.main(
        [
            "--operator-public-key",
            str(fixture["public"]),
            "--operator-public-key-sha256",
            b._sha(fixture["public"].read_bytes()),
            "--machine-id",
            "m_fixture",
            "--apply",
        ]
    )
    captured = capsys.readouterr()
    assert status == 1 and captured.err == ""
    assert json.loads(captured.out) == {
        "outcome": "stopped",
        "code": "bootstrap_stopped_operator_review_required",
    }
    assert "RAW-SECRET" not in captured.out


def test_preinit_service_restart_uses_fixed_command_and_no_caller_environment(monkeypatch):
    calls = []

    def execute(command, **kwargs):
        calls.append((command, kwargs))
        return type("Result", (), {"returncode": 0})()

    monkeypatch.setattr(b.subprocess, "run", execute)
    b._restart()
    assert calls[0][0] == ["/usr/bin/systemctl", "restart", "pap-openbao.service"]
    assert calls[0][1]["env"] == {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}


@pytest.mark.skipif(not hasattr(os, "memfd_create"), reason="Linux memfd required")
def test_client_context_uses_memfd_without_plaintext_files(fixture, monkeypatch):
    paths_before = set(fixture["root"].iterdir())
    key = serialization.load_pem_private_key(fixture["paths"].enrollment_key.read_bytes(), None)
    context = b._tls_context(fixture["ca"], fixture["ca"], key, "pap-bootstrap", fixture["now"])
    assert context.check_hostname
    assert set(fixture["root"].iterdir()) == paths_before


@pytest.mark.parametrize("defect", ["missing", "unexpected", "type", "path", "raw", "accessor", "malformed"])
def test_declarative_audit_is_validated_before_issuer_access(fixture, defect):
    original = fixture["api"].request

    def altered(identity, method, path, payload, token):
        status, value = original(identity, method, path, payload, token)
        if method != "GET" or path != "/v1/sys/audit":
            return status, value
        device = value["data"]["pap/"]
        if defect == "missing":
            value["data"] = {}
        elif defect == "unexpected":
            value["data"]["untrusted/"] = {"type": "file", "options": {"log_raw": "true"}}
        elif defect == "type":
            device["type"] = "socket"
        elif defect == "path":
            device["options"]["file_path"] = "/tmp/untrusted-audit"
        elif defect == "raw":
            device["options"]["log_raw"] = "true"
        elif defect == "accessor":
            device["options"]["hmac_accessor"] = "false"
        elif defect == "malformed":
            device["options"] = None
        return status, value

    fixture["api"].request = altered
    with pytest.raises(b.BootstrapError, match="bootstrap_declarative_audit_verification_failed"):
        fixture["create"]().run(apply=True)
    assert fixture["api"].unsealed
    assert not fixture["api"].configurations and not fixture["api"].revoked
    assert fixture["paths"].envelope.exists() and not fixture["paths"].receipt.exists()


@pytest.mark.parametrize(
    "method,path,expected_timeout",
    [
        ("POST", "/v1/sys/init", 60),
        ("GET", "/v1/sys/init", 10),
        ("POST", "/v1/sys/unseal", 10),
        ("POST", "/v1/sys/init-other", 10),
    ],
)
def test_only_one_shot_initialization_has_extended_transport_timeout(method, path, expected_timeout):
    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def read(self, limit):
            return b"{}"

    class Opener:
        def __init__(self):
            self.calls = []
            self.fail = False

        def open(self, request, *, timeout):
            self.calls.append((request.method, request.full_url, timeout))
            if self.fail:
                raise TimeoutError("synthetic transport failure must not trigger retry")
            return Response()

    transport = b._HTTPS.__new__(b._HTTPS)
    transport.opener = Opener()
    assert transport(method, path, {} if method == "POST" else None) == (200, {})
    assert transport.opener.calls == [(method, b.ORIGIN + path, expected_timeout)]
    transport.opener.calls.clear()
    transport.opener.fail = True
    with pytest.raises(b.BootstrapError, match="bootstrap_transport_unavailable"):
        transport(method, path, {} if method == "POST" else None)
    assert transport.opener.calls == [(method, b.ORIGIN + path, expected_timeout)]


@pytest.fixture
def checkpoint(fixture):
    api = fixture["api"]
    api.fail_path = "/v1/sys/audit"
    with pytest.raises(b.BootstrapError):
        fixture["create"]().run(apply=True)
    assert len(api.unsealed) == 3 and not api.configurations and not api.revoked
    api.fail_path = False
    packet = decrypt(fixture["paths"].envelope.read_bytes(), fixture["operator_key"])
    return packet, b._sha(fixture["paths"].envelope.read_bytes())


def test_active_health_wait_retries_only_reads_before_configuration(fixture):
    api = fixture["api"]
    api.health_statuses = [429, 503, 200]
    result = fixture["create"]().run(apply=True)
    assert result["outcome"] == "initialized"
    health = [
        i
        for i, (_, method, path, _, _) in enumerate(api.calls)
        if method == "GET" and path == "/v1/sys/health"
    ]
    audit = next(
        i
        for i, (_, method, path, _, _) in enumerate(api.calls)
        if method == "GET" and path == "/v1/sys/audit"
    )
    assert len(health) == 3 and max(health) < audit
    assert api.init_calls == api.restart_calls == 1 and len(api.unsealed) == 3


def test_active_health_timeout_never_retries_initialization_or_configuration(fixture):
    api = fixture["api"]
    api.health_default = 503
    ticks = [0.0]

    def sleep(duration):
        ticks[0] += duration

    with pytest.raises(b.BootstrapError, match="bootstrap_active_readiness_timeout"):
        fixture["create"](_sleep=sleep, _monotonic=lambda: ticks[0]).run(apply=True)
    assert ticks[0] == 30 and api.init_calls == api.restart_calls == 1
    assert len(api.unsealed) == 3 and not api.configurations and not api.revoked
    assert json.loads(fixture["paths"].attempt.read_bytes())["state"] == "recovery_envelope_durable"


def test_checkpoint_plan_is_read_only_and_completion_never_initializes_unseals_or_restarts(
    fixture, checkpoint, capsys
):
    packet, envelope_sha = checkpoint
    api, paths = fixture["api"], fixture["paths"]
    before = {p: p.read_bytes() for p in fixture["root"].iterdir()}
    prior_calls, prior_unsealed = len(api.calls), list(api.unsealed)
    plan = fixture["create"]().complete_checkpoint(packet, envelope_sha)
    assert plan["outcome"] == "checkpoint_plan" and plan["root_token_policy_verified"]
    assert all(method == "GET" for _, method, _, _, _ in api.calls[prior_calls:])
    assert {p: p.read_bytes() for p in fixture["root"].iterdir()} == before
    prior_journal_sha = b._sha(paths.attempt.read_bytes())
    result = fixture["create"]().complete_checkpoint(
        packet, envelope_sha, apply=True, expected_plan_sha256=plan["checkpoint_plan_sha256"]
    )
    assert result["outcome"] == "checkpoint_completed" and api.revoked
    assert api.init_calls == api.restart_calls == 1 and api.unsealed == prior_unsealed
    assert paths.envelope.read_bytes() == before[paths.envelope]
    receipt = json.loads(paths.receipt.read_bytes())
    journal = json.loads(paths.attempt.read_bytes())
    assert receipt["checkpoint_completion"] is True
    assert receipt["checkpoint_previous_attempt_sha256"] == prior_journal_sha
    assert receipt["checkpoint_plan_sha256"] == plan["checkpoint_plan_sha256"]
    assert journal["previous_attempt_sha256"] == receipt["configured_attempt_sha256"]
    previous = prior_journal_sha
    for record in receipt["checkpoint_journal_chain"]:
        assert record["previous_attempt_sha256"] == previous
        previous = b._sha(b._canonical(record) + b"\n")
    assert previous == receipt["configured_attempt_sha256"]
    assert len(receipt["checkpoint_journal_chain"]) == 2
    assert journal["checkpoint_plan_sha256"] == plan["checkpoint_plan_sha256"]
    assert capsys.readouterr().out == ""
    for p in fixture["root"].iterdir():
        if p != paths.enrollment_key:
            assert packet["initial_root_token"].encode() not in p.read_bytes()
            assert packet["operator_ca_private_key"].encode() not in p.read_bytes()


@pytest.mark.parametrize(
    "defect",
    [
        "envelope_hash",
        "packet_host",
        "packet_shares",
        "operator_key",
        "enrollment_key",
        "operator_ca",
        "journal_state",
        "bundle",
    ],
)
def test_checkpoint_rejects_binding_or_ca_mismatch_without_api_mutation(fixture, checkpoint, defect):
    packet, envelope_sha = checkpoint
    paths = fixture["paths"]
    if defect == "envelope_hash":
        envelope_sha = "0" * 64
    elif defect == "packet_host":
        packet["machine_id"] = "different-host"
    elif defect == "packet_shares":
        packet["initialization_response"]["keys_base64"] = []
    elif defect in {"operator_key", "enrollment_key"}:
        packet[("operator" if defect == "operator_key" else "enrollment") + "_ca_private_key"] = (
            b._private_pem(ec.generate_private_key(ec.SECP256R1()))
        )
    elif defect == "operator_ca":
        packet["operator_ca"] = packet["enrollment_ca"]
    elif defect == "journal_state":
        value = json.loads(paths.attempt.read_bytes())
        value["state"] = "configured"
        paths.attempt.write_bytes(b._canonical(value))
    elif defect == "bundle":
        paths.client_ca_bundle.write_text(packet["enrollment_ca"])
    count = len(fixture["api"].calls)
    with pytest.raises(b.BootstrapError, match="bootstrap_checkpoint_verification_failed"):
        fixture["create"]().complete_checkpoint(packet, envelope_sha)
    assert fixture["api"].calls[count:] == [] and not paths.receipt.exists()


@pytest.mark.parametrize(
    "defect", ["root_policy", "token_id", "transit_mount", "cert_auth", "issuer_policy", "operator_policy"]
)
def test_checkpoint_rejects_root_or_partial_remote_state_without_mutation(fixture, checkpoint, defect):
    packet, envelope_sha = checkpoint
    original = fixture["api"].request

    def altered(identity, method, path, payload, token):
        status, value = original(identity, method, path, payload, token)
        if path == "/v1/auth/token/lookup-self":
            if defect == "root_policy":
                value["data"]["policies"] = ["root", "default"]
            if defect == "token_id":
                value["data"]["id"] = "different-token"
        if path == "/v1/sys/mounts" and defect == "transit_mount":
            value["data"]["transit/"] = {"type": "transit"}
        if path == "/v1/sys/auth" and defect == "cert_auth":
            value["data"]["cert/"] = {"type": "cert"}
        if path == "/v1/sys/policies/acl/" + (
            "pap-issuer" if defect == "issuer_policy" else "pap-operator"
        ) and defect in {"issuer_policy", "operator_policy"}:
            return 200, {"data": {"policy": "existing"}}
        return status, value

    fixture["api"].request = altered
    count = len(fixture["api"].calls)
    with pytest.raises(b.BootstrapError):
        fixture["create"]().complete_checkpoint(packet, envelope_sha)
    assert all(method == "GET" for _, method, _, _, _ in fixture["api"].calls[count:])
    assert not fixture["api"].revoked and not fixture["paths"].receipt.exists()


@pytest.mark.parametrize("approval", [None, "0" * 64])
def test_checkpoint_apply_requires_exact_reviewed_plan_before_mutation(fixture, checkpoint, approval):
    packet, envelope_sha = checkpoint
    old = fixture["paths"].attempt.read_bytes()
    count = len(fixture["api"].calls)
    with pytest.raises(b.BootstrapError, match="bootstrap_checkpoint_plan_not_approved"):
        fixture["create"]().complete_checkpoint(
            packet, envelope_sha, apply=True, expected_plan_sha256=approval
        )
    assert fixture["paths"].attempt.read_bytes() == old
    assert all(method == "GET" for _, method, _, _, _ in fixture["api"].calls[count:])
    assert not fixture["api"].revoked


def test_checkpoint_plan_cannot_authorize_changed_journal(fixture, checkpoint):
    packet, envelope_sha = checkpoint
    plan = fixture["create"]().complete_checkpoint(packet, envelope_sha)
    path = fixture["paths"].attempt
    value = json.loads(path.read_bytes())
    value["recorded_at"] = "changed"
    path.write_bytes(b._canonical(value))
    with pytest.raises(b.BootstrapError, match="bootstrap_checkpoint_plan_not_approved"):
        fixture["create"]().complete_checkpoint(
            packet, envelope_sha, apply=True, expected_plan_sha256=plan["checkpoint_plan_sha256"]
        )
    assert not fixture["api"].revoked and not fixture["paths"].receipt.exists()
