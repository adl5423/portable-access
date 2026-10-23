"""Protected signer contract and adversarial provider-response tests."""

import base64
import hashlib
import ssl
import urllib.error
import urllib.request
import uuid
from contextlib import contextmanager
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from pap import signers
from pap.crypto import parse_public
from pap.signers import MAX_RESPONSE, OpenBaoSigner, SignerError, _NoRedirects, _trusted_file

GENERATION = "07c30e4a-3ab5-47b6-96b1-8680fe441080"
REFERENCE = "openbao:pap-07c30e4a3ab547b696b18680fe441080:1"
NAME = "pap-07c30e4a3ab547b696b18680fe441080"


class Transit:
    def __init__(self):
        self.keys = {}
        self.calls = []
        self.login_count = 0
        self.login_override = None
        self.key_changes = {}
        self.signature_change = lambda value: value
        self.denied = False

    def __call__(self, method, path, payload, headers):
        self.calls.append((method, path, payload, dict(headers)))
        if path == "/v1/auth/cert/login":
            self.login_count += 1
            assert "X-Vault-Token" not in headers
            return 200, self.login_override or {
                "auth": {"client_token": "test-only-token-" + str(self.login_count), "lease_duration": 100}
            }
        assert headers["X-Vault-Token"].startswith("test-only-token-")
        if self.denied:
            return 403, {"errors": ["sensitive-provider-message"]}
        if path.startswith("/v1/transit/keys/"):
            name = path.rsplit("/", 1)[1]
            if method == "POST":
                self.keys.setdefault(name, ec.generate_private_key(ec.SECP256R1()))
                return 204, {}
            if name not in self.keys:
                return 404, {}
            pem = (
                self.keys[name]
                .public_key()
                .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
                .decode()
            )
            data = {
                "name": name,
                "type": "ecdsa-p256",
                "derived": False,
                "exportable": False,
                "allow_plaintext_backup": False,
                "supports_signing": True,
                "latest_version": 1,
                "auto_rotate_period": 0,
                "keys": {"1": {"public_key": pem}},
            }
            data.update(self.key_changes)
            return 200, {"data": data}
        name = path.split("/")[-2]
        digest = base64.b64decode(payload["input"], validate=True)
        signature = self.keys[name].sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        r, s = utils.decode_dss_signature(signature)
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        value = "vault:v1:" + base64.urlsafe_b64encode(raw).decode().rstrip("=")
        return 200, {"data": {"signature": self.signature_change(value)}}


def signer(transit, **kwargs):
    return OpenBaoSigner(
        "https://bao.example.test:8200",
        role="pap-issuer",
        client_cert="/run/pap/cert.pem",
        client_key="/run/pap/key.pem",
        _transport=transit,
        **kwargs,
    )


def test_prepare_is_deterministic_and_recoverable_without_exported_private_keys():
    transit = Transit()
    provider = signer(transit)
    first = provider.prepare(GENERATION)
    second = provider.prepare(GENERATION)
    restored = signer(transit).prepare(GENERATION)
    assert first == second == restored
    assert first.reference == REFERENCE
    assert set(first.public_jwk) == {"kty", "crv", "x", "y"}
    creates = [call for call in transit.calls if call[0] == "POST" and "/keys/" in call[1]]
    assert len(creates) == 1
    assert creates[0][2] == {
        "type": "ecdsa-p256",
        "derived": False,
        "exportable": False,
        "allow_plaintext_backup": False,
        "auto_rotate_period": "0",
    }


def test_signatures_verify_locally_and_provider_receives_only_digest():
    transit = Transit()
    provider = signer(transit, namespace="organization/security")
    prepared = provider.prepare(GENERATION)
    signing_input = b"eyJhbGciOiJFUzI1NiJ9.eyJ0ZW5hbnQiOiJzZW5zaXRpdmUifQ"
    raw = provider.sign(prepared.reference, signing_input)
    assert len(raw) == 64
    der = utils.encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big"))
    parse_public(prepared.public_jwk).verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
    _, path, payload, headers = transit.calls[-1]
    assert path.endswith("/" + NAME + "/sha2-256")
    assert payload == {
        "input": base64.b64encode(hashlib.sha256(signing_input).digest()).decode(),
        "prehashed": True,
        "key_version": "1",
        "marshaling_algorithm": "jws",
    }
    assert headers["X-Vault-Namespace"] == "organization/security"
    assert signing_input.decode() not in str(payload)


def test_sign_after_restart_loads_pinned_public_generation():
    transit = Transit()
    signer(transit).prepare(GENERATION)
    restored = signer(transit)
    assert len(restored.sign(REFERENCE, b"a.b")) == 64
    assert any(call[0] == "GET" for call in transit.calls)


def test_automatic_reauthentication_before_token_expiry():
    transit = Transit()
    now = [100.0]
    provider = signer(transit, _clock=lambda: now[0])
    provider.prepare(GENERATION)
    now[0] = 179.0
    provider.sign(REFERENCE, b"a.b")
    assert transit.login_count == 1
    now[0] = 181.0
    provider.sign(REFERENCE, b"a.b")
    assert transit.login_count == 2
    assert transit.calls[-1][3]["X-Vault-Token"] == "test-only-token-2"


def test_certificate_replacement_discards_cached_authentication_without_retiring_keys():
    transit = Transit()
    provider = signer(transit)
    provider.prepare(GENERATION)
    assert transit.login_count == 1
    provider.reset_authentication()
    assert provider.health()["authenticated"] is True
    assert transit.login_count == 2
    assert len(provider.sign(REFERENCE, b"a.b")) == 64
    assert transit.login_count == 2


@pytest.mark.parametrize(
    "auth",
    [
        {},
        {"client_token": "too-short", "lease_duration": 100},
        {"client_token": "x" * 20 + "\r\n", "lease_duration": 100},
        {"client_token": "x" * 20, "lease_duration": 0},
        {"client_token": "x" * 20, "lease_duration": True},
        {"client_token": "x" * 20, "lease_duration": 100000},
    ],
)
def test_invalid_login_fails_closed(auth):
    transit = Transit()
    transit.login_override = {"auth": auth}
    with pytest.raises(SignerError, match="signer_login_invalid"):
        signer(transit).prepare(GENERATION)


@pytest.mark.parametrize(
    "changes",
    [
        {"exportable": True},
        {"exportable": 0},
        {"allow_plaintext_backup": True},
        {"type": "rsa-2048"},
        {"name": "another-tenant-key"},
        {"derived": True},
        {"supports_signing": False},
        {"latest_version": 2},
        {"latest_version": True},
        {"auto_rotate_period": 3600},
        {"min_encryption_version": 2},
        {"min_decryption_version": True},
        {"keys": {}},
        {"keys": {"1": {"public_key": "not-a-key"}}},
    ],
)
def test_key_configuration_and_public_metadata_are_validated(changes):
    transit = Transit()
    transit.key_changes = changes
    with pytest.raises(SignerError):
        signer(transit).prepare(GENERATION)


@pytest.mark.parametrize(
    "change",
    [
        lambda value: value.replace("vault:v1:", "vault:v2:"),
        lambda value: "vault:v1:" + "A" * 86,
        lambda value: "vault:v1:" + "A" * 85 + "+",
        lambda value: "vault:v1:" + "A" * 85,
        lambda value: None,
    ],
)
def test_signature_corruption_and_version_substitution_are_rejected(change):
    transit = Transit()
    provider = signer(transit)
    provider.prepare(GENERATION)
    transit.signature_change = change
    with pytest.raises(SignerError, match="signer_signature_invalid"):
        provider.sign(REFERENCE, b"a.b")


def test_another_private_key_cannot_sign_a_pinned_generation():
    transit = Transit()
    provider = signer(transit)
    provider.prepare(GENERATION)
    transit.keys[NAME] = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(SignerError, match="signer_signature_invalid"):
        provider.sign(REFERENCE, b"a.b")


def test_retirement_denies_reuse_without_destructive_remote_cleanup():
    transit = Transit()
    provider = signer(transit)
    provider.prepare(GENERATION)
    before = len(transit.calls)
    provider.retire(REFERENCE)
    provider.retire(REFERENCE)
    with pytest.raises(SignerError, match="signer_key_retired"):
        provider.sign(REFERENCE, b"a.b")
    with pytest.raises(SignerError, match="signer_key_retired"):
        provider.prepare(GENERATION)
    assert len(transit.calls) == before
    assert NAME in transit.keys


def test_provider_denial_is_scrubbed_and_next_operation_reauthenticates():
    transit = Transit()
    provider = signer(transit)
    provider.prepare(GENERATION)
    transit.denied = True
    with pytest.raises(SignerError, match="^signer_authentication_denied$"):
        provider.sign(REFERENCE, b"a.b")
    transit.denied = False
    provider.sign(REFERENCE, b"a.b")
    assert transit.login_count == 2


def test_transport_failures_do_not_disclose_tokens_or_provider_details():
    def transport(*args):
        raise RuntimeError("SECRET-TOKEN in https://user:password@private-host/")

    with pytest.raises(SignerError) as caught:
        signer(transport).health()
    assert str(caught.value) == "signer_transport_unavailable"
    assert caught.value.__cause__ is None


@pytest.mark.parametrize(
    "base",
    [
        "http://bao.example.test",
        "https://user:pass@bao.example.test",
        "https://bao.example.test/v1",
        "https://bao.example.test?x=y",
        "https://bao.example.test/#fragment",
        "https://bao.example.test:bad",
        "https://bao.example.test\r\nHost:evil",
        "file:///run/bao.sock",
    ],
)
def test_https_origin_is_mandatory_even_for_injected_test_transport(base):
    with pytest.raises(ValueError):
        OpenBaoSigner(base, role="pap", client_cert="/a", client_key="/b", _transport=Transit())


@pytest.mark.parametrize("reference", ["../../other", "openbao:pap-../other:1", REFERENCE + ":2", None])
def test_untrusted_key_references_cannot_select_another_path(reference):
    transit = Transit()
    with pytest.raises(SignerError, match="signer_reference_invalid"):
        signer(transit).sign(reference, b"a.b")
    assert transit.calls == []


def test_generation_ids_are_validated_before_any_provider_access():
    transit = Transit()
    with pytest.raises(SignerError, match="signer_generation_invalid"):
        signer(transit).prepare("../other")
    assert transit.calls == []
    assert signer(transit).prepare(str(uuid.uuid4())).reference.startswith("openbao:pap-")


def test_private_credential_files_reject_world_readable_and_symlinks(tmp_path):
    private_key = tmp_path / "key.pem"
    private_key.write_text("test-only")
    private_key.chmod(0o644)
    with pytest.raises(SignerError, match="signer_credential_file_invalid"):
        with _trusted_file(private_key, private=True):
            pass
    private_key.chmod(0o600)
    with _trusted_file(private_key, private=True) as descriptor:
        assert descriptor >= 0
    link = tmp_path / "link.pem"
    link.symlink_to(private_key)
    with pytest.raises(SignerError, match="signer_credential_file_invalid"):
        with _trusted_file(link, private=True):
            pass


def test_public_credentials_allow_read_access_but_reject_write_access(tmp_path):
    certificate = tmp_path / "cert.pem"
    certificate.write_text("test-only")
    certificate.chmod(0o644)
    with _trusted_file(certificate, private=False) as descriptor:
        assert descriptor >= 0
    certificate.chmod(0o666)
    with pytest.raises(SignerError, match="signer_credential_file_invalid"):
        with _trusted_file(certificate, private=False):
            pass


@pytest.mark.parametrize(
    "body",
    [
        b'{"auth":{},"auth":{}}',
        b"[]",
        b"{invalid-json",
        b"A" * (MAX_RESPONSE + 1),
    ],
)
def test_https_transport_bounds_and_validates_provider_json(monkeypatch, body):
    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size):
            assert size == MAX_RESPONSE + 1
            return body[:size]

    class Opener:
        def open(self, request, timeout):
            assert request.full_url == "https://bao.example.test:8200/v1/auth/cert/login"
            assert timeout == 5.0
            return Response()

    def build(*handlers):
        assert any(isinstance(item, urllib.request.ProxyHandler) and item.proxies == {} for item in handlers)
        assert any(isinstance(item, _NoRedirects) for item in handlers)
        return Opener()

    provider = OpenBaoSigner("https://bao.example.test:8200", role="pap", client_cert="/a", client_key="/b")
    monkeypatch.setattr(provider, "_ssl_context", ssl.create_default_context)
    monkeypatch.setattr(urllib.request, "build_opener", build)
    with pytest.raises(SignerError):
        provider.health()


def test_https_redirects_do_not_forward_provider_credentials(monkeypatch):
    class Opener:
        def open(self, request, timeout):
            raise urllib.error.HTTPError(
                request.full_url, 302, "redirect", {"Location": "https://attacker.test/"}, None
            )

    provider = OpenBaoSigner("https://bao.example.test:8200", role="pap", client_cert="/a", client_key="/b")
    monkeypatch.setattr(provider, "_ssl_context", ssl.create_default_context)
    monkeypatch.setattr(urllib.request, "build_opener", lambda *args: Opener())
    with pytest.raises(SignerError, match="signer_request_failed"):
        provider.health()
    assert _NoRedirects().redirect_request(None, None, 302, "redirect", {}, "https://attacker.test/") is None


def test_certificate_pair_is_loaded_from_one_atomic_generation(monkeypatch, tmp_path):
    old, new = tmp_path / "generation-1", tmp_path / "generation-2"
    for directory, label in ((old, "old"), (new, "new")):
        directory.mkdir(mode=0o700)
        for name in ("cert.pem", "key.pem"):
            (directory / name).write_text(label + "-" + name)
            (directory / name).chmod(0o600)
    current = tmp_path / "current"
    current.symlink_to(old, target_is_directory=True)
    loaded = []

    class Context:
        def load_cert_chain(self, certfile, keyfile, password):
            loaded.append((Path(certfile).read_text(), Path(keyfile).read_text()))

    original = signers._trusted_file

    @contextmanager
    def switching_file(path, *, private):
        with original(path, private=private) as descriptor:
            if not private:
                current.unlink()
                current.symlink_to(new, target_is_directory=True)
            yield descriptor

    provider = OpenBaoSigner(
        "https://bao.example.test",
        role="pap",
        client_cert=current / "cert.pem",
        client_key=current / "key.pem",
    )
    monkeypatch.setattr(signers, "_trusted_file", switching_file)
    monkeypatch.setattr(ssl, "create_default_context", Context)
    provider._ssl_context()
    assert loaded == [("old-cert.pem", "old-key.pem")]
    provider._ssl_context()
    assert loaded[-1] == ("new-cert.pem", "new-key.pem")


def test_certificate_directory_permissions_are_enforced(monkeypatch, tmp_path):
    tmp_path.chmod(0o777)
    provider = OpenBaoSigner(
        "https://bao.example.test",
        role="pap",
        client_cert=tmp_path / "cert.pem",
        client_key=tmp_path / "key.pem",
    )
    with pytest.raises(SignerError, match="signer_credential_directory_invalid"):
        provider._ssl_context()


def test_pki_issuance_uses_fixed_validated_operator_configuration():
    transit = Transit()
    calls = []

    def transport(method, path, payload, headers):
        if path.startswith("/v1/pki/issue/"):
            calls.append((method, path, payload))
            return 200, {"data": {"certificate": "test-only"}}
        return transit(method, path, payload, headers)

    assert signer(transport).issue_client_certificate("pap-client", "issuer.internal", ttl_seconds=300) == {
        "certificate": "test-only"
    }
    assert calls == [("POST", "/v1/pki/issue/pap-client", {"common_name": "issuer.internal", "ttl": "300s"})]
    for role, name, ttl in (("../other", "a", 300), ("pap", "a\r\n", 300), ("pap", "a", 7200)):
        with pytest.raises(SignerError, match="signer_certificate_request_invalid"):
            signer(transport).issue_client_certificate(role, name, ttl_seconds=ttl)


def run_openbao_acceptance():
    """Explicit Docker acceptance: ``PYTHONPATH=. python tests/test_signers.py --openbao``.

    Uses an initialized, unsealed TLS server, never OpenBao development mode.
    Synthetic bootstrap credentials remain in memory or a temporary directory;
    all container storage is destroyed afterward. This is not cloud acceptance.
    """
    import datetime
    import ipaddress
    import json
    import subprocess
    import tempfile
    import time

    from cryptography import x509
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    image = (
        "ghcr.io/openbao/openbao:2.5.3@sha256:"
        "fdc6da21ca6963560c32336fd7feb9cf2d5e52668f1a1647205a4b41171f0806"
    )
    container_name = "pap-bao-acceptance-" + uuid.uuid4().hex[:12]
    checks = []

    def docker(*args):
        completed = subprocess.run(["docker", *args], capture_output=True, timeout=120)
        if completed.returncode:
            raise RuntimeError("Docker acceptance setup failed; no credentials were logged")
        return completed.stdout.decode().strip()

    with tempfile.TemporaryDirectory(prefix="pap-openbao-") as temporary:
        directory = Path(temporary)
        directory.chmod(0o700)
        now = datetime.datetime.now(datetime.UTC)
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PAP acceptance CA")])
        ca = (
            x509.CertificateBuilder()
            .subject_name(ca_name)
            .issuer_name(ca_name)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
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
            .sign(ca_key, hashes.SHA256())
        )
        ca_pem = ca.public_bytes(serialization.Encoding.PEM).decode()
        (directory / "ca.pem").write_text(ca_pem)
        (directory / "ca.pem").chmod(0o600)

        def certificate(label, client):
            key = ec.generate_private_key(ec.SECP256R1())
            builder = (
                x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, label)]))
                .issuer_name(ca.subject)
                .public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - datetime.timedelta(minutes=1))
                .not_valid_after(now + datetime.timedelta(hours=1))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(
                    x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
                )
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
                .add_extension(
                    x509.ExtendedKeyUsage(
                        [ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]
                    ),
                    critical=False,
                )
            )
            if not client:
                builder = builder.add_extension(
                    x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                    critical=False,
                )
            result = builder.sign(ca_key, hashes.SHA256())
            (directory / (label + ".pem")).write_bytes(result.public_bytes(serialization.Encoding.PEM))
            (directory / (label + ".key")).write_bytes(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
            (directory / (label + ".pem")).chmod(0o600)
            (directory / (label + ".key")).chmod(0o600)

        certificate("server", False)
        certificate("pap-issuer", True)
        (directory / "server.hcl").write_text("""
disable_mlock = true
ui = false
storage "file" { path = "/bao/data" }
listener "tcp" {
  address = "0.0.0.0:8200"
  tls_cert_file = "/fixtures/server.pem"
  tls_key_file = "/fixtures/server.key"
  tls_client_ca_file = "/fixtures/ca.pem"
  tls_disable_client_certs = false
  tls_min_version = "tls12"
}
api_addr = "https://127.0.0.1:8200"
""")
        try:
            docker(
                "run",
                "--detach",
                "--name",
                container_name,
                "--user",
                "0:0",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--memory-swappiness=0",
                "--tmpfs",
                "/bao/data:rw,noexec,nosuid,size=32m",
                "--mount",
                f"type=bind,src={directory},dst=/fixtures,readonly",
                "--publish",
                "127.0.0.1::8200",
                "--entrypoint",
                "bao",
                image,
                "server",
                "-config=/fixtures/server.hcl",
            )
            address = docker("port", container_name, "8200/tcp")
            base = "https://" + address
            context = ssl.create_default_context(cafile=str(directory / "ca.pem"))
            context.load_cert_chain(str(directory / "pap-issuer.pem"), str(directory / "pap-issuer.key"))
            opener = urllib.request.build_opener(
                urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context), _NoRedirects()
            )

            def request(method, path, payload=None, token=None, allow_error=False):
                headers = {"Content-Type": "application/json"}
                if token:
                    headers["X-Vault-Token"] = token
                req = urllib.request.Request(
                    base + "/v1/" + path,
                    method=method,
                    headers=headers,
                    data=json.dumps(payload).encode() if payload is not None else None,
                )
                try:
                    response = opener.open(req, timeout=5)
                except urllib.error.HTTPError as error:
                    if not allow_error:
                        error.close()
                        raise RuntimeError("OpenBao acceptance operation failed: " + path) from None
                    response = error
                with response:
                    data = response.read(MAX_RESPONSE)
                    return json.loads(data) if data else {}

            deadline = time.monotonic() + 20
            while True:
                try:
                    status = request("GET", "sys/health", allow_error=True)
                    if "initialized" in status:
                        break
                except (OSError, urllib.error.URLError):
                    pass
                if time.monotonic() >= deadline:
                    # Initialization has not happened, so startup diagnostics
                    # cannot contain the synthetic root/unseal credentials.
                    details = subprocess.run(
                        ["docker", "logs", container_name], capture_output=True, timeout=5
                    )
                    raise RuntimeError("OpenBao TLS readiness timed out: " + details.stderr.decode()[-3000:])
                time.sleep(0.1)
            initialized = request("PUT", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
            root_token = initialized["root_token"]
            request("PUT", "sys/unseal", {"key": initialized["keys_base64"][0]})
            initialized.clear()
            checks.append("initialized-unsealed-non-dev-tls-server")
            request("POST", "sys/mounts/transit", {"type": "transit"}, root_token)
            request("POST", "sys/mounts/pki", {"type": "pki"}, root_token)
            ca_private = ca_key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            ).decode()
            request("POST", "pki/config/ca", {"pem_bundle": ca_pem + ca_private}, root_token)
            request(
                "POST",
                "pki/roles/pap-client",
                {
                    "allowed_domains": ["pap-issuer"],
                    "allow_bare_domains": True,
                    "allow_subdomains": False,
                    "allow_any_name": False,
                    "server_flag": False,
                    "client_flag": True,
                    "key_type": "ec",
                    "key_bits": 256,
                    "max_ttl": "1h",
                    "ttl": "1h",
                },
                root_token,
            )
            request("POST", "sys/auth/cert", {"type": "cert"}, root_token)
            policy = """
path "transit/keys/pap-*" { capabilities = ["create", "update", "read"] }
path "transit/sign/pap-*" { capabilities = ["update"] }
path "pki/issue/pap-client" { capabilities = ["update"] }
"""
            request("PUT", "sys/policies/acl/pap-signer", {"policy": policy}, root_token)
            request(
                "POST",
                "auth/cert/certs/pap-issuer",
                {
                    "certificate": ca_pem,
                    "allowed_common_names": "pap-issuer",
                    "token_policies": ["pap-signer"],
                    "token_ttl": 10,
                    "token_max_ttl": 10,
                    "token_no_default_policy": True,
                },
                root_token,
            )
            credentials = directory / "credentials"
            credentials.mkdir(mode=0o700)
            generation = credentials / ("generation-" + uuid.uuid4().hex)
            generation.mkdir(mode=0o700)
            for source, destination in (
                ("pap-issuer.pem", "client-cert.pem"),
                ("pap-issuer.key", "client-key.pem"),
            ):
                (generation / destination).write_bytes((directory / source).read_bytes())
                (generation / destination).chmod(0o600)
            (credentials / "current").symlink_to(generation.name, target_is_directory=True)
            provider = OpenBaoSigner(
                base,
                role="pap-issuer",
                ca_file=directory / "ca.pem",
                client_cert=credentials / "current" / "client-cert.pem",
                client_key=credentials / "current" / "client-key.pem",
            )
            prepared = provider.prepare(GENERATION)
            signature = provider.sign(prepared.reference, b"eyJhbGciOiJFUzI1NiJ9.e30")
            assert len(signature) == 64
            checks.append("certificate-authenticated-nonexportable-p256-signing")
            with pytest.raises(SignerError):
                provider._request("GET", "/v1/transit/export/signing-key/" + NAME)
            checks.append("private-key-export-denied")
            assert len(provider.sign(REFERENCE, b"a.b")) == 64
            old_token = provider._token
            time.sleep(8.2)
            assert len(provider.sign(REFERENCE, b"a.b")) == 64
            assert provider._token != old_token
            checks.append("automatic-certificate-login-token-renewal")
            from pap.certificates import CertificateManager

            manager = CertificateManager(
                provider, credentials, directory / "ca.pem", "pap-client", "pap-issuer"
            )
            serial = manager.current_certificate().serial_number
            assert manager.maintain(force=True)["renewed"] is True
            assert manager.current_certificate().serial_number != serial
            assert len(provider.sign(REFERENCE, b"a.b")) == 64
            checks.append("automatic-mtls-certificate-renewal-and-new-connection")
            replacement = provider.prepare(str(uuid.uuid4()))
            assert replacement.public_jwk != prepared.public_jwk
            assert len(provider.sign(replacement.reference, b"a.b")) == 64
            checks.append("new-generation-key-rotation")
            restored = OpenBaoSigner(
                base,
                role="pap-issuer",
                ca_file=directory / "ca.pem",
                client_cert=credentials / "current" / "client-cert.pem",
                client_key=credentials / "current" / "client-key.pem",
            )
            assert len(restored.sign(replacement.reference, b"a.b")) == 64
            checks.append("restart-with-public-reference-only")
            provider.retire(REFERENCE)
            with pytest.raises(SignerError, match="signer_key_retired"):
                provider.sign(REFERENCE, b"a.b")
            checks.append("local-retirement-denies-signing")
            request("POST", "auth/token/revoke", {"token": provider._token}, root_token)
            request("DELETE", "auth/cert/certs/pap-issuer", token=root_token)
            with pytest.raises(SignerError):
                provider.sign(replacement.reference, b"a.b")
            with pytest.raises(SignerError):
                provider.sign(replacement.reference, b"a.b")
            checks.append("server-side-token-and-certificate-role-revocation")
            digest = docker("image", "inspect", image, "--format", "{{index .RepoDigests 0}}")
            print(
                json.dumps(
                    {"passed": len(checks), "checks": checks, "image": digest, "cloud_acceptance": False}
                )
            )
        finally:
            subprocess.run(["docker", "rm", "--force", container_name], capture_output=True, timeout=20)


if __name__ == "__main__":
    import sys

    if sys.argv[1:] != ["--openbao"]:
        raise SystemExit("Usage: python tests/test_signers.py --openbao")
    run_openbao_acceptance()
