"""Certificate lifecycle validation and atomic activation failure recovery."""

import os
import stat
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from pap.certificates import CertificateManager
from pap.signers import SignerError


def ca_material(*, lifetime=timedelta(days=7)):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-only-client-ca")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + lifetime)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
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
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def leaf_material(
    authority,
    *,
    common_name="pap-issuer",
    lifetime=timedelta(hours=1),
    starts=timedelta(minutes=-1),
    eku=(ExtendedKeyUsageOID.CLIENT_AUTH,),
    curve=None,
    is_ca=False,
):
    issuer_key, issuer = authority
    key = ec.generate_private_key(curve or ec.SECP256R1())
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(issuer.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + starts)
        .not_valid_after(now + lifetime)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=bool(is_ca),
                crl_sign=bool(is_ca),
                encipher_only=None,
                decipher_only=None,
            ),
            critical=True,
        )
    )
    if is_ca is not None:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=is_ca, path_length=0 if is_ca else None), critical=True
        )
    if eku is not None:
        builder = builder.add_extension(x509.ExtendedKeyUsage(list(eku)), critical=False)
    cert = builder.sign(issuer_key, hashes.SHA256())
    return {
        "certificate": cert.public_bytes(serialization.Encoding.PEM).decode(),
        "private_key": key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ).decode(),
    }


class CertificateSigner:
    def __init__(self, response):
        self.response, self.calls = response, []

    def issue_client_certificate(self, role, common_name, *, ttl_seconds):
        self.calls.append((role, common_name, ttl_seconds))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def generation(directory, material, *, extra=False):
    folder = directory / ("generation-" + uuid.uuid4().hex)
    folder.mkdir(mode=0o700)
    for name, value in (
        ("client-cert.pem", material["certificate"]),
        ("client-key.pem", material["private_key"]),
    ):
        (folder / name).write_text(value)
        (folder / name).chmod(0o600)
    if extra:
        (folder / "operator-notes.txt").write_text("preserve unrelated contents")
    return folder


@pytest.fixture
def setup(tmp_path):
    authority = ca_material()
    directory = tmp_path / "credentials"
    directory.mkdir(mode=0o700)
    ca_file = tmp_path / "client-ca.pem"
    ca_file.write_bytes(authority[1].public_bytes(serialization.Encoding.PEM))
    ca_file.chmod(0o600)
    current = generation(directory, leaf_material(authority, lifetime=timedelta(minutes=2)))
    (directory / "current").symlink_to(current.name, target_is_directory=True)
    signer = CertificateSigner(leaf_material(authority))
    manager = CertificateManager(signer, directory, ca_file, "pap-client", "pap-issuer")
    return manager, signer, authority, directory, current


def test_due_certificate_renews_without_user_action_and_uses_private_generation(setup):
    manager, signer, _, directory, original = setup
    old_serial = manager.current_certificate().serial_number
    result = manager.maintain()
    activated = (directory / "current").resolve()
    assert result["renewed"] is True and activated != original
    assert manager.current_certificate().serial_number != old_serial
    assert signer.calls == [("pap-client", "pap-issuer", 3600)]
    assert stat.S_IMODE(activated.stat().st_mode) == 0o700
    assert {path.name for path in activated.iterdir()} == {"client-cert.pem", "client-key.pem"}
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in activated.iterdir())
    assert original.exists()


def test_healthy_certificate_does_not_request_unnecessary_replacements(setup):
    manager, signer, authority, directory, _ = setup
    healthy = generation(directory, leaf_material(authority))
    (directory / "current").unlink()
    (directory / "current").symlink_to(healthy.name, target_is_directory=True)
    assert manager.maintain()["renewed"] is False
    assert signer.calls == []


@pytest.mark.parametrize(
    "case",
    [
        "mismatched_key",
        "foreign_ca",
        "wrong_identity",
        "server_auth",
        "mixed_eku",
        "no_eku",
        "too_short",
        "too_long",
        "not_yet_valid",
        "expired",
        "wrong_curve",
        "malformed",
        "oversize",
    ],
)
def test_invalid_provider_material_never_replaces_working_generation(setup, case):
    manager, signer, authority, directory, original = setup
    response = leaf_material(authority)
    if case == "mismatched_key":
        response["private_key"] = leaf_material(authority)["private_key"]
    elif case == "foreign_ca":
        response = leaf_material(ca_material())
    elif case == "wrong_identity":
        response = leaf_material(authority, common_name="another-service")
    elif case == "server_auth":
        response = leaf_material(authority, eku=(ExtendedKeyUsageOID.SERVER_AUTH,))
    elif case == "mixed_eku":
        response = leaf_material(
            authority, eku=(ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH)
        )
    elif case == "no_eku":
        response = leaf_material(authority, eku=None)
    elif case == "too_short":
        response = leaf_material(authority, lifetime=timedelta(minutes=9))
    elif case == "too_long":
        response = leaf_material(authority, lifetime=timedelta(hours=2))
    elif case == "not_yet_valid":
        response = leaf_material(authority, starts=timedelta(minutes=1))
    elif case == "expired":
        response = leaf_material(authority, lifetime=timedelta(minutes=-5), starts=timedelta(hours=-1))
    elif case == "wrong_curve":
        response = leaf_material(authority, curve=ec.SECP384R1())
    elif case == "malformed":
        response = {"certificate": "invalid", "private_key": "invalid"}
    elif case == "oversize":
        response["private_key"] = "x" * 20000
    signer.response = response
    before = set(directory.iterdir())
    with pytest.raises(SignerError, match="client_certificate_renewal_failed"):
        manager.maintain()
    assert (directory / "current").resolve() == original
    assert set(directory.iterdir()) == before


def test_ca_certificate_is_never_accepted_as_a_client_leaf(setup):
    manager, signer, authority, directory, original = setup
    signer.response = leaf_material(authority, is_ca=True)
    with pytest.raises(SignerError, match="client_certificate_renewal_failed"):
        manager.maintain()
    assert (directory / "current").resolve() == original


def test_valid_non_ca_leaf_without_basic_constraints_is_accepted(setup):
    manager, signer, authority, directory, original = setup
    # OpenBao PKI issues ordinary client leaves without this optional extension.
    signer.response = leaf_material(authority, is_ca=None)
    assert manager.maintain()["renewed"] is True
    assert (directory / "current").resolve() != original


def test_certificate_cannot_outlive_configured_ca(setup):
    manager, signer, _, directory, original = setup
    shorter_ca = ca_material(lifetime=timedelta(minutes=30))
    manager.client_ca_file.write_bytes(shorter_ca[1].public_bytes(serialization.Encoding.PEM))
    signer.response = leaf_material(shorter_ca)
    with pytest.raises(SignerError, match="client_certificate_renewal_failed"):
        manager.maintain()
    assert (directory / "current").resolve() == original


def test_expired_current_certificate_requires_recovery_and_never_attempts_login(setup):
    manager, signer, authority, directory, _ = setup
    expired = generation(
        directory, leaf_material(authority, lifetime=timedelta(minutes=-1), starts=timedelta(hours=-1))
    )
    (directory / "current").unlink()
    (directory / "current").symlink_to(expired.name, target_is_directory=True)
    with pytest.raises(SignerError, match="client_certificate_expired"):
        manager.maintain(force=True)
    assert signer.calls == []


@pytest.mark.parametrize("existing", ["expired", "missing"])
def test_independent_enrollment_recovers_without_attempting_expired_kms_login(setup, existing):
    manager, signer, authority, directory, _ = setup
    (directory / "current").unlink()
    if existing == "expired":
        expired = generation(
            directory,
            leaf_material(authority, lifetime=timedelta(minutes=-1), starts=timedelta(hours=-1)),
        )
        (directory / "current").symlink_to(expired.name, target_is_directory=True)
    enroller = CertificateSigner(leaf_material(authority))
    manager.recovery_issuer = enroller
    signer.response = RuntimeError("KMS TLS and bearer login are deliberately unavailable")
    result = manager.maintain()
    assert result["recovered"] is True and result["renewed"] is True
    assert signer.calls == []
    assert enroller.calls == [("pap-client", "pap-issuer", 3600)]
    assert manager.current_certificate().not_valid_after_utc > datetime.now(UTC)
    assert manager.maintain()["renewed"] is False
    assert len(enroller.calls) == 1


def test_unavailable_independent_enrollment_preserves_expired_generation(setup):
    manager, signer, authority, directory, _ = setup
    expired = generation(
        directory, leaf_material(authority, lifetime=timedelta(minutes=-1), starts=timedelta(hours=-1))
    )
    (directory / "current").unlink()
    (directory / "current").symlink_to(expired.name, target_is_directory=True)
    manager.recovery_issuer = CertificateSigner(SignerError("enrollment_unavailable"))
    with pytest.raises(SignerError, match="enrollment_unavailable"):
        manager.maintain()
    assert (directory / "current").resolve() == expired
    assert signer.calls == []


def test_recovery_service_cannot_replace_a_credential_with_untrusted_material(setup):
    manager, signer, _, directory, original = setup
    manager.recovery_issuer = CertificateSigner(leaf_material(ca_material()))
    with pytest.raises(SignerError, match="client_certificate_renewal_failed"):
        manager.maintain(force=True)
    assert (directory / "current").resolve() == original
    assert signer.calls == []


@pytest.mark.parametrize("failure", ["write_key", "activate"])
def test_failed_write_or_activation_keeps_old_certificate_pair(setup, monkeypatch, failure):
    manager, _, _, directory, original = setup
    if failure == "write_key":
        original_open = os.open

        def fail_key(path, flags, *args, **kwargs):
            if str(path).endswith("client-key.pem") and flags & os.O_WRONLY:
                raise OSError("simulated disk-full")
            return original_open(path, flags, *args, **kwargs)

        monkeypatch.setattr(os, "open", fail_key)
    else:

        def fail_replace(*args, **kwargs):
            raise OSError("simulated failed pointer replacement")

        monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(SignerError, match="client_certificate_renewal_failed"):
        manager.maintain()
    assert (directory / "current").resolve() == original
    assert (
        manager.current_certificate().serial_number
        == x509.load_pem_x509_certificate((original / "client-cert.pem").read_bytes()).serial_number
    )


def test_provider_failure_is_scrubbed_and_preserves_generation(setup):
    manager, signer, _, directory, original = setup
    signer.response = RuntimeError("a-secret-bearing-provider-error")
    with pytest.raises(SignerError) as caught:
        manager.maintain()
    assert str(caught.value) == "client_certificate_renewal_failed"
    assert (directory / "current").resolve() == original


def test_writable_current_certificate_is_rejected(setup):
    manager, _, _, _, original = setup
    (original / "client-cert.pem").chmod(0o666)
    with pytest.raises(SignerError, match="signer_credential_file_invalid"):
        manager.maintain()


def test_cleanup_removes_only_expired_owned_generated_pairs(setup):
    manager, _, authority, directory, current = setup
    expired_material = leaf_material(authority, lifetime=timedelta(minutes=-10), starts=timedelta(hours=-1))
    expired = generation(directory, expired_material)
    unrelated = generation(directory, expired_material, extra=True)
    recent = generation(directory, leaf_material(authority))
    linked = directory / ("generation-" + uuid.uuid4().hex)
    linked.symlink_to(unrelated.name, target_is_directory=True)
    manager.cleanup()
    assert not expired.exists()
    assert current.exists() and unrelated.exists() and recent.exists() and linked.is_symlink()
    assert (unrelated / "operator-notes.txt").read_text() == "preserve unrelated contents"
