"""Verify the operator expiry fixture fails real TLS for the intended reason."""

import importlib.util
import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@pytest.fixture
def fixture(tmp_path):
    filename = Path(__file__).resolve().parents[1] / "deploy/linux/exercise_expired_certificates.py"
    spec = importlib.util.spec_from_file_location("expiry_exercise_fixture", filename)
    exercise = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(exercise)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Expiry test CA")])
    now = datetime.now(UTC)
    ca = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, None, None), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
        .sign(key, hashes.SHA256())
    )
    ca_file = tmp_path / "ca.pem"
    ca_file.write_bytes(ca.public_bytes(serialization.Encoding.PEM))

    def context(server, expired):
        if expired:
            cert, private = exercise.expired_leaf(ca, key, server=server, config={})
        else:
            leaf = ec.generate_private_key(ec.SECP256R1())
            cert = (
                x509.CertificateBuilder()
                .subject_name(
                    x509.Name(
                        [x509.NameAttribute(NameOID.COMMON_NAME, "localhost" if server else "pap-issuer")]
                    )
                )
                .issuer_name(ca.subject)
                .public_key(leaf.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1))
                .not_valid_after(now + timedelta(hours=1))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
                .add_extension(
                    x509.KeyUsage(True, False, False, False, False, False, False, None, None), True
                )
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf.public_key()), False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
                .add_extension(
                    x509.ExtendedKeyUsage(
                        [ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]
                    ),
                    False,
                )
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), False)
                .sign(key, hashes.SHA256())
                .public_bytes(serialization.Encoding.PEM)
            )
            private = leaf.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        prefix = ("server" if server else "client") + ("-expired" if expired else "-valid")
        cert_path, key_path = tmp_path / (prefix + ".pem"), tmp_path / (prefix + ".key")
        cert_path.write_bytes(cert)
        key_path.write_bytes(private)
        key_path.chmod(0o600)
        ctx = (
            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            if server
            else ssl.create_default_context(cafile=str(ca_file))
        )
        ctx.load_cert_chain(str(cert_path), str(key_path))
        ctx.load_verify_locations(cafile=str(ca_file))
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    return exercise, ca, key, context


def test_expiry_leaves_have_matching_keys_and_only_the_intended_eku(fixture):
    exercise, ca, key, _ = fixture
    for server in (False, True):
        cert_bytes, key_bytes = exercise.expired_leaf(ca, key, server=server, config={})
        cert = x509.load_pem_x509_certificate(cert_bytes)
        leaf_key = serialization.load_pem_private_key(key_bytes, password=None)
        cert.verify_directly_issued_by(ca)
        assert cert.public_key().public_numbers() == leaf_key.public_key().public_numbers()
        assert cert.not_valid_after_utc < datetime.now(UTC) - timedelta(minutes=59)
        assert not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
        assert set(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == {
            ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH
        }
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        assert usage.digital_signature and not usage.key_cert_sign and not usage.crl_sign


@pytest.mark.parametrize("expired_server", [False, True])
def test_real_verified_tls_rejects_expired_client_and_listener(fixture, expired_server):
    _, _, _, context = fixture
    server_context = context(server=True, expired=expired_server)
    client_context = context(server=False, expired=not expired_server)
    server_socket, client_socket = socket.socketpair()
    server_socket.settimeout(3)
    client_socket.settimeout(3)
    server_errors = []

    def serve():
        try:
            with server_socket, server_context.wrap_socket(server_socket, server_side=True) as tls:
                tls.recv(1)
                tls.sendall(b"x")
        except ssl.SSLError as error:
            server_errors.append(error)

    thread = threading.Thread(target=serve)
    thread.start()
    client_error = None
    try:
        with client_socket, client_context.wrap_socket(client_socket, server_hostname="localhost") as tls:
            tls.sendall(b"x")
            tls.recv(1)
    except ssl.SSLError as error:
        client_error = error
    finally:
        thread.join(4)
    assert not thread.is_alive()
    verifier_error = client_error if expired_server else server_errors[0]
    assert isinstance(verifier_error, ssl.SSLCertVerificationError)
    assert verifier_error.verify_code == 10
