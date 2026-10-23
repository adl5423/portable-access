"""Automatic issuer mTLS certificate renewal, independent of application processes."""

import os
import re
import stat
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .signers import SignerError, _trusted_file
from .storage import private_directory


class CertificateManager:
    def __init__(
        self,
        signer,
        directory: Path,
        client_ca_file: Path,
        role: str,
        common_name: str,
        *,
        recovery_issuer=None,
    ):
        self.signer, self.directory = signer, directory
        self.client_ca_file, self.role, self.common_name = client_ca_file, role, common_name
        self.recovery_issuer = recovery_issuer
        if not directory.is_absolute() or not client_ca_file.is_absolute():
            raise ValueError("absolute certificate paths required")
        private_directory(directory)
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", role) or not re.fullmatch(
            r"[A-Za-z0-9_.-]{1,128}", common_name
        ):
            raise ValueError("invalid certificate identity")

    def current_certificate(self):
        with _trusted_file(self.directory / "current" / "client-cert.pem", private=False) as fd:
            return x509.load_pem_x509_certificate(os.read(fd, 65536))

    def maintain(self, *, force: bool = False):
        try:
            now = datetime.now(UTC)
            # Only the independently authenticated OS enrollment service may
            # recover a missing or expired credential. The KMS cannot bootstrap
            # its own mTLS connection using an expired client certificate.
            try:
                (self.directory / "current").lstat()
            except FileNotFoundError:
                if self.recovery_issuer is None:
                    raise SignerError("client_certificate_missing") from None
                current = None
            else:
                current = self.current_certificate()
            expired = current is None or current.not_valid_after_utc <= now
            if expired and self.recovery_issuer is None:
                raise SignerError("client_certificate_expired")
            if current is not None and not force and current.not_valid_after_utc - now > timedelta(minutes=5):
                return {"renewed": False, "expires_at": current.not_valid_after_utc.timestamp()}
            provider = self.recovery_issuer or self.signer
            data = provider.issue_client_certificate(self.role, self.common_name, ttl_seconds=3600)
            cert_pem, key_pem = data.get("certificate"), data.get("private_key")
            if (
                not isinstance(cert_pem, str)
                or not isinstance(key_pem, str)
                or max(len(cert_pem), len(key_pem)) > 16384
            ):
                raise ValueError("invalid issued certificate material")
            cert = x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
            key = serialization.load_pem_private_key(key_pem.encode("ascii"), password=None)
            if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
                raise ValueError("invalid client key")
            if cert.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            ) != key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
            ):
                raise ValueError("client certificate key mismatch")
            if [a.value for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)] != [
                self.common_name
            ]:
                raise ValueError("certificate identity mismatch")
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            if set(eku) != {ExtendedKeyUsageOID.CLIENT_AUTH}:
                raise ValueError("client-only EKU required")
            try:
                is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            except x509.ExtensionNotFound:
                # RFC 5280: absence of basicConstraints also identifies a non-CA leaf.
                is_ca = False
            usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
            if is_ca or not usage.digital_signature or usage.key_cert_sign or usage.crl_sign:
                raise ValueError("client leaf must not have certificate authority permissions")
            if cert.not_valid_before_utc > now + timedelta(seconds=5) or not now + timedelta(
                minutes=10
            ) < cert.not_valid_after_utc <= now + timedelta(seconds=3610):
                raise ValueError("invalid certificate lifetime")
            with _trusted_file(self.client_ca_file, private=False) as fd:
                issuer = x509.load_pem_x509_certificate(os.read(fd, 65536))
            if (
                not issuer.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                or not issuer.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign
            ):
                raise ValueError("pinned issuer must be a certificate authority")
            if issuer.not_valid_before_utc > now or issuer.not_valid_after_utc <= cert.not_valid_after_utc:
                raise ValueError("client CA expires before issued leaf")
            cert.verify_directly_issued_by(issuer)
            directory = self.directory / ("generation-" + uuid.uuid4().hex)
            directory.mkdir(mode=0o700)
            try:
                for filename, value in (("client-cert.pem", cert_pem), ("client-key.pem", key_pem)):
                    fd = os.open(
                        directory / filename, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600
                    )
                    with os.fdopen(fd, "wb") as output:
                        output.write(value.encode("ascii"))
                        output.flush()
                        os.fsync(output.fileno())
                self._fsync(directory)
                # One pointer switches the pair. Signer snapshots this directory once per TLS context.
                pointer = self.directory / ("next-" + uuid.uuid4().hex)
                os.symlink(directory.name, pointer)
                os.replace(pointer, self.directory / "current")
                self._fsync(self.directory)
            except BaseException:
                # Do not switch to incomplete material. A leftover immutable generation is safe.
                raise
            self.cleanup()
            return {
                "renewed": True,
                "recovered": expired,
                "expires_at": cert.not_valid_after_utc.timestamp(),
            }
        except SignerError:
            raise
        except Exception:
            raise SignerError("client_certificate_renewal_failed") from None

    @staticmethod
    def _fsync(directory):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def cleanup(self):
        current = (self.directory / "current").resolve(strict=True)
        now = datetime.now(UTC)
        for directory in self.directory.iterdir():
            if (
                not re.fullmatch(r"generation-[0-9a-f]{32}", directory.name)
                or directory.is_symlink()
                or directory == current
            ):
                continue
            info = directory.stat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
                continue
            try:
                cert = x509.load_pem_x509_certificate((directory / "client-cert.pem").read_bytes())
                if cert.not_valid_after_utc > now - timedelta(minutes=5):
                    continue
                # Only the two generated files, never an operator's arbitrary directory contents.
                if {p.name for p in directory.iterdir()} == {"client-cert.pem", "client-key.pem"}:
                    (directory / "client-key.pem").unlink()
                    (directory / "client-cert.pem").unlink()
                    directory.rmdir()
            except (OSError, ValueError):
                continue
