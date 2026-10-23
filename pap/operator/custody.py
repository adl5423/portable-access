"""RSA custody backends. Private key material never leaves Keychain custody."""

from __future__ import annotations

import ctypes
import getpass
import hashlib
import os
import stat
import sys
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

MAX_PRIVATE_BYTES = 64 * 1024


class CustodyError(ValueError):
    """A safe, operator-facing failure message without secret data."""


class _KeychainNotFound(CustodyError):
    pass


class Custody(Protocol):
    def public_der(self) -> bytes: ...
    def decrypt(self, ciphertext: bytes) -> bytes: ...


def public_key(der: bytes) -> rsa.RSAPublicKey:
    try:
        key = serialization.load_der_public_key(der)
    except (ValueError, TypeError) as exc:
        raise CustodyError("Invalid RSA public key DER") from exc
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size != 4096:
        raise CustodyError("Operator custody requires an RSA-4096 public key")
    if key.public_numbers().e != 65537:
        raise CustodyError("Operator custody requires RSA exponent 65537")
    return key


def public_der(key: rsa.RSAPublicKey) -> bytes:
    # Security.framework exports RSA as PKCS#1. Accept SPKI on import too, but
    # make newly generated custody pins independent of the backend.
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.PKCS1)


def public_pin(der: bytes) -> str:
    public_key(der)
    return hashlib.sha256(der).hexdigest()


def public_jwk(der: bytes) -> dict[str, str]:
    import base64

    numbers = public_key(der).public_numbers()

    def encode(n):
        return (
            base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big"))
            .rstrip(b"=")
            .decode("ascii")
        )

    return {"kty": "RSA", "n": encode(numbers.n), "e": encode(numbers.e)}


def _trusted_parent(path: Path) -> None:
    parent = path.absolute().parent
    for candidate in (parent, *parent.parents):
        info = candidate.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid()):
            raise CustodyError("Private path has an untrusted directory")
        if info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
            raise CustodyError("Private path has a writable parent directory")


def private_read(path: Path, maximum: int = MAX_PRIVATE_BYTES) -> bytes:
    """Read a regular owner-only file without following a symlink."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        _trusted_parent(path)
        fd = os.open(path, flags)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise CustodyError("Private input must be an owner-only regular file")
            if info.st_size > maximum:
                raise CustodyError("Private input exceeds its size limit")
            chunks = []
            remaining = maximum + 1
            while remaining:
                chunk = os.read(fd, min(remaining, 65536))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            value = b"".join(chunks)
            if len(value) > maximum:
                raise CustodyError("Private input exceeds its size limit")
            return value
        finally:
            os.close(fd)
    except OSError as exc:
        raise CustodyError("Cannot read private input safely") from exc


def trusted_public_path(path: Path) -> None:
    _trusted_parent(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
        raise CustodyError("Public input must be a trusted regular file with no shared write access")


def public_read(path: Path, maximum: int = MAX_PRIVATE_BYTES) -> bytes:
    trusted_public_path(path)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid not in (0, os.getuid())
                or info.st_mode & 0o022
                or not 0 < info.st_size <= maximum
            ):
                raise CustodyError("Public input is unsafe or exceeds its size limit")
            value = os.read(fd, maximum + 1)
            if len(value) > maximum:
                raise CustodyError("Public input exceeds its size limit")
            return value
        finally:
            os.close(fd)
    except OSError as exc:
        raise CustodyError("Cannot read public input safely") from exc


def write_new_private(path: Path, data: bytes) -> None:
    """Exclusive, durable creation. Existing backups are never replaced."""
    parent = path.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _trusted_parent(path)
    info = parent.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise CustodyError("Destination directory must be owner-only")
    directory = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    try:
        fd = os.open(
            path.name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory,
        )
    except FileExistsError as exc:
        os.close(directory)
        raise CustodyError("Destination already exists; preserve the previous backup") from exc
    except BaseException:
        os.close(directory)
        raise
    try:
        with os.fdopen(fd, "wb") as target:
            target.write(data)
            target.flush()
            os.fsync(target.fileno())
        os.fsync(directory)
    except BaseException:
        # Keep an incomplete file as evidence. Never overwrite an uncertain
        # one-shot key creation or backup automatically.
        raise
    finally:
        os.close(directory)


def read_passphrase(fd: int | None = None, *, confirm: bool = False) -> bytes:
    if fd is None:
        if not sys.stdin.isatty():
            raise CustodyError("Use an interactive terminal or --passphrase-fd")
        first = getpass.getpass("Operator key passphrase: ").encode()
        if confirm and first != getpass.getpass("Repeat passphrase: ").encode():
            raise CustodyError("Passphrases do not match")
    else:
        if fd < 3:
            raise CustodyError("Passphrase FD must be a separate inherited descriptor, at least 3")
        first = os.read(fd, 4097)
        if len(first) > 4096:
            raise CustodyError("Passphrase exceeds its size limit")
        first = first.rstrip(b"\r\n")
    if not first or confirm and len(first) < 16:
        raise CustodyError("New custody passphrases require at least 16 bytes")
    return first


class EncryptedPEMCustody:
    def __init__(self, path: Path, passphrase: bytes):
        try:
            key = serialization.load_pem_private_key(private_read(path), password=passphrase)
        except (ValueError, TypeError) as exc:
            raise CustodyError("Cannot unlock encrypted operator key") from exc
        if not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 4096:
            raise CustodyError("Operator custody requires an RSA-4096 private key")
        self._key = key

    @classmethod
    def create(cls, path: Path, passphrase: bytes) -> EncryptedPEMCustody:
        if len(passphrase) < 16:
            raise CustodyError("New custody passphrases require at least 16 bytes")
        key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        encrypted = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(passphrase),
        )
        write_new_private(path, encrypted)
        return cls(path, passphrase)

    def public_der(self) -> bytes:
        return public_der(self._key.public_key())

    def decrypt(self, ciphertext: bytes) -> bytes:
        try:
            return self._key.decrypt(
                ciphertext,
                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
            )
        except ValueError as exc:
            raise CustodyError("Custody envelope authentication failed") from exc


class _Security:
    def __init__(self) -> None:
        if sys.platform != "darwin":
            raise CustodyError("The Keychain backend is available on macOS only")
        self.cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        self.sec = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
        P = ctypes.c_void_p
        self.cf.CFStringCreateWithCString.argtypes = [P, ctypes.c_char_p, ctypes.c_uint32]
        self.cf.CFStringCreateWithCString.restype = P
        self.cf.CFDataCreate.argtypes = [P, P, ctypes.c_long]
        self.cf.CFDataCreate.restype = P
        self.cf.CFDataGetLength.argtypes = [P]
        self.cf.CFDataGetLength.restype = ctypes.c_long
        self.cf.CFDataGetBytePtr.argtypes = [P]
        self.cf.CFDataGetBytePtr.restype = P
        self.cf.CFNumberCreate.argtypes = [P, ctypes.c_int, P]
        self.cf.CFNumberCreate.restype = P
        self.cf.CFDictionaryCreate.argtypes = [P, P, P, ctypes.c_long, P, P]
        self.cf.CFDictionaryCreate.restype = P
        self.cf.CFRelease.argtypes = [P]
        self.sec.SecItemCopyMatching.argtypes = [P, ctypes.POINTER(P)]
        self.sec.SecItemCopyMatching.restype = ctypes.c_int32
        self.sec.SecKeyCreateRandomKey.argtypes = [P, ctypes.POINTER(P)]
        self.sec.SecKeyCreateRandomKey.restype = P
        self.sec.SecKeyCopyPublicKey.argtypes = [P]
        self.sec.SecKeyCopyPublicKey.restype = P
        self.sec.SecKeyCopyExternalRepresentation.argtypes = [P, ctypes.POINTER(P)]
        self.sec.SecKeyCopyExternalRepresentation.restype = P
        self.sec.SecKeyCreateDecryptedData.argtypes = [P, P, P, ctypes.POINTER(P)]
        self.sec.SecKeyCreateDecryptedData.restype = P

    def constant(self, name: str) -> int:
        library = self.cf if name.startswith("kCF") else self.sec
        return ctypes.c_void_p.in_dll(library, name).value  # type: ignore[return-value]

    def string(self, value: str) -> int:
        return self.cf.CFStringCreateWithCString(None, value.encode(), 0x08000100)

    def data(self, value: bytes) -> int:
        buf = ctypes.create_string_buffer(value)
        return self.cf.CFDataCreate(None, buf, len(value))

    def bytes(self, value: int) -> bytes:
        return ctypes.string_at(self.cf.CFDataGetBytePtr(value), self.cf.CFDataGetLength(value))

    def dictionary(self, pairs: list[tuple[int, int]]) -> int:
        keys = (ctypes.c_void_p * len(pairs))(*(a for a, _ in pairs))
        values = (ctypes.c_void_p * len(pairs))(*(b for _, b in pairs))
        # Retain callbacks keep nested attributes alive throughout key creation.
        keys_callbacks = ctypes.addressof(ctypes.c_char.in_dll(self.cf, "kCFTypeDictionaryKeyCallBacks"))
        values_callbacks = ctypes.addressof(ctypes.c_char.in_dll(self.cf, "kCFTypeDictionaryValueCallBacks"))
        return self.cf.CFDictionaryCreate(None, keys, values, len(pairs), keys_callbacks, values_callbacks)

    def release(self, *values: int | None) -> None:
        for value in values:
            if value:
                self.cf.CFRelease(value)


class MacOSKeychainCustody:
    """Persistent RSA software key managed by Security.framework.

    This is OS Keychain custody, not a Secure Enclave or hardware KMS claim.
    The public operator API provides no private-key export method.
    """

    def __init__(self, application_tag: str):
        if not application_tag or len(application_tag.encode()) > 240 or "\x00" in application_tag:
            raise CustodyError("Invalid Keychain application tag")
        self._api = _Security()
        self.application_tag = application_tag
        self._key = self._lookup()

    def _lookup(self) -> int:
        a = self._api
        tag = a.data(self.application_tag.encode())
        query = a.dictionary(
            [
                (a.constant("kSecClass"), a.constant("kSecClassKey")),
                (a.constant("kSecAttrApplicationTag"), tag),
                (a.constant("kSecAttrKeyType"), a.constant("kSecAttrKeyTypeRSA")),
                (a.constant("kSecAttrKeyClass"), a.constant("kSecAttrKeyClassPrivate")),
                (a.constant("kSecReturnRef"), a.constant("kCFBooleanTrue")),
            ]
        )
        result = ctypes.c_void_p()
        try:
            status = a.sec.SecItemCopyMatching(query, ctypes.byref(result))
            if status == -25300:
                raise _KeychainNotFound("Keychain key is not present")
            if status != 0 or not result.value:
                raise CustodyError("Keychain key is unavailable; unlock the operator login keychain")
            return result.value
        finally:
            a.release(query, tag)

    @classmethod
    def create(
        cls, application_tag: str, label: str = "Portable Access operator recovery"
    ) -> MacOSKeychainCustody:
        if not application_tag or len(application_tag.encode()) > 240 or "\x00" in application_tag:
            raise CustodyError("Invalid Keychain application tag")
        a = _Security()
        tag = a.data(application_tag.encode())
        name = a.string(label)
        number = ctypes.c_int(4096)
        size = a.cf.CFNumberCreate(None, 9, ctypes.byref(number))
        private = a.dictionary(
            [
                (a.constant("kSecAttrIsPermanent"), a.constant("kCFBooleanTrue")),
                (a.constant("kSecAttrApplicationTag"), tag),
                (a.constant("kSecAttrLabel"), name),
                (a.constant("kSecAttrIsExtractable"), a.constant("kCFBooleanFalse")),
            ]
        )
        attrs = a.dictionary(
            [
                (a.constant("kSecAttrKeyType"), a.constant("kSecAttrKeyTypeRSA")),
                (a.constant("kSecAttrKeySizeInBits"), size),
                (a.constant("kSecPrivateKeyAttrs"), private),
            ]
        )
        error = ctypes.c_void_p()
        key = None
        try:
            # Duplicate application tags must fail instead of silently creating
            # two custody identities. Keychain returns errSecDuplicateItem.
            try:
                existing = cls(application_tag)
            except _KeychainNotFound:
                existing = None
            if existing is not None:
                raise CustodyError("Keychain application tag already exists")
            key = a.sec.SecKeyCreateRandomKey(attrs, ctypes.byref(error))
            if not key:
                raise CustodyError("Keychain key creation failed")
        finally:
            a.release(key, error.value, attrs, private, size, name, tag)
        return cls(application_tag)

    def public_der(self) -> bytes:
        a = self._api
        public = a.sec.SecKeyCopyPublicKey(self._key)
        error = ctypes.c_void_p()
        external = None
        try:
            external = a.sec.SecKeyCopyExternalRepresentation(public, ctypes.byref(error))
            if not external:
                raise CustodyError("Cannot export Keychain public key")
            value = a.bytes(external)
            public_key(value)
            return value
        finally:
            a.release(external, error.value, public)

    def decrypt(self, ciphertext: bytes) -> bytes:
        a = self._api
        data = a.data(ciphertext)
        error = ctypes.c_void_p()
        result = None
        try:
            result = a.sec.SecKeyCreateDecryptedData(
                self._key, a.constant("kSecKeyAlgorithmRSAEncryptionOAEPSHA256"), data, ctypes.byref(error)
            )
            if not result:
                raise CustodyError("Custody envelope authentication failed")
            return a.bytes(result)
        finally:
            a.release(result, error.value, data)

    def __del__(self) -> None:
        key = getattr(self, "_key", None)
        if key:
            self._api.release(key)
            self._key = None
