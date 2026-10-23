#!/usr/bin/env python3
"""Migrate one existing PAP OpenBao 2.7.1 Raft node from Shamir to static seal.

The CLI provides read-only planning. Applying requires the Python in-memory
``StaticSealMigrator.apply`` method and three predecessor Shamir shares. There is
no CLI, environment, file, or logging channel for those shares or the static key.

Before planning, the operator supplies a consistent protected Raft snapshot and a
separate successor recovery envelope, durably copied off-host and decrypted there
to verify the static key and predecessor recovery contents. Their root-owned
receipts are pinned, explicit custody attestations, not proof of a remote disk.

The caller installs the boot client, unit credentials, public boot configuration,
and independently recovered runtime key before apply. This helper changes only
the pinned OpenBao HCL, invokes exactly two OpenBao service restarts, and submits
three migrate=true unseal requests over verified loopback mTLS. Every mutation is
preceded by a durable uncertainty journal. An existing attempt always prevents an
automatic rerun. Neither initialization, recovery reset, Raft deletion, share
retries, nor automatic rollback is implemented.

Primary references, checked against OpenBao v2.7.1 source:
https://openbao.org/docs/configuration/seal/static/
https://openbao.org/docs/concepts/seal/#seal-migration
https://openbao.org/docs/api/system/unseal/
https://github.com/openbao/openbao/blob/v2.7.1/internal/vault/logical_system.go
"""

from __future__ import annotations

import argparse
import base64
import ctypes
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import time
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

if __package__:
    from . import bootstrap_openbao as b
else:
    import bootstrap_openbao as b

SCHEMA = "pap-static-seal-migration-v1"
KEY_FILE = "/run/credentials/pap-openbao.service/seal-current"
MAX_ARTIFACT = 1024 * 1024 * 1024
HEX = re.compile(r"[0-9a-f]{64}\Z")
VERSION = "2.7.1"


class MigrationError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def require(condition, code):
    if not condition:
        raise MigrationError(code)


def _instant(value):
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        require(result.tzinfo is not None, "migration_timestamp_timezone_required")
        return result.astimezone(UTC)
    except (ValueError, TypeError, AttributeError):
        raise MigrationError("migration_timestamp_invalid") from None


def _safe_json(path, *, owner, private=False, parents=None):
    try:
        return b._json(b._read(path, owner=owner, private=private, parent_owners=parents))
    except b.BootstrapError as error:
        raise MigrationError(error.code) from None


def _hash_file(path, *, owner, private, parent_owners=None, maximum=MAX_ARTIFACT):
    b._protected_parent(path, parent_owners or {0, owner})
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        require(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == owner
            and 0 < before.st_size <= maximum
            and not stat.S_IMODE(before.st_mode) & (0o077 if private else 0o022),
            "migration_artifact_untrusted",
        )
        digest = hashlib.sha256()
        count = 0
        while chunk := os.read(descriptor, min(1024 * 1024, maximum + 1 - count)):
            count += len(chunk)
            require(count <= maximum, "migration_artifact_too_large")
            digest.update(chunk)
        after = os.fstat(descriptor)
        require(
            count == before.st_size
            and before.st_size == after.st_size
            and before.st_mtime_ns == after.st_mtime_ns
            and before.st_ctime_ns == after.st_ctime_ns,
            "migration_artifact_changed",
        )
        return digest.hexdigest()
    finally:
        os.close(descriptor)


def static_configuration(previous: bytes, key_id: str) -> bytes:
    require(isinstance(previous, bytes) and 0 < len(previous) < b.MAX_FILE, "migration_hcl_invalid")
    require(isinstance(key_id, str) and HEX.fullmatch(key_id), "migration_key_id_invalid")
    try:
        previous.decode("utf-8")
    except UnicodeError:
        raise MigrationError("migration_hcl_invalid") from None
    require(not re.search(rb'(?m)^\s*seal\s+"', previous), "migration_existing_seal_block_forbidden")
    return previous.rstrip() + (
        f'\n\nseal "static" {{\n  current_key_id = "{key_id}"\n  current_key = "file://{KEY_FILE}"\n}}\n'
    ).encode("ascii")


def _validated_shares(shares):
    require(type(shares) is list and len(shares) == 3, "migration_exactly_three_shares_required")
    require(
        all(isinstance(share, str) and 40 <= len(share) <= 128 for share in shares) and len(set(shares)) == 3,
        "migration_shares_invalid",
    )
    try:
        for share in shares:
            decoded = base64.b64decode(share, validate=True)
            require(
                len(decoded) == 33 and base64.b64encode(decoded).decode("ascii") == share,
                "migration_shares_invalid",
            )
    except (ValueError, UnicodeError):
        raise MigrationError("migration_shares_invalid") from None


@dataclass(frozen=True)
class MigrationPaths:
    config: Path = Path("/etc/pap/openbao.hcl")
    public_config: Path = Path("/etc/pap/boot.json")
    runtime_key: Path = Path("/run/pap-boot/private/current.key")
    operator_public_key: Path = Path("/etc/pap/operator-public.der")
    old_recovery: Path = Path("/var/lib/pap-kms/operator-recovery.enc.json")
    successor_recovery: Path = Path("/etc/pap/enrollment/static-seal-successor.enc.json")
    successor_receipt: Path = Path("/etc/pap/enrollment/static-seal-successor-custody.json")
    backup_artifact: Path = Path("/etc/pap/enrollment/pre-static-seal-backup.snap")
    backup_receipt: Path = Path("/etc/pap/enrollment/pre-static-seal-backup.json")
    journal: Path = Path("/etc/pap/enrollment/static-seal-migration-attempt.json")
    receipt: Path = Path("/etc/pap/enrollment/static-seal-migration-receipt.json")
    lock: Path = Path("/run/pap-static-seal-migration.lock")
    openbao_binary: Path = Path("/usr/local/bin/bao")
    bootstrap: b.BootstrapPaths = b.DEFAULT_PATHS


@dataclass(frozen=True)
class MigrationPins:
    machine_id: str
    host_identity_sha256: str
    enrollment_ca_sha256: str
    operator_public_key_sha256: str
    public_config_sha256: str
    config_before_sha256: str
    old_recovery_sha256: str
    successor_recovery_sha256: str
    successor_receipt_sha256: str
    backup_artifact_sha256: str
    backup_receipt_sha256: str
    openbao_binary_sha256: str
    key_id: str
    deployment_id: str
    proof_origin: str
    seal_origin: str
    cluster_id: str


DEFAULT_PATHS = MigrationPaths()


def _harden():
    b._harden()
    require(ctypes.CDLL(None, use_errno=True).prctl(38, 1, 0, 0, 0) == 0, "migration_privilege_lock_failed")
    require(len(Path("/proc/swaps").read_text().splitlines()) == 1, "migration_no_swap_required")


def _restart():
    try:
        result = subprocess.run(
            ["/usr/bin/systemctl", "restart", "pap-openbao.service"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=45,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        require(result.returncode == 0, "migration_openbao_restart_failed")
    except (OSError, subprocess.TimeoutExpired):
        raise MigrationError("migration_openbao_restart_outcome_unknown") from None


def _pid():
    try:
        result = subprocess.run(
            ["/usr/bin/systemctl", "show", "pap-openbao.service", "--property=MainPID", "--value"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=5,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        require(
            result.returncode == 0 and re.fullmatch(rb"[0-9]+\s*", result.stdout),
            "migration_openbao_pid_unavailable",
        )
        value = int(result.stdout)
        require(value > 1, "migration_openbao_pid_invalid")
        return value
    except (OSError, subprocess.TimeoutExpired):
        raise MigrationError("migration_openbao_pid_unavailable") from None


def _runtime_tmpfs(path: Path):
    mountinfo = Path("/proc/self/mountinfo").read_text()
    require(len(mountinfo) <= b.MAX_FILE, "migration_mount_metadata_too_large")
    matches = []
    for line in mountinfo.splitlines():
        before, separator, after = line.partition(" - ")
        if not separator or len(before.split()) < 6 or len(after.split()) < 3:
            raise MigrationError("migration_mount_metadata_invalid")
        mount = Path(re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), before.split()[4]))
        if path == mount or mount in path.parents:
            matches.append((len(mount.parts), after.split()[0]))
    deepest = max((depth for depth, _ in matches), default=-1)
    visible = [filesystem for depth, filesystem in matches if depth == deepest]
    require(visible == ["tmpfs"], "migration_runtime_key_tmpfs_required")


def _credential_property(name: str):
    require(name in {"LoadCredential", "LoadCredentialEncrypted"}, "migration_credential_property_invalid")
    try:
        result = subprocess.run(
            [
                "/usr/bin/busctl",
                "--json=short",
                "get-property",
                "org.freedesktop.systemd1",
                "/org/freedesktop/systemd1/unit/pap_2dopenbao_2eservice",
                "org.freedesktop.systemd1.Service",
                name,
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=5,
            check=False,
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
        require(
            result.returncode == 0 and len(result.stdout) <= 8192, "migration_credential_wiring_unavailable"
        )
        value = b._json(result.stdout)
        require(
            set(value) == {"type", "data"}
            and value.get("type") == "a(ss)"
            and type(value.get("data")) is list
            and len(value["data"]) <= 64,
            "migration_credential_wiring_invalid",
        )
        for row in value["data"]:
            require(
                type(row) is list
                and len(row) == 2
                and all(type(item) is str and 0 < len(item) <= 4096 for item in row),
                "migration_credential_wiring_invalid",
            )
        return value["data"]
    except b.BootstrapError:
        raise MigrationError("migration_credential_wiring_invalid") from None
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        raise MigrationError("migration_credential_wiring_unavailable") from None


def _credential_wiring(path: Path):
    # systemctl 257 formats these structured properties as [unprintable].
    # Read only the two typed public metadata properties, never credential data.
    regular = _credential_property("LoadCredential")
    encrypted = _credential_property("LoadCredentialEncrypted")
    require(
        regular == [["seal-current", str(path)]] and encrypted == [],
        "migration_credential_wiring_invalid",
    )


class StaticSealMigrator:
    """Single-node one-shot migration; underscored injections are isolated-test seams."""

    def __init__(
        self,
        pins: MigrationPins,
        *,
        _paths: MigrationPaths = DEFAULT_PATHS,
        _owner_uid: int = 0,
        _owner_gid: int = 0,
        _kms_uid: int = 989,
        _transport_factory: Callable | None = None,
        _context_factory: Callable = b._tls_context,
        _stage_config: Callable | None = None,
        _restart_service: Callable = _restart,
        _process_id: Callable = _pid,
        _harden_process: Callable = _harden,
        _verify_runtime_storage: Callable = _runtime_tmpfs,
        _verify_credential_wiring: Callable = _credential_wiring,
        _clock: Callable = lambda: datetime.now(UTC),
        _sleep: Callable = time.sleep,
        _monotonic: Callable = time.monotonic,
    ):
        self.pins, self.paths, self.owner, self.kms = pins, _paths, _owner_uid, _kms_uid
        self.group = _owner_gid
        for name, value in asdict(pins).items():
            require(isinstance(value, str), "migration_pins_invalid")
            if name.endswith("sha256") or name == "key_id":
                require(HEX.fullmatch(value), "migration_pins_invalid")
        require(re.fullmatch(r"m_[a-z0-9]{10,64}", pins.machine_id), "migration_machine_id_invalid")
        require(re.fullmatch(r"[A-Za-z0-9_-]{1,128}", pins.deployment_id), "migration_deployment_invalid")
        require(
            re.fullmatch(r"https://[a-z0-9-]+\.netlify\.app", pins.seal_origin),
            "migration_custody_origin_invalid",
        )
        require(re.fullmatch(r"https://[a-z0-9.-]+", pins.proof_origin), "migration_proof_origin_invalid")
        require(re.fullmatch(r"[0-9a-f-]{36}", pins.cluster_id), "migration_cluster_id_invalid")
        self.stage_config = _stage_config or self._stage
        self.restart, self.process_id = _restart_service, _process_id
        self.clock, self.sleep, self.monotonic = _clock, _sleep, _monotonic
        self.verify_runtime_storage = _verify_runtime_storage
        self.verify_credential_wiring = _verify_credential_wiring
        self.bootstrap = b.Bootstrapper(
            _paths.operator_public_key,
            pins.operator_public_key_sha256,
            pins.machine_id,
            _paths=_paths.bootstrap,
            _owner_uid=_owner_uid,
            _kms_uid=_kms_uid,
            _transport_factory=_transport_factory,
            _context_factory=_context_factory,
            _harden_process=_harden_process,
            _clock=_clock,
        )
        self.journal_hash = None
        self.journal_states = []
        self.approved_plan = None

    def _read(self, path, *, private=False, kms_parent=False):
        return b._read(
            path,
            owner=self.owner,
            private=private,
            parent_owners={0, self.owner, self.kms} if kms_parent else {0, self.owner},
        )

    def _pinned(self, path, pin, *, private=False, kms_parent=False):
        value = self._read(path, private=private, kms_parent=kms_parent)
        require(b._sha(value) == pin, "migration_input_pin_mismatch")
        return value

    def _request(self, transport, method, path, payload=None, *, expected=(200,), with_status=False):
        require(
            (method, path)
            in {("GET", "/v1/sys/seal-status"), ("GET", "/v1/sys/health"), ("POST", "/v1/sys/unseal")},
            "migration_api_operation_forbidden",
        )
        if method == "POST":
            require(
                isinstance(payload, dict)
                and set(payload) == {"key", "migrate"}
                and payload.get("migrate") is True
                and isinstance(payload.get("key"), str),
                "migration_unseal_payload_forbidden",
            )
        try:
            status, value = transport(method, path, payload, timeout=5)
            require(
                type(status) is int and status in expected and isinstance(value, dict),
                "migration_api_request_failed",
            )
            return (status, value) if with_status else value
        except MigrationError:
            raise
        except Exception:
            raise MigrationError("migration_transport_outcome_unknown") from None

    def _identity(self):
        return self.bootstrap._identity("bootstrap")

    def _status(self, transport):
        value = self._request(transport, "GET", "/v1/sys/seal-status")
        require(
            value.get("initialized") is True
            and value.get("version") == VERSION
            and value.get("storage_type") == "raft",
            "migration_existing_raft_required",
        )
        require(
            type(value.get("t")) is int
            and value["t"] == 3
            and type(value.get("n")) is int
            and value["n"] == 5,
            "migration_existing_three_of_five_required",
        )
        return value

    def _active(self, transport, status, *, allow_pending=False):
        require(
            status.get("sealed") is False and status.get("cluster_id") == self.pins.cluster_id,
            "migration_original_cluster_not_active",
        )
        health_status, health = self._request(
            transport, "GET", "/v1/sys/health", expected=(200, 429, 472, 473, 503), with_status=True
        )
        # The shared HTTPS transport deliberately strips HTTPError bodies.
        # Seal status above has already bound the original unsealed cluster.
        if allow_pending and health_status != 200 and not health:
            return False
        require(
            health.get("initialized") is True
            and type(health.get("sealed")) is bool
            and type(health.get("standby")) is bool
            and health.get("cluster_id", self.pins.cluster_id) == self.pins.cluster_id,
            "migration_original_cluster_not_active",
        )
        ready = health_status == 200 and health["sealed"] is False and health["standby"] is False
        require(ready or allow_pending, "migration_original_cluster_not_active")
        return ready

    def _inputs(self):
        self.bootstrap._load()
        require(
            self.bootstrap.host_identity_sha256 == self.pins.host_identity_sha256
            and self.bootstrap.ca_sha256 == self.pins.enrollment_ca_sha256,
            "migration_host_or_ca_pin_mismatch",
        )
        require(
            _hash_file(self.paths.openbao_binary, owner=self.owner, private=False)
            == self.pins.openbao_binary_sha256,
            "migration_openbao_binary_pin_mismatch",
        )
        public_bytes = self._pinned(self.paths.public_config, self.pins.public_config_sha256, private=True)
        public_info = self.paths.public_config.lstat()
        require(
            public_info.st_gid == self.group and stat.S_IMODE(public_info.st_mode) == 0o600,
            "migration_public_config_permissions_invalid",
        )
        public = b._json(public_bytes)
        require(
            set(public)
            == {"seal_origin", "proof_origin", "machine_id", "deployment_id", "key_id", "proxy_gid"}
            and all(
                public.get(field) == getattr(self.pins, field)
                for field in ("seal_origin", "proof_origin", "machine_id", "deployment_id", "key_id")
            )
            and type(public["proxy_gid"]) is int
            and public["proxy_gid"] > 0,
            "migration_public_config_binding_invalid",
        )
        key_info, parent_info = self.paths.runtime_key.lstat(), self.paths.runtime_key.parent.lstat()
        require(
            stat.S_ISREG(key_info.st_mode)
            and key_info.st_uid == self.owner
            and key_info.st_gid == self.group
            and stat.S_IMODE(key_info.st_mode) == 0o400
            and key_info.st_size == 32
            and stat.S_ISDIR(parent_info.st_mode)
            and parent_info.st_uid == self.owner
            and parent_info.st_gid == self.group
            and stat.S_IMODE(parent_info.st_mode) == 0o700,
            "migration_runtime_key_permissions_invalid",
        )
        require(
            _hash_file(self.paths.runtime_key, owner=self.owner, private=True, maximum=32)
            == self.pins.key_id,
            "migration_runtime_key_id_mismatch",
        )
        self.verify_runtime_storage(self.paths.runtime_key)
        self.verify_credential_wiring(self.paths.runtime_key)
        self._pinned(self.paths.old_recovery, self.pins.old_recovery_sha256, private=True, kms_parent=True)
        successor_bytes = self._pinned(
            self.paths.successor_recovery, self.pins.successor_recovery_sha256, private=True
        )
        successor = b._json(successor_bytes)
        aad = successor.get("aad", {})
        require(
            aad.get("schema") == b.SCHEMA
            and aad.get("stage") == "static-seal-successor-pre-migration"
            and aad.get("static_seal_key_id") == self.pins.key_id
            and aad.get("previous_envelope_sha256") == self.pins.old_recovery_sha256,
            "migration_successor_envelope_binding_invalid",
        )
        shared = {
            name: getattr(self.pins, name)
            for name in ("machine_id", "host_identity_sha256", "enrollment_ca_sha256")
        }
        require(
            all(aad.get(name) == value for name, value in shared.items()),
            "migration_successor_envelope_binding_invalid",
        )
        require(
            aad.get("operator_public_key_sha256") == self.pins.operator_public_key_sha256,
            "migration_successor_envelope_binding_invalid",
        )
        custody = b._json(
            self._pinned(self.paths.successor_receipt, self.pins.successor_receipt_sha256, private=True)
        )
        expected = {
            **shared,
            "schema": "pap-static-seal-successor-custody-v1",
            "key_id": self.pins.key_id,
            "previous_envelope_sha256": self.pins.old_recovery_sha256,
            "successor_envelope_sha256": self.pins.successor_recovery_sha256,
            "offhost_durable": True,
            "decryption_verified": True,
            "contains_static_key": True,
            "contains_predecessor_recovery": True,
        }
        require(
            all(
                custody.get(name) == value and type(custody.get(name)) is type(value)
                for name, value in expected.items()
            ),
            "migration_successor_custody_not_verified",
        )
        backup = b._json(
            self._pinned(self.paths.backup_receipt, self.pins.backup_receipt_sha256, private=True)
        )
        expected = {
            **shared,
            "schema": "pap-static-seal-backup-v1",
            "cluster_id": self.pins.cluster_id,
            "artifact_sha256": self.pins.backup_artifact_sha256,
            "consistent": True,
            "protected": True,
            "offhost_durable": True,
            "method": "openbao-raft-snapshot",
        }
        require(
            all(
                backup.get(name) == value and type(backup.get(name)) is type(value)
                for name, value in expected.items()
            ),
            "migration_consistent_backup_required",
        )
        require(
            _hash_file(self.paths.backup_artifact, owner=self.owner, private=True)
            == self.pins.backup_artifact_sha256,
            "migration_backup_artifact_pin_mismatch",
        )
        for receipt in (custody, backup):
            require(
                self.clock() - timedelta(hours=1) <= _instant(receipt.get("recorded_at")) <= self.clock(),
                "migration_custody_or_backup_stale",
            )

    def _inspect(self):
        require(
            not self.paths.journal.exists()
            and not self.paths.journal.is_symlink()
            and not self.paths.receipt.exists()
            and not self.paths.receipt.is_symlink(),
            "migration_prior_attempt_operator_review_required",
        )
        self._inputs()
        before = self._pinned(self.paths.config, self.pins.config_before_sha256)
        after = static_configuration(before, self.pins.key_id)
        transport = self._identity()
        status = self._status(transport)
        require(
            status.get("type") == "shamir"
            and status.get("sealed") is False
            and status.get("migration") is False
            and status.get("recovery_seal") is False
            and status.get("progress") == 0,
            "migration_pristine_shamir_state_required",
        )
        self._active(transport, status)
        return {
            "bindings": asdict(self.pins),
            "config_after_sha256": b._sha(after),
            "openbao_pid_before": self.process_id(),
            "origin": b.ORIGIN,
            "static_key_file": KEY_FILE,
            "version": VERSION,
            "storage_type": "raft",
            "old_seal": "shamir",
            "new_seal": "static",
            "shares": 5,
            "threshold": 3,
            "helper_sha256": _hash_file(Path(__file__).absolute(), owner=self.owner, private=False),
            "bootstrap_helper_sha256": _hash_file(
                Path(b.__file__).absolute(), owner=self.owner, private=False
            ),
            "raft_initialization_deletion_or_reset_permitted": False,
            "offhost_custody_is_explicit_operator_attestation": True,
            "runtime_key_hash_verified": True,
            "runtime_key_on_tmpfs": True,
            "effective_load_credential_verified": True,
        }

    def plan(self):
        try:
            inspected = self._inspect()
            recorded = self.clock()
            value = {
                "schema": SCHEMA,
                "mode": "read_only_plan",
                **inspected,
                "recorded_at": recorded.isoformat(),
                "expires_at": (recorded + timedelta(minutes=5)).isoformat(),
            }
            value["plan_sha256"] = b._sha(b._canonical(value))
            return value
        except MigrationError:
            raise
        except b.BootstrapError as error:
            raise MigrationError(error.code) from None
        except Exception:
            raise MigrationError("migration_plan_failed") from None

    @contextmanager
    def _locked(self):
        b._protected_parent(self.paths.lock, {0, self.owner})
        descriptor = os.open(self.paths.lock, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(descriptor)
            require(
                stat.S_ISREG(info.st_mode)
                and info.st_uid == self.owner
                and stat.S_IMODE(info.st_mode) == 0o600,
                "migration_lock_untrusted",
            )
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise MigrationError("migration_already_running") from None
            yield
        finally:
            os.close(descriptor)

    def _journal(self, state, **details):
        value = {
            "schema": "pap-static-seal-migration-attempt-v1",
            "state": state,
            "machine_id": self.pins.machine_id,
            "plan_sha256": self.approved_plan,
            "key_id": self.pins.key_id,
            "recorded_at": self.clock().isoformat(),
            **details,
        }
        if self.journal_hash:
            value["previous_attempt_sha256"] = self.journal_hash
        data = b._canonical(value) + b"\n"
        b._write(
            self.paths.journal,
            data,
            owner=self.owner,
            parent_owners={0, self.owner},
            private=True,
            previous_sha256=self.journal_hash,
        )
        self.journal_hash = b._sha(data)
        self.journal_states.append(value)

    def _stage(self, data):
        b._write(
            self.paths.config,
            data,
            owner=self.owner,
            parent_owners={0, self.owner},
            private=False,
            previous_sha256=self.pins.config_before_sha256,
        )

    def _wait_status(self, *, sealed, migration, expected_pid, deadline_seconds=45):
        transport = self._identity()
        deadline = self.monotonic() + deadline_seconds
        for _ in range(180):
            require(self.process_id() == expected_pid, "migration_openbao_process_changed_unexpectedly")
            try:
                value = self._status(transport)
            except MigrationError as error:
                if error.code != "migration_transport_outcome_unknown":
                    raise
            else:
                require(
                    value.get("type") == "static" and value.get("recovery_seal") is True,
                    "migration_static_seal_not_configured",
                )
                if value.get("sealed") is sealed and value.get("migration") is migration:
                    if sealed:
                        require(value.get("progress") == 0, "migration_unexpected_unseal_progress")
                    else:
                        try:
                            if self._active(transport, value, allow_pending=True):
                                return transport, value
                        except MigrationError as error:
                            if error.code != "migration_transport_outcome_unknown":
                                raise
                    if sealed:
                        return transport, value
            remaining = deadline - self.monotonic()
            require(remaining > 0, "migration_seal_status_deadline")
            self.sleep(min(0.25, remaining))
        raise MigrationError("migration_seal_status_deadline")

    def apply(self, planned: dict, *, expected_plan_sha256: str, shares: list[str]):
        """Apply once. Shares exist only as the caller's in-memory Python values."""
        try:
            _validated_shares(shares)
            require(isinstance(planned, dict), "migration_plan_invalid")
            unsigned = {name: value for name, value in planned.items() if name != "plan_sha256"}
            require(
                HEX.fullmatch(expected_plan_sha256)
                and planned.get("plan_sha256") == expected_plan_sha256
                and b._sha(b._canonical(unsigned)) == expected_plan_sha256,
                "migration_plan_hash_mismatch",
            )
            require(
                _instant(planned["recorded_at"])
                <= self.clock()
                < _instant(planned["expires_at"])
                <= _instant(planned["recorded_at"]) + timedelta(minutes=5),
                "migration_plan_expired",
            )
            with self._locked():
                inspected = self._inspect()
                require(
                    all(planned.get(name) == value for name, value in inspected.items()),
                    "migration_preconditions_changed",
                )
                self.approved_plan = expected_plan_sha256
                self._journal("config_stage_requested")
                before = self._pinned(self.paths.config, self.pins.config_before_sha256)
                self.stage_config(static_configuration(before, self.pins.key_id))
                self._pinned(self.paths.config, planned["config_after_sha256"])
                self._journal("migration_restart_requested")
                self.restart()
                migration_pid = self.process_id()
                require(migration_pid != planned["openbao_pid_before"], "migration_restart_not_observed")
                transport, _ = self._wait_status(sealed=True, migration=True, expected_pid=migration_pid)
                for index, share in enumerate(shares):
                    require(
                        self.process_id() == migration_pid, "migration_openbao_process_changed_unexpectedly"
                    )
                    self._journal("migration_share_requested", share_index=index + 1)
                    value = self._request(
                        transport, "POST", "/v1/sys/unseal", {"key": share, "migrate": True}
                    )
                    require(
                        value.get("initialized") is True
                        and value.get("type") == "static"
                        and value.get("t") == 3
                        and value.get("n") == 5
                        and value.get("sealed") is (index < 2)
                        and value.get("progress") == (index + 1 if index < 2 else 0),
                        "migration_share_response_requires_operator_review",
                    )
                    self._journal("migration_share_acknowledged", share_index=index + 1)
                _, migrated = self._wait_status(sealed=False, migration=False, expected_pid=migration_pid)
                self._journal("migration_complete_restart_verification_requested")
                self.restart()
                automatic_pid = self.process_id()
                require(
                    automatic_pid not in {planned["openbao_pid_before"], migration_pid},
                    "migration_second_restart_not_observed",
                )
                _, automatic = self._wait_status(sealed=False, migration=False, expected_pid=automatic_pid)
                self._pinned(self.paths.config, planned["config_after_sha256"])
                self._journal("automatic_unseal_verified")
                receipt = {
                    "schema": "pap-static-seal-migration-receipt-v1",
                    "state": "complete",
                    "recorded_at": self.clock().isoformat(),
                    "plan_sha256": expected_plan_sha256,
                    "bindings": asdict(self.pins),
                    "config_after_sha256": planned["config_after_sha256"],
                    "old_seal": "shamir",
                    "new_seal": automatic["type"],
                    "migration_complete": migrated["migration"] is False,
                    "automatic_unseal_after_second_restart": automatic["sealed"] is False,
                    "same_cluster_id": automatic["cluster_id"] == self.pins.cluster_id,
                    "processes": {
                        "before": planned["openbao_pid_before"],
                        "migration": migration_pid,
                        "automatic_unseal": automatic_pid,
                    },
                    "migration_share_requests": 3,
                    "share_requests_after_second_restart": 0,
                    "openbao_service_restarts": 2,
                    "initialization_requests": 0,
                    "raft_deletion_or_reset": False,
                    "static_key_external_retrievals": 0,
                    "runtime_key_hash_verified": True,
                    "cold_boot_verified": False,
                    "issuer_signing_and_revocation_acceptance_separate": True,
                    "production_accepted": False,
                    "journal_chain": list(self.journal_states),
                }
                b._write(
                    self.paths.receipt,
                    b._canonical(receipt) + b"\n",
                    owner=self.owner,
                    parent_owners={0, self.owner},
                    private=True,
                )
                self._journal("complete")
                return receipt
        except BaseException as error:
            if self.journal_hash:
                try:
                    self._journal("stopped_operator_review_required")
                except BaseException:
                    pass
            if isinstance(error, MigrationError):
                raise
            if isinstance(error, b.BootstrapError):
                raise MigrationError(error.code) from None
            raise MigrationError("migration_stopped_operator_review_required") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only plan; apply is Python in-memory API only")
    parser.add_argument("--pins", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        import pwd

        pins = MigrationPins(**_safe_json(args.pins, owner=0, private=True))
        result = StaticSealMigrator(pins, _kms_uid=pwd.getpwnam("pap-kms").pw_uid).plan()
        print(json.dumps(result, sort_keys=True))
        return 0
    except BaseException as error:
        code = (
            error.code if isinstance(error, (MigrationError, b.BootstrapError)) else "migration_plan_failed"
        )
        print(json.dumps({"outcome": "stopped", "code": code}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
