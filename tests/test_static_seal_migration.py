"""Migration safety gates using synthetic material and an isolated fake server."""

import base64
import copy
import json
import os
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from tools import bootstrap_openbao as b
from tools import migrate_static_seal as m

MACHINE = "m_abcdefghijklmnopqrstuvwxyz"
CLUSTER = "619ce522-f6c9-4f57-ad04-62b056ae41fd"
SHARES = [base64.b64encode(bytes([index]) * 33).decode() for index in range(1, 6)]


def write(path, value, *, mode=0o600):
    path.write_bytes(value if isinstance(value, bytes) else b._canonical(value))
    path.chmod(mode)


@pytest.fixture(scope="module")
def operator():
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


class FakeAPI:
    def __init__(self, paths):
        self.paths = paths
        self.pid = 900
        self.restarts = 0
        self.posts = []
        self.calls = []
        self.phase = "shamir"
        self.progress = 0
        self.fail_share = None
        self.bad_share = None
        self.fail_restart = None
        self.no_new_pid = False
        self.fail_auto = False
        self.wrong_cluster = False
        self.fail_poll = False
        self.pending_health = []
        self.required_journal_states = []
        self.now = datetime.now(UTC)
        self.elapsed = 0.0

    def clock(self):
        return self.now

    def monotonic(self):
        return self.elapsed

    def sleep(self, seconds):
        self.elapsed += seconds
        self.now += timedelta(seconds=seconds)

    def context(self, server_ca, client_ca, key, name, now):
        assert server_ca == client_ca
        assert name == "pap-bootstrap"
        return object()

    def factory(self, context, identity):
        assert identity == "bootstrap"
        return self.request

    def request(self, method, path, payload=None, token=None, **kwargs):
        assert token is None
        self.calls.append((method, path))
        if method == "POST":
            assert path == "/v1/sys/unseal", "No initialization, deletion, reset, or other mutation"
            assert self.restarts == 1, "No shares after the automatic-unseal restart"
            assert payload == {"key": SHARES[len(self.posts)], "migrate": True}
            journal = json.loads(self.paths.journal.read_text())
            assert journal["state"] == "migration_share_requested"
            assert journal["share_index"] == len(self.posts) + 1
            self.posts.append(payload)
            if self.fail_share == len(self.posts):
                raise OSError("unknown outcome " + payload["key"])
            self.progress += 1
            if self.progress == 3:
                self.phase, self.progress = "migrated", 0
            value = self.status()
            if self.bad_share == len(self.posts):
                value["progress"] = 999
            return 200, value
        if path == "/v1/sys/seal-status":
            if self.fail_poll and self.restarts:
                raise OSError("poll transport failure")
            return 200, self.status()
        if path == "/v1/sys/health":
            if self.restarts and self.pending_health:
                status, standby = self.pending_health.pop(0)
                if status == "transport":
                    raise OSError("synthetic transient readiness probe failure")
                if standby is None:
                    return status, {}
                return status, {
                    "initialized": True,
                    "sealed": status == 503,
                    "standby": standby,
                    "cluster_id": CLUSTER,
                }
            return 200, {
                "initialized": True,
                "sealed": False,
                "standby": False,
                "cluster_id": "0" * 36 if self.wrong_cluster else CLUSTER,
            }
        pytest.fail("Unexpected API path")

    def status(self):
        return {
            "type": "shamir" if self.phase == "shamir" else "static",
            "initialized": True,
            "sealed": self.phase == "migration" or self.fail_auto and self.restarts == 2,
            "t": 3,
            "n": 5,
            "progress": self.progress,
            "version": "2.7.1",
            "storage_type": "raft",
            "migration": self.phase == "migration",
            "recovery_seal": self.phase != "shamir",
            "cluster_id": "0" * 36 if self.wrong_cluster else CLUSTER,
        }

    def restart(self):
        journal = json.loads(self.paths.journal.read_text())
        assert journal["state"] == (
            "migration_restart_requested"
            if self.restarts == 0
            else "migration_complete_restart_verification_requested"
        )
        assert b'seal "static"' in self.paths.config.read_bytes()
        self.restarts += 1
        if self.fail_restart == self.restarts:
            raise OSError("restart uncertain, private detail")
        if not self.no_new_pid:
            self.pid += 1
        self.phase = "migration" if self.restarts == 1 else "automatic"


@pytest.fixture
def fixture(tmp_path, operator):
    tmp_path.chmod(0o700)
    # BSD temp children inherit the directory group; match this synthetic host's
    # declared service group before creating its protected inputs.
    os.chown(tmp_path, -1, os.getegid())
    enrollment, state, runtime = tmp_path / "enrollment", tmp_path / "state", tmp_path / "private"
    enrollment.mkdir(mode=0o700)
    state.mkdir(mode=0o700)
    runtime.mkdir(mode=0o700)
    bootpaths = b.BootstrapPaths(
        enrollment_ca=tmp_path / "enrollment-ca.pem",
        enrollment_key=enrollment / "ca-key.pem",
        machine_id=tmp_path / "machine-id",
    )
    paths = m.MigrationPaths(
        config=tmp_path / "openbao.hcl",
        public_config=tmp_path / "boot.json",
        runtime_key=runtime / "current.key",
        operator_public_key=tmp_path / "operator-public.der",
        old_recovery=state / "old.enc.json",
        successor_recovery=enrollment / "successor.enc.json",
        successor_receipt=enrollment / "custody.json",
        backup_artifact=enrollment / "backup.snap",
        backup_receipt=enrollment / "backup.json",
        journal=enrollment / "attempt.json",
        receipt=enrollment / "receipt.json",
        lock=tmp_path / "lock",
        openbao_binary=tmp_path / "bao",
        bootstrap=bootpaths,
    )
    ca, ca_key = b._new_operator_ca(datetime.now(UTC))
    write(bootpaths.enrollment_ca, b._certificate_pem(ca).encode(), mode=0o644)
    write(bootpaths.enrollment_key, b._private_pem(ca_key).encode())
    write(bootpaths.machine_id, b"f" * 32, mode=0o644)
    der = operator.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    write(paths.operator_public_key, der, mode=0o644)
    write(paths.config, Path("deploy/linux/openbao/openbao.enrollment.hcl").read_bytes(), mode=0o644)
    key_id = b._sha(b"S" * 32)
    write(paths.runtime_key, b"S" * 32, mode=0o400)
    public = {
        "machine_id": MACHINE,
        "key_id": key_id,
        "deployment_id": "example-deployment",
        "proof_origin": "https://authority.example.com",
        "seal_origin": "https://synthetic-isolated-custody.netlify.app",
        "proxy_gid": 986,
    }
    write(paths.public_config, public)
    write(paths.old_recovery, {"ciphertext": "synthetic_predecessor_not_real"})
    write(paths.backup_artifact, b"Synthetic protected consistent Raft snapshot, not a live fixture")
    write(paths.openbao_binary, b"Synthetic version-pinned OpenBao executable, never executed", mode=0o755)
    shared = {
        "machine_id": MACHINE,
        "host_identity_sha256": b._sha(b"f" * 32),
        "enrollment_ca_sha256": b._sha(ca.public_bytes(serialization.Encoding.DER)),
    }
    aad = {
        **shared,
        "schema": b.SCHEMA,
        "cipher": "AES-256-GCM",
        "wrap": "RSA-OAEP-SHA256",
        "stage": "static-seal-successor-pre-migration",
        "static_seal_key_id": key_id,
        "previous_envelope_sha256": b._sha(paths.old_recovery.read_bytes()),
        "operator_public_key_sha256": b._sha(der),
    }
    write(paths.successor_recovery, {"aad": aad, "ciphertext": "synthetic_ciphertext_only"})
    custody = {
        **shared,
        "schema": "pap-static-seal-successor-custody-v1",
        "key_id": key_id,
        "previous_envelope_sha256": b._sha(paths.old_recovery.read_bytes()),
        "successor_envelope_sha256": b._sha(paths.successor_recovery.read_bytes()),
        "offhost_durable": True,
        "decryption_verified": True,
        "contains_static_key": True,
        "contains_predecessor_recovery": True,
        "recorded_at": datetime.now(UTC).isoformat(),
    }
    backup = {
        **shared,
        "schema": "pap-static-seal-backup-v1",
        "cluster_id": CLUSTER,
        "artifact_sha256": b._sha(paths.backup_artifact.read_bytes()),
        "consistent": True,
        "protected": True,
        "offhost_durable": True,
        "method": "openbao-raft-snapshot",
        "recorded_at": datetime.now(UTC).isoformat(),
    }
    write(paths.successor_receipt, custody)
    write(paths.backup_receipt, backup)
    pins = m.MigrationPins(
        **shared,
        operator_public_key_sha256=b._sha(der),
        public_config_sha256=b._sha(paths.public_config.read_bytes()),
        config_before_sha256=b._sha(paths.config.read_bytes()),
        old_recovery_sha256=b._sha(paths.old_recovery.read_bytes()),
        successor_recovery_sha256=b._sha(paths.successor_recovery.read_bytes()),
        successor_receipt_sha256=b._sha(paths.successor_receipt.read_bytes()),
        backup_artifact_sha256=b._sha(paths.backup_artifact.read_bytes()),
        backup_receipt_sha256=b._sha(paths.backup_receipt.read_bytes()),
        openbao_binary_sha256=b._sha(paths.openbao_binary.read_bytes()),
        key_id=key_id,
        deployment_id=public["deployment_id"],
        proof_origin=public["proof_origin"],
        seal_origin=public["seal_origin"],
        cluster_id=CLUSTER,
    )
    api = FakeAPI(paths)

    def factory(**overrides):
        selected_pins = overrides.pop("_pins", pins)
        options = dict(
            _paths=paths,
            _owner_uid=os.geteuid(),
            _owner_gid=os.getegid(),
            _kms_uid=os.geteuid(),
            _transport_factory=api.factory,
            _context_factory=api.context,
            _restart_service=api.restart,
            _process_id=lambda: api.pid,
            _harden_process=lambda: None,
            _verify_runtime_storage=lambda path: None,
            _verify_credential_wiring=lambda path: None,
            _clock=api.clock,
            _sleep=api.sleep,
            _monotonic=api.monotonic,
        )
        options.update(overrides)
        return m.StaticSealMigrator(selected_pins, **options)

    return SimpleNamespace(paths=paths, pins=pins, api=api, create=factory, custody=custody, backup=backup)


def apply(fixture):
    migrator = fixture.create()
    plan = migrator.plan()
    return migrator, migrator.apply(plan, expected_plan_sha256=plan["plan_sha256"], shares=SHARES[:3])


def test_plan_is_read_only_and_binds_every_source_and_input(fixture):
    before = fixture.paths.config.read_bytes()
    plan = fixture.create().plan()
    assert plan["bindings"] == asdict(fixture.pins)
    assert plan["origin"] == "https://127.0.0.1:8200"
    assert plan["helper_sha256"] == b._sha(Path(m.__file__).read_bytes())
    assert plan["bootstrap_helper_sha256"] == b._sha(Path(b.__file__).read_bytes())
    assert fixture.paths.config.read_bytes() == before
    assert not fixture.paths.journal.exists() and not fixture.paths.receipt.exists()
    assert not fixture.api.posts and not fixture.api.restarts
    assert all(method == "GET" for method, _ in fixture.api.calls)


@pytest.mark.parametrize("clock_kind", ["advancing_nineteen_microseconds", "actual_wall_clock"])
def test_plan_ttl_uses_one_instant_and_applies_with_an_advancing_clock(fixture, clock_kind):
    def advancing():
        value = fixture.api.now
        fixture.api.now += timedelta(microseconds=19)
        return value

    clock = advancing if clock_kind == "advancing_nineteen_microseconds" else lambda: datetime.now(UTC)
    migrator = fixture.create(_clock=clock)
    planned = migrator.plan()
    assert m._instant(planned["expires_at"]) - m._instant(planned["recorded_at"]) == timedelta(minutes=5)
    receipt = migrator.apply(planned, expected_plan_sha256=planned["plan_sha256"], shares=SHARES[:3])
    assert receipt["state"] == "complete"
    assert fixture.api.restarts == 2 and len(fixture.api.posts) == 3


def test_successful_migration_uses_three_shares_once_then_restart_without_shares(fixture):
    migrator, receipt = apply(fixture)
    assert receipt["state"] == "complete" and receipt["migration_complete"]
    assert receipt["same_cluster_id"] and receipt["automatic_unseal_after_second_restart"]
    assert receipt["openbao_service_restarts"] == 2 and len(fixture.api.posts) == 3
    assert receipt["share_requests_after_second_restart"] == 0
    assert receipt["initialization_requests"] == 0 and not receipt["raft_deletion_or_reset"]
    assert not receipt["cold_boot_verified"] and not receipt["production_accepted"]
    assert json.loads(fixture.paths.journal.read_text())["state"] == "complete"
    assert json.loads(fixture.paths.receipt.read_text()) == receipt
    for share in SHARES:
        assert share not in fixture.paths.journal.read_text() + fixture.paths.receipt.read_text()
    assert [entry["state"] for entry in migrator.journal_states][:3] == [
        "config_stage_requested",
        "migration_restart_requested",
        "migration_share_requested",
    ]
    with pytest.raises(m.MigrationError, match="prior_attempt"):
        fixture.create().plan()


@pytest.mark.parametrize(
    "which",
    [
        "config",
        "public_config",
        "old_recovery",
        "successor_recovery",
        "successor_receipt",
        "backup_artifact",
        "backup_receipt",
        "openbao_binary",
    ],
)
def test_every_artifact_pin_is_checked_before_mutation(fixture, which):
    path = getattr(fixture.paths, which)
    path.write_bytes(path.read_bytes() + b"changed")
    with pytest.raises(m.MigrationError):
        fixture.create().plan()
    assert not fixture.paths.journal.exists() and not fixture.api.restarts and not fixture.api.posts


@pytest.mark.parametrize(
    "which",
    [
        "public_config",
        "old_recovery",
        "successor_recovery",
        "successor_receipt",
        "backup_artifact",
        "backup_receipt",
    ],
)
def test_private_artifacts_cannot_be_world_readable(fixture, which):
    getattr(fixture.paths, which).chmod(0o644)
    with pytest.raises(m.MigrationError):
        fixture.create().plan()
    assert not fixture.paths.journal.exists()


@pytest.mark.parametrize(
    "target,field,value,code",
    [
        ("custody", "offhost_durable", False, "custody_not_verified"),
        ("custody", "decryption_verified", False, "custody_not_verified"),
        ("custody", "contains_static_key", False, "custody_not_verified"),
        ("custody", "contains_predecessor_recovery", False, "custody_not_verified"),
        ("backup", "consistent", False, "consistent_backup_required"),
        ("backup", "offhost_durable", False, "consistent_backup_required"),
        ("backup", "protected", 1, "consistent_backup_required"),
        ("backup", "method", "unchecked_running_directory_copy", "consistent_backup_required"),
        ("backup", "cluster_id", "0" * 36, "consistent_backup_required"),
    ],
)
def test_custody_and_consistency_are_required_not_just_receipt_bytes(fixture, target, field, value, code):
    content = copy.deepcopy(getattr(fixture, target))
    content[field] = value
    path = fixture.paths.successor_receipt if target == "custody" else fixture.paths.backup_receipt
    write(path, content)
    pin = "successor_receipt_sha256" if target == "custody" else "backup_receipt_sha256"
    fixture.pins = replace(fixture.pins, **{pin: b._sha(path.read_bytes())})
    with pytest.raises(m.MigrationError, match=code):
        fixture.create(_pins=fixture.pins).plan()
    assert not fixture.paths.journal.exists()


@pytest.mark.parametrize(
    "kind",
    [
        "uninitialized",
        "already_static",
        "sealed",
        "migration",
        "wrong_cluster",
        "wrong_version",
        "wrong_storage",
        "wrong_threshold",
        "progress",
    ],
)
def test_unexpected_baseline_never_stages_or_restarts(fixture, kind):
    original = fixture.api.status

    def changed():
        value = original()
        field, result = {
            "uninitialized": ("initialized", False),
            "already_static": ("type", "static"),
            "sealed": ("sealed", True),
            "migration": ("migration", True),
            "wrong_cluster": ("cluster_id", "0" * 36),
            "wrong_version": ("version", "2.8.0"),
            "wrong_storage": ("storage_type", "file"),
            "wrong_threshold": ("t", 2),
            "progress": ("progress", 1),
        }[kind]
        value[field] = result
        return value

    fixture.api.status = changed
    with pytest.raises(m.MigrationError):
        fixture.create().plan()
    assert not fixture.paths.journal.exists() and not fixture.api.restarts and not fixture.api.posts


@pytest.mark.parametrize("share_index", [1, 2, 3])
def test_uncertain_share_is_journaled_and_never_retried(fixture, share_index):
    fixture.api.fail_share = share_index
    migrator = fixture.create()
    plan = migrator.plan()
    with pytest.raises(m.MigrationError) as captured:
        migrator.apply(plan, expected_plan_sha256=plan["plan_sha256"], shares=SHARES[:3])
    assert len(fixture.api.posts) == share_index and fixture.api.restarts == 1
    assert json.loads(fixture.paths.journal.read_text())["state"] == "stopped_operator_review_required"
    assert not fixture.paths.receipt.exists()
    assert all(share not in str(captured.value) + fixture.paths.journal.read_text() for share in SHARES)
    with pytest.raises(m.MigrationError, match="prior_attempt"):
        fixture.create().apply(plan, expected_plan_sha256=plan["plan_sha256"], shares=SHARES[:3])
    assert len(fixture.api.posts) == share_index and fixture.api.restarts == 1


@pytest.mark.parametrize("restart", [1, 2])
def test_uncertain_restart_is_not_repeated(fixture, restart):
    fixture.api.fail_restart = restart
    migrator = fixture.create()
    plan = migrator.plan()
    with pytest.raises(m.MigrationError):
        migrator.apply(plan, expected_plan_sha256=plan["plan_sha256"], shares=SHARES[:3])
    assert fixture.api.restarts == restart
    with pytest.raises(m.MigrationError, match="prior_attempt"):
        fixture.create().plan()


@pytest.mark.parametrize(
    "kind",
    [
        "plan_hash",
        "changed_plan",
        "expired",
        "changed_pid",
        "shares_duplicate",
        "shares_missing",
        "shares_invalid",
    ],
)
def test_apply_preconditions_fail_without_any_journal_or_mutation(fixture, kind):
    migrator = fixture.create()
    plan = migrator.plan()
    expected, shares = plan["plan_sha256"], SHARES[:3]
    if kind == "plan_hash":
        expected = "0" * 64
    elif kind == "changed_plan":
        plan["config_after_sha256"] = "0" * 64
    elif kind == "expired":
        fixture.api.now += timedelta(minutes=6)
    elif kind == "changed_pid":
        fixture.api.pid += 1
    elif kind == "shares_duplicate":
        shares = [SHARES[0]] * 3
    elif kind == "shares_missing":
        shares = SHARES[:2]
    elif kind == "shares_invalid":
        shares = ["!" * 44, *SHARES[1:3]]
    with pytest.raises(m.MigrationError):
        migrator.apply(plan, expected_plan_sha256=expected, shares=shares)
    assert not fixture.paths.journal.exists() and not fixture.api.restarts and not fixture.api.posts


def test_second_restart_must_auto_unseal_without_fallback_shares(fixture):
    fixture.api.fail_auto = True
    with pytest.raises(m.MigrationError, match="seal_status_deadline"):
        apply(fixture)
    assert fixture.api.restarts == 2 and len(fixture.api.posts) == 3
    assert not fixture.paths.receipt.exists() and fixture.api.elapsed == 45


def test_unseal_waits_for_raft_leadership_with_only_read_probes(fixture):
    fixture.api.pending_health = [("transport", False), (429, True), (503, False), (200, True)]
    _, receipt = apply(fixture)
    assert receipt["automatic_unseal_after_second_restart"]
    assert fixture.api.restarts == 2 and len(fixture.api.posts) == 3
    assert not fixture.api.pending_health
    assert fixture.api.elapsed == 1


@pytest.mark.parametrize("status", [429, 472, 473, 503])
def test_real_transport_stripped_health_error_body_is_read_only_pending(fixture, status):
    fixture.api.pending_health = [(status, None)]
    _, receipt = apply(fixture)
    assert receipt["automatic_unseal_after_second_restart"]
    assert fixture.api.restarts == 2 and len(fixture.api.posts) == 3
    assert fixture.api.elapsed == 0.25


def test_staging_failure_retains_attempt_and_never_restarts(fixture):
    def stage(data):
        assert json.loads(fixture.paths.journal.read_text())["state"] == "config_stage_requested"
        raise OSError("uncertain staging")

    migrator = fixture.create(_stage_config=stage)
    plan = migrator.plan()
    with pytest.raises(m.MigrationError):
        migrator.apply(plan, expected_plan_sha256=plan["plan_sha256"], shares=SHARES[:3])
    assert not fixture.api.restarts and not fixture.api.posts
    assert fixture.paths.journal.exists()


def test_no_restart_without_durable_journal(fixture, monkeypatch):
    migrator = fixture.create()
    plan = migrator.plan()
    monkeypatch.setattr(b, "_write", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("disk failure")))
    before = fixture.paths.config.read_bytes()
    with pytest.raises(m.MigrationError):
        migrator.apply(plan, expected_plan_sha256=plan["plan_sha256"], shares=SHARES[:3])
    assert fixture.paths.config.read_bytes() == before and not fixture.api.restarts and not fixture.api.posts


def test_hcl_contains_only_public_key_id_and_runtime_file_reference(fixture):
    previous = fixture.paths.config.read_bytes()
    updated = m.static_configuration(previous, fixture.pins.key_id)
    assert updated.startswith(previous.rstrip())
    assert b'current_key = "file:///run/credentials/pap-openbao.service/seal-current"' in updated
    assert fixture.pins.key_id.encode() in updated
    assert b"env://" not in updated and all(share.encode() not in updated for share in SHARES)
    with pytest.raises(m.MigrationError, match="existing_seal_block"):
        m.static_configuration(updated, fixture.pins.key_id)


def test_api_allowlist_forbids_initialization_and_reset_before_transport(fixture):
    migrator = fixture.create()
    for method, path in (
        ("POST", "/v1/sys/init"),
        ("DELETE", "/v1/sys/storage/raft"),
        ("POST", "/v1/sys/seal"),
    ):
        with pytest.raises(m.MigrationError, match="operation_forbidden"):
            migrator._request(fixture.api.request, method, path, {})
    assert not fixture.api.calls


@pytest.mark.parametrize("kind", ["missing", "mode", "length", "wrong_key", "directory", "symlink"])
def test_actual_runtime_key_is_checked_before_config_change(fixture, kind):
    path = fixture.paths.runtime_key
    if kind == "missing":
        path.unlink()
    elif kind == "mode":
        path.chmod(0o600)
    elif kind == "length":
        path.chmod(0o600)
        write(path, b"too short", mode=0o400)
    elif kind == "wrong_key":
        path.chmod(0o600)
        write(path, b"W" * 32, mode=0o400)
    elif kind == "directory":
        path.parent.chmod(0o755)
    elif kind == "symlink":
        target = path.with_name("alternate.key")
        path.rename(target)
        path.symlink_to(target.name)
    with pytest.raises(m.MigrationError):
        fixture.create().plan()
    assert not fixture.paths.journal.exists() and not fixture.api.posts and not fixture.api.restarts


def test_plan_requires_runtime_storage_and_effective_systemd_wiring(fixture):
    for name in ("_verify_runtime_storage", "_verify_credential_wiring"):

        def reject(path):
            raise m.MigrationError("synthetic_precondition_failure")

        with pytest.raises(m.MigrationError, match="synthetic_precondition_failure"):
            fixture.create(**{name: reject}).plan()
    assert not fixture.paths.journal.exists()


@pytest.mark.parametrize(
    "regular,encrypted,accepted",
    [
        (
            {"type": "a(ss)", "data": [["seal-current", "/run/pap-boot/private/current.key"]]},
            {"type": "a(ss)", "data": []},
            True,
        ),
        (
            {
                "type": "a(ss)",
                "data": [
                    ["other-credential", "/other/public/path"],
                    ["seal-current", "/run/pap-boot/private/current.key"],
                ],
            },
            {"type": "a(ss)", "data": []},
            False,
        ),
        ({"type": "a(ss)", "data": []}, {"type": "a(ss)", "data": []}, False),
        ({"type": "a(ss)", "data": [["seal-current", "/wrong.key"]]}, {"type": "a(ss)", "data": []}, False),
        (
            {
                "type": "a(ss)",
                "data": [
                    ["seal-current", "/run/pap-boot/private/current.key"],
                    ["seal-current", "/run/pap-boot/private/current.key"],
                ],
            },
            {"type": "a(ss)", "data": []},
            False,
        ),
        (
            {"type": "a(ss)", "data": [["seal-current", "/run/pap-boot/private/current.key"]]},
            {"type": "a(ss)", "data": [["seal-current", "/other/encrypted/path"]]},
            False,
        ),
        (
            {"type": "a(ss)", "data": [["seal-current", "/run/pap-boot/private/current.key"]]},
            {"type": "a(ss)", "data": [["unexpected-credential", "/other/encrypted/path"]]},
            False,
        ),
        (
            {"type": "a(ssb)", "data": [["seal-current", "/run/pap-boot/private/current.key", False]]},
            {"type": "a(ss)", "data": []},
            False,
        ),
        (
            {"type": "a(ss)", "data": [[["seal-current", "/run/pap-boot/private/current.key"]]]},
            {"type": "a(ss)", "data": []},
            False,
        ),
        (
            {"type": "a(ss)", "data": ["seal-current:/run/pap-boot/private/current.key"]},
            {"type": "a(ss)", "data": []},
            False,
        ),
        ({"type": "a(ss)", "data": [["seal-current", True]]}, {"type": "a(ss)", "data": []}, False),
        (
            {"type": "a(ss)", "data": [["seal-current", "/run/pap-boot/private/current.key"]]},
            {"type": "a(ss)", "data": {}},
            False,
        ),
        (
            {"type": "a(ss)", "data": [["seal-current", "/run/pap-boot/private/current.key"]], "extra": []},
            {"type": "a(ss)", "data": []},
            False,
        ),
    ],
)
def test_default_effective_wiring_check_uses_only_typed_metadata(monkeypatch, regular, encrypted, accepted):
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        value = regular if args[-1] == "LoadCredential" else encrypted
        return SimpleNamespace(returncode=0, stdout=json.dumps(value).encode())

    monkeypatch.setattr(m.subprocess, "run", run)
    if accepted:
        m._credential_wiring(Path("/run/pap-boot/private/current.key"))
    else:
        with pytest.raises(m.MigrationError, match="credential_wiring_invalid"):
            m._credential_wiring(Path("/run/pap-boot/private/current.key"))
    expected = [
        "/usr/bin/busctl",
        "--json=short",
        "get-property",
        "org.freedesktop.systemd1",
        "/org/freedesktop/systemd1/unit/pap_2dopenbao_2eservice",
        "org.freedesktop.systemd1.Service",
    ]
    assert calls[0] == [*expected, "LoadCredential"]
    assert all(
        args in [[*expected, "LoadCredential"], [*expected, "LoadCredentialEncrypted"]] for args in calls
    )
    if accepted:
        assert calls == [[*expected, "LoadCredential"], [*expected, "LoadCredentialEncrypted"]]


@pytest.mark.parametrize(
    "payload",
    [
        b"LoadCredential=[unprintable]\n",
        b"[unprintable]",
        b'{"type":"a(ss)","type":"a(ss)","data":[]}',
        b'{"type":"a(ss)","data":[],"data":[["seal-current","/run/pap-boot/private/current.key"]]}',
        b"\xff",
        b"[]",
    ],
)
def test_wiring_never_falls_back_to_untyped_or_duplicate_metadata(monkeypatch, payload):
    monkeypatch.setattr(
        m.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=payload)
    )
    with pytest.raises(m.MigrationError, match="credential_wiring_invalid"):
        m._credential_wiring(Path("/run/pap-boot/private/current.key"))


@pytest.mark.parametrize("failure", ["exit", "size", "timeout", "missing_binary"])
def test_wiring_transport_failures_are_bounded_and_sanitized(monkeypatch, failure):
    def run(args, **kwargs):
        assert kwargs["timeout"] == 5
        if failure == "timeout":
            raise m.subprocess.TimeoutExpired(args, 5, output=b"must_not_leak")
        if failure == "missing_binary":
            raise FileNotFoundError("must_not_leak")
        return SimpleNamespace(
            returncode=1 if failure == "exit" else 0,
            stdout=b"must_not_leak" if failure == "exit" else b"x" * 8193,
        )

    monkeypatch.setattr(m.subprocess, "run", run)
    with pytest.raises(m.MigrationError, match="credential_wiring_unavailable") as captured:
        m._credential_wiring(Path("/run/pap-boot/private/current.key"))
    assert "must_not_leak" not in str(captured.value)


@pytest.mark.parametrize(
    "mounts,accepted",
    [
        ("1 0 0:1 / / rw - ext4 /dev/root rw\n2 1 0:2 / /run rw - tmpfs tmpfs rw\n", True),
        ("1 0 0:1 / / rw - ext4 /dev/root rw\n", False),
        (
            "1 0 0:1 / / rw - ext4 /dev/root rw\n2 1 0:2 / /run rw - tmpfs tmpfs rw\n"
            "3 2 0:3 / /run/pap-boot/private rw - ext4 /dev/disk rw\n",
            False,
        ),
        (
            "1 0 0:1 / / rw - ext4 /dev/root rw\n2 1 0:2 / /run rw - tmpfs tmpfs rw\n"
            "3 2 0:3 / /run rw - ext4 /dev/disk rw\n",
            False,
        ),
    ],
)
def test_default_storage_check_requires_visible_tmpfs(monkeypatch, mounts, accepted):
    original = Path.read_text

    def read(path, *args, **kwargs):
        return mounts if path == Path("/proc/self/mountinfo") else original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    if accepted:
        m._runtime_tmpfs(Path("/run/pap-boot/private/current.key"))
    else:
        with pytest.raises(m.MigrationError, match="runtime_key_tmpfs_required"):
            m._runtime_tmpfs(Path("/run/pap-boot/private/current.key"))


def test_unseal_reset_payload_is_not_an_available_operation(fixture):
    with pytest.raises(m.MigrationError, match="unseal_payload_forbidden"):
        fixture.create()._request(fixture.api.request, "POST", "/v1/sys/unseal", {"reset": True})
    assert not fixture.api.calls
