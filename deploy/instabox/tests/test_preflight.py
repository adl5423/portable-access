"""Deterministic preflight checks. These do not certify an actual VM."""

import importlib.util
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "preflight.py"
SPEC = importlib.util.spec_from_file_location("instabox_preflight", SCRIPT)
preflight = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preflight)


@pytest.fixture
def storage(monkeypatch):
    inventory = {"/data": {"device": "254:1", "root": "/", "fstype": "ext4", "readonly": False}}
    attributes = {
        "/data": SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_dev=1, st_ino=1),
        "/data/pap": SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_dev=1, st_ino=2),
    }
    identities = {"pap-issuer": 501, "pap-kms": 502, "pap-proxy": 503}
    for index, (name, (source, target)) in enumerate(preflight.MAPPINGS.items(), start=10):
        private = name in {"issuer", "kms", "proxy"}
        uid = identities.get({"issuer": "pap-issuer", "kms": "pap-kms", "proxy": "pap-proxy"}.get(name), 0)
        source_attributes = SimpleNamespace(
            st_mode=stat.S_IFDIR | (0o700 if private else 0o755), st_uid=uid, st_dev=1, st_ino=index
        )
        attributes[str(source)] = source_attributes
        attributes[str(target)] = source_attributes
        inventory[str(target)] = {
            "device": "254:1",
            "root": "/" + source.relative_to("/data").as_posix(),
            "fstype": "ext4",
            "readonly": False,
        }

    def identity(name):
        if name not in identities:
            raise KeyError(name)
        return SimpleNamespace(pw_uid=identities[name])

    original_lstat = Path.lstat
    original_statvfs = preflight.os.statvfs
    monkeypatch.setattr(preflight, "mounts", lambda: inventory)
    monkeypatch.setattr(
        preflight.Path, "lstat", lambda path: attributes.get(str(path)) or original_lstat(path)
    )
    monkeypatch.setattr(preflight.pwd, "getpwnam", identity)
    monkeypatch.setattr(
        preflight.os,
        "statvfs",
        lambda path: (
            SimpleNamespace(f_bavail=10 * preflight.GIB, f_frsize=1)
            if str(path) == "/data"
            else original_statvfs(path)
        ),
    )
    return inventory, attributes


def run_storage(**kwargs):
    results = {}
    preflight.check_storage(lambda name, passed, _requirement: results.update({name: bool(passed)}), **kwargs)
    return results


def test_exact_private_persistent_mappings_pass(storage):
    assert all(run_storage().values())


@pytest.mark.parametrize("name", ["issuer", "kms", "proxy", "config", "software"])
def test_any_unbacked_state_configuration_or_software_mount_fails_closed(storage, name):
    inventory, _ = storage
    del inventory[str(preflight.MAPPINGS[name][1])]
    assert run_storage()[f"persistent_{name}_mapping"] is False


def test_a_bind_mount_to_the_wrong_directory_is_rejected(storage):
    inventory, _ = storage
    inventory["/var/lib/pap-issuer"]["root"] = "/other-state"
    assert run_storage()["persistent_issuer_mapping"] is False


def test_state_mount_on_another_device_is_rejected_even_when_a_mountpoint_exists(storage):
    inventory, _ = storage
    inventory["/var/lib/pap-issuer"]["device"] = "254:2"
    assert run_storage()["persistent_issuer_mapping"] is False


def test_world_readable_signing_state_is_rejected(storage):
    _, attributes = storage
    attributes["/var/lib/pap-kms"].st_mode = stat.S_IFDIR | 0o755
    assert run_storage()["persistent_kms_mapping"] is False


def test_application_owned_config_or_software_is_rejected(storage):
    _, attributes = storage
    attributes["/etc/pap"].st_uid = 999
    attributes["/opt/pap"].st_uid = 999
    results = run_storage()
    assert results["persistent_config_mapping"] is False
    assert results["persistent_software_mapping"] is False


def test_symlink_instead_of_bound_directory_is_rejected(storage):
    _, attributes = storage
    attributes["/var/lib/pap-issuer"].st_mode = stat.S_IFLNK | 0o777
    assert run_storage()["persistent_issuer_mapping"] is False


def test_systemd_readonly_parent_view_is_allowed_only_with_writable_own_state(storage):
    inventory, _ = storage
    inventory["/data"]["readonly"] = True
    inventory["/etc/pap"]["readonly"] = True
    inventory["/opt/pap"]["readonly"] = True
    assert all(run_storage(role="issuer", service_view=True).values())
    assert run_storage(role="issuer")["persistent_data_writable"] is False
    inventory["/var/lib/pap-issuer"]["readonly"] = True
    assert run_storage(role="issuer", service_view=True)["persistent_issuer_writable"] is False


def test_volatile_storage_and_missing_private_parent_fail_closed(storage):
    inventory, attributes = storage
    inventory["/data"]["fstype"] = "tmpfs"
    attributes["/data/pap"].st_mode = stat.S_IFDIR | 0o755
    results = run_storage()
    assert results["persistent_filesystem_type"] is False
    assert results["private_persistence_parent"] is False


def test_data_must_itself_be_a_dedicated_mount(storage):
    inventory, _ = storage
    del inventory["/data"]
    assert run_storage() == {"persistent_data_mount": False}


def test_mountinfo_escaping_is_parsed_without_shell_execution():
    assert preflight.unescape_mount(r"/a\040b\134c") == "/a b\\c"
