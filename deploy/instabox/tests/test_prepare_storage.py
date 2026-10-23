import importlib.util
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "prepare-storage.py"


@pytest.fixture
def storage():
    specification = importlib.util.spec_from_file_location("pap_prepare_storage", SOURCE)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def canonical(storage):
    return "".join(
        f"{source} {target} none {storage.OPTIONS} 0 0\n" for _, source, target, _ in storage.MAPPINGS
    ).encode()


def test_existing_unrelated_fstab_lines_are_preserved_by_planning(storage):
    raw = b"# existing host configuration\nUUID=host-root / ext4 defaults 0 1\n"
    assert len(storage.missing_fstab_entries(raw)) == 5
    assert raw == b"# existing host configuration\nUUID=host-root / ext4 defaults 0 1\n"


def test_exact_complete_fstab_is_idempotent(storage):
    assert storage.missing_fstab_entries(canonical(storage)) == []


def test_equivalent_option_order_and_inline_comments_are_retained(storage):
    raw = canonical(storage).replace(
        b"bind,x-systemd.requires-mounts-for=/data", b"x-systemd.requires-mounts-for=/data,bind"
    )
    raw = raw.replace(b" 0 0\n", b" 0 0 # approved PAP bind\n")
    assert storage.missing_fstab_entries(raw) == []


@pytest.mark.parametrize(
    "entry",
    [
        "/unrelated /var/lib/pap-issuer none bind,x-systemd.requires-mounts-for=/data 0 0",
        "/data/pap/state/issuer /public none bind 0 0",
        "/data/pap/state/issuer/credentials /public none bind 0 0",
        "/unrelated /etc/pap/nested none bind 0 0",
        "/data/pap/state/issuer /var/lib/pap-issuer none bind 0 0",
        "/data/pap/state/issuer /var/lib/pap-issuer none rbind,x-systemd.requires-mounts-for=/data 0 0",
        "/data/pap/state/issuer /var/lib/pap-issuer none bind,x-systemd.requires-mounts-for=/data,rw 0 0",
        "/data/pap/state/issuer /var/lib/pap-issuer none bind,x-systemd.requires-mounts-for=/data 0 1",
        "/data/pap/state/issuer /var/lib/pap-issuer none bind,x-systemd.requires-mounts-for=/data 0 0 unexpected",
        "/data/pap/state/issuer /var/lib/other/../pap-issuer none bind,x-systemd.requires-mounts-for=/data 0 0",
        '"/data/pap/state/issuer" "/var/lib/pap-issuer" none bind,x-systemd.requires-mounts-for=/data 0 0',
        "/data/pap/state/issuer var/lib/pap-issuer none bind,x-systemd.requires-mounts-for=/data 0 0",
    ],
)
def test_conflicting_reserved_entries_are_rejected(storage, entry):
    with pytest.raises(storage.PreparationError, match="fstab_conflicting"):
        storage.missing_fstab_entries(entry.encode() + b"\n")


def test_duplicate_bind_entries_are_rejected(storage):
    with pytest.raises(storage.PreparationError, match="fstab_conflicting"):
        storage.missing_fstab_entries(canonical(storage) * 2)


@pytest.mark.parametrize("raw", [b"\x00", b"\xff", b"#" * (1024 * 1024 + 1)])
def test_invalid_fstab_bytes_are_rejected(storage, raw):
    with pytest.raises(storage.PreparationError, match="fstab_invalid"):
        storage.missing_fstab_entries(raw)


def test_mount_inventory_preserves_stacked_records_and_decodes_paths(storage):
    raw = "31 1 8:1 / /data rw - ext4 /dev/vda rw\n32 1 8:1 /pap/state/issuer /var/lib/pap-issuer rw - ext4 /dev/vda rw\n33 1 8:2 /elsewhere /var/lib/pap-issuer ro - ext4 /dev/vdb ro\n"
    inventory = storage.mount_inventory(raw)
    assert len(inventory["/var/lib/pap-issuer"]) == 2
    assert inventory["/var/lib/pap-issuer"][1]["readonly"] is True
    assert storage.unescape(r"/one\040two") == "/one two"


@pytest.fixture
def bound_storage(storage, monkeypatch):
    metadata = {storage.DATA: SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)}
    inventory = {"/data": [{"device": "8:1", "root": "/", "fstype": "ext4", "readonly": False}]}
    for index, (_, source, target, mode) in enumerate(storage.MAPPINGS):
        info = SimpleNamespace(st_mode=stat.S_IFDIR | mode, st_uid=0, st_gid=0, st_dev=1, st_ino=index + 10)
        metadata[source] = metadata[target] = info
        inventory[str(target)] = [
            {
                "device": "8:1",
                "root": "/" + source.relative_to(storage.DATA).as_posix(),
                "fstype": "ext4",
                "readonly": False,
            }
        ]
    monkeypatch.setattr(storage, "safe_ancestors", lambda _: None)
    monkeypatch.setattr(storage, "expected_owner", lambda *args, **kwargs: {(0, 0)})
    monkeypatch.setattr(storage, "directory_info", lambda path, *args, **kwargs: metadata.get(path))
    original = storage.Path.lstat
    monkeypatch.setattr(
        storage.Path,
        "lstat",
        lambda path, *args, **kwargs: metadata[path] if path in metadata else original(path, *args, **kwargs),
    )
    return storage, inventory, metadata


def test_exact_existing_bind_plan_is_idempotent(bound_storage):
    storage, inventory, _ = bound_storage
    result = storage.storage_plan(inventory)
    assert len(result) == 5
    assert all(
        item["already_bound"] and not item["create_target"] and not item["create_source"] for item in result
    )


@pytest.mark.parametrize(
    "change", ["wrong_root", "wrong_device", "read_only", "wrong_inode", "stacked", "nested"]
)
def test_wrong_existing_mounts_are_rejected(bound_storage, change):
    storage, inventory, metadata = bound_storage
    record = inventory["/var/lib/pap-issuer"][0]
    if change == "wrong_root":
        record["root"] = "/another-source"
    elif change == "wrong_device":
        record["device"] = "8:2"
    elif change == "read_only":
        record["readonly"] = True
    elif change == "wrong_inode":
        metadata[Path("/var/lib/pap-issuer")] = SimpleNamespace(st_dev=2, st_ino=20)
    elif change == "stacked":
        inventory["/var/lib/pap-issuer"].append(dict(record))
    else:
        inventory["/etc/pap/unexpected"] = [dict(record)]
    with pytest.raises(storage.PreparationError):
        storage.storage_plan(inventory)


def test_missing_acknowledgement_is_rejected_before_host_reads(storage):
    with pytest.raises(storage.PreparationError, match="acknowledgement"):
        storage.require_host(False)
