#!/usr/bin/env python3
"""Exercise actual storage helper file operations only in a disposable root Linux container."""

import hashlib
import importlib.util
import json
import os
import stat
import sys
from pathlib import Path


def main():
    if sys.platform != "linux" or os.geteuid() != 0 or not Path("/.dockerenv").is_file():
        raise RuntimeError("disposable Docker Linux root required")
    source = Path(__file__).with_name("prepare-storage.py")
    specification = importlib.util.spec_from_file_location("pap_storage_prepare", source)
    storage = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(storage)
    fixture = Path("/fixture")
    if fixture.stat().st_uid != 0 or stat.S_IMODE(fixture.stat().st_mode) != 0o700 or any(fixture.iterdir()):
        raise RuntimeError("fresh private /fixture tmpfs required")
    checks = {}
    fstab = fixture / "fstab"
    original = b"# existing host configuration\nUUID=unchanged / ext4 defaults 0 1\n"
    fstab.write_bytes(original)
    fstab.chmod(0o640)
    os.setxattr(fstab, "user.pap-test", b"preserved")
    snapshot = storage.read_fstab(fstab)
    original_inode = fstab.stat().st_ino
    checks["append_changes_file"] = storage.append_fstab(snapshot, fstab) is True
    current, info = storage.read_fstab(fstab)
    checks["unrelated_bytes_preserved_exactly"] = current.startswith(original)
    checks["all_five_entries_present"] = storage.missing_fstab_entries(current) == []
    checks["fstab_replaced_atomically"] = info.st_ino != original_inode
    checks["fstab_owner_group_mode_preserved"] = (
        info.st_uid == info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o640
    )
    checks["fstab_extended_attribute_preserved"] = os.getxattr(fstab, "user.pap-test") == b"preserved"
    before = fstab.stat()
    checks["complete_fstab_is_not_rewritten"] = (
        storage.append_fstab((current, info), fstab) is False and fstab.stat().st_ino == before.st_ino
    )
    stale = storage.read_fstab(fstab)
    # Use an independent incomplete fixture to exercise optimistic concurrency.
    race = fixture / "race-fstab"
    race.write_bytes(original)
    race.chmod(0o600)
    stale = storage.read_fstab(race)
    changed = original + b"# concurrent administrator edit\n"
    race.write_bytes(changed)
    try:
        storage.append_fstab(stale, race)
    except storage.PreparationError:
        checks["concurrent_fstab_change_is_preserved"] = race.read_bytes() == changed
    else:
        checks["concurrent_fstab_change_is_preserved"] = False
    alias = fixture / "fstab-link"
    alias.symlink_to(fstab)
    try:
        storage.read_fstab(alias)
    except OSError:
        checks["fstab_symlink_is_rejected"] = True
    else:
        checks["fstab_symlink_is_rejected"] = False
    directory = fixture / "software"
    storage.create_directory(directory, 0o755)
    metadata = directory.stat()
    checks["new_directory_has_exact_root_ownership_mode"] = (
        metadata.st_uid == metadata.st_gid == 0 and stat.S_IMODE(metadata.st_mode) == 0o755
    )
    private = fixture / "private-state"
    storage.create_directory(private, 0o700)
    (private / "existing-state").write_bytes(b"preserve")
    try:
        storage.directory_info(private, 0o700, {(0, 0)}, empty=True)
    except storage.PreparationError:
        checks["nonempty_unmounted_directory_rejected"] = (
            private / "existing-state"
        ).read_bytes() == b"preserve"
    else:
        checks["nonempty_unmounted_directory_rejected"] = False
    checks["no_temporary_fstab_files_left"] = not list(fixture.glob(".pap-fstab-*"))
    result = {
        "passed": all(checks.values()),
        "checks": checks,
        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
        "probe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "scope": "Actual Linux atomic fstab helper operations and protected directory checks",
        "not_verified": [
            "real /data filesystem",
            "bind mount execution",
            "systemd reload",
            "Instabox host preparation",
        ],
    }
    print(json.dumps(result, indent=2))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
