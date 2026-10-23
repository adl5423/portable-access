#!/usr/bin/env python3
"""Exercise bounded state adoption on actual files in a disposable Docker /var/lib tmpfs."""

import hashlib
import importlib.util
import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace


def run_probe():
    if sys.platform != "linux" or os.geteuid() != 0 or not Path("/.dockerenv").is_file():
        raise RuntimeError("installer state probe requires root in a disposable Docker Linux container")
    specification = importlib.util.spec_from_file_location(
        "pap_installer", Path(__file__).with_name("install.py")
    )
    installer = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(installer)
    paths = sorted(installer.BOOTSTRAP_STATE_DIRECTORIES) + [Path("/var/lib/pap-outside-fixture")]
    if any(path.exists() or path.is_symlink() for path in paths):
        raise RuntimeError("refusing to replace existing state fixture paths")
    checks = {}
    scratch = Path(tempfile.mkdtemp(prefix="pap-install-", dir="/tmp"))
    try:
        for index, path in enumerate(paths[:3]):
            path.mkdir(mode=0o700)
            target_uid = 60001 + index
            installer.directory(path, target_uid, target_uid, 0o700)
            after = path.stat()
            checks[f"adopts_empty_{path.name}"] = (
                after.st_uid == after.st_gid == target_uid and stat.S_IMODE(after.st_mode) == 0o700
            )
            installer.directory(path, target_uid, target_uid, 0o700)
            checks[f"matching_{path.name}_is_idempotent"] = path.stat().st_uid == target_uid
            os.chown(path, 0, 0)
        target = Path("/var/lib/pap-issuer")
        marker = target / "existing-state"
        marker.write_bytes(b"preserve")
        try:
            installer.directory(target, 60001, 60001, 0o700)
        except ValueError:
            checks["populated_state_is_rejected_without_chown"] = (
                target.stat().st_uid == marker.stat().st_uid == 0
            )
        else:
            checks["populated_state_is_rejected_without_chown"] = False
        marker.unlink()
        target.chmod(0o750)
        checks["nonprivate_state_is_rejected"] = not installer.adopt_empty_state_directory(
            target, 60001, 60001, 0o700
        )
        target.chmod(0o700)
        outside = paths[-1]
        outside.mkdir(mode=0o700)
        checks["arbitrary_empty_path_is_rejected"] = not installer.adopt_empty_state_directory(
            outside, 60001, 60001, 0o700
        )
        target.rmdir()
        target.symlink_to(outside, target_is_directory=True)
        try:
            installer.adopt_empty_state_directory(target, 60001, 60001, 0o700)
        except OSError:
            checks["symlink_is_rejected_without_target_chown"] = outside.stat().st_uid == 0
        else:
            checks["symlink_is_rejected_without_target_chown"] = False
        target.unlink()
        target.mkdir(mode=0o700)
        original_fstat = installer.os.fstat
        alternate = scratch.stat()

        def mismatched_fstat(descriptor):
            info = original_fstat(descriptor)
            return SimpleNamespace(
                st_dev=alternate.st_dev,
                st_ino=alternate.st_ino,
                st_uid=info.st_uid,
                st_gid=info.st_gid,
                st_mode=info.st_mode,
            )

        installer.os.fstat = mismatched_fstat
        try:
            checks["inode_mismatch_is_rejected_without_chown"] = (
                not installer.adopt_empty_state_directory(target, 60001, 60001, 0o700)
                and target.stat().st_uid == 0
            )
        finally:
            installer.os.fstat = original_fstat
        return {
            "passed": all(checks.values()),
            "checks": checks,
            "installer_sha256": hashlib.sha256(Path(installer.__file__).read_bytes()).hexdigest(),
            "probe_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "scope": "Actual Linux filesystem ownership transfer, safe refusals, injected inode mismatch",
            "not_verified": ["physical Instabox bind mounts", "host provisioning", "production daemon boot"],
        }
    finally:
        for path in paths:
            if path.is_symlink():
                path.unlink()
            elif path.exists():
                shutil.rmtree(path)
        shutil.rmtree(scratch)


if __name__ == "__main__":
    result = run_probe()
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result["passed"] else 1)
