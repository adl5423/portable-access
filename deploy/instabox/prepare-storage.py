#!/usr/bin/env python3
"""Prepare only PAP's five persistent bind mounts on a designated fresh Linux VM.

The default prints a read-only plan. --apply creates protected directories,
preserves and atomically appends the required fstab entries, and mounts only the
five literal mappings. It never runs mount -a, initializes keys, or starts PAP.
"""

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import posixpath
import pwd
import re
import stat
import subprocess
import sys
import uuid
from pathlib import Path, PurePosixPath

DATA = Path("/data")
FSTAB = Path("/etc/fstab")
MAPPINGS = (
    ("issuer", Path("/data/pap/state/issuer"), Path("/var/lib/pap-issuer"), 0o700),
    ("kms", Path("/data/pap/state/kms"), Path("/var/lib/pap-kms"), 0o700),
    ("proxy", Path("/data/pap/state/proxy"), Path("/var/lib/pap-proxy"), 0o700),
    ("config", Path("/data/pap/config"), Path("/etc/pap"), 0o755),
    ("software", Path("/data/pap/software"), Path("/opt/pap"), 0o755),
)
ENROLLER_MAPPING = ("enroller", Path("/data/pap/state/enroller"), Path("/var/lib/pap-enroller"), 0o710)
OPTIONS = "bind,x-systemd.requires-mounts-for=/data"
MAX_FSTAB = 1024 * 1024
LOCAL_FILESYSTEMS = {"ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "zfs"}


class PreparationError(ValueError):
    pass


def require_host(acknowledged):
    if not acknowledged or sys.platform != "linux" or os.getuid() != 0 or os.geteuid() != 0:
        raise PreparationError("root_linux_dedicated_host_acknowledgement_required")
    if Path("/proc/1/comm").read_text().strip() != "systemd":
        raise PreparationError("booted_host_systemd_required")
    if os.stat("/proc/1/ns/mnt").st_ino != os.stat("/proc/self/ns/mnt").st_ino:
        raise PreparationError("host_mount_namespace_required")


def safe_ancestors(path):
    for ancestor in reversed(path.parents):
        info = ancestor.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise PreparationError("unsafe_root_directory_ancestor")


def unescape(value):
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match[1], 8)), value)


def mount_inventory(raw=None):
    if raw is None:
        raw = Path("/proc/self/mountinfo").read_text()
    result = {}
    try:
        for line in raw.splitlines():
            before, after = line.split(" - ", 1)
            fields, filesystem = before.split(), after.split()
            record = {
                "device": fields[2],
                "root": unescape(fields[3]),
                "fstype": filesystem[0],
                "readonly": "ro" in fields[5].split(","),
            }
            result.setdefault(unescape(fields[4]), []).append(record)
    except (ValueError, IndexError):
        raise PreparationError("mount_inventory_invalid") from None
    return result


def canonical_path(value):
    value = unescape(value).strip("\"'")
    return posixpath.normpath("/" + value.lstrip("/")) if value else ""


def reserved_path(value):
    candidate = PurePosixPath(canonical_path(value))
    roots = [Path("/data/pap"), *(target for _, _, target, _ in MAPPINGS)]
    return any(candidate == root or root in candidate.parents for root in roots)


def missing_fstab_entries(raw):
    """Preserve unrelated lines; reject aliases and conflicts involving PAP paths."""
    if not isinstance(raw, bytes) or len(raw) > MAX_FSTAB or b"\0" in raw:
        raise PreparationError("fstab_invalid")
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise PreparationError("fstab_invalid") from None
    expected = {str(target): str(source) for _, source, target, _ in MAPPINGS}
    present = set()
    for line in text.splitlines():
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if len(fields) < 2:
            if reserved_path(fields[0]):
                raise PreparationError("fstab_conflicting_pap_entry")
            continue
        source, target = canonical_path(fields[0]), canonical_path(fields[1])
        if not reserved_path(source) and not reserved_path(target):
            continue
        if (
            len(fields) < 6
            or target not in expected
            or source != expected[target]
            or fields[0] != source
            or fields[1] != target
            or fields[2] != "none"
            or set(fields[3].split(",")) != set(OPTIONS.split(","))
            or len(fields[3].split(",")) != 2
            or fields[4:6] != ["0", "0"]
            or (len(fields) > 6 and not fields[6].startswith("#"))
            or target in present
        ):
            raise PreparationError("fstab_conflicting_pap_entry")
        present.add(target)
    return [(source, target) for _, source, target, _ in MAPPINGS if str(target) not in present]


def read_fstab(path=FSTAB):
    safe_ancestors(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o022
            or info.st_size > MAX_FSTAB
        ):
            raise PreparationError("fstab_ownership_or_type_invalid")
        chunks, size = [], 0
        while True:
            chunk = os.read(descriptor, 65536)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_FSTAB:
                raise PreparationError("fstab_invalid")
        raw = b"".join(chunks)
        current = path.lstat()
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise PreparationError("fstab_changed_during_read")
        missing_fstab_entries(raw)
        return raw, info
    finally:
        os.close(descriptor)


def append_fstab(snapshot, path=FSTAB):
    raw, info = snapshot
    missing = missing_fstab_entries(raw)
    if not missing:
        return False
    extra = b"" if not raw or raw.endswith(b"\n") else b"\n"
    extra += b"# PAP persistent directories; managed by prepare-storage.py\n"
    extra += "".join(f"{source} {target} none {OPTIONS} 0 0\n" for source, target in missing).encode()
    if len(raw) + len(extra) > MAX_FSTAB:
        raise PreparationError("fstab_result_too_large")
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    name = ".pap-fstab-" + uuid.uuid4().hex
    descriptor = None
    try:
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        os.fchown(descriptor, info.st_uid, info.st_gid)
        os.fchmod(descriptor, stat.S_IMODE(info.st_mode))
        with os.fdopen(os.dup(descriptor), "wb") as output:
            output.write(raw + extra)
            output.flush()
        # Keep security labels and ACL metadata where the filesystem provides them.
        for attribute in os.listxattr(path, follow_symlinks=False):
            os.setxattr(descriptor, attribute, os.getxattr(path, attribute, follow_symlinks=False))
        os.fsync(descriptor)
        current_raw, current_info = read_fstab(path)
        if current_raw != raw or (
            current_info.st_dev,
            current_info.st_ino,
            current_info.st_mtime_ns,
            current_info.st_ctime_ns,
        ) != (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns):
            raise PreparationError("fstab_changed_concurrently")
        os.replace(name, path.name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
        return True
    finally:
        if descriptor is not None:
            os.close(descriptor)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(name, dir_fd=parent)
        os.close(parent)


def expected_owner(role, *, bound):
    owners = {(0, 0)}
    if bound and role in {"issuer", "kms", "proxy", "enroller"}:
        try:
            account = pwd.getpwnam("pap-" + role)
        except KeyError:
            return owners
        if account.pw_uid == 0 or account.pw_gid == 0:
            raise PreparationError("privileged_service_identity")
        owners.add((account.pw_uid, account.pw_gid))
    return owners


def directory_info(path, mode, owners, *, empty):
    # Check all currently existing ancestors. Missing descendants will be created
    # only after the entire plan and fstab have passed validation.
    for ancestor in reversed(path.parents):
        try:
            info = ancestor.lstat()
        except FileNotFoundError:
            return None
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise PreparationError("unsafe_root_directory_ancestor")
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if (
        not stat.S_ISDIR(info.st_mode)
        or (info.st_uid, info.st_gid) not in owners
        or stat.S_IMODE(info.st_mode) != mode
    ):
        raise PreparationError("unsafe_existing_pap_directory")
    if empty:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            actual = os.fstat(descriptor)
            if (actual.st_dev, actual.st_ino) != (info.st_dev, info.st_ino):
                raise PreparationError("directory_changed_during_inspection")
            with os.scandir(descriptor) as entries:
                if next(entries, None) is not None:
                    raise PreparationError("unmounted_pap_directory_is_not_empty")
        finally:
            os.close(descriptor)
    return info


def storage_plan(inventory=None):
    inventory = mount_inventory() if inventory is None else inventory
    data_records = inventory.get(str(DATA), [])
    safe_ancestors(DATA)
    data = DATA.lstat()
    if (
        len(data_records) != 1
        or not stat.S_ISDIR(data.st_mode)
        or data.st_uid != 0
        or stat.S_IMODE(data.st_mode) & 0o022
        or data_records[0]["readonly"]
        or data_records[0]["fstype"] not in LOCAL_FILESYSTEMS
    ):
        raise PreparationError("safe_persistent_data_mount_required")
    data_mount = data_records[0]
    directory_info(Path("/data/pap"), 0o700, {(0, 0)}, empty=False)
    directory_info(Path("/data/pap/state"), 0o700, {(0, 0)}, empty=False)
    targets = {str(target) for _, _, target, _ in MAPPINGS}
    for mountpoint in inventory:
        if reserved_path(mountpoint) and mountpoint not in targets:
            raise PreparationError("unexpected_mount_in_pap_storage")
    plan = []
    for role, source, target, mode in MAPPINGS:
        safe_ancestors(target)
        records = inventory.get(str(target), [])
        if len(records) > 1:
            raise PreparationError("stacked_pap_mounts_rejected")
        bound = bool(records)
        owners = expected_owner(role, bound=bound)
        source_info = directory_info(source, mode, owners, empty=not bound)
        target_info = directory_info(target, mode, owners, empty=not bound)
        if bound:
            expected_root = str(PurePosixPath(data_mount["root"]) / source.relative_to(DATA).as_posix())
            record = records[0]
            if (
                source_info is None
                or target_info is None
                or record["device"] != data_mount["device"]
                or record["root"] != expected_root
                or record["fstype"] != data_mount["fstype"]
                or record["readonly"]
                or (source_info.st_dev, source_info.st_ino) != (target_info.st_dev, target_info.st_ino)
            ):
                raise PreparationError("conflicting_pap_bind_mount")
        plan.append(
            {
                "role": role,
                "source": str(source),
                "target": str(target),
                "mode": oct(mode),
                "already_bound": bound,
                "create_source": source_info is None,
                "create_target": target_info is None,
            }
        )
    return plan


def create_directory(path, mode):
    safe_ancestors(path)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.mkdir(path.name, mode=0o700, dir_fd=parent)
        descriptor = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            os.fchown(descriptor, 0, 0)
            os.fchmod(descriptor, mode)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(parent)
    finally:
        os.close(parent)


def command(binary, *arguments):
    executable = Path(binary).resolve(strict=True)
    safe_ancestors(executable)
    info = executable.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
        raise PreparationError("untrusted_system_binary")
    completed = subprocess.run(
        [str(executable), *arguments],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=20,
        check=False,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )
    if completed.returncode != 0:
        raise PreparationError("host_storage_command_failed")


@contextlib.contextmanager
def preparation_lock():
    path = Path("/run/pap-storage-prepare.lock")
    safe_ancestors(path)
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise PreparationError("unsafe_preparation_lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(descriptor)


def prepare(*, apply):
    snapshot = read_fstab()
    missing = missing_fstab_entries(snapshot[0])
    plan = storage_plan()
    if not apply:
        return {
            "read_only": True,
            "applied": False,
            "mappings": plan,
            "fstab_entries_to_append": len(missing),
            "fstab_sha256": hashlib.sha256(snapshot[0]).hexdigest(),
        }
    for path, mode in ((Path("/data/pap"), 0o700), (Path("/data/pap/state"), 0o700)):
        if not path.exists():
            create_directory(path, mode)
    for entry in plan:
        if entry["create_source"]:
            create_directory(Path(entry["source"]), int(entry["mode"], 8))
        if entry["create_target"]:
            create_directory(Path(entry["target"]), int(entry["mode"], 8))
    storage_plan()
    changed = append_fstab(snapshot)
    mounted = []
    for entry in plan:
        if entry["already_bound"]:
            continue
        current = next(item for item in storage_plan() if item["role"] == entry["role"])
        if not current["already_bound"]:
            command("/usr/bin/mount", "--no-mtab", "--bind", entry["source"], entry["target"])
            mounted.append(entry["role"])
        if not next(item for item in storage_plan() if item["role"] == entry["role"])["already_bound"]:
            raise PreparationError("bind_mount_verification_failed")
    if changed or mounted:
        command("/usr/bin/systemctl", "daemon-reload")
    final = storage_plan()
    final_fstab, _ = read_fstab()
    if missing_fstab_entries(final_fstab) or not all(entry["already_bound"] for entry in final):
        raise PreparationError("storage_preparation_incomplete")
    return {
        "read_only": False,
        "applied": True,
        "storage_prepared": True,
        "fstab_changed": changed,
        "mounts_created": mounted,
        "mappings": final,
        "fstab_sha256": hashlib.sha256(final_fstab).hexdigest(),
        "production_accepted": False,
    }


def main():
    global MAPPINGS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acknowledge-dedicated-vm", action="store_true")
    parser.add_argument(
        "--with-enroller",
        action="store_true",
        help="also prepare the fixed local certificate broker state bind",
    )
    parser.add_argument(
        "--apply", action="store_true", help="perform the reviewed bounded storage preparation"
    )
    arguments = parser.parse_args()
    if arguments.with_enroller and ENROLLER_MAPPING not in MAPPINGS:
        MAPPINGS = (*MAPPINGS, ENROLLER_MAPPING)
    try:
        require_host(arguments.acknowledge_dedicated_vm)
        os.umask(0o077)
        if arguments.apply:
            with preparation_lock():
                result = prepare(apply=True)
        else:
            result = prepare(apply=False)
        print(json.dumps(result, indent=2))
        return 0
    except PreparationError as error:
        print(
            json.dumps(
                {
                    "applied": False,
                    "storage_prepared": False,
                    "error": str(error),
                    "may_require_inspection": bool(arguments.apply),
                    "production_accepted": False,
                }
            )
        )
        return 1
    except (OSError, subprocess.SubprocessError):
        print(
            json.dumps(
                {
                    "applied": False,
                    "storage_prepared": False,
                    "error": "host_storage_unavailable",
                    "may_require_inspection": bool(arguments.apply),
                    "production_accepted": False,
                }
            )
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
