#!/usr/bin/env python3
"""Read-only host prerequisites and persistent-mount checks for a dedicated PAP VM.

This program creates no files, changes no services, opens no network connections,
and prints no environment variables, credential files or command stderr.
"""

import argparse
import grp
import json
import os
import pwd
import re
import stat
import subprocess
import sys
from pathlib import Path, PurePosixPath

GIB = 1024**3
PERSISTENT_ROOT = Path("/data")
MAPPINGS = {
    "issuer": (Path("/data/pap/state/issuer"), Path("/var/lib/pap-issuer")),
    "kms": (Path("/data/pap/state/kms"), Path("/var/lib/pap-kms")),
    "proxy": (Path("/data/pap/state/proxy"), Path("/var/lib/pap-proxy")),
    "config": (Path("/data/pap/config"), Path("/etc/pap")),
    "software": (Path("/data/pap/software"), Path("/opt/pap")),
}
ROLES = ("pap-issuer", "pap-kms", "pap-admin", "pap-app", "pap-proxy")


def enable_enroller():
    global ROLES
    MAPPINGS["enroller"] = (Path("/data/pap/state/enroller"), Path("/var/lib/pap-enroller"))
    if "pap-enroller" not in ROLES:
        ROLES = (*ROLES, "pap-enroller")


def unescape_mount(value):
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)


def mounts():
    result = {}
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        before, after = line.split(" - ", 1)
        fields, fs = before.split(), after.split()
        result[unescape_mount(fields[4])] = {
            "device": fields[2],
            "root": unescape_mount(fields[3]),
            "fstype": fs[0],
            "readonly": "ro" in fields[5].split(","),
        }
    return result


def command(argv):
    """Only execute the root-owned fixed system binary selected by the caller."""
    binary = Path(argv[0]).resolve(strict=True)
    for path in (binary, *binary.parents):
        info = path.stat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise ValueError("untrusted system binary")
    return subprocess.run(
        [str(binary), *argv[1:]],
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )


def check_storage(add, role="all", minimum_free=2 * GIB, service_view=False):
    """Verify backing device AND mount root, rather than accepting any bind mount."""
    try:
        inventory = mounts()
    except (OSError, ValueError, IndexError):
        add("persistent_mount_inventory", False, "cannot read Linux mount metadata")
        return
    data = inventory.get(str(PERSISTENT_ROOT))
    try:
        root_info = PERSISTENT_ROOT.lstat()
        data_ok = stat.S_ISDIR(root_info.st_mode) and data is not None
    except OSError:
        data_ok = False
    add("persistent_data_mount", data_ok, "require /data to be a real dedicated mount, not a symlink")
    if not data_ok:
        return
    if not service_view:
        add(
            "persistent_data_writable",
            not data["readonly"],
            "the persistent /data filesystem must be writable on the host",
        )
    volatile = {"tmpfs", "ramfs", "overlay", "aufs", "squashfs", "nfs", "nfs4", "cifs", "9p"}
    add(
        "persistent_filesystem_type",
        data["fstype"] not in volatile,
        "require nonvolatile storage with tested local locking and fsync semantics",
    )
    try:
        parent = Path("/data/pap").lstat()
        parent_ok = (
            stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and not stat.S_IMODE(parent.st_mode) & 0o077
        )
    except OSError:
        parent_ok = False
    add("private_persistence_parent", parent_ok, "/data/pap must be a root-owned directory with mode 0700")
    try:
        usage = os.statvfs(PERSISTENT_ROOT)
        add(
            "persistent_storage_capacity",
            usage.f_bavail * usage.f_frsize >= minimum_free,
            "require the configured minimum available persistent disk capacity",
        )
    except OSError:
        add("persistent_storage_capacity", False, "cannot inspect available persistent disk capacity")
    selected = set(MAPPINGS) if role == "all" else {role, "config", "software"}
    for name in sorted(selected):
        source, target = MAPPINGS[name]
        mapping = inventory.get(str(target))
        expected_root = str(PurePosixPath(data["root"]) / source.relative_to(PERSISTENT_ROOT).as_posix())
        try:
            source_stat, target_stat = source.lstat(), target.lstat()
            directory_ok = stat.S_ISDIR(source_stat.st_mode) and stat.S_ISDIR(target_stat.st_mode)
            expected_uid = 0
            if name in {"issuer", "kms", "proxy", "enroller"}:
                try:
                    expected_uid = pwd.getpwnam(
                        {
                            "issuer": "pap-issuer",
                            "kms": "pap-kms",
                            "proxy": "pap-proxy",
                            "enroller": "pap-enroller",
                        }[name]
                    ).pw_uid
                except KeyError:
                    pass
                safe_modes = (
                    not (stat.S_IMODE(source_stat.st_mode) | stat.S_IMODE(target_stat.st_mode)) & 0o077
                )
                if name == "enroller":
                    safe_modes = (
                        stat.S_IMODE(source_stat.st_mode) == stat.S_IMODE(target_stat.st_mode) == 0o710
                    )
                    expected_gid = 0
                    try:
                        expected_gid = grp.getgrnam("pap-kms").gr_gid
                    except KeyError:
                        pass
                    safe_modes = safe_modes and source_stat.st_gid == target_stat.st_gid == expected_gid
            else:
                safe_modes = (
                    not (stat.S_IMODE(source_stat.st_mode) | stat.S_IMODE(target_stat.st_mode)) & 0o022
                )
            directory_ok = (
                directory_ok and safe_modes and source_stat.st_uid == target_stat.st_uid == expected_uid
            )
            same_inode = source_stat.st_dev == target_stat.st_dev and source_stat.st_ino == target_stat.st_ino
        except OSError:
            directory_ok = same_inode = False
        safe = (
            directory_ok
            and same_inode
            and mapping is not None
            and mapping["device"] == data["device"]
            and mapping["root"] == expected_root
        )
        add(f"persistent_{name}_mapping", safe, f"require {source} bound exactly to {target}")
        if name in {"issuer", "kms", "proxy", "enroller"}:
            add(
                f"persistent_{name}_writable",
                mapping is not None and not mapping["readonly"],
                "the service's own persistent state mount must be writable",
            )


def check_system(add, acknowledged):
    add("linux_kernel", sys.platform == "linux", "this profile requires a Linux VM")
    add("root_preflight", os.geteuid() == 0, "run the read-only preflight as host root")
    add(
        "dedicated_host_acknowledged",
        acknowledged,
        "the host must be dedicated to PAP, not a shared research or application VM",
    )
    try:
        pid1 = Path("/proc/1/comm").read_text().strip()
    except OSError:
        pid1 = "unavailable"
    add(
        "systemd_pid1",
        pid1 == "systemd" and Path("/run/systemd/system").is_dir(),
        "require a booted host systemd instance as PID 1",
    )
    try:
        result = command(["/usr/bin/systemctl", "--version"])
        match = re.match(r"systemd (\d+)\b", result.stdout)
        add(
            "systemd_version",
            result.returncode == 0 and match is not None and int(match.group(1)) >= 252,
            "require systemd 252 or later",
        )
        result = command(["/usr/bin/systemctl", "is-system-running"])
        add(
            "systemd_manager_health",
            result.returncode == 0 and result.stdout.strip() == "running",
            "require systemd running without degraded or maintenance state",
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        add("systemd_management", False, "cannot validate the root-owned systemd tooling")
    try:
        controllers = set(Path("/sys/fs/cgroup/cgroup.controllers").read_text().split())
        add(
            "cgroup_v2_controllers",
            {"cpu", "memory", "pids"} <= controllers,
            "require cgroup v2 CPU, memory and task-count controls",
        )
    except OSError:
        add("cgroup_v2_controllers", False, "cannot inspect cgroup v2 controllers")
    for namespace in ("mnt", "pid", "net", "ipc", "uts", "cgroup"):
        add(
            f"namespace_{namespace}_present",
            Path(f"/proc/self/ns/{namespace}").exists(),
            "namespace handles must exist; enforcement still requires the isolation acceptance test",
        )
    try:
        status = Path("/proc/1/status").read_text()
        effective = re.search(r"^CapEff:\s+([0-9a-fA-F]+)$", status, re.MULTILINE)
        mask = int(effective.group(1), 16) if effective else 0
        required = (1 << 0) | (1 << 1) | (1 << 6) | (1 << 7) | (1 << 21)
        add(
            "systemd_host_capabilities",
            mask & required == required,
            "host init needs CHOWN, DAC_OVERRIDE, SETGID, SETUID and SYS_ADMIN for the supplied isolation profile",
        )
    except (OSError, ValueError):
        add("systemd_host_capabilities", False, "cannot inspect host-init capabilities")
    try:
        add(
            "swap_disabled",
            len(Path("/proc/swaps").read_text().splitlines()) <= 1,
            "disable swap for the integrated-storage OpenBao profile without mlock",
        )
    except OSError:
        add("swap_disabled", False, "cannot inspect active swap")
    try:
        result = command(["/usr/bin/timedatectl", "show", "--property=NTPSynchronized", "--value"])
        add(
            "clock_synchronized",
            result.returncode == 0 and result.stdout.strip() == "yes",
            "short-lived credential validation requires a synchronized clock",
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        add("clock_synchronized", False, "cannot verify clock synchronization")


def check_installed(add):
    identities = {}
    for name in ROLES:
        try:
            identity = pwd.getpwnam(name)
            identities[name] = identity
            safe = (
                identity.pw_uid > 0
                and identity.pw_gid > 0
                and identity.pw_shell in ("/usr/sbin/nologin", "/sbin/nologin", "/bin/false")
            )
            secondary = [
                group for group in grp.getgrall() if name in group.gr_mem and group.gr_gid != identity.pw_gid
            ]
            secondary_ok = not secondary
            if name == "pap-enroller":
                try:
                    secondary_ok = {group.gr_gid for group in secondary} == {
                        pwd.getpwnam("pap-issuer").pw_gid
                    } and identity.pw_gid == pwd.getpwnam("pap-kms").pw_gid
                except KeyError:
                    secondary_ok = False
            add(
                f"identity_{name}",
                safe and secondary_ok,
                "require a distinct nonroot service account without login or supplementary groups",
            )
        except KeyError:
            add(f"identity_{name}", False, "dedicated service account is not installed")
    add(
        "distinct_service_uids",
        len(identities) == len(ROLES) and len({value.pw_uid for value in identities.values()}) == len(ROLES),
        "all five service UIDs must be distinct",
    )
    expected = {
        "pap-authority.service": "pap-issuer",
        "pap-openbao.service": "pap-kms",
        "pap-caddy.service": "pap-proxy",
    }
    if "pap-enroller" in ROLES:
        expected["pap-enroller.service"] = "pap-enroller"
    for unit, identity in expected.items():
        try:
            result = command(
                [
                    "/usr/bin/systemctl",
                    "show",
                    unit,
                    "--property=User",
                    "--property=NoNewPrivileges",
                    "--property=ProtectSystem",
                    "--property=PrivateTmp",
                ]
            )
            properties = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
            correct = (
                properties.get("User") == identity
                and properties.get("NoNewPrivileges") == "yes"
                and properties.get("ProtectSystem") == "strict"
                and properties.get("PrivateTmp") == "yes"
            )
            add(
                f"unit_{unit}",
                result.returncode == 0 and correct,
                "require the expected UID and loaded systemd sandbox settings",
            )
        except (OSError, ValueError, subprocess.SubprocessError):
            add(f"unit_{unit}", False, "cannot inspect the loaded service settings")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acknowledge-dedicated-vm", action="store_true")
    parser.add_argument(
        "--with-enroller", action="store_true", help="also validate the local certificate broker"
    )
    parser.add_argument(
        "--installed", action="store_true", help="also inspect installed accounts and loaded unit properties"
    )
    parser.add_argument(
        "--storage-only",
        action="store_true",
        help="only validate persistent mappings, suitable for a service pre-start check",
    )
    parser.add_argument("--role", choices=("all", "issuer", "kms", "proxy", "enroller"), default="all")
    parser.add_argument("--minimum-free-gib", type=int, choices=range(1, 101), default=2)
    arguments = parser.parse_args()
    if arguments.with_enroller or arguments.role == "enroller":
        enable_enroller()
    results = []

    def add(name, passed, requirement):
        results.append({"check": name, "passed": bool(passed), "requirement": requirement})

    if not arguments.storage_only:
        check_system(add, arguments.acknowledge_dedicated_vm)
    check_storage(add, arguments.role, arguments.minimum_free_gib * GIB, service_view=arguments.storage_only)
    if arguments.installed and not arguments.storage_only:
        check_installed(add)
    passed = all(item["passed"] for item in results)
    print(
        json.dumps(
            {
                "profile": "instabox-dedicated-pap-vm-v0.2",
                "read_only": True,
                "host_prerequisites_passed": passed,
                "production_accepted": False,
                "checks": results,
                "remaining_acceptance": [
                    "verify provider idle-pause and public-request wake behavior on the current plan",
                    "verify public HTTPS proxy behavior and TLS trust without exposing OpenBao or administration",
                    "test enforced systemd isolation and authenticated OpenBao access on this VM",
                    "verify provider storage protection, independent backups and restore",
                    "verify cold restart, bind mounts, auto-unseal and certificate renewal recovery",
                    "perform real Netlify enrollment, operation, renewal and revocation acceptance",
                ],
            },
            indent=2,
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
