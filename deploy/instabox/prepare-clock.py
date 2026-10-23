#!/usr/bin/env python3
"""Configure an authenticated time client on a fresh Debian PAP host.

Preserves the provider's masked timesyncd unit. Refuses existing chrony policy or
another active time daemon. No public NTP or command listener is enabled.
"""

import fcntl
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

CONFIG = b"""# PAP dedicated-host authenticated clock client
server time.cloudflare.com iburst nts
server nts.netnod.se iburst nts
server gbg1.nts.netnod.se iburst nts
minsources 2
driftfile /var/lib/chrony/chrony.drift
ntsdumpdir /var/lib/chrony
makestep 1.0 3
rtcsync
port 0
cmdport 0
"""


def run(argv, timeout=20):
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "DEBIAN_FRONTEND": "noninteractive"},
    )


def trusted_directory(path):
    for part in (path, *path.parents):
        info = part.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise ValueError("untrusted directory")


def main():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("root on the dedicated Linux host required")
    if "ID=debian" not in Path("/etc/os-release").read_text().splitlines():
        raise ValueError("this bootstrap is limited to Debian")
    lock = os.open("/run/pap-clock-prepare.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("untrusted preparation lock")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for name in ("chrony", "chronyd", "ntp", "ntpsec", "systemd-timesyncd"):
            if run(["systemctl", "is-active", "--quiet", name + ".service"]).returncode == 0:
                raise ValueError("a time service is already active; retain its policy")
        config = Path("/etc/chrony/chrony.conf")
        if config.exists() or config.is_symlink():
            raise ValueError("existing time policy requires review, not replacement")
        trusted_directory(Path("/etc"))
        config.parent.mkdir(mode=0o755, exist_ok=True)
        trusted_directory(config.parent)
        fd = os.open(config, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, "wb") as output:
            output.write(CONFIG)
            output.flush()
            os.fsync(output.fileno())
        for argv in (
            ["apt-get", "update"],
            [
                "apt-get",
                "install",
                "--no-install-recommends",
                "--no-remove",
                "-y",
                "-o",
                "Dpkg::Options::=--force-confold",
                "chrony",
            ],
        ):
            if run(argv, timeout=150).returncode != 0:
                raise RuntimeError("package installation failed; policy retained for operator review")
        if config.read_bytes() != CONFIG:
            run(["systemctl", "stop", "chrony.service"])
            raise ValueError("package did not preserve the reviewed clock policy")
        if run(["systemctl", "enable", "--now", "chrony.service"]).returncode != 0:
            raise RuntimeError("time client could not start")
        run(["chronyc", "waitsync", "20", "0.1", "100", "1"], timeout=25)
        auth = run(["chronyc", "-N", "authdata"])
        authenticated = 0
        for line in auth.stdout.splitlines():
            fields = line.split()
            if len(fields) == 10 and fields[1] == "NTS":
                try:
                    authenticated += int(fields[3]) > 0 and int(fields[4]) > 0 and int(fields[8]) > 0
                except ValueError:
                    pass
        sync = run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
        accepted = sync.returncode == 0 and sync.stdout.strip() == "yes" and authenticated >= 2
        print(
            json.dumps(
                {
                    "clock_synchronized": accepted,
                    "authenticated_nts_sources": authenticated,
                    "public_ntp_listener": False,
                    "provider_timesyncd_mask_changed": False,
                    "tracking": run(["chronyc", "tracking"]).stdout.strip(),
                    "authdata": auth.stdout.strip(),
                }
            )
        )
        return 0 if accepted else 1
    finally:
        os.close(lock)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        print(
            json.dumps({"clock_synchronized": False, "error": "clock_preparation_failed_review_host_state"})
        )
        raise SystemExit(1) from None
