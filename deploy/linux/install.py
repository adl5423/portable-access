#!/usr/bin/env python3
"""Install reviewed PAP units and pre-provisioned certificates on a fresh Linux host.

Does not download binaries, initialize/unseal OpenBao, enroll cloud sites, start
services, or overwrite existing credentials. Run on the intended host as root.
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
from pathlib import Path

ASSETS = Path(__file__).resolve().parent
# The documented standalone installer uses the host's standard-library Python.
# Load the reviewed source reader without requiring PAP in that interpreter.
if __package__ in (None, ""):
    sys.path.insert(0, str(ASSETS.parents[1]))

from pap.configuration import parse_config_json  # noqa: E402

ROLES = ("pap-issuer", "pap-kms", "pap-admin", "pap-app", "pap-proxy")
BOOTSTRAP_STATE_DIRECTORIES = frozenset(
    Path("/var/lib") / name for name in ("pap-issuer", "pap-kms", "pap-proxy")
)


def read_file(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 8 * 1024 * 1024:
            raise ValueError("input must be a regular file smaller than 8 MiB")
        with os.fdopen(os.dup(descriptor), "rb") as source:
            return source.read()
    finally:
        os.close(descriptor)


def verify_parents(path):
    for parent in reversed(path.parents):
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise ValueError(f"unsafe destination ancestor: {parent}")


def directory(path, uid, gid, mode):
    verify_parents(path)
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        info = path.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != uid
            or info.st_gid != gid
            or stat.S_IMODE(info.st_mode) != mode
        ):
            if adopt_empty_state_directory(path, uid, gid, mode):
                return
            raise ValueError(f"existing directory has unexpected ownership or mode: {path}") from None
    else:
        os.chown(path, uid, gid)
        path.chmod(mode)


def adopt_empty_state_directory(path, uid, gid, mode):
    """Transfer one fresh private state directory, including a real bind mount.

    This deliberately cannot transfer arbitrary paths, populated state, or
    directories that another unprivileged identity can already modify. Ownership
    changes apply to the verified directory descriptor only, never its contents.
    """
    if path not in BOOTSTRAP_STATE_DIRECTORIES or mode != 0o700 or uid <= 0 or gid <= 0:
        return False
    verify_parents(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        current = path.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != 0o700
            or (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino)
            or not stat.S_ISDIR(current.st_mode)
        ):
            return False
        with os.scandir(descriptor) as entries:
            if next(entries, None) is not None:
                return False
        # Only root can mutate this empty directory before the transfer. The
        # installer also rejects running service accounts before reaching here.
        os.fchown(descriptor, uid, gid)
        updated = os.fstat(descriptor)
        current = path.lstat()
        if (
            (current.st_dev, current.st_ino) != (updated.st_dev, updated.st_ino)
            or not stat.S_ISDIR(current.st_mode)
            or updated.st_uid != uid
            or updated.st_gid != gid
            or stat.S_IMODE(updated.st_mode) != mode
        ):
            raise ValueError("state directory changed during bootstrap ownership transfer")
        return True
    finally:
        os.close(descriptor)


def private_child_directory(path, uid, gid):
    """Create only within the verified dedicated service state directory."""
    parent = path.parent.lstat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != uid or stat.S_IMODE(parent.st_mode) != 0o700:
        raise ValueError(f"unsafe service state parent: {path.parent}")
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError(f"unsafe existing private directory: {path}") from None
    else:
        os.chown(path, uid, gid)


def write_new(path, content, uid, gid, mode):
    # O_EXCL avoids replacing state, a renewal generation, or a symlink target.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, mode)
        with os.fdopen(os.dup(descriptor), "wb") as destination:
            destination.write(content)
            destination.flush()
            os.fsync(destination.fileno())
    finally:
        os.close(descriptor)


def accounts(enrollment=False):
    result = {}
    for name in ROLES:
        try:
            account = pwd.getpwnam(name)
        except KeyError:
            subprocess.run(
                [
                    "/usr/sbin/useradd",
                    "--system",
                    "--user-group",
                    "--no-create-home",
                    "--home-dir",
                    "/nonexistent",
                    "--shell",
                    "/usr/sbin/nologin",
                    name,
                ],
                check=True,
            )
            account = pwd.getpwnam(name)
        group = grp.getgrgid(account.pw_gid)
        extra_groups = [item.gr_name for item in grp.getgrall() if name in item.gr_mem]
        allowed_members = ["pap-enroller"] if enrollment and name == "pap-issuer" else []
        if (
            account.pw_uid == 0
            or account.pw_gid == 0
            or group.gr_name != name
            or any(member not in allowed_members for member in group.gr_mem)
            or extra_groups
            or account.pw_shell not in {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false"}
            or any(
                other.pw_name != name
                and other.pw_gid == account.pw_gid
                and not (enrollment and name == "pap-kms" and other.pw_name == "pap-enroller")
                for other in pwd.getpwall()
            )
            or any(other.pw_name != name and other.pw_uid == account.pw_uid for other in pwd.getpwall())
        ):
            raise ValueError(
                f"service account must have a dedicated group, no supplementary groups, and no login: {name}"
            )
        result[name] = account
    if enrollment:
        try:
            account = pwd.getpwnam("pap-enroller")
        except KeyError:
            subprocess.run(
                [
                    "/usr/sbin/useradd",
                    "--system",
                    "--gid",
                    "pap-kms",
                    "--groups",
                    "pap-issuer",
                    "--no-create-home",
                    "--home-dir",
                    "/nonexistent",
                    "--shell",
                    "/usr/sbin/nologin",
                    "pap-enroller",
                ],
                check=True,
            )
            account = pwd.getpwnam("pap-enroller")
        secondary = {item.gr_gid for item in grp.getgrall() if "pap-enroller" in item.gr_mem}
        if (
            account.pw_uid <= 0
            or account.pw_gid != result["pap-kms"].pw_gid
            or secondary != {result["pap-issuer"].pw_gid}
            or account.pw_shell not in {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false"}
            or any(
                other.pw_name != "pap-enroller" and other.pw_uid == account.pw_uid for other in pwd.getpwall()
            )
        ):
            raise ValueError(
                "enroller must have a separate UID, KMS primary group and only issuer supplementary group"
            )
        result["pap-enroller"] = account
    if len({item.pw_uid for item in result.values()}) != len(result):
        raise ValueError("service UIDs must be distinct")
    return result


def verify_binary(path):
    verify_parents(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
        raise ValueError(f"binary must be a root-owned regular file without group/other write access: {path}")
    if not info.st_mode & 0o111:
        raise ValueError(f"binary is not executable: {path}")


def require_stopped_accounts(identities):
    """Avoid writing bootstrap credentials while an existing service can race us."""
    uids = {identity.pw_uid for identity in identities.values()}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            status = (entry / "status").read_text()
        except (FileNotFoundError, ProcessLookupError):
            continue
        for line in status.splitlines():
            if line.startswith("Uid:") and any(int(value) in uids for value in line.split()[1:]):
                raise ValueError(
                    "service accounts must have no running processes during bootstrap installation"
                )


def configured(arguments):
    config = parse_config_json(read_file(arguments.config), maximum_bytes=1024 * 1024)
    if not isinstance(config, dict):
        raise ValueError("authority configuration must be an object")
    if not re.fullmatch(
        r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", arguments.hostname
    ):
        raise ValueError("hostname must be a lowercase public DNS hostname")
    expected = {
        "issuer": "https://" + arguments.hostname,
        "state_dir": "/var/lib/pap-issuer",
        "listen_host": "127.0.0.1",
        "listen_port": 9480,
    }
    for name, value in expected.items():
        if config.get(name) != value:
            raise ValueError(f"authority config {name} must match the supplied deployment profile")
    expected_kms = {
        "provider": "openbao",
        "base_url": "https://127.0.0.1:8200",
        "role": "pap-issuer",
        "client_cert": "/var/lib/pap-issuer/credentials/current/client-cert.pem",
        "client_key": "/var/lib/pap-issuer/credentials/current/client-key.pem",
        "ca_file": "/etc/pap/openbao-ca.pem",
        "client_ca_file": "/etc/pap/openbao-client-ca.pem",
        "pki_role": "pap-issuer",
        "common_name": "pap-issuer",
    }
    if getattr(arguments, "enrollment_ca_cert", None):
        expected_kms.update(
            ca_file="/etc/pap/enrollment-ca.pem",
            client_ca_file="/etc/pap/enrollment-ca.pem",
            enrollment_socket="/run/pap-enroller/enroll.sock",
            enrollment_uid=0,
        )
    if config.get("kms") != expected_kms:
        raise ValueError("KMS configuration must match the supplied OpenBao isolation profile")
    return config


def validate_runtime_config(config):
    """Use the installed daemon schema before publishing any policy or key file."""
    runtime = Path("/opt/pap/venv/bin/python")
    verify_parents(runtime)
    info = runtime.lstat()
    if info.st_uid != 0 or not (stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)):
        raise ValueError("runtime interpreter must be controlled by root")
    # A venv interpreter is commonly a symlink. Validate its complete resolved
    # target and both sets of parents, rather than accepting a writable target.
    verify_binary(runtime.resolve(strict=True))
    value = json.dumps(config, separators=(",", ":")).encode("utf-8")
    if len(value) > 1024 * 1024:
        raise ValueError("production configuration exceeds the runtime limit")
    code = (
        "import json,sys\n"
        "from pap.production import ProductionConfig\n"
        "try:\n"
        " value=sys.stdin.buffer.read(1048577)\n"
        " if len(value)>1048576: raise ValueError('configuration too large')\n"
        " ProductionConfig.model_validate(json.loads(value))\n"
        "except Exception:\n"
        " sys.exit(1)\n"
        "sys.stdout.write('configuration-valid\\n')\n"
    )
    try:
        completed = subprocess.run(
            [str(runtime), "-I", "-c", code],
            input=value,
            capture_output=True,
            timeout=10,
            check=False,
            cwd="/",
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("installed runtime configuration validation unavailable") from None
    if completed.returncode != 0 or completed.stdout != b"configuration-valid\n":
        # Pydantic errors may repeat input values; never expose subprocess
        # stderr or validation details in an operator-facing installation log.
        raise ValueError("production configuration rejected by the installed runtime")


def install_enrollment(config, credentials, identities):
    """Install a local root-issued trust boundary without initializing OpenBao."""
    issuer, kms, broker = [identities[name] for name in ("pap-issuer", "pap-kms", "pap-enroller")]
    state = Path("/var/lib/pap-enroller")
    verify_parents(state)
    try:
        state.mkdir(mode=0o710)
    except FileExistsError:
        fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if (
                info.st_uid != 0
                or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o710
                or (state.lstat().st_dev, state.lstat().st_ino) != (info.st_dev, info.st_ino)
            ):
                raise ValueError("enroller state must be a fresh root-owned directory with mode 0710")
            with os.scandir(fd) as entries:
                if next(entries, None) is not None:
                    raise ValueError("enroller state is not empty")
            os.fchown(fd, broker.pw_uid, kms.pw_gid)
        finally:
            os.close(fd)
    else:
        state.chmod(0o710)
        os.chown(state, broker.pw_uid, kms.pw_gid)
    directory(Path("/etc/pap/enrollment"), 0, 0, 0o700)
    write_new(Path("/etc/pap/enrollment/ca-key.pem"), credentials["enrollment_ca_key"], 0, 0, 0o600)
    write_new(Path("/etc/pap/enrollment-ca.pem"), credentials["enrollment_ca_cert"], 0, 0, 0o644)
    # Bootstrap adds a separate operator public CA before first initialization.
    # The broker's CA must never authorize an administrative OpenBao role.
    write_new(Path("/etc/pap/openbao-client-ca.pem"), credentials["enrollment_ca_cert"], 0, 0, 0o644)
    enrollment = {
        "ca_cert": "/etc/pap/enrollment-ca.pem",
        "ca_key": "/run/credentials/pap-enroller.service/enrollment-ca-key",
        "socket": "/run/pap-enroller/enroll.sock",
        "issuer_uid": issuer.pw_uid,
        "issuer_gid": issuer.pw_gid,
        "broker_uid": broker.pw_uid,
        "listener_dir": "/var/lib/pap-enroller/listener",
        "listener_gid": kms.pw_gid,
    }
    write_new(
        Path("/etc/pap/enrollment.json"),
        (json.dumps(enrollment, indent=2) + "\n").encode(),
        0,
        kms.pw_gid,
        0o640,
    )


def main():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise SystemExit("installation requires root on the intended Linux host")
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--hostname", required=True)
    legacy_names = (
        "issuer-client-cert",
        "issuer-client-key",
        "openbao-ca",
        "openbao-server-cert",
        "openbao-server-key",
        "openbao-client-ca",
    )
    for name in legacy_names:
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--enrollment-ca-cert", type=Path)
    parser.add_argument("--enrollment-ca-key", type=Path)
    arguments = parser.parse_args()
    try:
        enrollment = arguments.enrollment_ca_cert is not None or arguments.enrollment_ca_key is not None
        if enrollment:
            if not (arguments.enrollment_ca_cert and arguments.enrollment_ca_key):
                raise ValueError("enrollment mode requires both CA certificate and key")
            if any(getattr(arguments, name.replace("-", "_")) for name in legacy_names):
                raise ValueError("enrollment and pre-provisioned certificate inputs are mutually exclusive")
            key_info = arguments.enrollment_ca_key.lstat()
            verify_parents(arguments.enrollment_ca_key)
            if key_info.st_uid != 0 or stat.S_IMODE(key_info.st_mode) & 0o077:
                raise ValueError("enrollment CA key input must be root-owned and private")
            credential_names = ("enrollment_ca_cert", "enrollment_ca_key")
        else:
            credential_names = tuple(name.replace("-", "_") for name in legacy_names)
            if not all(getattr(arguments, name) for name in credential_names):
                raise ValueError("all six pre-provisioned certificate inputs are required")
        config = configured(arguments)
        for binary in (Path("/opt/pap/venv/bin/pap"), Path("/usr/local/bin/bao"), Path("/usr/bin/caddy")):
            verify_binary(binary)
        identities = accounts(enrollment=enrollment)
        require_stopped_accounts(identities)
        issuer, kms, admin, proxy = [
            identities[name] for name in ("pap-issuer", "pap-kms", "pap-admin", "pap-proxy")
        ]
        config["admin_uid"] = admin.pw_uid
        if enrollment:
            config["kms"]["enrollment_uid"] = identities["pap-enroller"].pw_uid
        validate_runtime_config(config)
        credentials = {name: read_file(getattr(arguments, name)) for name in credential_names}
        directory(Path("/etc/pap"), 0, 0, 0o755)
        for name in ("pap-issuer", "pap-kms", "pap-proxy"):
            identity = identities[name]
            directory(Path("/var/lib") / name, identity.pw_uid, identity.pw_gid, 0o700)
        for path, identity in (
            (Path("/var/lib/pap-issuer/credentials"), issuer),
            (Path("/var/lib/pap-kms/credentials"), kms),
            (Path("/var/lib/pap-kms/data"), kms),
        ):
            private_child_directory(path, identity.pw_uid, identity.pw_gid)
        if enrollment:
            install_enrollment(config, credentials, identities)
        else:
            bootstrap = Path("/var/lib/pap-issuer/credentials/bootstrap")
            private_child_directory(bootstrap, issuer.pw_uid, issuer.pw_gid)
            for name, source in (
                ("client-cert.pem", "issuer_client_cert"),
                ("client-key.pem", "issuer_client_key"),
            ):
                write_new(bootstrap / name, credentials[source], issuer.pw_uid, issuer.pw_gid, 0o600)
            os.symlink("bootstrap", bootstrap.parent / "current")
            for name, source in (
                ("server.crt", "openbao_server_cert"),
                ("server.key", "openbao_server_key"),
                ("client-ca.crt", "openbao_client_ca"),
            ):
                write_new(
                    Path("/var/lib/pap-kms/credentials") / name,
                    credentials[source],
                    kms.pw_uid,
                    kms.pw_gid,
                    0o600,
                )
            write_new(Path("/etc/pap/openbao-ca.pem"), credentials["openbao_ca"], 0, issuer.pw_gid, 0o640)
            write_new(
                Path("/etc/pap/openbao-client-ca.pem"),
                credentials["openbao_client_ca"],
                0,
                issuer.pw_gid,
                0o640,
            )
        write_new(
            Path("/etc/pap/authority.json"),
            (json.dumps(config, indent=2) + "\n").encode(),
            0,
            issuer.pw_gid,
            0o640,
        )
        write_new(
            Path("/etc/pap/openbao.hcl"),
            read_file(ASSETS / ("openbao/openbao.enrollment.hcl" if enrollment else "openbao/openbao.hcl")),
            0,
            kms.pw_gid,
            0o640,
        )
        caddy = read_file(ASSETS / "caddy/Caddyfile.example").replace(
            b"pap.example.com", arguments.hostname.encode()
        )
        write_new(Path("/etc/pap/Caddyfile"), caddy, 0, proxy.pw_gid, 0o640)
        for unit in sorted((ASSETS / "systemd").glob("pap-*")):
            if unit.is_dir() or (unit.name == "pap-enroller.service" and not enrollment):
                continue
            write_new(Path("/etc/systemd/system") / unit.name, read_file(unit), 0, 0, 0o644)
        tmpfiles = read_file(ASSETS / "tmpfiles.d/pap.conf")
        if enrollment:
            tmpfiles += b"d /run/pap-enroller 0750 pap-enroller pap-issuer -\n"
            for service in ("pap-openbao.service", "pap-authority.service"):
                destination = Path("/etc/systemd/system") / (service + ".d")
                directory(destination, 0, 0, 0o755)
                write_new(
                    destination / "enrollment.conf",
                    read_file(ASSETS / "systemd" / (service + ".d") / "enrollment.conf"),
                    0,
                    0,
                    0o644,
                )
        write_new(Path("/etc/tmpfiles.d/pap.conf"), tmpfiles, 0, 0, 0o644)
        subprocess.run(["/usr/bin/systemd-tmpfiles", "--create", "/etc/tmpfiles.d/pap.conf"], check=True)
        subprocess.run(["/usr/bin/systemctl", "daemon-reload"], check=True)
        print(
            json.dumps(
                {
                    "installed": True,
                    "started": False,
                    "admin_uid": admin.pw_uid,
                    "next": "complete the OpenBao bootstrap and verify units before enabling services",
                }
            )
        )
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        # Paths and error types are safe to expose. Input credential bytes never appear here.
        raise SystemExit(
            f"installation stopped: {type(error).__name__}; inspect ownership, prerequisites, and existing paths"
        ) from None


if __name__ == "__main__":
    main()
