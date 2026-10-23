"""Deployment regressions and a separate, real Linux kernel isolation exercise."""

import importlib.util
import json
import os
import stat
import sys
from pathlib import Path

import pytest

ASSETS = Path(__file__).resolve().parents[1] / "deploy/linux"


def load_asset(name):
    specification = importlib.util.spec_from_file_location(f"pap_{name}_asset", ASSETS / f"{name}.py")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def unit(name):
    return (ASSETS / "systemd" / name).read_text()


@pytest.mark.parametrize(
    "name,user", [("pap-authority.service", "pap-issuer"), ("pap-openbao.service", "pap-kms")]
)
def test_privileged_services_have_separate_unprivileged_sandboxes(name, user):
    content = unit(name)
    for directive in (
        f"User={user}\n",
        f"Group={user}\n",
        "NoNewPrivileges=yes\n",
        "CapabilityBoundingSet=\n",
        "AmbientCapabilities=\n",
        "ProtectSystem=strict\n",
        "ProtectHome=yes\n",
        "PrivateTmp=yes\n",
        "PrivateDevices=yes\n",
        "ProtectProc=invisible\n",
        "RestrictNamespaces=yes\n",
        "RestrictSUIDSGID=yes\n",
        "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX\n",
        "UMask=0077\n",
    ):
        assert directive in content
    assert "EnvironmentFile=" not in content
    assert "-dev" not in content


def test_authority_has_only_private_state_write_access_and_activated_admin_socket():
    content = unit("pap-authority.service")
    assert "ReadWritePaths=/var/lib/pap-issuer\n" in content
    assert "ExecStart=/opt/pap/venv/bin/pap production --config /etc/pap/authority.json\n" in content
    assert "Sockets=pap-admin.socket\n" in content
    assert "CAP_CHOWN" not in content
    socket_unit = unit("pap-admin.socket")
    for directive in (
        "ListenStream=/run/pap-admin/admin.sock\n",
        "Accept=no\n",
        "Service=pap-authority.service\n",
        "FileDescriptorName=pap-admin\n",
        "SocketUser=pap-admin\n",
        "SocketGroup=pap-admin\n",
        "SocketMode=0600\n",
        "DirectoryMode=0700\n",
    ):
        assert directive in socket_unit
    assert "d /run/pap-admin 0700 pap-admin pap-admin -" in (ASSETS / "tmpfiles.d/pap.conf").read_text()


def test_kms_has_verified_tls_and_loopback_listeners_without_development_mode():
    content = (ASSETS / "openbao/openbao.hcl").read_text()
    for directive in (
        'address = "127.0.0.1:8200"',
        'cluster_address = "127.0.0.1:8201"',
        "tls_require_and_verify_client_cert = true",
        'tls_min_version = "tls12"',
        'storage "raft"',
        'path = "/var/lib/pap-kms/data"',
    ):
        assert directive in content
    assert "tls_disable" not in content
    assert "token" not in content
    assert "-dev" not in unit("pap-openbao.service")


def test_gateway_has_separate_uid_and_private_administration():
    content = unit("pap-caddy.service")
    assert "User=pap-proxy\n" in content
    assert "CapabilityBoundingSet=CAP_NET_BIND_SERVICE\n" in content
    assert "InaccessiblePaths=/var/lib/pap-issuer /var/lib/pap-kms /run/pap-admin\n" in content
    caddy = (ASSETS / "caddy/Caddyfile.example").read_text()
    assert "admin unix//var/lib/pap-proxy/admin.sock|0600" in caddy
    assert "reverse_proxy 127.0.0.1:9480" in caddy
    assert "max_size 64KB" in caddy
    assert "log {" not in caddy  # Do not enable access logging of request credentials.


def test_empty_configuration_enrolls_no_cloud_projects():
    content = json.loads((ASSETS / "authority.example.json").read_text())
    assert content["sites"] == []
    assert content["admin_uid"] == 0  # Installer resolves pap-admin; daemon must reject uninstalled example.
    assert content["kms"]["client_key"].startswith("/var/lib/pap-issuer/credentials/current/")
    assert content["kms"]["client_ca_file"] == "/etc/pap/openbao-client-ca.pem"
    assert content["kms"]["client_ca_file"] != content["kms"]["ca_file"]
    assert "token" not in content["kms"]


def test_installer_rejects_nonroot_before_any_mutation(monkeypatch):
    installer = load_asset("install")
    monkeypatch.setattr(installer.os, "geteuid", lambda: 12345)
    with pytest.raises(SystemExit, match="requires root"):
        installer.main()


def test_installer_never_follows_input_symlinks_or_replaces_credentials(tmp_path):
    installer = load_asset("install")
    target = tmp_path / "key"
    target.write_bytes(b"fixture")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(OSError):
        installer.read_file(link)
    with pytest.raises(FileExistsError):
        installer.write_new(target, b"replacement", os.getuid(), os.getgid(), 0o600)
    assert target.read_bytes() == b"fixture"


def test_installer_creates_credentials_with_exact_mode(tmp_path):
    installer = load_asset("install")
    target = tmp_path / "new-key"
    installer.write_new(target, b"fixture", os.getuid(), os.getgid(), 0o600)
    assert stat.S_IMODE(target.stat().st_mode) == 0o600


def test_installer_state_adoption_is_limited_to_exact_service_paths(tmp_path):
    installer = load_asset("install")
    target = tmp_path / "pap-issuer"
    target.mkdir(mode=0o700)
    before = target.stat()
    assert installer.adopt_empty_state_directory(target, 60001, 60001, 0o700) is False
    after = target.stat()
    assert (after.st_uid, after.st_gid, after.st_mode) == (before.st_uid, before.st_gid, before.st_mode)
    assert installer.BOOTSTRAP_STATE_DIRECTORIES == frozenset(
        Path("/var/lib") / name for name in ("pap-issuer", "pap-kms", "pap-proxy")
    )


def test_installer_state_adoption_refuses_privileged_owner_or_permissive_mode():
    installer = load_asset("install")
    target = Path("/var/lib/pap-issuer")
    for uid, gid, mode in ((0, 60001, 0o700), (60001, 0, 0o700), (60001, 60001, 0o750)):
        assert installer.adopt_empty_state_directory(target, uid, gid, mode) is False


@pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="requires Linux root in a disposable container to start four independent UID processes",
)
def test_actual_linux_uid_process_boundaries():
    result = load_asset("isolation_probe").run_probe()
    assert result["passed"], result["checks"]
    assert len(result["checks"]) >= 26
    assert all(result["checks"].values())


@pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0 or not Path("/.dockerenv").is_file(),
    reason="fixed /run pathname test requires root in a disposable Docker Linux container",
)
def test_actual_production_runtime_activation():
    result = load_asset("runtime_activation_probe").run_probe(ASSETS.parents[1])
    assert result["passed"], result["checks"]
    assert len(result["checks"]) >= 14
    assert all(result["checks"].values())
