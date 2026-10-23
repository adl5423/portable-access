"""Trust-boundary regression checks for the local certificate broker profile."""

import importlib.util
import json
import os
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "deploy/linux"


def load(path):
    spec = importlib.util.spec_from_file_location("pap_deployment_fixture", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def config_input(tmp_path):
    source = json.loads((ASSETS / "authority.enrollment.example.json").read_text())
    path = tmp_path / "authority.json"
    path.write_text(json.dumps(source))
    return source, path


def test_enrollment_profile_requires_fixed_local_paths_and_an_unresolved_uid(tmp_path):
    install = load(ASSETS / "install.py")
    source, path = config_input(tmp_path)
    args = SimpleNamespace(config=path, hostname="pap.example.com", enrollment_ca_cert=tmp_path / "ca.pem")
    assert install.configured(args)["kms"]["enrollment_uid"] == 0
    source["kms"]["enrollment_socket"] = "/tmp/attacker.sock"
    path.write_text(json.dumps(source))
    with pytest.raises(ValueError, match="KMS configuration"):
        install.configured(args)


def test_legacy_and_enrollment_profiles_cannot_be_mixed(tmp_path):
    install = load(ASSETS / "install.py")
    _, path = config_input(tmp_path)
    args = SimpleNamespace(config=path, hostname="pap.example.com", enrollment_ca_cert=None)
    with pytest.raises(ValueError, match="KMS configuration"):
        install.configured(args)


def test_broker_receives_only_an_ephemeral_private_credential_and_no_network():
    content = (ASSETS / "systemd/pap-enroller.service").read_text()
    for directive in (
        "User=pap-enroller\n",
        "Group=pap-kms\n",
        "SupplementaryGroups=pap-issuer\n",
        "LoadCredential=enrollment-ca-key:/etc/pap/enrollment/ca-key.pem\n",
        "RestrictAddressFamilies=AF_UNIX\n",
        "CapabilityBoundingSet=\n",
        "AmbientCapabilities=\n",
        "NoNewPrivileges=yes\n",
        "ProtectSystem=strict\n",
        "StateDirectoryMode=0710\n",
        "ReadWritePaths=/var/lib/pap-enroller /run/pap-enroller\n",
        "MemorySwapMax=0\n",
    ):
        assert directive in content
    assert "Environment=" not in content
    assert "EnvironmentFile=" not in content
    assert "CAP_CHOWN" not in content
    assert "ExecReload" not in content


def test_listener_recovery_keeps_mutual_tls_and_does_not_need_privileged_reload():
    content = (ASSETS / "openbao/openbao.enrollment.hcl").read_text()
    assert 'address = "127.0.0.1:8200"' in content
    assert "tls_require_and_verify_client_cert = true" in content
    assert "tls_auto_reload = true" in content
    assert 'tls_auto_reload_interval = "5s"' in content
    assert 'tls_client_ca_file = "/etc/pap/openbao-client-ca.pem"' in content
    assert 'tls_key_file = "/var/lib/pap-enroller/listener/current/server.key"' in content
    assert "tls_disable" not in content
    assert "seal " not in content
    assert "disable_mlock" not in content
    assert 'audit "file" "pap" {' in content
    assert 'file_path = "/var/lib/pap-kms/audit.jsonl"' in content
    assert 'log_raw = "false"' in content
    assert 'hmac_accessor = "true"' in content
    assert "unsafe_allow_api_audit_creation" not in content
    dependency = (ASSETS / "systemd/pap-openbao.service.d/enrollment.conf").read_text()
    assert "Wants=pap-enroller.service\n" in dependency
    assert "Requires=pap-enroller.service" not in dependency
    assert "After=pap-enroller.service\n" in dependency


def test_sixth_storage_bind_is_explicit_and_keeps_the_original_five():
    storage = load(ROOT / "deploy/instabox/prepare-storage.py")
    original = tuple(storage.MAPPINGS)
    raw = "".join(
        f"{source} {target} none {storage.OPTIONS} 0 0\n" for _, source, target, _ in original
    ).encode()
    assert storage.missing_fstab_entries(raw) == []
    storage.MAPPINGS = (*storage.MAPPINGS, storage.ENROLLER_MAPPING)
    assert storage.missing_fstab_entries(raw) == [
        (Path("/data/pap/state/enroller"), Path("/var/lib/pap-enroller"))
    ]
    assert storage.MAPPINGS[:-1] == original
    assert storage.ENROLLER_MAPPING[-1] == 0o710


def test_duplicate_or_redirected_enroller_bind_is_rejected():
    storage = load(ROOT / "deploy/instabox/prepare-storage.py")
    storage.MAPPINGS = (*storage.MAPPINGS, storage.ENROLLER_MAPPING)
    line = f"/data/pap/state/enroller /var/lib/pap-enroller none {storage.OPTIONS} 0 0\n".encode()
    with pytest.raises(storage.PreparationError, match="conflicting"):
        storage.missing_fstab_entries(line * 2)
    with pytest.raises(storage.PreparationError, match="conflicting"):
        storage.missing_fstab_entries(line.replace(b"/data/pap/state/enroller", b"/data/other"))


def mocked_installed_runtime(install, monkeypatch):
    """Run the real daemon schema while checking the isolated subprocess contract."""
    from pap.production import ProductionConfig

    runtime = Path("/opt/pap/venv/bin/python")
    original_lstat, original_resolve = Path.lstat, Path.resolve
    monkeypatch.setattr(
        Path,
        "lstat",
        lambda path: (
            SimpleNamespace(st_uid=0, st_mode=stat.S_IFLNK | 0o777)
            if path == runtime
            else original_lstat(path)
        ),
    )
    monkeypatch.setattr(
        Path,
        "resolve",
        lambda path, **kwargs: Path(sys.executable) if path == runtime else original_resolve(path, **kwargs),
    )
    verified = []
    monkeypatch.setattr(install, "verify_parents", lambda path: verified.append(("parents", path)))
    monkeypatch.setattr(install, "verify_binary", lambda path: verified.append(("binary", path)))
    seen = []

    def run(command, **kwargs):
        assert command[:3] == [str(runtime), "-I", "-c"]
        assert "ProductionConfig.model_validate" in command[3]
        assert kwargs["cwd"] == "/"
        assert kwargs["env"] == {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
        assert kwargs["timeout"] == 10
        config = json.loads(kwargs["input"])
        seen.append(config)
        try:
            ProductionConfig.model_validate(config)
        except ValueError as error:
            return SimpleNamespace(returncode=1, stdout=b"", stderr=str(error).encode())
        return SimpleNamespace(returncode=0, stdout=b"configuration-valid\n", stderr=b"")

    monkeypatch.setattr(install.subprocess, "run", run)
    return verified, seen


def resolved_config():
    config = json.loads((ASSETS / "authority.enrollment.example.json").read_text())
    config["admin_uid"] = os.getuid() + 10000
    config["kms"]["enrollment_uid"] = os.getuid() + 10001
    config["sites"] = [
        {
            "site_id": "00000000-0000-4000-8000-000000000001",
            "origin": "https://example-pap.netlify.app",
            "subject": "netlify-00000000-0000-4000-8000-000000000001",
            "tenant": "pap-demo",
            "environment": "production",
            "grant_id": "00000000-0000-4000-8000-000000000002",
            "grant_expires_at": 1795290378,
            "trusted_site_contexts": True,
            "resource_path": "/api/pap/records",
            "resource_action": "records.read",
        }
    ]
    return config


def test_installer_uses_real_daemon_schema_in_an_isolated_interpreter(monkeypatch):
    install = load(ASSETS / "install.py")
    verified, seen = mocked_installed_runtime(install, monkeypatch)
    config = resolved_config()
    install.validate_runtime_config(config)
    assert seen == [config]
    assert ("parents", Path("/opt/pap/venv/bin/python")) in verified
    assert ("binary", Path(sys.executable)) in verified


def test_colon_subject_is_rejected_before_any_configuration_or_credential_write(
    tmp_path, monkeypatch, capsys
):
    install = load(ASSETS / "install.py")
    config = resolved_config()
    config["sites"][0]["subject"] = "netlify:00000000-0000-4000-8000-000000000001"
    config["admin_uid"] = 0
    config["kms"]["enrollment_uid"] = 0
    path = tmp_path / "invalid-public-config.json"
    path.write_text(json.dumps(config))
    ca, key = tmp_path / "ca.pem", tmp_path / "ca-key.pem"
    ca.write_bytes(b"fixture")
    key.write_bytes(b"fixture")
    read_file = install.read_file
    reads = []

    def read(path):
        reads.append(path)
        return read_file(path)

    monkeypatch.setattr(install, "read_file", read)
    _, seen = mocked_installed_runtime(install, monkeypatch)
    patched_lstat = Path.lstat
    monkeypatch.setattr(
        Path,
        "lstat",
        lambda candidate: (
            SimpleNamespace(st_uid=0, st_mode=stat.S_IFREG | 0o600)
            if candidate == key
            else patched_lstat(candidate)
        ),
    )
    monkeypatch.setattr(install.sys, "platform", "linux")
    monkeypatch.setattr(install.os, "geteuid", lambda: 0)
    monkeypatch.setattr(install.os, "umask", lambda mode: 0o022)
    monkeypatch.setattr(
        install.sys,
        "argv",
        [
            "install.py",
            "--config",
            str(path),
            "--hostname",
            "pap.example.com",
            "--enrollment-ca-cert",
            str(ca),
            "--enrollment-ca-key",
            str(key),
        ],
    )
    roles = ("pap-issuer", "pap-kms", "pap-admin", "pap-app", "pap-proxy", "pap-enroller")
    identities = {
        name: SimpleNamespace(pw_uid=os.getuid() + 10000 + index, pw_gid=os.getgid() + 10000 + index)
        for index, name in enumerate(roles)
    }
    monkeypatch.setattr(install, "accounts", lambda **kwargs: identities)
    monkeypatch.setattr(install, "require_stopped_accounts", lambda value: None)
    writes = []
    monkeypatch.setattr(install, "directory", lambda *args: writes.append(args))
    monkeypatch.setattr(install, "write_new", lambda *args: writes.append(args))
    monkeypatch.setattr(install, "install_enrollment", lambda *args: writes.append(args))
    with pytest.raises(SystemExit, match="installation stopped: ValueError"):
        install.main()
    assert len(seen) == 1
    assert seen[0]["admin_uid"] == identities["pap-admin"].pw_uid
    assert seen[0]["kms"]["enrollment_uid"] == identities["pap-enroller"].pw_uid
    assert not writes
    assert reads == [path]
    assert not capsys.readouterr().out


def test_runtime_schema_rejection_does_not_log_input_or_pydantic_details(monkeypatch):
    install = load(ASSETS / "install.py")
    mocked_installed_runtime(install, monkeypatch)
    config = resolved_config()
    config["sites"][0]["subject"] = "fixture-private-diagnostic-value:invalid"
    with pytest.raises(ValueError, match="^production configuration rejected by the installed runtime$"):
        install.validate_runtime_config(config)
