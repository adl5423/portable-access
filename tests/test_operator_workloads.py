"""Public setup must preserve policy linkage without touching custody or a network."""

import copy
import json
import os
import stat
import uuid

import pytest

from pap.operator import cli
from pap.operator.workloads import (
    CONFIG_NAME,
    REGISTRATION_NAME,
    WorkloadSetupError,
    check_workload,
    check_workload_files,
    create_workload,
)

NOW = 1_800_000_000


def make_bundle(tmp_path, *, name="bundle", adapter="https-origin", **options):
    directory = tmp_path / name
    arguments = {
        "adapter": adapter, "issuer": "https://authority.example.com",
        "audience": "urn:pap:example", "origin": "https://workload.example.com",
        "tenant": "project", "output_directory": directory, "now": NOW,
    }
    if adapter == "netlify":
        arguments.update(origin="https://workload.netlify.app", workload_id=str(uuid.uuid4()))
    arguments.update(options)
    result = create_workload(**arguments)
    return (
        directory, result,
        json.loads((directory / CONFIG_NAME).read_text()),
        json.loads((directory / REGISTRATION_NAME).read_text()),
    )


def authority_for(registration):
    return {
        "issuer": registration["issuer"], "audience": registration["audience"],
        "sites": [copy.deepcopy(registration["site"])],
        # The caller's UID must not affect offline remote-policy validation.
        "admin_uid": os.getuid(), "kms": {"enrollment_uid": os.getuid()},
    }


@pytest.mark.parametrize("adapter", ["netlify", "https-origin"])
def test_default_public_pair_is_disabled_and_has_finite_expiry(tmp_path, adapter):
    directory, result, config, registration = make_bundle(tmp_path, adapter=adapter)
    trust_key = "productionSiteIsolated" if adapter == "netlify" else "trustOriginDeployment"
    assert result["ok"] and result["ready"] is False
    assert config["enabled"] is False and config[trust_key] is False
    assert registration["site"]["trusted_site_contexts"] is False
    assert registration["site"]["grant_expires_at"] == NOW + 7 * 86400
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert all(stat.S_IMODE((directory / name).stat().st_mode) == 0o600
               for name in (CONFIG_NAME, REGISTRATION_NAME))
    checked = check_workload(config, registration, now=NOW)
    assert checked["ok"] and checked["ready"] is False
    assert {item["code"] for item in checked["findings"]} == {
        "origin_trust_pending", "workload_disabled", "authority_config_not_checked",
    }
    assert checked["deployment_accepted"] is False


def test_fresh_public_pair_has_new_identity_subject_and_grant(tmp_path):
    _, _, _, first = make_bundle(tmp_path, name="first")
    _, _, _, second = make_bundle(tmp_path, name="second")
    for field in ("site_id", "subject", "grant_id"):
        assert first["site"][field] != second["site"][field]


@pytest.mark.parametrize("days", [0, 31, True, 7.5])
def test_new_grants_are_bounded_before_output_creation(tmp_path, days):
    with pytest.raises(WorkloadSetupError, match="grant_days_out_of_range"):
        make_bundle(tmp_path, grant_days=days)
    assert not (tmp_path / "bundle").exists()


def test_enable_requires_explicit_origin_trust_before_creation(tmp_path):
    with pytest.raises(WorkloadSetupError, match="origin_trust_acknowledgment_required"):
        make_bundle(tmp_path, enabled=True)
    assert not (tmp_path / "bundle").exists()


def test_netlify_requires_actual_site_id(tmp_path):
    with pytest.raises(WorkloadSetupError, match="netlify_site_id_required"):
        make_bundle(tmp_path, adapter="netlify", workload_id=None)
    assert not (tmp_path / "bundle").exists()


@pytest.mark.parametrize("adapter", ["netlify", "https-origin"])
def test_ready_requires_enabled_trusted_exact_registration(tmp_path, adapter):
    _, _, config, registration = make_bundle(tmp_path, adapter=adapter, enabled=True, trust_origin=True)
    checked = check_workload(config, registration, authority_config=authority_for(registration),
                             require_ready=True, now=NOW)
    assert checked["ok"] and checked["ready"]
    assert checked["findings"] == []
    assert checked["scope"] == "public_workload_bindings"
    assert checked["deployment_accepted"] is False


@pytest.mark.parametrize("fields", [("resourcePath",), ("resourceAction",), ("resourcePath", "resourceAction")])
@pytest.mark.parametrize("use_null", [False, True])
def test_netlify_optional_resource_defaults_match_sdk_without_mutating_input(tmp_path, fields, use_null):
    _, _, config, registration = make_bundle(tmp_path, adapter="netlify", enabled=True, trust_origin=True)
    for field in fields:
        if use_null:
            config[field] = None
        else:
            del config[field]
    before = copy.deepcopy(config)
    checked = check_workload(config, registration, authority_config=authority_for(registration),
                             require_ready=True, now=NOW)
    assert checked["ok"] and checked["ready"]
    assert checked["findings"] == []
    assert config == before


@pytest.mark.parametrize("field", ["resourcePath", "resourceAction"])
@pytest.mark.parametrize("value", [False, 0, {}, [], ""])
def test_netlify_resource_defaults_do_not_coerce_invalid_values(tmp_path, field, value):
    _, _, config, registration = make_bundle(tmp_path, adapter="netlify", enabled=True, trust_origin=True)
    config[field] = value
    checked = check_workload(config, registration, authority_config=authority_for(registration), now=NOW)
    assert not checked["ok"] and not checked["ready"]
    assert checked["findings"][-1]["code"] == "invalid_public_config_binding"


@pytest.mark.parametrize("field, registration_field, custom", [
    ("resourcePath", "resource_path", "/api/custom"),
    ("resourceAction", "resource_action", "custom.read"),
])
def test_netlify_omitted_resource_still_has_to_match_exact_registration(tmp_path, field, registration_field, custom):
    _, _, config, registration = make_bundle(tmp_path, adapter="netlify", enabled=True, trust_origin=True)
    del config[field]
    registration["site"][registration_field] = custom
    checked = check_workload(config, registration, authority_config=authority_for(registration), now=NOW)
    assert not checked["ok"] and not checked["ready"]
    assert {"code": "binding_mismatch", "field": "config." + field, "severity": "error"} in checked["findings"]


@pytest.mark.parametrize("field", ["resourcePath", "resourceAction"])
@pytest.mark.parametrize("use_null", [False, True])
def test_https_resource_fields_remain_required(tmp_path, field, use_null):
    _, _, config, registration = make_bundle(tmp_path, enabled=True, trust_origin=True)
    if use_null:
        config[field] = None
    else:
        del config[field]
    checked = check_workload(config, registration, authority_config=authority_for(registration), now=NOW)
    assert not checked["ok"] and not checked["ready"]


def test_require_ready_without_authority_config_fails(tmp_path):
    _, _, config, registration = make_bundle(tmp_path, enabled=True, trust_origin=True)
    checked = check_workload(config, registration, require_ready=True, now=NOW)
    assert not checked["ok"] and not checked["ready"]
    assert "activation_not_ready" in {item["code"] for item in checked["findings"]}


@pytest.mark.parametrize("field,value", [
    ("issuerURL", "https://other.example.com"), ("audience", "urn:pap:other"),
    ("workloadID", "d876f32c-8bf3-4e8b-8e17-c34017a5eeca"), ("grantID", "other-grant"),
    ("resourceOrigin", "https://other.example.com"), ("resourcePath", "/api/other"),
    ("resourceAction", "other.read"), ("tenant", "other-tenant"),
])
def test_configuration_pair_mismatches_are_rejected(tmp_path, field, value):
    _, _, config, registration = make_bundle(tmp_path)
    config[field] = value
    checked = check_workload(config, registration, now=NOW)
    assert not checked["ok"]
    assert {"code": "binding_mismatch", "field": "config." + field, "severity": "error"} in checked["findings"]
    assert value not in json.dumps(checked)


def test_changed_trust_acknowledgment_is_rejected(tmp_path):
    _, _, config, registration = make_bundle(tmp_path)
    config["trustOriginDeployment"] = True
    checked = check_workload(config, registration, now=NOW)
    assert not checked["ok"]
    assert "origin_trust_mismatch" in {item["code"] for item in checked["findings"]}


def test_expired_grant_is_rejected_even_if_authority_contains_it(tmp_path):
    _, _, config, registration = make_bundle(tmp_path, enabled=True, trust_origin=True)
    registration["site"]["grant_expires_at"] = NOW
    checked = check_workload(config, registration, authority_config=authority_for(registration),
                             require_ready=True, now=NOW)
    assert not checked["ok"] and not checked["ready"]
    assert "grant_expired" in {item["code"] for item in checked["findings"]}


@pytest.mark.parametrize("field", ["issuer", "audience"])
def test_authority_global_binding_mismatch_rejected(tmp_path, field):
    _, _, config, registration = make_bundle(tmp_path, enabled=True, trust_origin=True)
    authority = authority_for(registration)
    authority[field] = "mismatched-authority-setting"
    checked = check_workload(config, registration, authority_config=authority, require_ready=True, now=NOW)
    assert not checked["ok"]
    assert "authority_" + field + "_mismatch" in {item["code"] for item in checked["findings"]}


def test_duplicate_and_rebound_authority_sites_rejected(tmp_path):
    _, _, config, registration = make_bundle(tmp_path, enabled=True, trust_origin=True)
    authority = authority_for(registration)
    authority["sites"].append(copy.deepcopy(authority["sites"][0]))
    checked = check_workload(config, registration, authority_config=authority, now=NOW)
    assert not checked["ok"]
    assert checked["findings"][-1]["code"] == "duplicate_authority_binding"
    authority["sites"].pop()
    authority["sites"][0]["tenant"] = "another-tenant"
    checked = check_workload(config, registration, authority_config=authority, now=NOW)
    assert not checked["ok"]
    assert "authority_binding_mismatch" in {item["code"] for item in checked["findings"]}


def test_unknown_member_names_and_values_are_never_returned(tmp_path):
    _, _, config, registration = make_bundle(tmp_path)
    config["unknown-sensitive-member"] = "sensitive-value-never-returned"
    checked = check_workload(config, registration, now=NOW)
    assert not checked["ok"]
    serialized = json.dumps(checked)
    assert "unknown-sensitive-member" not in serialized
    assert "sensitive-value-never-returned" not in serialized


def test_existing_output_is_never_replaced(tmp_path):
    directory, _, _, _ = make_bundle(tmp_path)
    before = {name: (directory / name).read_bytes() for name in (CONFIG_NAME, REGISTRATION_NAME)}
    with pytest.raises(WorkloadSetupError, match="output_already_exists"):
        make_bundle(tmp_path)
    assert all((directory / name).read_bytes() == value for name, value in before.items())


def test_interrupted_pair_creation_preserves_partial_output(tmp_path, monkeypatch):
    from pap.operator import workloads

    original = workloads._write_new

    def interrupted(directory, name, value):
        if name == REGISTRATION_NAME:
            raise OSError("synthetic interrupted write")
        return original(directory, name, value)

    monkeypatch.setattr(workloads, "_write_new", interrupted)
    with pytest.raises(OSError, match="synthetic interrupted write"):
        make_bundle(tmp_path)
    assert (tmp_path / "bundle" / CONFIG_NAME).is_file()
    with pytest.raises(WorkloadSetupError, match="output_already_exists"):
        make_bundle(tmp_path)


def test_output_symlink_parent_is_rejected(tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(actual, target_is_directory=True)
    with pytest.raises(WorkloadSetupError, match="unsafe_output_parent"):
        make_bundle(tmp_path, output_directory=linked / "bundle")
    assert not (actual / "bundle").exists()


@pytest.mark.parametrize("raw", [b'{"enabled":false,"enabled":true}', b'{"value":NaN}', b'[]'])
def test_checker_rejects_ambiguous_or_non_object_json_without_echo(tmp_path, raw):
    directory, _, _, _ = make_bundle(tmp_path)
    (directory / CONFIG_NAME).write_bytes(raw)
    checked = check_workload_files(directory / CONFIG_NAME, directory / REGISTRATION_NAME)
    assert not checked["ok"]
    assert checked["findings"] == [{"code": "invalid_or_unsafe_json_file", "field": "config", "severity": "error"}]


def test_cli_does_not_load_custody_and_returns_error_for_not_ready(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, "harden_process", lambda: None)

    def custody_forbidden(*args, **kwargs):
        raise AssertionError("public setup attempted to load custody")

    monkeypatch.setattr(cli, "load_custody", custody_forbidden)
    monkeypatch.setattr("pap.operator.workloads.time.time", lambda: NOW)
    assert cli.main([
        "workload-init", "--adapter", "https-origin", "--issuer", "https://authority.example.com",
        "--audience", "urn:pap:example", "--origin", "https://workload.example.com",
        "--tenant", "project", "--output-directory", str(tmp_path / "bundle"),
    ]) == 0
    assert json.loads(capsys.readouterr().out)["registration_required"]
    assert cli.main([
        "workload-check", "--config", str(tmp_path / "bundle" / CONFIG_NAME),
        "--registration", str(tmp_path / "bundle" / REGISTRATION_NAME), "--require-ready",
    ]) == 2
    checked = json.loads(capsys.readouterr().out)
    assert not checked["ok"] and not checked["ready"]
