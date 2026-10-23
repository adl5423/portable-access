"""Offline evidence and control-plane boundaries for a real expiry-pause test."""

import copy
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from tools import exercise_natural_expired_pause as p

BASE = datetime(2026, 10, 22, 22, 5, 40, tzinfo=UTC)
EXPIRY = datetime(2026, 10, 22, 22, 53, 55, tzinfo=UTC)
PAUSE = datetime(2026, 10, 22, 22, 36, 11, tzinfo=UTC)
OBSERVATION = datetime(2026, 10, 23, 1, 4, 0, tzinfo=UTC)
PUBLISHED = OBSERVATION + timedelta(minutes=1)
AFTER = PUBLISHED + timedelta(minutes=3)
MACHINE = "example-pap-host"
IDENTIFIER = "m_abcdefghijklmnopqrstuvwxyz"
SITE = "00000000-0000-4000-8000-000000000001"
DEPLOY = "6ada86ce25c9de98cff425c6"


def baseline():
    return {
        "recorded_at": p.iso(BASE),
        "kms_unsealed": True,
        "kms_tls_verification_enabled": True,
        "clock_kernel_synchronized": True,
        "authenticated_nts_sources": 3,
        "all_four_pids": {name: index + 200 for index, name in enumerate(sorted(p.UNITS))},
        "certificates": {
            name: {
                "not_before": p.iso(EXPIRY - timedelta(hours=1)),
                "not_after": p.iso(EXPIRY),
                "der_sha256": str(index) * 64,
            }
            for index, name in enumerate(p.LEAVES, start=1)
        },
    }


def planned():
    return p.plan(baseline(), machine=MACHINE, machine_id=IDENTIFIER, netlify_site_id=SITE, idle_seconds=1800)


def pause():
    return {
        "recorded_at": p.iso(OBSERVATION),
        "name": MACHINE,
        "id": IDENTIFIER,
        "state": "suspended",
        "desiredState": "suspended",
        "autoSuspendAfterSeconds": 1800,
        "updatedAt": p.iso(PAUSE),
        "processesPreserved": True,
        "unrelated_sensitive_value": "must_not_be_retained",
    }


def event():
    return {
        "deploy": {"site_id": SITE, "deploy_id": DEPLOY},
        "registration": {
            "published_at": p.iso(PUBLISHED),
            "deploy_id": DEPLOY,
            "state": "ready",
            "context": "production",
        },
        "genuine_platform_event": {
            "deploy_id": DEPLOY,
            "safe_deploy_check_reports": [
                {"stage": stage, "outcome": "passed", "code": "operation_succeeded"}
                for stage in ("initial-read", "second-read")
            ],
        },
    }


def after():
    value = baseline()
    value["recorded_at"] = p.iso(AFTER)
    for index, cert in enumerate(value["certificates"].values(), start=3):
        cert.update(
            {
                "not_before": p.iso(PUBLISHED + timedelta(seconds=90)),
                "not_after": p.iso(PUBLISHED + timedelta(seconds=3690)),
                "der_sha256": str(index) * 64,
            }
        )
    value.update(
        {
            "old_revocation_preserved": True,
            "replacement_workload_and_grant_enabled": True,
            "certificate_auth_login": {
                "successful_responses_after": 12,
                "latest_successful_response_at": p.iso(PUBLISHED + timedelta(seconds=95)),
            },
        }
    )
    return value


def attestations():
    return {
        key: True
        for key in (
            "no_guest_or_public_calls_during_idle",
            "no_machine_lifecycle_or_clock_changes",
            "no_certificate_edits_or_test_fixtures",
            "genuine_event_was_first_wake_request",
            "post_wake_snapshot_after_first_success",
        )
    }


def evaluate(**overrides):
    values = {"pause": pause(), "after": after(), "event": event(), "attestations": attestations()}
    values.update(overrides)
    return p.evaluate(planned(), **values)


def test_existing_source_baseline_plan_has_exact_timeline():
    value = planned()
    assert value["suspension_must_start_before"] == "2026-10-22T22:47:55+00:00"
    assert value["wake_not_before"] == "2026-10-22T22:55:55+00:00"
    assert value["guest_or_public_requests_permitted_during_idle"] == 0
    assert not value["passed"] and not value["automatic_deployment_or_machine_action_permitted"]


def test_plan_waits_for_later_of_two_expiries():
    value = baseline()
    value["certificates"]["openbao_listener"]["not_after"] = p.iso(EXPIRY + timedelta(seconds=30))
    value["certificates"]["openbao_listener"]["not_before"] = p.iso(EXPIRY - timedelta(seconds=3570))
    result = p.plan(value, machine=MACHINE, machine_id=IDENTIFIER, netlify_site_id=SITE, idle_seconds=1800)
    assert result["wake_not_before"] == "2026-10-22T22:56:25+00:00"


@pytest.mark.parametrize(
    "change,code",
    [
        (
            lambda v: v.update(recorded_at=p.iso(BASE + timedelta(minutes=20))),
            "baseline_too_close_to_automatic_renewal",
        ),
        (lambda v: v.update(clock_kernel_synchronized=False), "baseline_trusted_clock_required"),
        (lambda v: v.update(authenticated_nts_sources=1), "baseline_trusted_clock_required"),
        (lambda v: v.update(kms_tls_verification_enabled=False), "baseline_verified_kms_required"),
        (lambda v: v["all_four_pids"].update({"pap-openbao.service": 0}), "service_pids_invalid"),
    ],
)
def test_plan_rejects_unsafe_baseline(change, code):
    value = baseline()
    change(value)
    with pytest.raises(p.EvidenceError, match=code):
        p.plan(value, machine=MACHINE, machine_id=IDENTIFIER, netlify_site_id=SITE, idle_seconds=1800)


@pytest.mark.parametrize(
    "change,code",
    [
        (
            lambda v: v.update(updatedAt=p.iso(EXPIRY - timedelta(minutes=4))),
            "suspension_after_renewal_window",
        ),
        (lambda v: v.update(state="running"), "provider_not_suspended"),
        (lambda v: v.update(desiredState="running"), "provider_not_suspended"),
        (lambda v: v.update(autoSuspendAfterSeconds=300), "provider_idle_policy_changed"),
        (lambda v: v.update(id="m_aaaaaaaaaaaa"), "provider_machine_mismatch"),
    ],
)
def test_suspension_requires_original_machine_policy_and_safe_transition(change, code):
    value = pause()
    change(value)
    with pytest.raises(p.EvidenceError, match=code):
        p.assess_suspension(planned(), value)


def test_evaluation_accepts_real_wall_clock_expiry_but_bounds_claims():
    result = evaluate()
    assert result["passed"]
    assert result["both_baseline_leaves_expired_before_wake"]
    assert result["actual_expired_pause_lower_bound_seconds"] == 7805
    assert not result["boot_id_unchanged"]
    assert not result["continuous_suspension_independently_observed"]
    assert not result["cold_boot_auto_unseal_verified_by_this_exercise"]
    assert not result["sdk_retry_branch_observed"] and not result["production_accepted"]
    assert "unrelated_sensitive_value" not in json.dumps(result)


@pytest.mark.parametrize(
    "kind",
    [
        "before_expiry",
        "stale_leaf",
        "before_wake_leaf",
        "old_login",
        "unchanged_login_count",
        "restarted",
        "unsynced",
        "revocation",
        "missing_read",
        "missing_attestation",
        "early_deploy",
        "wrong_site",
        "wrong_event_deploy",
        "not_production",
    ],
)
def test_acceptance_rejects_missing_or_conflicting_evidence(kind):
    values = {"pause": pause(), "after": after(), "event": event(), "attestations": attestations()}
    if kind == "before_expiry":
        values["pause"]["recorded_at"] = p.iso(EXPIRY + timedelta(seconds=30))
    elif kind == "stale_leaf":
        values["after"]["certificates"]["issuer_client"] = baseline()["certificates"]["issuer_client"]
    elif kind == "before_wake_leaf":
        values["after"]["certificates"]["issuer_client"].update(
            not_before=p.iso(EXPIRY + timedelta(seconds=30)),
            not_after=p.iso(EXPIRY + timedelta(seconds=3630)),
        )
    elif kind == "old_login":
        values["after"]["certificate_auth_login"]["latest_successful_response_at"] = p.iso(BASE)
    elif kind == "unchanged_login_count":
        values["after"]["certificate_auth_login"]["successful_responses_before"] = 12
    elif kind == "restarted":
        values["after"]["all_four_pids"]["pap-openbao.service"] += 100
    elif kind == "unsynced":
        values["after"]["clock_kernel_synchronized"] = False
    elif kind == "revocation":
        values["after"]["old_revocation_preserved"] = False
    elif kind == "missing_read":
        values["event"]["genuine_platform_event"]["safe_deploy_check_reports"].pop()
    elif kind == "missing_attestation":
        values["attestations"].pop("genuine_event_was_first_wake_request")
    elif kind == "early_deploy":
        values["event"]["registration"]["published_at"] = p.iso(EXPIRY)
    elif kind == "wrong_site":
        values["event"]["deploy"]["site_id"] = "13e2ddf2-77a9-4c05-89a3-632e44ea136d"
    elif kind == "wrong_event_deploy":
        values["event"]["genuine_platform_event"]["deploy_id"] = "0" * 24
    elif kind == "not_production":
        values["event"]["registration"]["context"] = "deploy-preview"
    with pytest.raises(p.EvidenceError):
        evaluate(**values)


class FakeClock:
    def __init__(self, value=OBSERVATION):
        self.now = value
        self.elapsed = 0.0

    def wall(self):
        return self.now

    def mono(self):
        return self.elapsed

    def sleep(self, seconds):
        self.elapsed += seconds
        self.now += timedelta(seconds=seconds)


def test_observer_only_calls_get_allowlists_and_never_wakes():
    calls = []
    clock = FakeClock()

    def run(args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(returncode=0, stdout=json.dumps(pause()).encode())

    result = p.observe(
        planned(),
        cli="/private/tmp/instabox",
        run=run,
        wall_clock=clock.wall,
        monotonic=clock.mono,
        sleep=clock.sleep,
    )
    assert [args for args, _ in calls] == [["/private/tmp/instabox", "get", "--json", MACHINE]]
    assert result["wake_may_be_prepared"] and not result["passed"]
    assert result["guest_or_public_requests"] == result["machine_mutations"] == result["deployments"] == 0
    assert "unrelated_sensitive_value" not in json.dumps(result)


def test_observer_stops_on_unexpected_wake():
    clock = FakeClock(EXPIRY - timedelta(minutes=8))
    rows = [pause(), pause()]
    rows[1].update(state="running", desiredState="running")

    def run(args, **kwargs):
        return SimpleNamespace(returncode=0, stdout=json.dumps(rows.pop(0)).encode())

    with pytest.raises(p.EvidenceError, match="unexpected_provider_resume"):
        p.observe(
            planned(),
            cli="/private/tmp/instabox",
            run=run,
            wall_clock=clock.wall,
            monotonic=clock.mono,
            sleep=clock.sleep,
        )


def test_observer_transport_errors_have_bounded_deadline_without_raw_output():
    clock = FakeClock()
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=1, stdout=b"secret failure details")

    with pytest.raises(p.EvidenceError, match="control_plane_observation_deadline"):
        p.observe(
            planned(),
            cli="/private/tmp/instabox",
            timeout_seconds=31,
            poll_seconds=15,
            run=run,
            wall_clock=clock.wall,
            monotonic=clock.mono,
            sleep=clock.sleep,
        )
    assert len(calls) == 3 and clock.elapsed == 31


def test_receipt_publication_never_overwrites_historical_bytes(tmp_path):
    target = tmp_path / "receipt.json"
    p.save_new(target, {"passed": False})
    previous = target.read_bytes()
    with pytest.raises(p.EvidenceError, match="receipt_already_exists"):
        p.save_new(target, {"passed": True})
    assert target.read_bytes() == previous


def test_cli_plan_is_offline_and_binds_exact_input_hash(tmp_path, monkeypatch):
    source = tmp_path / "baseline.json"
    source.write_text(json.dumps(baseline()))
    target = tmp_path / "plan.json"
    original = copy.deepcopy(baseline())
    monkeypatch.setattr(p.subprocess, "run", lambda *args, **kwargs: pytest.fail("plan ran a process"))
    assert (
        p.main(
            [
                "plan",
                "--baseline",
                str(source),
                "--machine",
                MACHINE,
                "--machine-id",
                IDENTIFIER,
                "--netlify-site-id",
                SITE,
                "--idle-seconds",
                "1800",
                "--output",
                str(target),
            ]
        )
        == 0
    )
    assert p.load(target)["input_receipts"] == [p.file_receipt(source)]
    assert p.load(source) == original


@pytest.mark.parametrize("value", ["2026-10-22T22:05:40", "junk", None])
def test_timestamp_must_be_explicitly_aware(value):
    with pytest.raises(p.EvidenceError):
        p.instant(value)
