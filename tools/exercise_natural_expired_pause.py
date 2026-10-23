#!/usr/bin/env python3
"""Coordinate a real, naturally suspended PAP host crossing both leaf expiries.

This tool never contacts the guest, publishes a deploy, starts/stops a machine,
changes its idle policy, edits certificates, or changes a clock. ``plan`` and
``evaluate`` use saved evidence only. ``observe`` invokes only the official
Instabox CLI's control-plane ``get --json`` and writes allowlisted metadata.

Run the last guest snapshot while both leaves have more than the fixed idle
interval plus their five-minute renewal window remaining. Stop all guest and
public probes. Observe suspension before that renewal window. Wait until BOTH
captured leaves expired, plus the safety margin, and then explicitly deploy the
existing Netlify background function. Its genuine deploy event must be the first
wake request. Capture the guest again only after the event's first read succeeds.

An already suspended machine can use a saved source-bound baseline. Its provider
transition timestamp supplies the pause boundary, but this is explicitly weaker
than observing the transition in real time. A plan is not an acceptance result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

SCHEMA = "pap-natural-expired-pause-v1"
LEAVES = ("issuer_client", "openbao_listener")
PAUSED = {"paused", "suspended"}
UNITS = {"pap-authority.service", "pap-enroller.service", "pap-openbao.service", "pap-caddy.service"}
SHA256 = re.compile(r"[0-9a-f]{64}")
NAME = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}")
MAX_JSON = 2 * 1024 * 1024


class EvidenceError(Exception):
    """An explicit, non-secret evidence failure code."""


def require(condition, code):
    if not condition:
        raise EvidenceError(code)


def instant(value):
    require(isinstance(value, str), "timestamp_required")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise EvidenceError("timestamp_invalid") from None
    require(result.tzinfo is not None, "timestamp_timezone_required")
    return result.astimezone(UTC)


def timestamp(value):
    require(isinstance(value, (float, int)) and not isinstance(value, bool), "unix_time_invalid")
    require(math.isfinite(value), "unix_time_invalid")
    try:
        return datetime.fromtimestamp(value, UTC)
    except (ValueError, OSError, OverflowError):
        raise EvidenceError("unix_time_invalid") from None


def iso(value):
    return value.astimezone(UTC).isoformat()


def load(path):
    data = Path(path).read_bytes()
    require(len(data) <= MAX_JSON, "evidence_too_large")
    try:
        value = json.loads(data)
    except ValueError:
        raise EvidenceError("evidence_json_invalid") from None
    require(isinstance(value, dict), "evidence_object_required")
    return value


def file_receipt(path):
    data = Path(path).read_bytes()
    require(len(data) <= MAX_JSON, "evidence_too_large")
    return {"file": Path(path).name, "sha256": hashlib.sha256(data).hexdigest()}


def save_new(path, value):
    """Atomic, durable publication without overwriting a historical receipt."""
    target = Path(path)
    require(not target.exists() and not target.is_symlink(), "receipt_already_exists")
    data = (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix=".pap-pause-", dir=target.parent, delete=False) as stream:
            temporary = Path(stream.name)
            os.chmod(temporary, 0o600)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        # A hard link atomically refuses a concurrently created target.
        os.link(temporary, target)
        descriptor = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def clock_ready(snapshot):
    if snapshot.get("clock_kernel_synchronized") is not True:
        return False
    count = snapshot.get("authenticated_nts_sources", 0)
    return isinstance(count, int) and not isinstance(count, bool) and count >= 2


def certificates(snapshot):
    result = {}
    for name in LEAVES:
        value = snapshot.get("certificates", {}).get(name, {})
        digest = value.get("der_sha256", "")
        require(isinstance(digest, str) and SHA256.fullmatch(digest), "leaf_fingerprint_missing")
        start, expiry = instant(value.get("not_before")), instant(value.get("not_after"))
        require(timedelta(0) < expiry - start <= timedelta(hours=1), "leaf_lifetime_invalid")
        result[name] = {"not_before": start, "not_after": expiry, "der_sha256": digest}
    return result


def pids(snapshot):
    value = snapshot.get("all_four_pids", snapshot.get("processes"))
    require(isinstance(value, dict) and set(value) == UNITS, "service_pids_missing")
    require(all(type(pid) is int and pid > 1 for pid in value.values()), "service_pids_invalid")
    require(len(set(value.values())) == len(UNITS), "service_pids_not_distinct")
    return value


def metadata(value, machine, machine_id):
    """Do not retain raw provider responses, environment values, or access URLs."""
    name = value.get("machine_name", value.get("name"))
    identifier = value.get("machine_id", value.get("id"))
    require(name == machine and identifier == machine_id, "provider_machine_mismatch")
    interval = value.get("auto_suspend_after_seconds", value.get("autoSuspendAfterSeconds"))
    require(type(interval) is int and 0 < interval <= 7200, "provider_idle_interval_invalid")
    updated = value.get("provider_updated_at", value.get("updatedAt"))
    instant(updated)
    observed = value.get("recorded_at")
    if observed is None:
        observed = iso(datetime.now(UTC))
    instant(observed)
    return {
        "recorded_at": observed,
        "machine_name": name,
        "machine_id": identifier,
        "state": value.get("state"),
        "desired_state": value.get("desired_state", value.get("desiredState")),
        "auto_suspend_after_seconds": interval,
        "provider_updated_at": updated,
        "processes_preserved": value.get("processes_preserved", value.get("processesPreserved")),
    }


def plan(
    before, *, machine, machine_id, netlify_site_id, idle_seconds, expiry_margin=120, suspension_margin=60
):
    require(NAME.fullmatch(machine), "machine_name_invalid")
    require(
        isinstance(machine_id, str) and re.fullmatch(r"m_[a-z0-9]{10,64}", machine_id), "machine_id_invalid"
    )
    try:
        require(str(uuid.UUID(netlify_site_id)) == netlify_site_id, "netlify_site_id_invalid")
    except (ValueError, TypeError, AttributeError):
        raise EvidenceError("netlify_site_id_invalid") from None
    require(type(idle_seconds) is int and 1 <= idle_seconds <= 7200, "idle_interval_invalid")
    require(type(expiry_margin) is int and 30 <= expiry_margin <= 900, "expiry_margin_invalid")
    require(type(suspension_margin) is int and 30 <= suspension_margin <= 300, "suspension_margin_invalid")
    require(
        before.get("kms_unsealed") is True and before.get("kms_tls_verification_enabled") is True,
        "baseline_verified_kms_required",
    )
    require(clock_ready(before), "baseline_trusted_clock_required")
    pids(before)
    leaves = certificates(before)
    recorded = instant(before.get("recorded_at"))
    require(
        all(leaf["not_before"] <= recorded < leaf["not_after"] for leaf in leaves.values()),
        "baseline_leaves_not_current",
    )
    earliest = min(leaf["not_after"] for leaf in leaves.values())
    latest = max(leaf["not_after"] for leaf in leaves.values())
    # A suspended host cannot renew. Suspension must precede the first leaf's
    # five-minute renewal threshold, with an additional scheduling margin.
    pause_before = earliest - timedelta(seconds=300 + suspension_margin)
    require(
        recorded + timedelta(seconds=idle_seconds) < pause_before, "baseline_too_close_to_automatic_renewal"
    )
    return {
        "schema": SCHEMA,
        "mode": "plan",
        "machine_name": machine,
        "machine_id": machine_id,
        "netlify_site_id": netlify_site_id,
        "baseline_at": iso(recorded),
        "baseline_processes": pids(before),
        "baseline_certificates": {
            name: {key: iso(value) if isinstance(value, datetime) else value for key, value in leaf.items()}
            for name, leaf in leaves.items()
        },
        "operative_idle_interval_seconds": idle_seconds,
        "suspension_must_start_before": iso(pause_before),
        "wake_not_before": iso(latest + timedelta(seconds=expiry_margin)),
        "expiry_margin_seconds": expiry_margin,
        "suspension_margin_seconds": suspension_margin,
        "required_renewal_window_seconds": 300,
        "guest_or_public_requests_permitted_during_idle": 0,
        "wake_action": "explicit_genuine_netlify_deploy_event_only",
        "automatic_deployment_or_machine_action_permitted": False,
        "passed": False,
        "production_accepted": False,
    }


def assess_suspension(planned, observed):
    value = metadata(observed, planned["machine_name"], planned["machine_id"])
    require(value["state"] in PAUSED and value["desired_state"] in PAUSED, "provider_not_suspended")
    require(
        value["auto_suspend_after_seconds"] == planned["operative_idle_interval_seconds"],
        "provider_idle_policy_changed",
    )
    started, recorded = instant(value["provider_updated_at"]), instant(value["recorded_at"])
    require(instant(planned["baseline_at"]) < started <= recorded, "suspension_timeline_invalid")
    require(started < instant(planned["suspension_must_start_before"]), "suspension_after_renewal_window")
    return value


def observe(
    planned,
    *,
    cli,
    poll_seconds=30,
    timeout_seconds=5400,
    run=subprocess.run,
    wall_clock=lambda: datetime.now(UTC),
    monotonic=time.monotonic,
    sleep=time.sleep,
):
    """Control-plane only. Return permission to prepare a wake, never perform it."""
    require(Path(cli).is_absolute(), "absolute_instabox_cli_required")
    require(type(poll_seconds) is int and 15 <= poll_seconds <= 60, "poll_interval_invalid")
    require(type(timeout_seconds) is int and 1 <= timeout_seconds <= 14400, "observer_timeout_invalid")
    deadline = monotonic() + timeout_seconds
    observations = []
    paused = False
    while monotonic() < deadline:
        remaining = deadline - monotonic()
        try:
            response = run(
                [str(cli), "get", "--json", planned["machine_name"]],
                capture_output=True,
                timeout=min(20, max(0.1, remaining)),
                check=False,
            )
            require(response.returncode == 0, "provider_metadata_failed")
            require(len(response.stdout) <= MAX_JSON, "provider_metadata_too_large")
            raw = json.loads(response.stdout)
            raw["recorded_at"] = iso(wall_clock())
            value = metadata(raw, planned["machine_name"], planned["machine_id"])
        except (subprocess.TimeoutExpired, ValueError, EvidenceError, TypeError):
            observations.append({"recorded_at": iso(wall_clock()), "transport_error": True})
        else:
            observations.append(value)
            if value["state"] in PAUSED:
                assess_suspension(planned, value)
                paused = True
                if instant(value["recorded_at"]) >= instant(planned["wake_not_before"]):
                    return {
                        "schema": SCHEMA,
                        "mode": "observe",
                        "wake_may_be_prepared": True,
                        "scope": "control_plane_metadata_only",
                        "observations": observations,
                        "guest_or_public_requests": 0,
                        "machine_mutations": 0,
                        "deployments": 0,
                        "suspension_seen_before_expiry": any(
                            row.get("state") in PAUSED
                            and instant(row["recorded_at"])
                            < min(
                                instant(leaf["not_after"])
                                for leaf in planned["baseline_certificates"].values()
                            )
                            for row in observations
                            if "state" in row
                        ),
                        "passed": False,
                    }
            elif paused:
                raise EvidenceError("unexpected_provider_resume_before_authorized_wake")
            else:
                require(
                    instant(value["recorded_at"]) < instant(planned["suspension_must_start_before"]),
                    "provider_did_not_suspend_before_renewal",
                )
        sleep(min(poll_seconds, max(0, deadline - monotonic())))
    raise EvidenceError("control_plane_observation_deadline")


def evaluate(planned, *, pause, after, event, attestations):
    """Require saved deployment, clock, certificate, KMS and policy evidence."""
    paused = assess_suspension(planned, pause)
    observed_at = instant(paused["recorded_at"])
    require(observed_at >= instant(planned["wake_not_before"]), "paused_observation_before_both_expiries")
    require(
        all(
            attestations.get(key) is True
            for key in (
                "no_guest_or_public_calls_during_idle",
                "no_machine_lifecycle_or_clock_changes",
                "no_certificate_edits_or_test_fixtures",
                "genuine_event_was_first_wake_request",
                "post_wake_snapshot_after_first_success",
            )
        ),
        "required_execution_attestation_missing",
    )
    published = instant(event.get("registration", {}).get("published_at"))
    deploy = event.get("deploy", {})
    registration = event.get("registration", {})
    platform_event = event.get("genuine_platform_event", {})
    deploy_id = deploy.get("deploy_id", "")
    require(deploy.get("site_id") == planned["netlify_site_id"], "netlify_site_mismatch")
    require(
        isinstance(deploy_id, str)
        and re.fullmatch(r"[0-9a-f]{24}", deploy_id)
        and registration.get("deploy_id") == deploy_id
        and platform_event.get("deploy_id") == deploy_id,
        "genuine_event_deployment_binding_missing",
    )
    require(
        registration.get("state") == "ready" and registration.get("context") == "production",
        "genuine_production_deployment_required",
    )
    require(published >= observed_at, "netlify_deployment_precedes_paused_observation")
    recorded = instant(after.get("recorded_at"))
    require(recorded > published, "after_snapshot_precedes_deployment")
    reports = event.get("genuine_platform_event", {}).get("safe_deploy_check_reports", [])
    require(
        len(reports) == 2
        and {row.get("stage") for row in reports} == {"initial-read", "second-read"}
        and all(
            row.get("outcome") == "passed" and row.get("code") == "operation_succeeded" for row in reports
        ),
        "genuine_protected_reads_missing",
    )
    require(pids(after) == planned["baseline_processes"], "service_process_changed")
    require(
        after.get("kms_unsealed") is True and after.get("kms_tls_verification_enabled") is True,
        "recovered_verified_kms_required",
    )
    require(clock_ready(after), "post_wake_trusted_clock_required")
    fresh = certificates(after)
    old = planned["baseline_certificates"]
    for name in LEAVES:
        require(fresh[name]["der_sha256"] != old[name]["der_sha256"], "leaf_was_not_replaced")
        require(
            fresh[name]["not_before"] > instant(old[name]["not_after"]),
            "replacement_leaf_did_not_follow_actual_expiry",
        )
        require(
            published - timedelta(seconds=60) <= fresh[name]["not_before"] <= recorded,
            "replacement_leaf_not_bound_to_wake",
        )
        require(fresh[name]["not_after"] > recorded, "replacement_leaf_expired")
    login = after.get("certificate_auth_login", {})
    require(
        type(login.get("successful_responses_after")) is int and login["successful_responses_after"] > 0,
        "fresh_kms_login_not_proven",
    )
    require(
        published <= instant(login.get("latest_successful_response_at")) <= recorded,
        "fresh_kms_login_not_bound_to_wake",
    )
    if "successful_responses_before" in login:
        require(
            type(login["successful_responses_before"]) is int
            and login["successful_responses_after"] > login["successful_responses_before"],
            "fresh_kms_login_count_did_not_increase",
        )
    require(
        after.get("old_revocation_preserved") is True
        and after.get("replacement_workload_and_grant_enabled") is True,
        "persisted_policy_not_proven",
    )
    return {
        "schema": SCHEMA,
        "mode": "evaluate",
        "passed": True,
        "machine_name": planned["machine_name"],
        "machine_id": planned["machine_id"],
        "netlify_site_id": planned["netlify_site_id"],
        "netlify_deploy_id": deploy_id,
        "last_guest_baseline_at": planned["baseline_at"],
        "provider_paused_observation": paused,
        "wake_not_before": planned["wake_not_before"],
        "netlify_published_at": iso(published),
        "post_wake_snapshot_at": iso(recorded),
        "both_baseline_leaves_expired_before_wake": True,
        "same_four_service_processes": True,
        "kms_unsealed_without_operator_action": True,
        "fresh_certificate_auth_login_after_wake": True,
        "both_leaf_fingerprints_changed": True,
        "genuine_initial_and_second_protected_reads_passed": True,
        "authenticated_clock_recovered_automatically": True,
        "persisted_revocations_preserved": True,
        "actual_expired_pause_lower_bound_seconds": (
            observed_at - max(instant(leaf["not_after"]) for leaf in old.values())
        ).total_seconds(),
        "pause_transition_timing_basis": "provider_updated_at_metadata",
        "continuous_suspension_independently_observed": attestations.get("continuous_suspension_observed")
        is True,
        "boot_id_unchanged": after.get("boot_id_continuity_proven") is True,
        "boot_id_evidence_note": "A missing source-bound boot ID does not weaken the independently compared PIDs; it prevents an unchanged-boot claim.",
        "sdk_retry_branch_observed": False,
        "sdk_retry_note": "Two successful reads do not establish which internal retry branches executed.",
        "attestations": attestations,
        "cold_boot_auto_unseal_verified_by_this_exercise": False,
        "production_accepted": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    planning = commands.add_parser("plan")
    planning.add_argument("--baseline", type=Path, required=True)
    planning.add_argument("--machine", required=True)
    planning.add_argument("--machine-id", required=True)
    planning.add_argument("--netlify-site-id", required=True)
    planning.add_argument("--idle-seconds", type=int, required=True)
    planning.add_argument("--expiry-margin-seconds", type=int, default=120)
    planning.add_argument("--suspension-margin-seconds", type=int, default=60)
    watching = commands.add_parser("observe")
    watching.add_argument("--plan", type=Path, required=True)
    watching.add_argument("--instabox-cli", type=Path, required=True)
    watching.add_argument("--poll-seconds", type=int, default=30)
    watching.add_argument("--timeout-seconds", type=int, default=5400)
    evaluating = commands.add_parser("evaluate")
    for name in ("plan", "pause", "after", "event", "attestations"):
        evaluating.add_argument("--" + name, type=Path, required=True)
    for command in (planning, watching, evaluating):
        command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    inputs = []
    if args.command == "plan":
        result = plan(
            load(args.baseline),
            machine=args.machine,
            machine_id=args.machine_id,
            netlify_site_id=args.netlify_site_id,
            idle_seconds=args.idle_seconds,
            expiry_margin=args.expiry_margin_seconds,
            suspension_margin=args.suspension_margin_seconds,
        )
        inputs = [args.baseline]
    elif args.command == "observe":
        result = observe(
            load(args.plan),
            cli=args.instabox_cli,
            poll_seconds=args.poll_seconds,
            timeout_seconds=args.timeout_seconds,
        )
        inputs = [args.plan]
    else:
        inputs = [args.plan, args.pause, args.after, args.event, args.attestations]
        result = evaluate(
            load(args.plan),
            pause=load(args.pause),
            after=load(args.after),
            event=load(args.event),
            attestations=load(args.attestations),
        )
    result["recorded_at"] = iso(datetime.now(UTC))
    result["input_receipts"] = [file_receipt(path) for path in inputs]
    save_new(args.output, result)
    print(
        json.dumps(
            {
                "mode": args.command,
                "passed": result.get("passed", False),
                "wake_may_be_prepared": result.get("wake_may_be_prepared", False),
                "receipt": str(args.output),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (EvidenceError, OSError) as error:
        code = str(error) if isinstance(error, EvidenceError) else "evidence_io_failed"
        print(json.dumps({"passed": False, "error": code}), file=sys.stderr)
        raise SystemExit(2) from None
