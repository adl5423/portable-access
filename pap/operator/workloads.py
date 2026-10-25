"""Prepare and check public workload bindings without accessing custody or a network."""

from __future__ import annotations

import json
import os
import stat
import time
import uuid
from pathlib import Path

from ..cloud import Site, validate_sites
from ..configuration import parse_config_json
from ..identity_adapters import https_origin, identity_adapter
from ..workload import WorkloadConfig, WorkloadError
from .custody import CustodyError, public_read

CONFIG_NAME = "config.public.json"
REGISTRATION_NAME = "pap-registration.json"
_COMMON_CONFIG = {
    "enabled", "issuerURL", "grantID", "resourceOrigin", "resourcePath",
    "resourceAction", "tenant", "environment", "audience",
}
_SITE_REQUIRED = {
    "site_id", "origin", "subject", "tenant", "environment", "grant_id",
    "grant_expires_at", "trusted_site_contexts",
}
_SITE_ALLOWED = _SITE_REQUIRED | {"identity_adapter", "resource_path", "resource_action"}


class WorkloadSetupError(CustodyError):
    """Only fixed codes and known field paths may enter operator output."""

    def __init__(self, code: str, field: str):
        self.code, self.field = code, field
        super().__init__(code)


def _issue(code: str, field: str, *, severity: str = "error") -> dict:
    return {"code": code, "field": field, "severity": severity}


def _read(path: Path, field: str) -> dict:
    try:
        return parse_config_json(public_read(path, 1024 * 1024))
    except (CustodyError, OSError, ValueError, TypeError, RecursionError):
        raise WorkloadSetupError("invalid_or_unsafe_json_file", field) from None


def _site(value: object, field: str, *, proposal: bool = False) -> Site:
    if (
        not isinstance(value, dict)
        or not _SITE_REQUIRED <= value.keys()
        or not value.keys() <= _SITE_ALLOWED
        or type(value.get("trusted_site_contexts")) is not bool
    ):
        raise WorkloadSetupError("invalid_registration_schema", field)
    normalized = dict(value)
    if proposal:
        # A disabled proposal may be unacknowledged. This copy validates syntax
        # only; the original false value remains in the handoff and readiness result.
        normalized["trusted_site_contexts"] = True
    try:
        return Site(**normalized)
    except (ValueError, TypeError, AttributeError, WorkloadError):
        raise WorkloadSetupError("invalid_registration_binding", field) from None


def _public_config(value: object, adapter: str) -> WorkloadConfig:
    if adapter == "netlify":
        workload_key, trust_key = "siteID", "productionSiteIsolated"
    else:
        workload_key, trust_key = "workloadID", "trustOriginDeployment"
    if (
        not isinstance(value, dict)
        or set(value) != _COMMON_CONFIG | {workload_key, trust_key}
        or type(value.get("enabled")) is not bool
        or type(value.get(trust_key)) is not bool
    ):
        raise WorkloadSetupError("invalid_public_config_schema", "config")
    if value["enabled"] and not value[trust_key]:
        raise WorkloadSetupError("origin_trust_acknowledgment_required", "config")
    normalized = {
        **{key: value[key] for key in _COMMON_CONFIG},
        "workloadID": value[workload_key],
        "trustOriginDeployment": True,
        "enabled": True,
    }
    try:
        identity_adapter(adapter).validate_origin(value["resourceOrigin"])
        return WorkloadConfig.from_dict(normalized)
    except (ValueError, TypeError, AttributeError, WorkloadError):
        raise WorkloadSetupError("invalid_public_config_binding", "config") from None


def check_workload(
    config: dict,
    registration: dict,
    *,
    authority_config: dict | None = None,
    require_ready: bool = False,
    now: float | None = None,
) -> dict:
    """Validate public linkage, never current server health or historical revocation."""
    findings: list[dict] = []
    timestamp = time.time() if now is None else now
    try:
        if not isinstance(registration, dict) or set(registration) != {"issuer", "audience", "site"}:
            raise WorkloadSetupError("invalid_registration_schema", "registration")
        site = _site(registration["site"], "registration.site", proposal=True)
        workload = _public_config(config, site.identity_adapter)
        for field, left, right in (
            ("issuerURL", workload.issuer_url, registration["issuer"]),
            ("audience", workload.audience, registration["audience"]),
            ("workloadID", workload.workload_id, site.site_id),
            ("grantID", workload.grant_id, site.grant_id),
            ("resourceOrigin", workload.resource_origin, site.origin),
            ("resourcePath", workload.resource_path, site.resource_path),
            ("resourceAction", workload.resource_action, site.resource_action),
            ("tenant", workload.tenant, site.tenant),
            ("environment", workload.environment, site.environment),
        ):
            if left != right:
                findings.append(_issue("binding_mismatch", "config." + field))
        trust_key = "productionSiteIsolated" if site.identity_adapter == "netlify" else "trustOriginDeployment"
        trusted = config[trust_key] is True
        if trusted != registration["site"]["trusted_site_contexts"]:
            findings.append(_issue("origin_trust_mismatch", "registration.site.trusted_site_contexts"))
        if site.grant_expires_at <= timestamp:
            findings.append(_issue("grant_expired", "registration.site.grant_expires_at"))
        if not trusted:
            findings.append(_issue("origin_trust_pending", "config", severity="warning"))
        if config["enabled"] is not True:
            findings.append(_issue("workload_disabled", "config.enabled", severity="warning"))
        registered = False
        if authority_config is None:
            findings.append(_issue("authority_config_not_checked", "authority", severity="warning"))
        else:
            if not isinstance(authority_config, dict) or not isinstance(authority_config.get("sites"), list):
                raise WorkloadSetupError("invalid_authority_bindings", "authority")
            if len(authority_config["sites"]) > 1000:
                raise WorkloadSetupError("invalid_authority_bindings", "authority.sites")
            sites = [_site(entry, "authority.sites") for entry in authority_config["sites"]]
            try:
                validate_sites(sites)
            except (ValueError, TypeError, AttributeError):
                raise WorkloadSetupError("duplicate_authority_binding", "authority.sites") from None
            if authority_config.get("issuer") != workload.issuer_url:
                findings.append(_issue("authority_issuer_mismatch", "authority.issuer"))
            if authority_config.get("audience") != workload.audience:
                findings.append(_issue("authority_audience_mismatch", "authority.audience"))
            matching = [entry for entry in sites if entry.grant_id == site.grant_id]
            if matching:
                registered = matching[0] == site and trusted
                if matching[0] != site:
                    findings.append(_issue("authority_binding_mismatch", "authority.sites"))
            elif any(
                getattr(entry, field) == getattr(site, field)
                for entry in sites for field in ("site_id", "origin", "subject")
            ):
                findings.append(_issue("authority_binding_collision", "authority.sites"))
            else:
                findings.append(_issue("registration_missing", "authority.sites", severity="warning"))
        ready = (
            config["enabled"] is True and trusted and registered
            and not any(item["severity"] == "error" for item in findings)
        )
        if require_ready and not ready:
            findings.append(_issue("activation_not_ready", "workload"))
    except WorkloadSetupError as exc:
        findings.append(_issue(exc.code, exc.field))
        ready = False
    return {
        "ok": not any(item["severity"] == "error" for item in findings),
        "ready": ready,
        "scope": "public_workload_bindings",
        "deployment_accepted": False,
        "findings": findings,
    }


def check_workload_files(
    config_path: Path,
    registration_path: Path,
    *,
    authority_path: Path | None = None,
    require_ready: bool = False,
) -> dict:
    try:
        return check_workload(
            _read(config_path, "config"), _read(registration_path, "registration"),
            authority_config=_read(authority_path, "authority") if authority_path else None,
            require_ready=require_ready,
        )
    except WorkloadSetupError as exc:
        return {
            "ok": False, "ready": False, "scope": "public_workload_bindings",
            "deployment_accepted": False, "findings": [_issue(exc.code, exc.field)],
        }


def _create_directory(path: Path) -> int:
    if ".." in path.parts or not path.name:
        raise WorkloadSetupError("unsafe_output_directory", "output_directory")
    path = path.absolute()
    try:
        for parent in (path.parent, *path.parent.parents):
            info = parent.lstat()
            if (
                not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.getuid())
                or info.st_mode & 0o022 and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX)
            ):
                raise WorkloadSetupError("unsafe_output_parent", "output_directory")
        parent_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.mkdir(path.name, 0o700, dir_fd=parent_fd)
            descriptor = os.open(path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
            info = os.fstat(descriptor)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
                os.close(descriptor)
                raise WorkloadSetupError("unsafe_output_directory", "output_directory")
            os.fsync(parent_fd)
            return descriptor
        finally:
            os.close(parent_fd)
    except FileExistsError:
        raise WorkloadSetupError("output_already_exists", "output_directory") from None
    except OSError:
        raise WorkloadSetupError("cannot_create_output_directory", "output_directory") from None


def _write_new(directory: int, name: str, value: dict) -> None:
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
    with os.fdopen(descriptor, "wb") as destination:
        destination.write((json.dumps(value, indent=2, allow_nan=False) + "\n").encode())
        destination.flush()
        os.fsync(destination.fileno())


def create_workload(
    *, adapter: str, issuer: str, audience: str, origin: str, tenant: str,
    output_directory: Path, workload_id: str | None = None, grant_days: int = 7,
    resource_path: str = "/api/pap/records", resource_action: str = "records.read",
    enabled: bool = False, trust_origin: bool = False, now: float | None = None,
) -> dict:
    if type(grant_days) is not int or not 1 <= grant_days <= 30:
        raise WorkloadSetupError("grant_days_out_of_range", "grant_days")
    if type(enabled) is not bool or type(trust_origin) is not bool or enabled and not trust_origin:
        raise WorkloadSetupError("origin_trust_acknowledgment_required", "config")
    if adapter == "netlify" and workload_id is None:
        raise WorkloadSetupError("netlify_site_id_required", "workload_id")
    if adapter not in ("netlify", "https-origin"):
        raise WorkloadSetupError("unsupported_adapter", "adapter")
    try:
        https_origin(issuer)
        identity_adapter(adapter).validate_origin(origin)
    except (ValueError, TypeError):
        raise WorkloadSetupError("invalid_origin", "config") from None
    identifier = workload_id if workload_id is not None else str(uuid.uuid4())
    expires = int(time.time() if now is None else now) + grant_days * 86400
    site = {
        "site_id": identifier, "identity_adapter": adapter, "origin": origin,
        "subject": "pap-" + uuid.uuid4().hex, "tenant": tenant, "environment": "production",
        "grant_id": "pap-" + uuid.uuid4().hex, "grant_expires_at": expires,
        "trusted_site_contexts": trust_origin, "resource_path": resource_path,
        "resource_action": resource_action,
    }
    workload_key, trust_key = (
        ("siteID", "productionSiteIsolated") if adapter == "netlify"
        else ("workloadID", "trustOriginDeployment")
    )
    config = {
        "enabled": enabled, "issuerURL": issuer, workload_key: identifier,
        "grantID": site["grant_id"], "resourceOrigin": origin, "resourcePath": resource_path,
        "resourceAction": resource_action, "tenant": tenant, "environment": "production",
        "audience": audience, trust_key: trust_origin,
    }
    registration = {"issuer": issuer, "audience": audience, "site": site}
    checked = check_workload(config, registration, now=now)
    if not checked["ok"]:
        first = next(item for item in checked["findings"] if item["severity"] == "error")
        raise WorkloadSetupError(first["code"], first["field"])
    descriptor = _create_directory(output_directory)
    try:
        _write_new(descriptor, CONFIG_NAME, config)
        _write_new(descriptor, REGISTRATION_NAME, registration)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return {
        "ok": True, "ready": False, "scope": "public_workload_bindings",
        "files_created": [CONFIG_NAME, REGISTRATION_NAME], "grant_days": grant_days,
        "enabled": enabled, "origin_trust_acknowledged": trust_origin,
        "registration_required": True,
    }
