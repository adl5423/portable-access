"""Registered-origin authentication, replay defense and live-policy checks.

Provider HTTP calls use deterministic test doubles. No live Netlify account is used.
"""

import asyncio
import base64
import hashlib
import json
import socket
import time
import uuid
from dataclasses import replace
from pathlib import Path

import pytest

from pap import cloud
from pap.authority import Authority, Config
from pap.cloud import PublicResolver, Site, SiteRegistry, fetch_site_record, netlify_origin
from pap.crypto import Denied, fresh_key, proof, public_jwk, thumbprint
from pap.identity_adapters import IDENTITY_ADAPTERS, https_origin, identity_adapter, public_destination
from pap.storage import Store


@pytest.fixture
def registered(tmp_path):
    directory = tmp_path / "cloud-state"
    directory.mkdir(mode=0o700)
    store = Store(directory / "state.sqlite")
    authority = Authority(
        store,
        Config(issuer="https://issuer.security.example", audience="urn:pap:project-api"),
    )
    site = Site(
        site_id="11111111-1111-4111-8111-111111111111",
        origin="https://trusted-project.netlify.app",
        subject="netlify-project",
        tenant="tenant-a",
        environment="production",
        grant_id="grant-production",
        grant_expires_at=time.time() + 600,
        trusted_site_contexts=True,
    )
    registry = SiteRegistry(authority, [site])
    try:
        yield authority, registry, site
    finally:
        store.close()


def enrollment(registry, site, key=None):
    key = key or fresh_key()
    jwk = public_jwk(key)
    challenge = registry.challenge(site.grant_id, jwk)
    encoded = proof(
        key,
        "POST",
        registry.authority.config.issuer + "/v1/site/token",
        challenge["nonce"],
    )
    return key, jwk, challenge, encoded


def issue(registry, site):
    key, jwk, challenge, encoded = enrollment(registry, site)
    credential = registry.finish_exchange(challenge["challenge_id"], jwk, encoded, challenge)
    return key, credential


def access(registry, site, key, credential, **changes):
    values = {
        "method": "GET",
        "url": site.origin + site.resource_path,
        "tenant": site.tenant,
        "action": site.resource_action,
        "audience": registry.authority.config.audience,
    }
    values.update(changes)
    encoded = proof(
        key,
        values["method"],
        values["url"],
        credential["dpop_nonce"],
        credential["access_token"],
    )
    return registry.authorize(credential["access_token"], encoded, **values)


@pytest.mark.parametrize(
    "origin",
    [
        "http://trusted-project.netlify.app",
        "https://localhost",
        "https://127.0.0.1",
        "https://[::1]",
        "https://169.254.169.254",
        "https://trusted-project.netlify.app.evil.example",
        "https://evil.example/trusted-project.netlify.app",
        "https://user:password@trusted-project.netlify.app",
        "https://trusted-project.netlify.app:443",
        "https://trusted-project.netlify.app:8443",
        "https://trusted-project.netlify.app/",
        "https://trusted-project.netlify.app/.well-known/pap/site-proof",
        "https://trusted-project.netlify.app?destination=http://localhost",
        "https://trusted-project.netlify.app#fragment",
        "https://deploy-preview-42--trusted-project.netlify.app",
        "https://branch--trusted-project.netlify.app",
        "https://TRUSTED-PROJECT.netlify.app",
        "HTTPS://trusted-project.netlify.app",
        "https://trusted-project.netlify.app\n",
        "https://trusted-\tproject.netlify.app",
        "https://trusted-project.netlify.app\\@attacker.example",
        "https://trusted-project%2enetlify.app",
    ],
)
def test_origin_registration_rejects_noncanonical_and_hostile_destinations(origin):
    with pytest.raises(ValueError):
        netlify_origin(origin)


def test_registration_requires_explicit_production_trust_and_canonical_site_id(registered):
    _, _, site = registered
    assert netlify_origin(site.origin) == site.origin
    assert site.uid < 0
    for changes in [
        {"trusted_site_contexts": False},
        {"trusted_site_contexts": 1},
        {"environment": "deploy-preview"},
        {"site_id": site.site_id.replace("-", "")},
        {"subject": "../../another-tenant"},
        {"grant_expires_at": True},
        {"grant_expires_at": float("nan")},
    ]:
        with pytest.raises(ValueError):
            replace(site, **changes)


@pytest.mark.parametrize(
    "resource_path",
    [
        "//attacker.example/x",
        "/api/../admin",
        "/api/%2e%2e/admin",
        "/api/orders?tenant=other",
        "/api/orders#fragment",
        "/api//orders",
        "/api/orders/",
        "api/orders",
    ],
)
def test_registration_rejects_ambiguous_resource_paths(registered, resource_path):
    _, _, site = registered
    with pytest.raises(ValueError, match="resource path"):
        replace(site, resource_path=resource_path)


@pytest.mark.parametrize("field", ["origin", "site_id", "subject", "tenant", "grant_id"])
def test_duplicate_authority_bindings_are_rejected(registered, field):
    authority, _, site = registered
    second = replace(
        site,
        site_id="22222222-2222-4222-8222-222222222222",
        origin="https://second-project.netlify.app",
        subject="second-project",
        tenant="tenant-b",
        grant_id="grant-second",
    )
    # Distinct tenants can share a tenant, but immutable workload/origin/grant identifiers cannot collide.
    if field == "tenant":
        SiteRegistry(authority, [site, replace(second, tenant=site.tenant)])
        return
    with pytest.raises(ValueError, match="unique"):
        SiteRegistry(authority, [site, replace(second, **{field: getattr(site, field)})])


@pytest.mark.parametrize(
    "changes",
    [
        {"origin": "https://replacement-project.netlify.app"},
        {"site_id": "22222222-2222-4222-8222-222222222222"},
        {"subject": "replacement-subject"},
        {"tenant": "different-tenant"},
        {"resource_path": "/api/orders/current", "resource_action": "orders.read"},
    ],
)
def test_existing_grant_cannot_be_silently_rebound_on_restart(registered, changes):
    authority, _, site = registered
    with pytest.raises(ValueError, match="rebound"):
        SiteRegistry(authority, [replace(site, **changes)])


def test_unchanged_registration_is_idempotent_and_never_extends_an_existing_grant(registered):
    authority, _, site = registered
    initial_expiry = authority.store.db.execute(
        "SELECT expires FROM grants WHERE id=?", (site.grant_id,)
    ).fetchone()[0]
    SiteRegistry(authority, [site])
    SiteRegistry(authority, [replace(site, grant_expires_at=site.grant_expires_at + 3600)])
    assert (
        authority.store.db.execute("SELECT expires FROM grants WHERE id=?", (site.grant_id,)).fetchone()[0]
        == initial_expiry
    )
    assert authority.store.db.execute("SELECT COUNT(*) FROM workloads").fetchone()[0] == 1
    assert authority.store.db.execute("SELECT COUNT(*) FROM grants").fetchone()[0] == 1


def test_challenge_and_credential_are_bound_to_exact_site_key_and_issuer(registered):
    authority, registry, site = registered
    key, jwk, challenge, encoded = enrollment(registry, site)
    assert set(challenge) == {"challenge_id", "nonce", "jkt", "issuer", "site_id", "expires_at"}
    assert challenge["issuer"] == authority.config.issuer
    assert challenge["site_id"] == site.site_id
    assert challenge["jkt"] == thumbprint(jwk)
    assert time.time() < challenge["expires_at"] <= time.time() + 15
    assert str(uuid.UUID(challenge["challenge_id"])) == challenge["challenge_id"]
    found, expected = registry.exchange_context(challenge["challenge_id"], jwk, encoded)
    assert found == site
    assert expected == challenge
    credential = registry.finish_exchange(challenge["challenge_id"], jwk, encoded, challenge)
    assert set(credential) == {
        "access_token",
        "token_type",
        "expires_at",
        "expires_in",
        "dpop_nonce",
        "tenant",
        "environment",
    }
    assert credential["token_type"] == "DPoP"
    assert credential["tenant"] == site.tenant
    claims = authority.verify_token(credential["access_token"])
    assert claims["cnf"] == {"jkt": thumbprint(public_jwk(key))}
    assert claims["scope"] == site.resource_action
    metadata = access(registry, site, key, credential)
    assert metadata == {
        "subject": site.subject,
        "tenant": site.tenant,
        "environment": site.environment,
        "grant_id": site.grant_id,
        "action": site.resource_action,
        "expires_at": claims["exp"],
    }


@pytest.mark.parametrize(
    "change", ["missing", "extra", "nonce", "jkt", "issuer", "site_id", "expires_at", "id"]
)
def test_public_origin_proof_requires_exact_record_and_failed_checks_do_not_consume_it(registered, change):
    authority, registry, site = registered
    _, jwk, challenge, encoded = enrollment(registry, site)
    hostile = dict(challenge)
    if change == "missing":
        del hostile["nonce"]
    elif change == "extra":
        hostile["attacker"] = "injected"
    elif change == "expires_at":
        hostile["expires_at"] += 1
    elif change == "id":
        hostile["challenge_id"] = str(uuid.uuid4())
    else:
        hostile[change] = "attacker-controlled"
    with pytest.raises(Denied, match="site_proof_mismatch"):
        registry.finish_exchange(challenge["challenge_id"], jwk, encoded, hostile)
    assert authority.store.db.execute("SELECT 1 FROM site_challenges").fetchone() is None
    assert authority.store.db.execute("SELECT 1 FROM nonces").fetchone() is None
    assert authority.store.db.execute("SELECT 1 FROM buckets").fetchone() is None
    assert authority.store.db.execute("SELECT COUNT(*) FROM proofs").fetchone()[0] == 0
    registry.finish_exchange(challenge["challenge_id"], jwk, encoded, challenge)


def test_challenge_replay_is_denied_even_with_a_fresh_dpop_jti(registered):
    _, registry, site = registered
    key, jwk, challenge, encoded = enrollment(registry, site)
    registry.finish_exchange(challenge["challenge_id"], jwk, encoded, challenge)
    for encoded_proof in [
        encoded,
        proof(key, "POST", registry.authority.config.issuer + "/v1/site/token", challenge["nonce"]),
    ]:
        with pytest.raises(Denied, match="challenge_not_authorized"):
            registry.finish_exchange(challenge["challenge_id"], jwk, encoded_proof, challenge)


def test_challenge_cannot_be_rebound_to_another_key_nonce_or_token_endpoint(registered):
    _, registry, site = registered
    key, jwk, challenge, encoded = enrollment(registry, site)
    attacker = fresh_key()
    with pytest.raises(Denied, match="proof_key_mismatch"):
        registry.exchange_context(challenge["challenge_id"], public_jwk(attacker), encoded)
    for target, nonce, expected in [
        (registry.authority.config.issuer + "/v1/site/token", "other-nonce-long-enough", "invalid_nonce"),
        ("https://other-issuer.security.example/v1/site/token", challenge["nonce"], "proof_target_mismatch"),
    ]:
        with pytest.raises(Denied, match=expected):
            registry.exchange_context(challenge["challenge_id"], jwk, proof(key, "POST", target, nonce))


def test_expired_or_unknown_challenges_cannot_be_exchanged(registered, monkeypatch):
    authority, registry, site = registered
    key, jwk, challenge, encoded = enrollment(registry, site)
    with pytest.raises(Denied, match="invalid_nonce"):
        registry.exchange_context(str(uuid.uuid4()), jwk, encoded)
    advanced = time.time() + 16
    monkeypatch.setattr(cloud.time, "time", lambda: advanced)
    fresh_encoded = proof(key, "POST", authority.config.issuer + "/v1/site/token", challenge["nonce"])
    with pytest.raises(Denied, match="challenge_not_authorized"):
        registry.finish_exchange(challenge["challenge_id"], jwk, fresh_encoded, challenge)


def test_unauthenticated_challenges_cannot_reserve_nonce_slots_or_verified_quota(registered):
    authority, registry, site = registered
    attacker = public_jwk(fresh_key())
    changes = authority.store.db.total_changes
    challenges = [registry.challenge(site.grant_id, attacker) for _ in range(1000)]
    assert len({challenge["nonce"] for challenge in challenges}) == 1000
    assert all(len(challenge["nonce"]) == 71 for challenge in challenges)
    assert authority.store.db.total_changes == changes
    for table in ("nonces", "site_challenges", "buckets", "proofs"):
        assert authority.store.db.execute("SELECT count(*) FROM " + table).fetchone()[0] == 0
    _, credential = issue(registry, site)
    assert authority.verify_token(credential["access_token"])["sub"] == site.subject
    assert (
        authority.store.db.execute("SELECT count(*) FROM site_challenges WHERE consumed=1").fetchone()[0] == 1
    )


def test_selector_collision_is_rejected_before_enrollment_state_changes(registered, monkeypatch):
    authority, _, site = registered
    second = replace(
        site,
        site_id="22222222-2222-4222-8222-222222222222",
        origin="https://second-project.netlify.app",
        subject="second-project",
        tenant="tenant-b",
        grant_id="second-grant",
    )
    monkeypatch.setattr(SiteRegistry, "_selector", staticmethod(lambda _: b"x" * 16))
    changes = authority.store.db.total_changes
    with pytest.raises(ValueError, match="selectors must be unique"):
        SiteRegistry(authority, [site, second])
    assert authority.store.db.total_changes == changes


@pytest.mark.parametrize("offset", [0, 1, 5, 20, 21, 52])
def test_stateless_nonce_rejects_version_expiry_selector_and_mac_tampering(registered, offset):
    authority, registry, site = registered
    key, jwk, challenge, _ = enrollment(registry, site)
    raw = bytearray(base64.urlsafe_b64decode(challenge["nonce"] + "="))
    raw[offset] ^= 1
    tampered = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    encoded = proof(key, "POST", authority.config.issuer + "/v1/site/token", tampered)
    with pytest.raises(Denied, match="invalid_nonce"):
        registry.exchange_context(challenge["challenge_id"], jwk, encoded)
    assert authority.store.db.execute("SELECT 1 FROM site_challenges").fetchone() is None


@pytest.mark.parametrize("binding", ["issuer", "site_id", "origin", "grant_id", "jkt", "challenge_id"])
def test_stateless_mac_authenticates_every_enrollment_binding(registered, binding):
    authority, registry, site = registered
    key, jwk, challenge, _ = enrollment(registry, site)
    challenge_id = challenge["challenge_id"]
    if binding == "issuer":
        authority.config = replace(authority.config, issuer="https://replacement.security.example")
    elif binding in {"site_id", "origin", "grant_id"}:
        changed = {
            "site_id": "22222222-2222-4222-8222-222222222222",
            "origin": "https://different-project.netlify.app",
            "grant_id": "different-grant",
        }
        registry._selectors[registry._selector(site.grant_id)] = replace(site, **{binding: changed[binding]})
    elif binding == "jkt":
        key, jwk = fresh_key(), None
        jwk = public_jwk(key)
    else:
        challenge_id = str(uuid.uuid4())
    encoded = proof(key, "POST", authority.config.issuer + "/v1/site/token", challenge["nonce"])
    with pytest.raises(Denied, match="invalid_nonce"):
        registry.exchange_context(challenge_id, jwk, encoded)


def test_dpop_is_validated_before_stateless_nonce_or_database_admission(registered):
    authority, registry, site = registered
    _, jwk, challenge, _ = enrollment(registry, site)
    with pytest.raises(Denied, match="invalid_proof"):
        registry.exchange_context(challenge["challenge_id"], jwk, "not-a-jwt")
    assert authority.store.db.execute("SELECT 1 FROM site_challenges").fetchone() is None


def test_restart_rotates_challenge_mac_without_revoking_existing_access(registered):
    _, registry, site = registered
    key, credential = issue(registry, site)
    _, pending_jwk, challenge, encoded = enrollment(registry, site)
    restored = SiteRegistry(registry.authority, [site])
    with pytest.raises(Denied, match="invalid_nonce"):
        restored.exchange_context(challenge["challenge_id"], pending_jwk, encoded)
    assert access(restored, site, key, credential)["subject"] == site.subject


def test_verified_budget_limits_only_enrollments_that_proved_origin_control(registered):
    _, registry, site = registered
    for _ in range(30):
        issue(registry, site)
    _, jwk, challenge, encoded = enrollment(registry, site)
    with pytest.raises(Denied, match="rate_limited"):
        registry.finish_exchange(challenge["challenge_id"], jwk, encoded, challenge)


def test_interruption_before_issuance_preserves_one_retryable_pending_nonce(registered, monkeypatch):
    authority, registry, site = registered
    _, jwk, challenge, encoded = enrollment(registry, site)
    real_issue = authority.issue

    def interrupted(*args, **kwargs):
        raise RuntimeError("simulated interruption before issuance")

    monkeypatch.setattr(authority, "issue", interrupted)
    with pytest.raises(RuntimeError, match="interruption"):
        registry.finish_exchange(challenge["challenge_id"], jwk, encoded, challenge)
    digest = hashlib.sha256(challenge["nonce"].encode()).hexdigest()
    assert authority.store.db.execute("SELECT 1 FROM nonces WHERE digest=?", (digest,)).fetchone() is not None
    assert authority.store.db.execute("SELECT count(*) FROM proofs").fetchone()[0] == 0
    monkeypatch.setattr(authority, "issue", real_issue)
    credential = registry.finish_exchange(challenge["challenge_id"], jwk, encoded, challenge)
    assert authority.verify_token(credential["access_token"])["sub"] == site.subject
    assert authority.store.db.execute("SELECT 1 FROM nonces WHERE digest=?", (digest,)).fetchone() is None


def test_interruption_after_issuance_never_recreates_the_consumed_nonce(registered, monkeypatch):
    authority, registry, site = registered
    key, jwk, challenge, encoded = enrollment(registry, site)
    real_issue = authority.issue

    def interrupted_after_commit(*args, **kwargs):
        real_issue(*args, **kwargs)
        raise RuntimeError("simulated interruption after issuance commit")

    monkeypatch.setattr(authority, "issue", interrupted_after_commit)
    with pytest.raises(RuntimeError, match="after issuance"):
        registry.finish_exchange(challenge["challenge_id"], jwk, encoded, challenge)
    digest = hashlib.sha256(challenge["nonce"].encode()).hexdigest()
    assert authority.store.db.execute("SELECT 1 FROM nonces WHERE digest=?", (digest,)).fetchone() is None
    assert (
        authority.store.db.execute(
            "SELECT consumed FROM site_challenges WHERE id=?", (challenge["challenge_id"],)
        ).fetchone()[0]
        == 0
    )
    monkeypatch.setattr(authority, "issue", real_issue)
    for encoded_proof in (
        encoded,
        proof(key, "POST", authority.config.issuer + "/v1/site/token", challenge["nonce"]),
    ):
        with pytest.raises(Denied, match="invalid_nonce"):
            registry.finish_exchange(challenge["challenge_id"], jwk, encoded_proof, challenge)
    assert authority.store.db.execute("SELECT 1 FROM nonces WHERE digest=?", (digest,)).fetchone() is None
    assert (
        authority.store.db.execute("SELECT count(*) FROM audit WHERE event='credential.issued'").fetchone()[0]
        == 1
    )


@pytest.mark.parametrize("mutation", ["disabled-workload", "disabled-grant", "expired-grant"])
def test_current_policy_blocks_existing_access_pending_exchange_and_new_enrollment(registered, mutation):
    authority, registry, site = registered
    key, credential = issue(registry, site)
    _, pending_jwk, challenge, encoded = enrollment(registry, site)
    if mutation == "disabled-workload":
        authority.store.db.execute("UPDATE workloads SET enabled=0 WHERE id=?", (site.subject,))
    elif mutation == "disabled-grant":
        authority.store.db.execute("UPDATE grants SET enabled=0 WHERE id=?", (site.grant_id,))
    else:
        authority.store.db.execute("UPDATE grants SET expires=? WHERE id=?", (time.time() - 1, site.grant_id))
    with pytest.raises(Denied):
        access(registry, site, key, credential)
    with pytest.raises(Denied):
        registry.finish_exchange(challenge["challenge_id"], pending_jwk, encoded, challenge)
    with pytest.raises(Denied):
        registry.challenge(site.grant_id, public_jwk(fresh_key()))
    restored = SiteRegistry(authority, [replace(site, grant_expires_at=time.time() + 3600)])
    with pytest.raises(Denied):
        restored.challenge(site.grant_id, public_jwk(fresh_key()))


def test_authenticated_revocation_event_is_durable_and_does_not_regrant_on_restart(registered):
    authority, registry, site = registered
    key, credential = issue(registry, site)
    event_id = str(uuid.uuid4())
    first = authority.event(event_id, "revoke_workload", site.subject, "compromised")
    assert authority.event(event_id, "revoke_workload", site.subject, "compromised") == first
    restored = SiteRegistry(authority, [site])
    with pytest.raises(Denied):
        restored.challenge(site.grant_id, public_jwk(fresh_key()))
    with pytest.raises(Denied):
        access(restored, site, key, credential)


def test_revocation_survives_reopening_database_and_reconstructing_authority(registered):
    authority, registry, site = registered
    key, credential = issue(registry, site)
    authority.event(str(uuid.uuid4()), "revoke_workload", site.subject, "compromised")
    path = Path(authority.store.db.execute("PRAGMA database_list").fetchone()[2])
    authority.store.close()
    reopened = Store(path)
    try:
        restored = SiteRegistry(Authority(reopened, authority.config), [site])
        with pytest.raises(Denied):
            restored.challenge(site.grant_id, public_jwk(fresh_key()))
        with pytest.raises(Denied):
            access(restored, site, key, credential)
    finally:
        reopened.close()


@pytest.mark.parametrize(
    "changes",
    [
        {"method": "POST"},
        {"url": "https://attacker.example/api/pap/records"},
        {"url": "https://trusted-project.netlify.app/api/admin"},
        {"url": "https://trusted-project.netlify.app/api/pap/records?tenant=other"},
        {"url": "https://trusted-project.netlify.app/api/pap/records#fragment"},
        {"tenant": "tenant-b"},
        {"action": "notes.create"},
        {"audience": "urn:other:resource"},
    ],
)
def test_fixed_registered_resource_policy_cannot_be_overridden_by_request_metadata(registered, changes):
    _, registry, site = registered
    key, credential = issue(registry, site)
    with pytest.raises(Denied, match="resource_not_authorized"):
        access(registry, site, key, credential, **changes)


def test_reusable_custom_get_policy_issues_only_its_registered_action(tmp_path):
    directory = tmp_path / "custom-policy"
    directory.mkdir(mode=0o700)
    store = Store(directory / "state.sqlite")
    try:
        authority = Authority(store, Config(issuer="https://issuer.security.example"))
        site = Site(
            site_id="33333333-3333-4333-8333-333333333333",
            origin="https://orders-project.netlify.app",
            subject="orders-project",
            tenant="tenant-a",
            environment="production",
            grant_id="orders-grant",
            grant_expires_at=time.time() + 600,
            trusted_site_contexts=True,
            resource_path="/api/orders/current",
            resource_action="orders.read",
        )
        registry = SiteRegistry(authority, [site])
        key, credential = issue(registry, site)
        assert authority.verify_token(credential["access_token"])["scope"] == "orders.read"
        assert access(registry, site, key, credential)["action"] == "orders.read"
        with pytest.raises(Denied, match="resource_not_authorized"):
            access(
                registry, site, key, credential, action="records.read", url=site.origin + "/api/pap/records"
            )
    finally:
        store.close()


def test_resource_proof_replay_and_stolen_token_fail_while_fresh_proofs_succeed(registered):
    _, registry, site = registered
    key, credential = issue(registry, site)
    encoded = proof(
        key, "GET", site.origin + site.resource_path, credential["dpop_nonce"], credential["access_token"]
    )
    values = (
        "GET",
        site.origin + site.resource_path,
        site.tenant,
        site.resource_action,
        registry.authority.config.audience,
    )
    registry.authorize(credential["access_token"], encoded, *values)
    with pytest.raises(Denied, match="proof_replayed"):
        registry.authorize(credential["access_token"], encoded, *values)
    with pytest.raises(Denied, match="proof_key_mismatch"):
        access(registry, site, fresh_key(), credential)
    assert access(registry, site, key, credential)["subject"] == site.subject


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "192.168.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
        "2001:db8::1",
        "224.0.0.1",
        "ff0e::1",
        "168.63.129.16",
        "192.0.0.192",
        "192.88.99.1",
        "::ffff:127.0.0.1",
        "::ffff:1.1.1.1",
        "64:ff9b::a9fe:a9fe",
        "64:ff9b:1::a9fe:a9fe",
        "2002:7f00:1::",
        "2001:0000:4136:e378:8000:63bf:3fff:fdd2",
        "2606:4700:4700::1111%lo0",
    ],
)
def test_dns_resolution_rejects_nonpublic_ips_at_connection_time(monkeypatch, address):
    async def run():
        async def resolution(*_args, **_kwargs):
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 443))]

        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolution)
        with pytest.raises(OSError, match="nonpublic"):
            await PublicResolver("trusted-project.netlify.app").resolve("trusted-project.netlify.app", 443)

    asyncio.run(run())


def test_dns_resolution_pins_valid_ips_and_rejects_host_port_rebinding(monkeypatch):
    async def run():
        async def resolution(*_args, **_kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("1.1.1.1", 443))]

        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolution)
        resolver = PublicResolver("trusted-project.netlify.app")
        resolved = await resolver.resolve("trusted-project.netlify.app", 443)
        assert resolved[0]["host"] == "1.1.1.1"
        assert resolved[0]["hostname"] == "trusted-project.netlify.app"
        for host, port in [("other.netlify.app", 443), ("trusted-project.netlify.app", 80)]:
            with pytest.raises(OSError, match="unregistered"):
                await resolver.resolve(host, port)

    asyncio.run(run())


def mock_provider(monkeypatch, raw, *, status=200, content_type="application/json"):
    observed = {}

    class Content:
        def __init__(self):
            self.chunks = list(raw) if isinstance(raw, list) else [raw]

        async def read(self, maximum):
            observed.setdefault("read_limits", []).append(maximum)
            return self.chunks.pop(0) if self.chunks else b""

    class Response:
        content = Content()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

    response = Response()
    response.status = status
    response.content_type = content_type

    class Session:
        def __init__(self, **kwargs):
            observed["session"] = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        def get(self, url, **kwargs):
            observed["url"], observed["request"] = url, kwargs
            return response

    def connector(**kwargs):
        observed["connector"] = kwargs
        return object()

    monkeypatch.setattr(cloud.aiohttp, "ClientSession", Session)
    monkeypatch.setattr(cloud.aiohttp, "TCPConnector", connector)
    return observed


def test_origin_verification_uses_fixed_https_path_no_redirects_no_proxy_and_bounded_json(monkeypatch):
    challenge_id = str(uuid.uuid4())
    record = {"public": "record"}
    observed = mock_provider(monkeypatch, json.dumps(record).encode())
    assert asyncio.run(fetch_site_record("https://trusted-project.netlify.app", challenge_id)) == record
    assert observed["url"] == "https://trusted-project.netlify.app/.well-known/pap/site-proof/" + challenge_id
    assert observed["session"]["trust_env"] is False
    assert observed["request"]["allow_redirects"] is False
    assert observed["request"]["headers"] == {"Accept": "application/json", "Accept-Encoding": "identity"}
    assert observed["session"]["auto_decompress"] is False
    assert observed["connector"]["use_dns_cache"] is False
    assert observed["read_limits"][0] == 16385


@pytest.mark.parametrize(
    "raw,status,content_type",
    [
        (b'{"duplicate":1,"duplicate":2}', 200, "application/json"),
        (b"[]", 200, "application/json"),
        (b"{", 200, "application/json"),
        (b"x" * 16385, 200, "application/json"),
        (b"{}", 302, "application/json"),
        (b"{}", 200, "text/html"),
        (b"{}", 503, "application/json"),
    ],
)
def test_origin_verification_rejects_ambiguous_oversized_or_redirected_provider_responses(
    monkeypatch, raw, status, content_type
):
    mock_provider(monkeypatch, raw, status=status, content_type=content_type)
    with pytest.raises(Denied):
        asyncio.run(fetch_site_record("https://trusted-project.netlify.app", str(uuid.uuid4())))


@pytest.mark.parametrize("chunks", [[b"{}", b"unexpected-trailing-data"], [b"{}", b" " * 16384]])
def test_origin_verification_reads_to_eof_before_accepting_a_chunked_response(monkeypatch, chunks):
    mock_provider(monkeypatch, chunks)
    with pytest.raises(Denied):
        asyncio.run(fetch_site_record("https://trusted-project.netlify.app", str(uuid.uuid4())))


@pytest.mark.parametrize(
    "value",
    [
        "http://app.example.org",
        "https://app.example.org/",
        "https://APP.example.org",
        "HTTPS://app.example.org",
        "https://app.example.org:443",
        "https://app.example.org:8443",
        "https://user:password@app.example.org",
        "https://app.example.org/path",
        "https://app.example.org?target=localhost",
        "https://app.example.org#fragment",
        "https://app.example.org.",
        "https://app.example.org\n",
        "https://app.exa\tmple.org",
        "https://app.example.org\\@evil.example.org",
        "https://app%2eexample.org",
        "https://localhost",
        "https://foo.localhost",
        "https://foo.local",
        "https://metadata.google.internal",
        "https://foo.home.arpa",
        "https://127.0.0.1",
        "https://2130706433",
        "https://127.1",
        "https://0x7f000001",
        "https://[::1]",
        "https://éxample.org",
        "https://a..example.org",
        "https://-app.example.org",
        "https://app-.example.org",
        "https://" + "a" * 64 + ".example.org",
        None,
        1,
        {},
    ],
)
def test_portable_origin_rejects_ambiguous_or_local_destinations(value):
    with pytest.raises(ValueError, match="canonical public DNS"):
        https_origin(value)


@pytest.mark.parametrize(
    "origin",
    ["https://app.example.org", "https://service.project.up.railway.app", "https://app.onrender.com"],
)
def test_portable_origin_accepts_canonical_deployment_domains(origin):
    assert https_origin(origin) == origin
    with pytest.raises(ValueError, match="netlify"):
        netlify_origin(origin)


@pytest.mark.parametrize("identifier", ["unknown", "https-origin ", "NETLIFY", "pap.custom:adapter", None, []])
def test_identity_registry_is_closed_and_rejects_unknown_or_dynamic_adapters(identifier):
    with pytest.raises(ValueError, match="unknown identity adapter"):
        identity_adapter(identifier)


def test_identity_registry_cannot_be_modified_and_reports_actual_trust_method():
    assert set(IDENTITY_ADAPTERS) == {"netlify", "https-origin"}
    assert identity_adapter().identifier == "netlify"
    assert identity_adapter("https-origin").attestation == "origin-control"
    with pytest.raises(TypeError):
        IDENTITY_ADAPTERS["remote-oidc"] = object()


def test_legacy_netlify_binding_migrates_without_reprovisioning_or_extending_policy(registered):
    authority, _, site = registered
    previous = authority.store.setting("site:" + site.grant_id)
    previous.pop("identity_adapter")
    authority.store.set_setting("site:" + site.grant_id, previous)
    initial_expiry = authority.store.db.execute(
        "SELECT expires FROM grants WHERE id=?", (site.grant_id,)
    ).fetchone()[0]
    SiteRegistry(authority, [replace(site, grant_expires_at=site.grant_expires_at + 3600)])
    assert authority.store.setting("site:" + site.grant_id)["identity_adapter"] == "netlify"
    assert authority.store.db.execute(
        "SELECT expires FROM grants WHERE id=?", (site.grant_id,)
    ).fetchone()[0] == initial_expiry


@pytest.mark.parametrize("legacy", [False, True])
def test_existing_grant_cannot_switch_identity_adapters_even_for_the_same_origin(registered, legacy):
    authority, _, site = registered
    if legacy:
        previous = authority.store.setting("site:" + site.grant_id)
        previous.pop("identity_adapter")
        authority.store.set_setting("site:" + site.grant_id, previous)
    with pytest.raises(ValueError, match="silently rebound"):
        SiteRegistry(authority, [replace(site, identity_adapter="https-origin")])
    assert authority.store.setting("site:" + site.grant_id).get("identity_adapter", "netlify") == "netlify"


def test_identity_adapter_is_bound_into_challenge_mac(registered):
    _, registry, site = registered
    values = (str(uuid.uuid4()), thumbprint(public_jwk(fresh_key())), int(time.time()) + 15)
    assert registry._challenge_mac(site, *values) != registry._challenge_mac(
        replace(site, identity_adapter="https-origin"), *values
    )


def test_portable_adapter_enrollment_authorization_replay_and_revocation(registered):
    authority, _, site = registered
    portable = replace(
        site,
        site_id=str(uuid.uuid4()),
        origin="https://production-workload.example.org",
        subject="portable-workload",
        grant_id="portable-grant",
        identity_adapter="https-origin",
    )
    registry = SiteRegistry(authority, [portable])
    key, credential = issue(registry, portable)
    assert access(registry, portable, key, credential)["subject"] == portable.subject
    with pytest.raises(Denied, match="resource_not_authorized"):
        access(registry, portable, key, credential, url="https://other.example.org" + portable.resource_path)
    authority.event(str(uuid.uuid4()), "revoke_workload", portable.subject, "compromised")
    with pytest.raises(Denied, match="workload_not_authorized"):
        access(registry, portable, key, credential)
    with pytest.raises(Denied, match="workload_not_authorized"):
        enrollment(registry, portable)


def test_portable_fetch_uses_explicit_adapter_and_registered_fixed_path(monkeypatch):
    record = {"public": "record"}
    observed = mock_provider(monkeypatch, json.dumps(record).encode())
    challenge_id = str(uuid.uuid4())
    origin = "https://production-workload.example.org"
    assert asyncio.run(fetch_site_record(origin, challenge_id, identity_adapter="https-origin")) == record
    assert observed["url"] == origin + "/.well-known/pap/site-proof/" + challenge_id
    with pytest.raises(ValueError, match="netlify"):
        asyncio.run(fetch_site_record(origin, challenge_id))


def test_public_resolver_rejects_mixed_global_and_private_answers(monkeypatch):
    async def run():
        async def resolution(*_args, **_kwargs):
            return [
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("1.1.1.1", 443)),
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("169.254.169.254", 443)),
            ]

        monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolution)
        with pytest.raises(OSError, match="nonpublic"):
            await PublicResolver("production-workload.example.org").resolve("production-workload.example.org", 443)

    asyncio.run(run())


@pytest.mark.parametrize("address", ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "2001:4860:4860::8888"])
def test_public_destination_allows_direct_public_service_addresses(address):
    assert str(public_destination(address)) == address


def test_origin_verification_rejects_compressed_responses_before_reading_or_decompressing(monkeypatch):
    class Compressed:
        status = 200
        content_type = "application/json"
        headers = {"Content-Encoding": "gzip"}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        @property
        def content(self):
            raise AssertionError("compressed body must not be consumed")

    class Session:
        def __init__(self, **kwargs):
            assert kwargs["auto_decompress"] is False

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

        def get(self, *_args, **_kwargs):
            return Compressed()

    monkeypatch.setattr(cloud.aiohttp, "ClientSession", Session)
    monkeypatch.setattr(cloud.aiohttp, "TCPConnector", lambda **_kwargs: object())
    with pytest.raises(Denied, match="site_proof_invalid"):
        asyncio.run(fetch_site_record("https://trusted-project.netlify.app", str(uuid.uuid4())))
