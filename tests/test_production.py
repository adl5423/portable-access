"""Production HTTP wiring and actor behavior; separate suites exercise real KMS/Linux."""

import asyncio
import copy
import json
import os
import socket
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils
from pydantic import ValidationError

import pap.production as production
from pap.crypto import Denied, fresh_key, proof, public_jwk
from pap.production import ProductionConfig, ProductionRuntime
from pap.signers import PreparedKey, SignerError


def configuration(tmp_path):
    state = str(tmp_path / "authority")
    return {
        "issuer": "https://authority.example.test",
        "audience": "urn:pap:production-test",
        "state_dir": state,
        "admin_uid": os.getuid() + 1,
        "kms": {
            "provider": "openbao",
            "base_url": "https://127.0.0.1:8200",
            "role": "issuer",
            "client_cert": state + "/credentials/current/client-cert.pem",
            "client_key": state + "/credentials/current/client-key.pem",
            "ca_file": str(tmp_path / "transport-ca.pem"),
            "client_ca_file": str(tmp_path / "client-ca.pem"),
            "pki_role": "issuer",
            "common_name": "issuer",
        },
        "sites": [
            {
                "site_id": str(uuid.uuid4()),
                "origin": "https://pap-test.netlify.app",
                "subject": "netlify-test",
                "tenant": "test",
                "environment": "production",
                "grant_id": "test-grant",
                "grant_expires_at": time.time() + 1800,
                "trusted_site_contexts": True,
            }
        ],
    }


@pytest.mark.parametrize(
    "issuer",
    [
        "http://authority.example.test",
        "https://authority.example.test/",
        "https://authority.example.test:443",
        "HTTPS://authority.example.test",
        "https://user@authority.example.test",
        "https://authority.example.test\n",
        "https://127.0.0.1",
        "https://authority.example.test/path",
    ],
)
def test_config_requires_canonical_public_https_issuer(tmp_path, issuer):
    value = configuration(tmp_path)
    value["issuer"] = issuer
    with pytest.raises(ValidationError):
        ProductionConfig.model_validate(value)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda x: x.update(listen_host="0.0.0.0"),
        lambda x: x.update(admin_uid=os.getuid()),
        lambda x: x.update(signing_interval=90),
        lambda x: x.update(token_ttl=301),
        lambda x: x.update(state_dir="relative"),
        lambda x: x.update(unknown=True),
        lambda x: x["kms"].update(provider="local"),
        lambda x: x["kms"].update(token="forbidden"),
        lambda x: x["kms"].update(client_ca_file="relative"),
        lambda x: x["kms"].update(client_key="/other/current/client-key.pem"),
        lambda x: x["sites"][0].update(trusted_site_contexts=False),
        lambda x: x["sites"][0].update(environment="deploy-preview"),
    ],
)
def test_config_fails_closed_on_weaker_profiles(tmp_path, mutation):
    value = configuration(tmp_path)
    mutation(value)
    with pytest.raises(ValidationError):
        ProductionConfig.model_validate(value)


def test_empty_site_registry_is_valid_and_defaults_are_deliberate(tmp_path):
    value = configuration(tmp_path)
    value["sites"] = []
    config = ProductionConfig.model_validate(value)
    assert config.signing_interval == 86400 and config.token_ttl == 60
    assert config.sites == []


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value["kms"].update(enrollment_uid=None),
        lambda value: value["kms"].update(enrollment_uid=0),
        lambda value: value["kms"].update(enrollment_uid=os.getuid()),
        lambda value: value["kms"].update(enrollment_socket="/tmp/untrusted.sock"),
        lambda value: value["kms"].update(common_name="other-identity"),
        lambda value: value["kms"].update(base_url="https://other.example.test"),
    ],
)
def test_local_enrollment_cannot_weaken_identity_or_peer_boundary(tmp_path, mutation):
    value = configuration(tmp_path)
    value["kms"].update(
        enrollment_socket="/run/pap-enroller/enroll.sock",
        enrollment_uid=os.getuid() + 2,
        pki_role="pap-issuer",
        common_name="pap-issuer",
    )
    ProductionConfig.model_validate(value)
    mutation(value)
    with pytest.raises(ValidationError):
        ProductionConfig.model_validate(value)


def test_expired_credentials_are_recovered_before_the_first_kms_signing_operation():
    events = []

    class Certificates:
        def maintain(self):
            events.append("renewed-through-independent-identity")
            return {"renewed": True}

    class Signer:
        def reset_authentication(self):
            events.append("discarded-old-certificate-login")

        def sign(self, reference, data):
            events.append("kms-sign")
            return b"signature"

    managed = production.CertificateManagedSigner(Signer(), Certificates())
    assert managed.sign("reference", b"message") == b"signature"
    assert events == ["renewed-through-independent-identity", "discarded-old-certificate-login", "kms-sign"]

    class Unavailable:
        def maintain(self):
            raise SignerError("enrollment_unavailable")

    managed = production.CertificateManagedSigner(Signer(), Unavailable())
    with pytest.raises(SignerError, match="enrollment_unavailable"):
        managed.sign("reference", b"message")
    assert events.count("kms-sign") == 1


def test_readiness_waits_for_actual_kms_reauthentication_after_certificate_recovery(tmp_path):
    actor = production.AuthorityActor(ProductionConfig.model_validate(configuration(tmp_path)))

    class Certificates:
        calls = 0

        def maintain(self):
            self.calls += 1
            return {"renewed": self.calls == 1}

    class Signer:
        resets = 0
        checks = 0

        def reset_authentication(self):
            self.resets += 1

        def health(self):
            self.checks += 1
            if self.checks == 1:
                raise SignerError("signer_transport_unavailable")
            return {"authenticated": True}

    class Authority:
        calls = 0

        def maintenance(self):
            self.calls += 1

    actor.certificates, actor.signer, actor.authority = Certificates(), Signer(), Authority()
    with pytest.raises(SignerError):
        actor.maintain()
    assert actor.credentials_revalidation_pending is True
    assert actor.authority.calls == 0
    actor.maintain()
    assert actor.credentials_revalidation_pending is False
    assert actor.signer.resets == 1 and actor.signer.checks == 2
    assert actor.authority.calls == 1


def test_config_file_requires_root_policy_owner(tmp_path):
    if os.getuid() == 0:
        pytest.skip("root owner condition requires a non-root test process")
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(configuration(tmp_path)))
    path.chmod(0o600)
    with pytest.raises(ValueError, match="owned by root"):
        production.load_config(path)


def test_admin_listener_cannot_be_created_from_untrusted_environment(monkeypatch):
    for name in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"):
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ValueError, match="activation required"):
        production.activated_admin_socket(1234)


def test_production_cli_rejects_nonlinux(monkeypatch):
    monkeypatch.setattr(production.sys, "platform", "darwin")
    with pytest.raises(ValueError, match="non-root Linux"):
        production.require_isolated_linux()


class TestSigner:
    __test__ = False

    def __init__(self, *args, **kwargs):
        self.keys = {}
        self.fail = False
        self.authentication_resets = self.health_checks = 0

    def prepare(self, generation):
        key = self.keys.setdefault(generation, fresh_key())
        return PreparedKey(generation, public_jwk(key))

    def sign(self, reference, value):
        if self.fail:
            raise SignerError("signer_transport_unavailable")
        r, s = utils.decode_dss_signature(self.keys[reference].sign(value, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def retire(self, reference):
        pass

    def reset_authentication(self):
        self.authentication_resets += 1

    def health(self):
        self.health_checks += 1
        if self.fail:
            raise SignerError("signer_transport_unavailable")
        return {"authenticated": True}


class TestCertificates:
    __test__ = False

    def __init__(self, *args):
        pass

    def maintain(self):
        return {"renewed": False}

    def current_certificate(self):
        return SimpleNamespace(not_valid_after_utc=datetime.now(UTC) + timedelta(hours=1))


@pytest.fixture
async def service(tmp_path, monkeypatch):
    monkeypatch.setattr(production, "OpenBaoSigner", TestSigner)
    monkeypatch.setattr(production, "CertificateManager", TestCertificates)
    config = ProductionConfig.model_validate(configuration(tmp_path))
    runtime = ProductionRuntime(config)
    await runtime.call(runtime.actor.start)
    runtime.ready = True
    runtime.last_maintenance = time.monotonic()
    client = TestClient(TestServer(runtime.public_app()))
    await client.start_server()
    try:
        yield runtime, client
    finally:
        await client.close()
        await runtime.close()


async def enroll(runtime, client, monkeypatch):
    key = fresh_key()
    jwk = public_jwk(key)
    result = await client.post("/v1/site/challenge", json={"grant_id": "test-grant", "jwk": jwk})
    assert result.status == 200
    record = await result.json()
    captured = []

    async def fetch(origin, challenge_id):
        captured.append((origin, challenge_id))
        return copy.deepcopy(record)

    monkeypatch.setattr(production, "fetch_site_record", fetch)
    encoded = proof(key, "POST", runtime.config.issuer + "/v1/site/token", record["nonce"])
    response = await client.post(
        "/v1/site/token", json={"challenge_id": record["challenge_id"], "jwk": jwk}, headers={"DPoP": encoded}
    )
    assert response.status == 200, await response.text()
    assert captured == [(runtime.config.sites[0].origin, record["challenge_id"])]
    return key, await response.json(), (record, jwk, encoded)


def authorization_request(runtime, key, credential):
    site = runtime.config.sites[0]
    url = site.origin + site.resource_path
    return {
        "json": {
            "method": "GET",
            "url": url,
            "tenant": site.tenant,
            "action": site.resource_action,
            "audience": runtime.config.audience,
        },
        "headers": {
            "Authorization": "DPoP " + credential["access_token"],
            "DPoP": proof(key, "GET", url, credential["dpop_nonce"], credential["access_token"]),
        },
    }


async def test_http_enrollment_authorization_revocation_and_key_custody(service, monkeypatch):
    runtime, client = service
    key, credential, _ = await enroll(runtime, client, monkeypatch)
    response = await client.post("/v1/authorize", **authorization_request(runtime, key, credential))
    assert response.status == 200
    assert set(await response.json()) == {
        "subject",
        "tenant",
        "environment",
        "grant_id",
        "action",
        "expires_at",
    }
    await runtime.call(
        runtime.actor.authority.event, str(uuid.uuid4()), "revoke_workload", "netlify-test", "compromised"
    )
    response = await client.post("/v1/authorize", **authorization_request(runtime, key, credential))
    assert response.status == 403
    assert (await response.json())["error"] == "workload_not_authorized"
    assert (
        await runtime.call(
            lambda: runtime.actor.store.db.execute(
                "SELECT count(*) FROM signing_keys WHERE private IS NOT NULL"
            ).fetchone()[0]
        )
        == 0
    )


async def test_site_proof_fetch_is_after_crypto_validation_and_bound_to_registered_origin(
    service, monkeypatch
):
    runtime, client = service

    def forbidden(*args):
        raise AssertionError("invalid DPoP must never cause an outbound fetch")

    monkeypatch.setattr(production, "fetch_site_record", forbidden)
    key = fresh_key()
    result = await client.post("/v1/site/challenge", json={"grant_id": "test-grant", "jwk": public_jwk(key)})
    record = await result.json()
    response = await client.post(
        "/v1/site/token",
        json={"challenge_id": record["challenge_id"], "jwk": public_jwk(key)},
        headers={"DPoP": proof(key, "POST", "https://evil.example.test/v1/site/token", record["nonce"])},
    )
    assert response.status == 401


async def test_exchange_replay_is_rejected(service, monkeypatch):
    runtime, client = service
    _, _, (record, jwk, encoded) = await enroll(runtime, client, monkeypatch)
    response = await client.post(
        "/v1/site/token", json={"challenge_id": record["challenge_id"], "jwk": jwk}, headers={"DPoP": encoded}
    )
    assert response.status == 403


async def test_revocation_during_outbound_proof_fetch_prevents_issuance(service, monkeypatch):
    runtime, client = service
    key = fresh_key()
    jwk = public_jwk(key)
    response = await client.post("/v1/site/challenge", json={"grant_id": "test-grant", "jwk": jwk})
    record = await response.json()

    async def revoke(origin, challenge_id):
        await runtime.call(
            runtime.actor.authority.event, str(uuid.uuid4()), "revoke_workload", "netlify-test", "compromised"
        )
        return record

    monkeypatch.setattr(production, "fetch_site_record", revoke)
    response = await client.post(
        "/v1/site/token",
        json={"challenge_id": record["challenge_id"], "jwk": jwk},
        headers={"DPoP": proof(key, "POST", runtime.config.issuer + "/v1/site/token", record["nonce"])},
    )
    assert response.status == 403
    assert (
        await runtime.call(
            lambda: runtime.actor.store.db.execute(
                "SELECT count(*) FROM audit WHERE event='credential.issued'"
            ).fetchone()[0]
        )
        == 0
    )


async def test_mismatched_origin_record_and_failed_kms_never_return_a_token(service, monkeypatch):
    runtime, client = service
    key = fresh_key()
    jwk = public_jwk(key)
    response = await client.post("/v1/site/challenge", json={"grant_id": "test-grant", "jwk": jwk})
    record = await response.json()

    async def fetch(origin, challenge_id):
        return {**record, "issuer": "https://attacker.example.test"}

    monkeypatch.setattr(production, "fetch_site_record", fetch)
    response = await client.post(
        "/v1/site/token",
        json={"challenge_id": record["challenge_id"], "jwk": jwk},
        headers={"DPoP": proof(key, "POST", runtime.config.issuer + "/v1/site/token", record["nonce"])},
    )
    assert response.status == 403

    async def good_fetch(origin, challenge_id):
        return record

    monkeypatch.setattr(production, "fetch_site_record", good_fetch)
    await runtime.call(setattr, runtime.actor.signer, "fail", True)
    response = await client.post(
        "/v1/site/token",
        json={"challenge_id": record["challenge_id"], "jwk": jwk},
        headers={"DPoP": proof(key, "POST", runtime.config.issuer + "/v1/site/token", record["nonce"])},
    )
    assert response.status == 503
    assert "access_token" not in await response.json()


@pytest.mark.parametrize(
    "raw",
    [
        '{"grant_id":"test-grant","grant_id":"evil","jwk":{}}',
        '{"grant_id":"test-grant","jwk":{},"unknown":true}',
    ],
)
async def test_duplicate_and_unknown_request_members_are_rejected(service, raw):
    _, client = service
    response = await client.post("/v1/site/challenge", data=raw, headers={"Content-Type": "application/json"})
    assert response.status == 400


async def test_public_application_does_not_expose_admin_api(service):
    runtime, client = service
    assert (await client.get("/v0/status")).status == 404
    admin = TestClient(TestServer(runtime.admin_app()))
    await admin.start_server()
    try:
        response = await admin.get("/v0/status")
        assert response.status == 403
        assert (await response.json())["error"] == "local_identity_required"
    finally:
        await admin.close()


async def test_lifecycle_failure_and_staleness_fail_closed(service):
    runtime, client = service
    for failure, last in (("failed", time.monotonic()), (None, time.monotonic() - 16)):
        runtime.failure, runtime.last_maintenance = failure, last
        assert (await client.get("/health")).status == 503
        assert (await client.get("/.well-known/jwks.json")).status == 503


async def test_actor_does_not_block_event_loop_or_cross_sqlite_threads(service):
    runtime, _ = service
    worker = await runtime.call(threading.get_ident)
    assert worker != threading.get_ident()
    assert worker == await runtime.call(threading.get_ident)
    blocked = threading.Event()
    entered = threading.Event()

    def slow():
        entered.set()
        blocked.wait(2)

    task = asyncio.create_task(runtime.call(slow))
    try:
        for _ in range(100):
            if entered.is_set():
                break
            await asyncio.sleep(0.001)
        assert entered.is_set()
        # This coroutine runs while the actor thread waits.
        assert not task.done()
    finally:
        blocked.set()
        await task


async def test_actor_exception_cancellation_capacity_and_close_are_consistent(service):
    runtime, _ = service

    def fail():
        raise RuntimeError("synthetic")

    with pytest.raises(RuntimeError, match="synthetic"):
        await runtime.call(fail)
    await asyncio.sleep(0)
    assert runtime.pending == 0
    gate, entered = threading.Event(), threading.Event()

    def wait():
        entered.set()
        gate.wait(2)

    task = asyncio.create_task(runtime.call(wait))
    try:
        for _ in range(100):
            if entered.is_set():
                break
            await asyncio.sleep(0.001)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert runtime.pending == 1
    finally:
        gate.set()
    await runtime.call(lambda: None)
    await asyncio.sleep(0)
    assert runtime.pending == 0
    runtime.pending = 32
    with pytest.raises(Denied, match="authority_busy"):
        await runtime.call(lambda: None)
    await runtime.close()
    await runtime.close()


async def test_failed_start_does_not_mask_original_error_and_can_close_again(tmp_path, monkeypatch):
    runtime = ProductionRuntime(ProductionConfig.model_validate(configuration(tmp_path)))

    def fail():
        raise ValueError("startup-failure")

    monkeypatch.setattr(runtime.actor, "start", fail)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        with pytest.raises(ValueError, match="startup-failure"):
            await runtime.start(listener)
        await runtime.close()
    finally:
        listener.close()


@pytest.fixture
def persisted_external_authority(tmp_path):
    config = ProductionConfig.model_validate(configuration(tmp_path))
    path = tmp_path / "authority" / "authority.sqlite"
    store = production.Store(path)
    try:
        authority = production.Authority(
            store,
            production.Config(
                issuer=config.issuer,
                audience=config.audience,
                token_ttl=config.token_ttl,
                signing_interval=config.signing_interval,
            ),
            signer=TestSigner(),
        )
        active = dict(authority.active_key())
        assert active["private"] is None and active["provider_ref"]
        assert time.time() - active["created"] < config.signing_interval
    finally:
        store.close()
    return config, path, active


@pytest.mark.parametrize("renewed", [True, False])
async def test_startup_authentication_failure_blocks_existing_key_readiness_and_database_open(
    persisted_external_authority, monkeypatch, renewed
):
    config, database, active = persisted_external_authority
    value = config.model_dump()
    value["kms"].update(
        enrollment_socket="/run/pap-enroller/enroll.sock",
        enrollment_uid=os.getuid() + 2,
        pki_role="pap-issuer",
        common_name="pap-issuer",
    )
    config = ProductionConfig.model_validate(value)
    events = []
    original_database = database.read_bytes()

    class UnavailableSigner(TestSigner):
        def reset_authentication(self):
            events.append("discard-cached-authentication")

        def health(self):
            events.append("fresh-client-authentication-failed")
            raise SignerError("signer_transport_unavailable")

        def prepare(self, generation):
            pytest.fail("persisted active key must not need another generation")

        def sign(self, reference, value):
            pytest.fail("startup authentication must not be inferred from an incidental signature")

    class Certificates:
        def __init__(self, *args, **kwargs):
            assert kwargs.get("recovery_issuer") is not None

        def maintain(self):
            events.append("certificate-maintenance")
            return {"renewed": renewed}

    def forbidden_store(*args, **kwargs):
        pytest.fail("KMS readiness must be established before opening persistent authority state")

    monkeypatch.setattr(production, "OpenBaoSigner", UnavailableSigner)
    monkeypatch.setattr(production, "CertificateManager", Certificates)
    monkeypatch.setattr(production, "Store", forbidden_store)
    runtime = ProductionRuntime(config)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        with pytest.raises(SignerError, match="signer_transport_unavailable"):
            await runtime.start(listener)
        assert events == [
            "certificate-maintenance",
            "discard-cached-authentication",
            "fresh-client-authentication-failed",
        ]
        assert runtime.ready is False and runtime.runners == [] and runtime.task is None
        assert runtime.actor.store is None and runtime.actor.authority is None
        assert runtime.actor.registry is None and runtime.actor.lock is None
        assert database.read_bytes() == original_database
        assert active["state"] == "active" and active["private"] is None
    finally:
        await runtime.close()
        listener.close()


def test_startup_discards_legacy_old_certificate_login_before_fresh_health_and_database_open(
    persisted_external_authority, monkeypatch
):
    config, database, active = persisted_external_authority
    events, signers = [], []
    real_store = production.Store

    class CachedSigner(TestSigner):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.cached_identity = None
            self.actual_logins = 0
            signers.append(self)

        def reset_authentication(self):
            events.append("discard-old-certificate-login")
            self.cached_identity = None

        def health(self):
            if self.cached_identity is not None:
                events.append("cached-health-without-authentication")
            else:
                self.actual_logins += 1
                self.cached_identity = "new-certificate"
                events.append("fresh-new-certificate-login")
            return {"authenticated": True}

        def prepare(self, generation):
            pytest.fail("existing fresh active generation must survive startup")

        def sign(self, reference, value):
            pytest.fail("existing fresh active generation does not need a rotation signature")

    class LegacyCertificates:
        def __init__(self, signer, *args, **kwargs):
            assert not kwargs.get("recovery_issuer")
            self.signer = signer

        def maintain(self):
            # Legacy PKI issuance authenticates using the old leaf before publishing
            # its replacement, leaving a token that an unguarded health call can reuse.
            self.signer.cached_identity = "old-certificate"
            events.append("legacy-renewal-cached-old-login")
            return {"renewed": True}

    def observed_store(path):
        events.append("database-opened")
        return real_store(path)

    monkeypatch.setattr(production, "OpenBaoSigner", CachedSigner)
    monkeypatch.setattr(production, "CertificateManager", LegacyCertificates)
    monkeypatch.setattr(production, "Store", observed_store)
    actor = production.AuthorityActor(config)
    try:
        actor.start()
        assert events == [
            "legacy-renewal-cached-old-login",
            "discard-old-certificate-login",
            "fresh-new-certificate-login",
            "database-opened",
        ]
        assert signers[0].actual_logins == 1 and signers[0].cached_identity == "new-certificate"
        assert actor.authority.active_key()["kid"] == active["kid"]
        assert actor.authority.active_key()["private"] is None
        assert actor.store is not None and actor.registry is not None
    finally:
        actor.close()
