"""Credential custody, paid-call admission and fixed-provider boundary tests."""

import asyncio
import base64
import json
import os
import time
import uuid

import pytest
from aiohttp.test_utils import TestClient, TestServer
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import ValidationError
from test_production import TestCertificates, TestSigner, authorization_request, configuration, enroll

import pap.connectors as connectors
import pap.production as production
from pap.connectors import ConnectorConfig, ConnectorStore, CredentialRequest
from pap.crypto import Denied
from pap.signers import OpenBaoSigner, SignerError
from pap.storage import Store


class CredentialSigner(TestSigner):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.aes = AESGCM(AESGCM.generate_key(bit_length=256))

    def encrypt_provider_credential(self, provider, value):
        nonce = os.urandom(12)
        return (
            "vault:v1:"
            + base64.b64encode(nonce + self.aes.encrypt(nonce, value.encode(), provider.encode())).decode()
        )

    def decrypt_provider_credential(self, provider, value):
        raw = base64.b64decode(value.split(":", 2)[2])
        return self.aes.decrypt(raw[:12], raw[12:], provider.encode()).decode()


def import_keys(state):
    for provider in ("openai", "nasa", "nlr"):
        state.credential(
            CredentialRequest(provider=provider, action="import", credential="fixture-only-" + provider)
        )


@pytest.fixture
async def broker(tmp_path, monkeypatch):
    monkeypatch.setattr(production, "OpenBaoSigner", CredentialSigner)
    monkeypatch.setattr(production, "CertificateManager", TestCertificates)
    value = configuration(tmp_path)
    value["connectors"] = [{"operation": "space-briefing", "grant_id": "test-grant", "enabled": True}]
    runtime = production.ProductionRuntime(production.ProductionConfig.model_validate(value))
    await runtime.call(runtime.actor.start)
    await runtime.call(import_keys, runtime.actor.connectors)
    runtime.ready, runtime.last_maintenance = True, time.monotonic()
    client = TestClient(TestServer(runtime.public_app()))
    await client.start_server()
    try:
        yield runtime, client
    finally:
        await client.close()
        await runtime.close()


def result(operation, period):
    return {
        "operation": operation,
        "generated_at": connectors.instant(time.time()),
        "period": connectors.instant(period * 3600),
        "model": connectors.MODEL,
        "summary": "Fixture factual summary.",
        "sources": [],
        "cached": False,
    }


def test_disabled_default_and_strict_secret_request():
    assert not ConnectorConfig(operation="space-briefing", grant_id="test").enabled
    request = CredentialRequest(provider="openai", action="import", credential="fixture-only-secret")
    assert "fixture-only-secret" not in repr(request)
    for invalid in [
        {"provider": "openai", "action": "import"},
        {"provider": "openai", "action": "import", "credential": "bad\nvalue"},
        {"provider": "other", "action": "import", "credential": "fixture-only-secret"},
        {"provider": "openai", "action": "revoke", "credential": "fixture-only-secret"},
        {
            "provider": "openai",
            "action": "import",
            "credential": "fixture-only-secret",
            "url": "https://evil.test",
        },
    ]:
        with pytest.raises(ValidationError):
            CredentialRequest.model_validate(invalid)


def test_configuration_requires_a_unique_existing_grant(tmp_path):
    config = configuration(tmp_path)
    config["connectors"] = [{"operation": "space-briefing", "grant_id": "missing", "enabled": True}]
    with pytest.raises(ValidationError):
        production.ProductionConfig.model_validate(config)
    config["connectors"][0]["enabled"] = False
    production.ProductionConfig.model_validate(config)
    config["connectors"] *= 2
    with pytest.raises(ValidationError):
        production.ProductionConfig.model_validate(config)


def test_only_ciphertext_is_persisted_and_rotation_generations_survive_revoke(tmp_path):
    store = Store(tmp_path / "private" / "db.sqlite")
    state = ConnectorStore(store, CredentialSigner(), [])
    secret = "fixture-private-openai-credential"
    try:
        value = state.credential(CredentialRequest(provider="openai", action="import", credential=secret))
        assert value == {"provider": "openai", "configured": True, "generation": 1}
        row = store.db.execute("SELECT * FROM provider_credentials").fetchone()
        assert row["ciphertext"].startswith("vault:v1:")
        assert secret not in "\n".join(store.db.iterdump())
        assert state.signer.decrypt_provider_credential("openai", row["ciphertext"]) == secret
        state.credential(CredentialRequest(provider="openai", action="revoke"))
        value = state.credential(CredentialRequest(provider="openai", action="import", credential=secret))
        assert value["generation"] == 2
    finally:
        store.close()
    assert secret.encode() not in (tmp_path / "private" / "db.sqlite").read_bytes()


def test_abandoned_claim_is_not_retried_after_restart(tmp_path):
    store = Store(tmp_path / "private" / "db.sqlite")
    signer = CredentialSigner()
    config = [ConnectorConfig(operation="science-digest", grant_id="grant", enabled=True)]
    state = ConnectorStore(store, signer, config, clock=lambda: 7200)
    import_keys(state)
    claim = state.claim("science-digest", {"grant_id": "grant"})
    assert claim["key"] == ("grant", "science-digest", 2)
    state = ConnectorStore(store, signer, config, clock=lambda: 7200)
    with pytest.raises(Denied, match="connector_period_unavailable"):
        state.claim("science-digest", {"grant_id": "grant"})
    state.clock = lambda: 10800
    assert state.claim("science-digest", {"grant_id": "grant"})["key"][2] == 3
    with pytest.raises(Denied, match="connector_not_authorized"):
        state.claim("science-digest", {"grant_id": "other"})
    store.close()


async def test_broker_consumes_proof_once_caches_and_rechecks_revocation(broker, monkeypatch):
    runtime, client = broker
    calls = []

    async def generate(operation, credentials, period):
        calls.append(operation)
        assert credentials == {"openai": "fixture-only-openai", "nasa": "fixture-only-nasa"}
        return result(operation, period)

    monkeypatch.setattr(production, "generate", generate)
    key, credential, _ = await enroll(runtime, client, monkeypatch)
    request = authorization_request(runtime, key, credential)
    response = await client.post("/v1/connectors/space-briefing", **request)
    assert response.status == 200, await response.text()
    assert not (await response.json())["cached"]
    response = await client.post("/v1/connectors/space-briefing", **request)
    assert response.status == 401  # Same DPoP proof cannot replay even a cached read.
    response = await client.post(
        "/v1/connectors/space-briefing", **authorization_request(runtime, key, credential)
    )
    assert response.status == 200
    assert (await response.json())["cached"]
    assert calls == ["space-briefing"]
    await runtime.call(
        runtime.actor.authority.event, str(uuid.uuid4()), "revoke_workload", "netlify-test", "operator"
    )
    response = await client.post(
        "/v1/connectors/space-briefing", **authorization_request(runtime, key, credential)
    )
    assert response.status in {401, 403}
    assert calls == ["space-briefing"]


async def test_unknown_and_unauthenticated_operations_never_call_provider(broker, monkeypatch):
    runtime, client = broker

    async def never(*args):
        raise AssertionError("provider called")

    monkeypatch.setattr(production, "generate", never)
    assert (await client.post("/v1/connectors/unknown", json={})).status == 404
    assert (await client.post("/v1/connectors/space-briefing", json={})).status == 401
    assert (await client.post("/v0/connectors/credentials", json={})).status == 404
    key, credential, _ = await enroll(runtime, client, monkeypatch)
    request = authorization_request(runtime, key, credential)
    request["json"]["model"] = "caller-selected"
    assert (await client.post("/v1/connectors/space-briefing", **request)).status == 400


async def test_uncertain_paid_outcome_is_never_automatically_retried(broker, monkeypatch):
    runtime, client = broker
    calls = []

    async def uncertain(*args):
        calls.append(True)
        raise TimeoutError("provider may already have charged")

    monkeypatch.setattr(production, "generate", uncertain)
    key, credential, _ = await enroll(runtime, client, monkeypatch)
    for _ in range(2):
        response = await client.post(
            "/v1/connectors/space-briefing", **authorization_request(runtime, key, credential)
        )
        assert response.status == 503
        assert "charged" not in await response.text()
    assert len(calls) == 1


async def test_inflight_revocation_prevents_result_release(broker, monkeypatch):
    runtime, client = broker
    started, finish = asyncio.Event(), asyncio.Event()

    async def slow(operation, credentials, period):
        started.set()
        await finish.wait()
        return result(operation, period)

    monkeypatch.setattr(production, "generate", slow)
    key, credential, _ = await enroll(runtime, client, monkeypatch)
    pending = asyncio.create_task(
        client.post("/v1/connectors/space-briefing", **authorization_request(runtime, key, credential))
    )
    await asyncio.wait_for(started.wait(), 2)
    # The actor remains responsive while the upstream model request is pending.
    await runtime.call(
        runtime.actor.authority.event, str(uuid.uuid4()), "revoke_workload", "netlify-test", "operator"
    )
    finish.set()
    response = await pending
    assert response.status in {401, 403}


@pytest.mark.parametrize("action", ["revoke", "import"])
async def test_credential_change_blocks_cache_without_another_paid_attempt(broker, monkeypatch, action):
    runtime, client = broker
    calls = []

    async def generate(operation, credentials, period):
        calls.append(operation)
        return result(operation, period)

    monkeypatch.setattr(production, "generate", generate)
    key, credential, _ = await enroll(runtime, client, monkeypatch)
    response = await client.post(
        "/v1/connectors/space-briefing", **authorization_request(runtime, key, credential)
    )
    assert response.status == 200
    request = {"provider": "openai", "action": action}
    if action == "import":
        request["credential"] = "replacement-fixture-openai"
    await runtime.call(runtime.actor.connectors.credential, CredentialRequest.model_validate(request))
    response = await client.post(
        "/v1/connectors/space-briefing", **authorization_request(runtime, key, credential)
    )
    assert response.status == 503
    if action == "revoke":
        await runtime.call(
            runtime.actor.connectors.credential,
            CredentialRequest(
                provider="openai",
                action="import",
                credential="replacement-fixture-openai",
            ),
        )
        response = await client.post(
            "/v1/connectors/space-briefing", **authorization_request(runtime, key, credential)
        )
        assert response.status == 503
    assert calls == ["space-briefing"]


async def test_concurrent_requests_share_one_durable_paid_admission(broker, monkeypatch):
    runtime, client = broker
    started, finish = asyncio.Event(), asyncio.Event()
    calls = []

    async def slow(operation, credentials, period):
        calls.append(operation)
        started.set()
        await finish.wait()
        return result(operation, period)

    monkeypatch.setattr(production, "generate", slow)
    key, credential, _ = await enroll(runtime, client, monkeypatch)
    pending = asyncio.create_task(
        client.post("/v1/connectors/space-briefing", **authorization_request(runtime, key, credential))
    )
    await asyncio.wait_for(started.wait(), 2)
    response = await client.post(
        "/v1/connectors/space-briefing", **authorization_request(runtime, key, credential)
    )
    assert response.status == 503
    finish.set()
    assert (await pending).status == 200
    assert calls == ["space-briefing"]


async def test_unix_admin_import_requires_kernel_peer_identity(broker):
    runtime, _ = broker
    admin = TestClient(TestServer(runtime.admin_app()))
    await admin.start_server()
    try:
        response = await admin.post(
            "/v0/connectors/credentials",
            json={
                "provider": "openai",
                "action": "import",
                "credential": "private-fixture-credential",
            },
        )
        assert response.status == 403
        assert "private-fixture" not in await response.text()
    finally:
        await admin.close()


class FixtureHTTP:
    def __init__(self):
        self.calls = []

    async def request(self, method, origin, path, **kwargs):
        self.calls.append((method, origin, path, kwargs))
        if origin == "https://api.nasa.gov":
            day = kwargs["params"]["start_date"]
            return {
                "near_earth_objects": {
                    day: [{"name": "asteroid", "is_potentially_hazardous_asteroid": False}]
                }
            }
        if origin == "https://developer.nlr.gov":
            # The documented Nearest contract requires coordinates and radius.
            # An undocumented city filter previously returned HTTP200 with zero
            # records; a status-only fixture would miss that regression.
            assert path == "/api/alt-fuel-stations/v1/nearest.json"
            assert kwargs["params"] == {
                "fuel_type": "ELEC",
                "latitude": "38.3498",
                "longitude": "-81.6326",
                "radius": "25",
                "status": "E",
                "access": "public",
                "limit": "10",
            }
            return {
                "fuel_stations": [
                    {"station_name": "901 Lee Street Parking", "city": "Charleston", "ev_level2_evse_num": 2}
                ]
            }
        assert kwargs["timeout"] == 15
        assert set(kwargs["payload"]) == {"model", "store", "max_output_tokens", "instructions", "input"}
        assert kwargs["payload"]["model"] == "gpt-4.1-mini"
        assert kwargs["payload"]["store"] is False
        assert kwargs["payload"]["max_output_tokens"] == 192
        assert "fixture-private-" not in kwargs["payload"]["input"]
        return {
            "status": "completed",
            "output": [
                {
                    "type": "message",
                    "role": "assistant",
                    "content": [
                        {
                            "type": "output_text",
                            "text": "One asteroid and one station are listed. Listings are not real-time availability.",
                        }
                    ],
                }
            ],
        }


@pytest.mark.parametrize(
    "operation,providers",
    [("space-briefing", {"nasa"}), ("charging-briefing", {"nlr"}), ("science-digest", {"nasa", "nlr"})],
)
async def test_fixed_provider_requests_and_bounded_model_payload(operation, providers):
    http = FixtureHTTP()
    credentials = {p: "fixture-private-" + p for p in ("nasa", "nlr", "openai")}
    value = await connectors.generate(operation, credentials, 497000, http=http, clock=lambda: 1789203600)
    assert {source["provider"] for source in value["sources"]} == providers
    assert set(value) == {"operation", "generated_at", "period", "model", "summary", "sources", "cached"}
    assert all("?" not in source["url"] for source in value["sources"])
    assert all("fixture-private" not in json.dumps(source) for source in value["sources"])
    assert http.calls[-1][1:3] == ("https://api.openai.com", "/v1/responses")
    for method, origin, path, arguments in http.calls[:-1]:
        assert method == "GET" and "api_key" not in arguments["params"]
        assert "X-Api-Key" in arguments["headers"]
        assert "fixture-private" not in origin + path


async def test_nlr_documented_nearest_contract_returns_bounded_charleston_sample():
    source, data = await connectors._nlr(FixtureHTTP(), "fixture-private-nlr")
    assert source["records"] == 1
    assert source["url"] == "https://developer.nlr.gov/docs/transportation/alt-fuel-stations-v1/nearest/"
    assert "within 25 miles" in source["title"]
    assert data["location"] == "Within 25 miles of Charleston, WV"
    assert data["sample"][0]["name"] == "901 Lee Street Parking"


async def test_valid_empty_station_result_is_preserved_without_invented_data():
    class EmptyStations(FixtureHTTP):
        async def request(self, method, origin, path, **kwargs):
            await super().request(method, origin, path, **kwargs)
            return {"total_results": 0, "fuel_stations": []}

    source, data = await connectors._nlr(EmptyStations(), "fixture-private-nlr")
    assert source["records"] == 0 and data["sample"] == []


async def test_provider_transport_rejects_arbitrary_origins_before_network():
    with pytest.raises(Denied, match="connector_upstream_invalid"):
        await connectors.ProviderHTTP().request("GET", "https://evil.test", "/", headers={})


@pytest.mark.parametrize("text", ["fixture-private-openai", "😀" * 1025, "bad\x00output", ""])
async def test_model_secret_reflection_and_oversized_serialization_are_rejected(text):
    class MalformedModel(FixtureHTTP):
        async def request(self, method, origin, path, **kwargs):
            value = await super().request(method, origin, path, **kwargs)
            if origin == "https://api.openai.com":
                value["output"][0]["content"][0]["text"] = text
            return value

    with pytest.raises(Denied, match="connector_generation_invalid"):
        await connectors.generate(
            "space-briefing",
            {
                "openai": "fixture-private-openai",
                "nasa": "fixture-private-nasa",
            },
            497000,
            http=MalformedModel(),
        )


async def test_source_cannot_leak_a_known_credential_into_the_model_input():
    class SourceReflection(FixtureHTTP):
        async def request(self, method, origin, path, **kwargs):
            if origin == "https://api.openai.com":
                raise AssertionError("secret reached paid model request")
            value = await super().request(method, origin, path, **kwargs)
            day = kwargs["params"]["start_date"]
            value["near_earth_objects"][day][0]["name"] = "fixture-private-nasa"
            return value

    with pytest.raises(Denied, match="connector_upstream_invalid"):
        await connectors.generate(
            "space-briefing",
            {
                "openai": "fixture-private-openai",
                "nasa": "fixture-private-nasa",
            },
            497000,
            http=SourceReflection(),
        )


def test_transit_uses_dedicated_derived_context_and_validates_key_policy():
    calls = []
    policy = {
        "name": "pap-provider-credentials",
        "type": "aes256-gcm96",
        "derived": True,
        "exportable": False,
        "allow_plaintext_backup": False,
        "supports_encryption": True,
        "supports_decryption": True,
        "latest_version": 2,
        "auto_rotate_period": 86400,
    }
    secret = "fixture-only-provider-key"
    ciphertext = "vault:v2:" + base64.b64encode(b"encrypted-fixture-credential").decode()

    def transport(method, path, payload, headers):
        calls.append((method, path, payload))
        if path == "/v1/auth/cert/login":
            return 200, {"auth": {"client_token": "fixture-only-bao-token", "lease_duration": 60}}
        if path == "/v1/transit/keys/pap-provider-credentials":
            return 200, {"data": policy}
        assert base64.b64decode(payload["context"]) == b"pap-provider-credentials:v1:openai"
        if "/encrypt/" in path:
            assert base64.b64decode(payload["plaintext"]).decode() == secret
            return 200, {"data": {"ciphertext": ciphertext}}
        return 200, {"data": {"plaintext": base64.b64encode(secret.encode()).decode()}}

    signer = OpenBaoSigner(
        "https://bao.example.test",
        role="issuer",
        client_cert="/cert.pem",
        client_key="/key.pem",
        _transport=transport,
    )
    assert signer.encrypt_provider_credential("openai", secret) == ciphertext
    assert signer.decrypt_provider_credential("openai", ciphertext) == secret
    assert not any(method == "POST" and "/keys/" in path for method, path, payload in calls)
    policy["exportable"] = True
    with pytest.raises(SignerError, match="provider_key_configuration_invalid"):
        signer.encrypt_provider_credential("openai", secret)
    with pytest.raises(SignerError, match="provider_credential_invalid"):
        signer.decrypt_provider_credential("arbitrary", ciphertext)
