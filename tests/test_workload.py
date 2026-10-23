"""Origin SDK tests: real ES256/DPoP, no cloud calls or paid provider requests."""

import asyncio
import json
import time
import uuid
from dataclasses import replace

import aiohttp
import jwt
import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer, make_mocked_request
from multidict import CIMultiDict

from pap.crypto import fresh_key, thumbprint, verify_proof
from pap.workload import (
    HTTPSJSONTransport,
    JSONResponse,
    MemoryProofStore,
    WorkloadClient,
    WorkloadConfig,
    WorkloadError,
    _json,
    install_proof_route,
)


def public_config():
    return {
        "enabled": True, "issuerURL": "https://authority.example.com",
        "workloadID": "8c3fb051-3113-4734-a9a4-98cd036d88dc", "grantID": "docker-read",
        "resourceOrigin": "https://workload.example.com", "resourcePath": "/api/pap/records",
        "resourceAction": "records.read", "tenant": "example", "environment": "production",
        "audience": "urn:pap:docker-example", "trustOriginDeployment": True,
    }


class Clock:
    def __init__(self):
        self.current = int(time.time())

    def __call__(self):
        return self.current


class AuthorityTransport:
    """Trusted transport seam validates the actual SDK proofs and publication."""

    def __init__(self, config, store, clock):
        self.config, self.store, self.clock = config, store, clock
        self.signing_key = fresh_key()
        self.challenges = {}
        self.issued = []
        self.seen = set()
        self.resource_proofs = []
        self.resource_calls = 0
        self.token_calls = 0
        self.challenge_calls = 0
        self.closed = False
        self.mutate_challenge = lambda value: value
        self.mutate_credential = lambda value: value
        self.mutate_claims = lambda value: value
        self.mutate_authorization = lambda value: value
        self.token_started = asyncio.Event()
        self.token_gate = asyncio.Event()
        self.token_gate.set()
        self.fail_resource = None
        self.fail_challenge_once = False
        self.lose_token_response_once = False
        self.last_authorization_body = None
        self.authorization_calls = 0
        self.authorization_seen = set()

    async def request(self, method, url, *, body, headers):
        await asyncio.sleep(0)
        issuer = self.config["issuerURL"]
        if url == issuer + "/health":
            return JSONResponse(200, {"ready": True})
        if url == issuer + "/v1/site/challenge":
            assert method == "POST" and set(body) == {"grant_id", "jwk"}
            assert body["grant_id"] == self.config["grantID"]
            self.challenge_calls += 1
            if self.fail_challenge_once:
                self.fail_challenge_once = False
                raise TimeoutError("secret-upstream-error-must-never-escape")
            record = {
                "challenge_id": str(uuid.uuid4()), "nonce": "N" * 71,
                "jkt": thumbprint(body["jwk"]), "issuer": issuer,
                "site_id": self.config["workloadID"], "expires_at": self.clock() + 15,
            }
            self.challenges[record["challenge_id"]] = record
            return JSONResponse(200, self.mutate_challenge(dict(record)))
        if url == issuer + "/v1/site/token":
            self.token_calls += 1
            self.token_started.set()
            await self.token_gate.wait()
            assert method == "POST" and set(body) == {"challenge_id", "jwk"}
            record = self.challenges.pop(body["challenge_id"])
            assert await self.store.read(record["challenge_id"]) == record
            claims, jkt = verify_proof(
                headers["DPoP"], "POST", url, expected_jkt=record["jkt"], now=self.clock(),
            )
            assert claims["nonce"] == record["nonce"]
            assert claims["jti"] not in self.seen
            self.seen.add(claims["jti"])
            assert thumbprint(body["jwk"]) == jkt
            token_claims = self.mutate_claims({
                "iss": issuer, "aud": self.config["audience"], "sub": "docker-workload",
                "client_id": "docker-workload", "iat": self.clock(), "exp": self.clock() + 60,
                "jti": str(uuid.uuid4()), "cnf": {"jkt": jkt}, "tenant": self.config["tenant"],
                "environment": "production", "grant_id": self.config["grantID"], "epoch": 1,
                "scope": self.config["resourceAction"],
            })
            token = jwt.encode(token_claims, self.signing_key, algorithm="ES256", headers={
                "typ": "at+jwt", "kid": str(uuid.uuid4()),
            })
            self.issued.append(jkt)
            response = {
                "access_token": token, "token_type": "DPoP", "expires_at": self.clock() + 60,
                "expires_in": 60, "dpop_nonce": "D" * 32,
                "tenant": self.config["tenant"], "environment": "production",
            }
            if self.lose_token_response_once:
                self.lose_token_response_once = False
                raise TimeoutError("lost-response-with-possibly-issued-token")
            return JSONResponse(200, self.mutate_credential(response))
        if url == issuer + "/v1/authorize":
            self.authorization_calls += 1
            self.last_authorization_body = body
            assert body == {
                "method": "GET", "url": self.config["resourceOrigin"] + self.config["resourcePath"],
                "tenant": self.config["tenant"], "action": self.config["resourceAction"],
                "audience": self.config["audience"],
            }
            if headers["DPoP"] in self.authorization_seen:
                return JSONResponse(401, None)
            self.authorization_seen.add(headers["DPoP"])
            return JSONResponse(200, self.mutate_authorization({
                "subject": "docker-workload", "tenant": self.config["tenant"],
                "environment": "production", "grant_id": self.config["grantID"],
                "action": self.config["resourceAction"], "expires_at": self.clock() + 60,
            }))
        assert url == self.config["resourceOrigin"] + self.config["resourcePath"]
        assert method == "GET" and body is None and set(headers) == {"Authorization", "DPoP"}
        self.resource_calls += 1
        if self.fail_resource is not None:
            if self.fail_resource == "timeout":
                raise TimeoutError("response-secret-value")
            status, self.fail_resource = self.fail_resource, None
            return JSONResponse(status, {"error": "upstream-secret-value"})
        token = headers["Authorization"][5:]
        token_claims = jwt.decode(token, self.signing_key.public_key(), algorithms=["ES256"], options={
            "verify_aud": False, "verify_exp": False, "verify_iat": False,
        })
        claims, jkt = verify_proof(
            headers["DPoP"], "GET", url, token=token,
            expected_jkt=token_claims["cnf"]["jkt"], now=self.clock(),
        )
        assert claims["nonce"] == "D" * 32 and claims["jti"] not in self.seen
        self.seen.add(claims["jti"])
        self.resource_proofs.append((claims, jkt))
        return JSONResponse(200, {"records": [{"id": "example", "title": "public result"}]})

    async def close(self):
        self.closed = True


def fixture():
    config, clock = public_config(), Clock()
    store = MemoryProofStore(now=clock)
    transport = AuthorityTransport(config, store, clock)
    client = WorkloadClient(config, store=store, transport=transport, now=clock)
    return client, transport, store, clock


@pytest.mark.parametrize(("field", "value"), [
    ("enabled", False), ("enabled", 1), ("trustOriginDeployment", False),
    ("environment", "preview"), ("issuerURL", "http://authority.example.com"),
    ("issuerURL", "https://user:secret@authority.example.com"),
    ("resourceOrigin", "https://127.0.0.1"), ("resourceOrigin", "https://localhost"),
    ("resourceOrigin", "https://Workload.example.com"),
    ("resourceOrigin", "https://workload.example.com:443"),
    ("resourceOrigin", "https://workload.example.com/path"),
    ("resourceOrigin", "https://workload.example.com?query=yes"),
    ("workloadID", "not-uuid"), ("resourcePath", "/api/../secret"),
    ("resourcePath", "/api/%2Fsecret"), ("resourceAction", "WRITE ALL"),
    ("grantID", "wrong grant"), ("tenant", "tenant\n"), ("audience", "audience\x00"),
])
def test_config_rejects_unsafe_or_unacknowledged_bindings(field, value):
    config = public_config()
    config[field] = value
    with pytest.raises(WorkloadError):
        WorkloadConfig.from_dict(config)


def test_config_is_public_frozen_and_has_no_extra_credential_inputs():
    config = public_config()
    parsed = WorkloadConfig.from_dict(config)
    assert parsed.resource_origin == "https://workload.example.com"
    with pytest.raises(WorkloadError):
        WorkloadConfig.from_dict({**config, "apiKey": "never-accept-secret-input"})
    with pytest.raises(WorkloadError):
        replace(parsed, trust_origin_deployment=False)
    assert "token" not in repr(parsed).lower()


async def test_real_proofs_single_flight_and_renew_before_expiry():
    client, transport, store, clock = fixture()
    async with client:
        results = await asyncio.gather(*(client.get_json() for _ in range(20)))
        assert len(results) == 20 and all(set(result) == {"records"} for result in results)
        assert transport.token_calls == 1 and len(set(transport.issued)) == 1
        assert len({claims["jti"] for claims, _jkt in transport.resource_proofs}) == 20
        assert store._records == {}
        assert not hasattr(client, "access_token") and not hasattr(client, "private_key")
        clock.current += 51
        await client.get_json()
        assert transport.token_calls == 2 and len(set(transport.issued)) == 2
        assert transport.resource_proofs[0][1] != transport.resource_proofs[-1][1]
    assert transport.closed and client._cached is None
    with pytest.raises(WorkloadError, match="client_closed"):
        await client.get_json()


@pytest.mark.parametrize(("field", "value"), [
    ("issuer", "https://evil.example.com"), ("site_id", str(uuid.uuid4())),
    ("jkt", "A" * 43), ("expires_at", 1), ("challenge_id", "../escape"),
])
async def test_changed_challenge_cannot_be_published(field, value):
    client, transport, store, _clock = fixture()
    transport.mutate_challenge = lambda record: {**record, field: value}
    async with client:
        with pytest.raises(WorkloadError):
            await client.get_json()
    assert not store._records and transport.token_calls == 0 and transport.resource_calls == 0


@pytest.mark.parametrize(("field", "value"), [
    ("iss", "https://evil.example.com"), ("aud", "wrong-audience"),
    ("grant_id", "wrong-grant"), ("tenant", "wrong-tenant"),
    ("environment", "preview"), ("cnf", {"jkt": "A" * 43}),
    ("scope", "other.read"), ("exp", 1), ("client_id", "different-subject"),
])
async def test_misbound_token_is_never_cached_or_used(field, value):
    client, transport, store, _clock = fixture()
    transport.mutate_claims = lambda claims: {**claims, field: value}
    async with client:
        with pytest.raises(WorkloadError, match="credential_binding_mismatch"):
            await client.get_json()
        assert client._cached is None
    assert not store._records and transport.resource_calls == 0


@pytest.mark.parametrize(("field", "value"), [
    ("tenant", "other"), ("environment", "preview"), ("token_type", "Bearer"),
    ("access_token", "plain-bearer-key"), ("expires_in", 4000), ("expires_at", True),
])
async def test_invalid_credential_response_is_rejected(field, value):
    client, transport, store, _clock = fixture()
    transport.mutate_credential = lambda response: {**response, field: value}
    async with client:
        with pytest.raises(WorkloadError):
            await client.get_json()
    assert not store._records and transport.resource_calls == 0


async def test_store_change_after_publish_prevents_issuance():
    client, transport, store, _clock = fixture()
    original = store.read

    async def changed(challenge_id):
        return {**await original(challenge_id), "nonce": "changed-by-store" * 3}

    store.read = changed
    async with client:
        with pytest.raises(WorkloadError, match="proof_publication_mismatch"):
            await client.get_json()
    assert not store._records and transport.token_calls == 0


@pytest.mark.parametrize("fail_resource", ["timeout", 500, 429, 403])
async def test_resource_unknown_outcomes_are_not_resubmitted_or_exposed(fail_resource):
    client, transport, _store, _clock = fixture()
    transport.fail_resource = fail_resource
    async with client:
        with pytest.raises(WorkloadError) as caught:
            await client.get_json()
    assert transport.resource_calls == 1 and "secret" not in str(caught.value)


async def test_definitive_401_gets_one_fresh_key_and_proof_attempt():
    client, transport, _store, _clock = fixture()
    transport.fail_resource = 401
    async with client:
        await client.get_json()
    assert transport.resource_calls == 2 and len(set(transport.issued)) == 2


@pytest.mark.parametrize("failure", ["fail_challenge_once", "lose_token_response_once"])
async def test_issuer_recovery_uses_fresh_challenge_and_key(failure):
    client, transport, store, _clock = fixture()
    setattr(transport, failure, True)
    async with client:
        assert "records" in await client.get_json()
    assert transport.challenge_calls == 2 and transport.resource_calls == 1 and not store._records
    if failure == "lose_token_response_once":
        assert len(set(transport.issued)) == 2


async def test_cancel_one_caller_does_not_cancel_shared_renewal():
    client, transport, _store, _clock = fixture()
    transport.token_gate.clear()
    async with client:
        first = asyncio.create_task(client.get_json())
        second = asyncio.create_task(client.get_json())
        await transport.token_started.wait()
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        transport.token_gate.set()
        assert "records" in await second
    assert transport.token_calls == 1


async def test_close_cancels_pending_issuance_and_cleans_public_proof():
    client, transport, store, _clock = fixture()
    transport.token_gate.clear()
    pending = asyncio.create_task(client.get_json())
    await transport.token_started.wait()
    assert len(store._records) == 1
    await client.close()
    with pytest.raises(WorkloadError, match="client_closed"):
        await pending
    assert not store._records and client._cached is None and transport.closed


async def test_callback_is_get_only_noncacheable_expiring_and_has_no_publisher():
    now = time.time()
    store = MemoryProofStore()
    record = {
        "challenge_id": str(uuid.uuid4()), "nonce": "N" * 71, "jkt": "A" * 43,
        "issuer": public_config()["issuerURL"], "site_id": public_config()["workloadID"],
        "expires_at": now + 15,
    }
    await store.publish(record)
    app = web.Application()
    install_proof_route(app, store)
    async with TestClient(TestServer(app)) as client:
        target = "/.well-known/pap/site-proof/" + record["challenge_id"]
        response = await client.get(target)
        assert response.status == 200 and await response.json() == record
        assert "no-store" in response.headers["Cache-Control"]
        for method in ("POST", "PUT", "DELETE", "HEAD"):
            response = await client.request(method, target)
            assert response.status == 405
            assert response.headers["Allow"] == "GET"
        response = await client.get(target + "?jwk=attacker")
        assert response.status == 400
        response = await client.get(target, data=b"body")
        assert response.status == 400
        response = await client.get("/.well-known/pap/site-proof/" + str(uuid.uuid4()))
        assert response.status == 404
    assert set(record) == {"challenge_id", "nonce", "jkt", "issuer", "site_id", "expires_at"}
    assert "jwk" not in json.dumps(record) and "private" not in json.dumps(record)


async def test_proof_store_expiry_bounds_copy_and_conflict():
    clock = Clock()
    store = MemoryProofStore(max_records=1, now=clock)
    record = {
        "challenge_id": str(uuid.uuid4()), "nonce": "N" * 71, "jkt": "A" * 43,
        "issuer": public_config()["issuerURL"], "site_id": public_config()["workloadID"],
        "expires_at": clock() + 15,
    }
    await store.publish(record)
    read = await store.read(record["challenge_id"])
    read["nonce"] = "mutated"
    assert await store.read(record["challenge_id"]) == record
    with pytest.raises(WorkloadError, match="proof_record_conflict"):
        await store.publish({**record, "nonce": "X" * 71})
    with pytest.raises(WorkloadError, match="proof_store_full"):
        await store.publish({**record, "challenge_id": str(uuid.uuid4())})
    with pytest.raises(WorkloadError, match="challenge_expired"):
        await store.publish({**record, "expires_at": clock() + 121})
    clock.current += 16
    assert await store.read(record["challenge_id"]) is None


async def test_verifier_ignores_spoofed_hosts_and_consumes_original_headers_once():
    client, transport, _store, _clock = fixture()
    headers = {
        "Authorization": "DPoP a.b.c", "DPoP": "a.b.c", "Host": "evil.example.com",
        "X-Forwarded-Host": "evil.example.com", "Forwarded": "host=evil.example.com",
    }
    request = make_mocked_request("GET", public_config()["resourcePath"], headers=headers)
    async with client:
        result = await client.authorize_request(request)
    assert result["grant_id"] == "docker-read"
    assert transport.last_authorization_body["url"] == "https://workload.example.com/api/pap/records"


@pytest.mark.parametrize(("method", "target", "headers"), [
    ("POST", "/api/pap/records", {"Authorization": "DPoP a.b.c", "DPoP": "a.b.c"}),
    ("GET", "/api/pap/records?q=1", {"Authorization": "DPoP a.b.c", "DPoP": "a.b.c"}),
    ("GET", "/api/pap/%72ecords", {"Authorization": "DPoP a.b.c", "DPoP": "a.b.c"}),
    ("GET", "/api/pap/records", {"Authorization": "Bearer raw-key", "DPoP": "a.b.c"}),
    ("GET", "/api/pap/records", {"Authorization": "DPoP a.b.c"}),
    ("GET", "/api/pap/records", CIMultiDict([
        ("Authorization", "DPoP a.b.c"), ("Authorization", "DPoP other.key.here"), ("DPoP", "a.b.c"),
    ])),
])
async def test_verifier_rejects_ambiguous_or_unsupported_request(method, target, headers):
    client, transport, _store, _clock = fixture()
    async with client:
        with pytest.raises(WorkloadError):
            await client.authorize_request(make_mocked_request(method, target, headers=headers))
    assert transport.last_authorization_body is None


@pytest.mark.parametrize(("field", "value"), [
    ("tenant", "other"), ("grant_id", "other"), ("action", "other.read"),
    ("environment", "preview"), ("expires_at", 1),
])
async def test_verifier_rejects_misbound_authorization(field, value):
    client, transport, _store, _clock = fixture()
    transport.mutate_authorization = lambda result: {**result, field: value}
    request = make_mocked_request("GET", public_config()["resourcePath"], headers={
        "Authorization": "DPoP a.b.c", "DPoP": "a.b.c",
    })
    async with client:
        with pytest.raises(WorkloadError, match="authorization_binding_mismatch"):
            await client.authorize_request(request)


@pytest.mark.parametrize("raw", [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'\xff', b''])
def test_strict_json_rejects_duplicate_nonfinite_or_invalid_utf8(raw):
    with pytest.raises(WorkloadError, match="invalid_json"):
        _json(raw)


async def test_default_transport_rejects_private_dns_and_unregistered_targets(monkeypatch):
    import socket

    loop = asyncio.get_running_loop()

    async def private_dns(*_args, **_kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))]

    monkeypatch.setattr(loop, "getaddrinfo", private_dns)
    transport = HTTPSJSONTransport({"https://authority.example.com"})
    try:
        with pytest.raises(WorkloadError, match="upstream_unavailable"):
            await transport.request("GET", "https://authority.example.com/health", body=None, headers={})
        for target in ("https://evil.example.com/x", "https://authority.example.com/x?q=1", "http://authority.example.com/x"):
            with pytest.raises(WorkloadError, match="unregistered_destination"):
                await transport.request("GET", target, body=None, headers={})
        session = transport._sessions["https://authority.example.com"]
        assert session.trust_env is False and isinstance(session.cookie_jar, aiohttp.DummyCookieJar)
    finally:
        await transport.close()


async def test_get_broker_response_can_take_longer_than_post_timeout(monkeypatch):
    """The same origin/session can issue a token and serve a slower broker read."""
    calls = []

    class Content:
        async def iter_chunked(self, _size):
            yield b"{}"

    class Response:
        status = 200
        content_type = "application/json"
        headers = {}
        content_length = 2
        content = Content()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

    def capture(session, method, _url, **kwargs):
        calls.append((session, method, kwargs["timeout"], kwargs["headers"]))
        return Response()

    monkeypatch.setattr(aiohttp.ClientSession, "request", capture)
    transport = HTTPSJSONTransport({"https://authority.example.com"})
    try:
        await transport.request("POST", "https://authority.example.com/v1/site/token", body={}, headers={})
        await transport.request("GET", "https://authority.example.com/api/pap/records", body=None, headers={})
        assert calls[0][0] is calls[1][0]
        assert calls[0][2].total == calls[0][2].sock_read == 8
        assert calls[1][2].total == calls[1][2].sock_read == 30
        assert calls[0][2].connect == calls[1][2].connect == 3
        assert all(call[3]["Accept-Encoding"] == "identity" for call in calls)
    finally:
        await transport.close()


async def test_transport_rejects_compressed_response_even_if_upstream_ignores_identity(monkeypatch):
    class Response:
        status = 200
        content_type = "application/json"
        headers = {"Content-Encoding": "gzip"}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

    def compressed(_session, _method, _url, **kwargs):
        assert kwargs["headers"]["Accept-Encoding"] == "identity"
        return Response()

    monkeypatch.setattr(aiohttp.ClientSession, "request", compressed)
    transport = HTTPSJSONTransport({"https://authority.example.com"})
    try:
        with pytest.raises(WorkloadError, match="invalid_upstream_response"):
            await transport.request("GET", "https://authority.example.com/health", body=None, headers={})
    finally:
        await transport.close()


async def test_verifier_does_not_cache_authorization_or_hide_replay_rejection():
    client, transport, _store, _clock = fixture()
    request = make_mocked_request("GET", public_config()["resourcePath"], headers={
        "Authorization": "DPoP a.b.c", "DPoP": "a.b.c",
    })
    async with client:
        assert (await client.authorize_request(request))["tenant"] == "example"
        with pytest.raises(WorkloadError, match="access_denied"):
            await client.authorize_request(request)
    assert transport.authorization_calls == 2
