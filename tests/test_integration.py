"""Real sockets, TLS, background lifecycle and user-facing credential-free SDK."""

import asyncio
import ssl
import tempfile
import uuid
from pathlib import Path

import aiohttp
import pytest
import pytest_asyncio

from pap.agent import Agent, Client
from pap.authority import Config
from pap.crypto import Denied, proof
from pap.demo import scenario
from pap.runtime import Runtime


@pytest_asyncio.fixture
async def host():
    with tempfile.TemporaryDirectory(
        prefix="pap-test-", dir="/private/tmp" if Path("/private/tmp").exists() else "/tmp"
    ) as directory:
        path = Path(directory)
        path.chmod(0o700)
        runtime = Runtime(path, Config(token_ttl=6, signing_interval=3, tls_interval=4, grant_ttl=60))
        agent = Agent(path)
        await runtime.start()
        await agent.start()
        try:
            yield runtime, agent, Client(path / "agent.sock")
        finally:
            await agent.close()
            await runtime.close()


async def test_real_https_without_app_credentials(host):
    runtime, agent, client = host
    assert (await client.records())["records"][0]["value"] == "protected"
    # The SDK object has only a local socket path, no bearer token or secret key.
    assert set(vars(client)) == {"socket_path"}
    assert agent.renewals == 1
    assert (runtime.state / "authority.sqlite").stat().st_mode & 0o777 == 0o600
    assert (runtime.state / "agent.sock").stat().st_mode & 0o777 == 0o600


async def test_http_contract_errors_and_no_token_export(host):
    runtime, _, _ = host
    async with aiohttp.ClientSession(
        connector=aiohttp.UnixConnector(path=str(runtime.state / "agent.sock"))
    ) as session:
        for route in ("/v0/token", "/v0/challenge", "/v0/events"):
            async with session.post("http://agent" + route, json={}) as response:
                assert response.status == 404
        async with session.post("http://agent/v0/notes", json={"message": "test"}) as response:
            assert response.status == 400
        async with session.get("http://agent/v0/records?tenant=other") as response:
            assert response.status == 400
        async with session.get(
            "http://agent/v0/records", headers={"Origin": "https://evil.invalid"}
        ) as response:
            assert response.status == 403
        async with session.post(
            "http://agent/v0/notes",
            json={"message": "test", "extra": "no"},
            headers={"Idempotency-Key": str(uuid.uuid4())},
        ) as response:
            assert response.status == 400


async def test_native_endpoint_checks_replay_and_tenant(host):
    runtime, agent, _ = host
    credential = agent.credential
    url = runtime.origin + "/v0/tenants/demo/records"
    context = ssl.create_default_context(cadata=runtime.tls_pem)
    headers = {
        "Authorization": "DPoP " + credential.token,
        "DPoP": proof(credential.key, "GET", url, credential.nonce, credential.token),
    }
    async with aiohttp.ClientSession() as session:

        async def send():
            async with session.get(url, headers=headers, ssl=context) as response:
                return response.status

        assert sorted(await asyncio.gather(send(), send())) == [200, 401]
        other = runtime.origin + "/v0/tenants/other/records"
        headers["DPoP"] = proof(credential.key, "GET", other, credential.nonce, credential.token)
        async with session.get(other, headers=headers, ssl=context) as response:
            assert response.status == 403
        async with session.get(url, ssl=context) as response:
            assert response.status == 401


async def test_idempotent_sdk_write_and_conflict(host):
    _, _, client = host
    operation_key = str(uuid.uuid4())
    first = await client.create_note("one", idempotency_key=operation_key)
    assert first == await client.create_note("one", idempotency_key=operation_key)
    with pytest.raises(Denied) as denied:
        await client.create_note("two", idempotency_key=operation_key)
    assert denied.value.status == 409


async def test_grant_expiry_without_lifecycle_sweep(host):
    runtime, agent, client = host
    runtime.store.db.execute("UPDATE grants SET expires=0")
    with pytest.raises(Denied) as denied:
        await client.records()
    assert denied.value.status == 403
    with pytest.raises(Denied):
        await agent.refresh(force=True)


async def test_issuer_emergency_replacement_is_automatic(host):
    runtime, agent, client = host
    old = runtime.authority.active_key()["kid"]
    runtime.authority.event(str(uuid.uuid4()), "revoke_issuer_key", old, "compromised")
    assert (await client.records())["tenant"] == "demo"
    assert runtime.authority.active_key()["kid"] != old
    assert agent.renewals == 2


async def test_state_outage_fails_closed(host):
    runtime, _, client = host
    runtime.failure = "lifecycle_unavailable"
    with pytest.raises(Denied) as denied:
        await client.records()
    assert denied.value.status == 503


async def test_database_outage_fails_closed(host):
    runtime, _, client = host
    runtime.store.db.close()
    with pytest.raises(Denied) as denied:
        await client.records()
    assert denied.value.status == 503


async def test_tls_rotation_between_bootstrap_and_handshake_recovers(host, monkeypatch):
    runtime, agent, client = host
    original = agent.local
    rotated = False

    async def bootstrap_then_rotate(method, path, **kwargs):
        nonlocal rotated
        result = await original(method, path, **kwargs)
        if path == "/v0/bootstrap" and not rotated:
            runtime.rotate_tls()
            rotated = True
        return result

    monkeypatch.setattr(agent, "local", bootstrap_then_rotate)
    assert (await client.records())["tenant"] == "demo"
    assert rotated


async def test_tls_mismatch_never_disables_verification(host, monkeypatch):
    runtime, agent, client = host
    old_certificate = runtime.tls_pem
    runtime.rotate_tls()
    original = agent.local

    async def stale_trust(method, path, **kwargs):
        result = await original(method, path, **kwargs)
        if path == "/v0/bootstrap":
            result["tls_certificate"] = old_certificate
        return result

    monkeypatch.setattr(agent, "local", stale_trust)
    with pytest.raises(Denied) as denied:
        await client.records()
    assert denied.value.status == 503


async def test_grant_lease_expires_without_an_operator():
    with tempfile.TemporaryDirectory(
        prefix="pap-expiry-", dir="/private/tmp" if Path("/private/tmp").exists() else "/tmp"
    ) as directory:
        state = Path(directory)
        state.chmod(0o700)
        runtime = Runtime(state, Config(grant_ttl=3))
        agent = Agent(state)
        try:
            await runtime.start()
            await agent.start()
            assert (await Client(state / "agent.sock").records())["tenant"] == "demo"
            await asyncio.sleep(3.3)
            assert runtime.authority.status()["grants"][0]["enabled"] == 0
            with pytest.raises(Denied) as denied:
                await Client(state / "agent.sock").records()
            assert denied.value.status == 403
        finally:
            await agent.close()
            await runtime.close()


async def test_full_automatic_lifecycle_acceptance():
    report = await scenario()
    assert report["passed"], report["checks"]
    assert len(report["checks"]) >= 14
