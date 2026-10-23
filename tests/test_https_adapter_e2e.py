"""Real TLS through the production HTTP runtime and the Docker example app.

External KMS custody uses the production suite's test double. The shared example
fixture trusts a temporary CA and maps enrolled DNS names to isolated loopback
TLS listeners; production public-DNS restrictions remain independently tested.
"""

import asyncio
import importlib.util
import json
import time
import uuid
from pathlib import Path

import aiohttp
import pytest

import pap.production as production
from pap.cloud import PublicResolver, Site, SiteRegistry
from pap.crypto import Denied, fresh_key, public_jwk, thumbprint
from pap.production import ProductionConfig, ProductionRuntime
from pap.workload import HTTPSJSONTransport, MemoryProofStore, WorkloadClient, WorkloadConfig, WorkloadError


def support_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def test_production_runtime_docker_app_tls_expiry_replay_and_revocation(tmp_path, monkeypatch):
    root = Path(__file__).resolve().parents[1]
    production_support = support_module("pap_production_support", root / "tests" / "test_production.py")
    tls_support = support_module(
        "pap_example_tls_support", root / "examples" / "docker-https" / "tests" / "test_example.py"
    )
    monkeypatch.setattr(production, "OpenBaoSigner", production_support.TestSigner)
    monkeypatch.setattr(production, "CertificateManager", production_support.TestCertificates)
    public = json.loads((tls_support.EXAMPLE / "config.public.json").read_text())
    public.update(enabled=True, trustOriginDeployment=True)
    config = WorkloadConfig.from_dict(public)
    registration = json.loads((tls_support.EXAMPLE / "registration.example.json").read_text())
    registration["grant_expires_at"] = time.time() + 600
    registration["trusted_site_contexts"] = True
    runtime_value = production_support.configuration(tmp_path)
    runtime_value.update(issuer=config.issuer_url, audience=config.audience, token_ttl=12)
    runtime_value["sites"].append(registration)
    runtime = ProductionRuntime(ProductionConfig.model_validate(runtime_value))
    await runtime.call(runtime.actor.start)
    runtime.ready, runtime.last_maintenance = True, time.monotonic()
    server_tls, client_tls = tls_support.tls_contexts(tmp_path)
    runners, ports = [], {}
    workload_client = None
    try:
        # A legacy binding and its policy survive upgrading beside the new adapter.
        def migrate_legacy():
            name = "site:test-grant"
            old = runtime.actor.store.setting(name)
            old.pop("identity_adapter")
            runtime.actor.store.set_setting(name, old)
            runtime.actor.registry = SiteRegistry(
                runtime.actor.authority, [Site(**site.model_dump()) for site in runtime.config.sites]
            )
            assert runtime.actor.store.setting(name)["identity_adapter"] == "netlify"
            assert runtime.actor.registry.site_for_grant("test-grant").origin == "https://pap-test.netlify.app"

        await runtime.call(migrate_legacy)
        runner, ports["authority.example.com"] = await tls_support.tls_server(runtime.public_app(), server_tls)
        runners.append(runner)
        original_connector = aiohttp.TCPConnector

        def fixture_connector(*args, **kwargs):
            # Only the test network routing/CA changes. HTTP, TLS certificate and
            # hostname verification, protocol handling and runtime routes are real.
            assert isinstance(kwargs["resolver"], PublicResolver)
            kwargs.update(resolver=tls_support.FixtureResolver(ports), ssl=client_tls)
            return original_connector(*args, **kwargs)

        monkeypatch.setattr(aiohttp, "TCPConnector", fixture_connector)
        transport = HTTPSJSONTransport({config.issuer_url, config.resource_origin})
        store = MemoryProofStore()
        workload_client = WorkloadClient(config, store=store, transport=transport)
        app = tls_support.example.create_app(config, client=workload_client)
        runner, ports["workload.example.com"] = await tls_support.tls_server(app, server_tls)
        runners.append(runner)
        captured = []
        original_request = transport.request

        async def capture(method, url, *, body, headers):
            if method == "GET" and url == config.resource_origin + config.resource_path:
                captured.append(dict(headers))
            return await original_request(method, url, body=body, headers=headers)

        monkeypatch.setattr(transport, "request", capture)
        first = await workload_client.get_json()
        assert first["access"]["grant_id"] == config.grant_id
        first_expiry = workload_client._cached.expires_at
        first_jkt = thumbprint(public_jwk(workload_client._cached.key))
        assert store._records == {}
        replay = await original_request(
            "GET", config.resource_origin + config.resource_path, body=None, headers=captured[-1]
        )
        assert replay.status == 401
        for path, expected in [
            ("/.well-known/pap/site-proof/" + str(uuid.uuid4()), 405), ("/check", 404),
        ]:
            response = await original_request("POST", config.resource_origin + path, body={}, headers={})
            assert response.status == expected
        await asyncio.sleep(max(0, first_expiry - time.time()) + 0.05)
        assert time.time() > first_expiry
        second = await workload_client.get_json()
        assert second["records"] == first["records"]
        assert thumbprint(public_jwk(workload_client._cached.key)) != first_jkt
        assert store._records == {}
        await runtime.call(
            runtime.actor.authority.event, str(uuid.uuid4()), "revoke_workload", registration["subject"], "compromised"
        )
        with pytest.raises(WorkloadError, match="access_denied"):
            await workload_client.get_json()
        with pytest.raises(Denied, match="workload_not_authorized"):
            await runtime.call(runtime.actor.registry.challenge, config.grant_id, public_jwk(fresh_key()))
        assert await runtime.call(lambda: runtime.actor.store.db.execute(
            "SELECT count(*) FROM audit WHERE event='credential.issued'"
        ).fetchone()[0]) == 2
    finally:
        if workload_client is not None:
            await workload_client.close()
        for runner in reversed(runners):
            await runner.cleanup()
        await runtime.close()
