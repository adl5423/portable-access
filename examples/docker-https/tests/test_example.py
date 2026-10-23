"""Local TLS acceptance uses a private CA, never disabled TLS verification."""

import asyncio
import importlib.util
import json
import socket
import ssl
import stat
import tempfile
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import aiohttp
import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.abc import AbstractResolver
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from pap.authority import Authority, Config
from pap.cloud import Site, SiteRegistry
from pap.crypto import Denied, proof, thumbprint
from pap.storage import Store
from pap.workload import HTTPSJSONTransport, MemoryProofStore, WorkloadClient, WorkloadConfig, WorkloadError

EXAMPLE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("docker_https_example", EXAMPLE / "app.py")
example = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(example)
ISSUER = "https://authority.example.com"
ORIGIN = "https://workload.example.com"


class FixtureResolver(AbstractResolver):
    """Only this test resolver can route a canonical HTTPS name to local TLS ports."""

    def __init__(self, ports):
        self.ports = ports

    async def resolve(self, host, port=0, family=socket.AF_INET):
        assert host in self.ports and port == 443
        return [{"hostname": host, "host": "127.0.0.1", "port": self.ports[host], "family": socket.AF_INET,
                 "proto": socket.IPPROTO_TCP, "flags": 0}]

    async def close(self):
        pass


class FixtureTLS(HTTPSJSONTransport):
    def __init__(self, ports, context):
        super().__init__({ISSUER, ORIGIN})
        self.ports, self.context = ports, context

    async def request(self, method, url, *, body, headers):
        from urllib.parse import urlsplit

        origin = "https://" + urlsplit(url).hostname
        if origin not in self._sessions:
            self._sessions[origin] = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(ssl=self.context, resolver=FixtureResolver(self.ports)),
                trust_env=False, cookie_jar=aiohttp.DummyCookieJar(), auto_decompress=False,
                skip_auto_headers={"Accept-Encoding"},
                timeout=aiohttp.ClientTimeout(total=5),
            )
        return await super().request(method, url, body=body, headers=headers)


def tls_contexts(directory):
    now = datetime.now(UTC)
    ca_key, leaf_key = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PAP test CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=1))
          .not_valid_after(now + timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
          .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, None, None), True)
          .sign(ca_key, hashes.SHA256()))
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "workload.example.com")])).issuer_name(ca_name)
        .public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), False)
        .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, None, None), True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False)
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("workload.example.com"), x509.DNSName("authority.example.com")]), False)
        .sign(ca_key, hashes.SHA256()))
    ca_path, cert_path, key_path = directory / "ca.pem", directory / "leaf.pem", directory / "test-tls-key.pem"
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    cert_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM,
                                               serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    key_path.chmod(0o600)
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert_path, key_path)
    client = ssl.create_default_context(cafile=str(ca_path))
    assert client.verify_mode == ssl.CERT_REQUIRED and client.check_hostname
    return server, client


async def tls_server(app, context):
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    listener = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=context)
    await listener.start()
    return runner, listener._server.sockets[0].getsockname()[1]


@pytest_asyncio.fixture
async def deployment(tmp_path):
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    store = Store(state / "authority.sqlite")
    authority = Authority(store, Config(issuer=ISSUER, audience="urn:pap:docker-example", token_ttl=12))
    registration = json.loads((EXAMPLE / "registration.example.json").read_text())
    registration["grant_expires_at"] = time.time() + 600
    site = Site(**registration)
    registry = SiteRegistry(authority, [site])
    settings = json.loads((EXAMPLE / "config.public.json").read_text())
    settings["enabled"] = True
    settings["trustOriginDeployment"] = True
    config = WorkloadConfig.from_dict(settings)
    server_context, client_context = tls_contexts(tmp_path)
    ports, issued, authorized = {}, [], []
    transport = FixtureTLS(ports, client_context)

    @web.middleware
    async def denied(request, handler):
        try:
            return await handler(request)
        except Denied as error:
            return web.json_response({"error": error.code}, status=error.status)

    async def challenge(request):
        body = await request.json()
        return web.json_response(registry.challenge(body["grant_id"], body["jwk"]))

    async def token(request):
        body = await request.json()
        registered, _record = registry.exchange_context(body["challenge_id"], body["jwk"], request.headers["DPoP"])
        record = await transport.request("GET", registered.origin + "/.well-known/pap/site-proof/" + body["challenge_id"],
                                         body=None, headers={})
        assert record.status == 200
        credential = registry.finish_exchange(body["challenge_id"], body["jwk"], request.headers["DPoP"], record.value)
        issued.append({"jkt": thumbprint(body["jwk"]), "expires_at": credential["expires_at"]})
        return web.json_response(credential)

    async def authorize(request):
        values = await request.json()
        authorized.append(values)
        return web.json_response(registry.authorize(request.headers["Authorization"][5:], request.headers["DPoP"], **values))

    async def health(_request):
        return web.json_response({"ready": True})

    async def boundary(request):
        scenario = request.match_info["scenario"]
        if scenario == "redirect":
            raise web.HTTPFound(ISSUER + "/health")
        if scenario == "oversize":
            return web.Response(body=b'"' + b"x" * 16384 + b'"', content_type="application/json")
        if scenario == "compressed":
            return web.Response(body=b"{}", content_type="application/json", headers={"Content-Encoding": "gzip"})
        if scenario == "chunked":
            response = web.StreamResponse(headers={"Content-Type": "application/json"})
            await response.prepare(request)
            await response.write(b"x" * 16385)
            await response.write_eof()
            return response
        return web.Response(text="{}", content_type="text/plain")

    authority_app = web.Application(middlewares=[denied])
    authority_app.router.add_post("/v1/site/challenge", challenge)
    authority_app.router.add_post("/v1/site/token", token)
    authority_app.router.add_post("/v1/authorize", authorize)
    authority_app.router.add_get("/health", health)
    authority_app.router.add_get("/boundary/{scenario}", boundary)
    authority_runner, ports["authority.example.com"] = await tls_server(authority_app, server_context)
    client = WorkloadClient(config, store=MemoryProofStore(), transport=transport)
    app = example.create_app(config, client=client)
    workload_runner, ports["workload.example.com"] = await tls_server(app, server_context)
    try:
        yield SimpleNamespace(client=client, app=app, transport=transport, ports=ports, config=config,
                              registry=registry, site=site, store=store, issued=issued, authorized=authorized)
    finally:
        await workload_runner.cleanup()
        await authority_runner.cleanup()
        await transport.close()
        store.close()


async def test_real_tls_enrollment_authorization_expiry_renewal_and_revocation(deployment):
    first = await deployment.client.get_json()
    assert first["records"][0]["id"] == "example-1"
    assert first["access"]["tenant"] == "docker-example"
    assert len(deployment.issued) == 1 and len(deployment.authorized) == 1
    old = deployment.issued[0]
    await asyncio.sleep(max(0, old["expires_at"] - time.time()) + 0.05)
    second = await deployment.client.get_json()
    assert second["records"] == first["records"]
    assert len(deployment.issued) == 2 and deployment.issued[-1]["jkt"] != old["jkt"]
    assert time.time() > old["expires_at"]
    deployment.store.db.execute("UPDATE grants SET enabled=0 WHERE id=?", (deployment.site.grant_id,))
    with pytest.raises(WorkloadError) as failure:
        await deployment.client.get_json()
    assert failure.value.status in (401, 403)


async def test_canonical_url_ignores_host_and_forwarding_headers_and_replay_denied(deployment):
    credential = await deployment.client._active()
    target = ORIGIN + deployment.config.resource_path
    encoded = proof(credential.key, "GET", target, credential.nonce, credential.token)
    headers = {"Authorization": "DPoP " + credential.token, "DPoP": encoded, "Host": "attacker.invalid",
               "Forwarded": "host=attacker.invalid;proto=http", "X-Forwarded-Host": "attacker.invalid"}
    first = await deployment.transport.request("GET", target, body=None, headers=headers)
    assert first.status == 200
    assert deployment.authorized[-1]["url"] == target
    second = await deployment.transport.request("GET", target, body=None, headers=headers)
    assert second.status in (401, 403)


async def test_foreign_origin_proof_cannot_authorize_registered_resource(deployment):
    credential = await deployment.client._active()
    encoded = proof(credential.key, "GET", "https://attacker.example.com/api/pap/records", credential.nonce, credential.token)
    response = await deployment.transport.request("GET", ORIGIN + deployment.config.resource_path, body=None,
                                                 headers={"Authorization": "DPoP " + credential.token, "DPoP": encoded})
    assert response.status in (401, 403)


@pytest.mark.parametrize("method,path,status", [
    ("GET", "/api/pap/records?x=1", 400), ("POST", "/api/pap/records", 405),
    ("HEAD", "/api/pap/records", 405), ("GET", "/api/pap/records/", 404),
    ("POST", "/.well-known/pap/site-proof/11111111-1111-4111-8111-111111111111", 405),
    ("POST", "/check", 404),
])
async def test_unconfigured_operations_cannot_reach_authority(deployment, method, path, status):
    resolver = FixtureResolver(deployment.ports)
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=deployment.transport.context, resolver=resolver)) as client:
        async with client.request(method, ORIGIN + path, allow_redirects=False) as response:
            assert response.status == status
    assert deployment.authorized == [] and deployment.issued == []


async def test_invalid_authorization_and_untrusted_tls_fail_closed(deployment):
    response = await deployment.transport.request("GET", ORIGIN + deployment.config.resource_path, body=None,
                                                 headers={"Authorization": "Bearer attacker", "DPoP": "invalid"})
    assert response.status == 401 and deployment.authorized == []
    untrusted = FixtureTLS(deployment.ports, ssl.create_default_context())
    try:
        with pytest.raises(WorkloadError, match="upstream_unavailable"):
            await untrusted.request("GET", ISSUER + "/health", body=None, headers={})
    finally:
        await untrusted.close()


@pytest.mark.parametrize("scenario,code", [
    ("oversize", "response_too_large"), ("chunked", "response_too_large"),
    ("compressed", "invalid_upstream_response"), ("content-type", "invalid_upstream_response"),
])
async def test_verified_tls_transport_rejects_unsafe_http_responses(deployment, scenario, code):
    with pytest.raises(WorkloadError, match=code):
        await deployment.transport.request("GET", ISSUER + "/boundary/" + scenario, body=None, headers={})


async def test_verified_tls_transport_does_not_follow_redirect(deployment):
    result = await deployment.transport.request("GET", ISSUER + "/boundary/redirect", body=None, headers={})
    assert result.status == 302 and result.value is None


async def test_private_control_invokes_running_process_store(deployment):
    # macOS limits Unix socket paths to 104 bytes, shorter than pytest's usual directory.
    with tempfile.TemporaryDirectory(prefix="pap-socket-", dir="/tmp") as directory:
        socket_path = Path(directory) / "private" / "control.sock"
        example.prepare_socket(socket_path)
        runner = web.AppRunner(example.control_app(deployment.app), access_log=None)
        await runner.setup()
        await web.UnixSite(runner, str(socket_path)).start()
        socket_path.chmod(0o600)
        try:
            assert await example.check(socket_path, 0) == 0
            assert len(deployment.issued) == 1 and len(deployment.authorized) == 1
        finally:
            await runner.cleanup()


async def test_disabled_defaults_liveness_readiness_and_control(tmp_path):
    from aiohttp.test_utils import TestClient, TestServer

    assert example.load_config(EXAMPLE / "config.public.json") is None
    app = example.create_app(None)
    async with TestClient(TestServer(app)) as client:
        assert (await client.get("/health/live")).status == 200
        assert (await client.get("/health/ready")).status == 503
        assert (await client.get("/api/pap/records")).status == 503
        assert (await client.post("/check")).status == 404
        assert (await client.post("/.well-known/pap/site-proof/a")).status == 405
    control = example.control_app(example.create_app(None))
    async with TestClient(TestServer(control)) as client:
        assert (await client.post("/check", data=b"", headers={"Content-Type": "application/json"})).status == 503


def test_configuration_and_local_socket_paths_are_bounded_and_private(tmp_path):
    config = tmp_path / "config.json"
    config.write_text('{"enabled":true,"enabled":false}')
    with pytest.raises(ValueError):
        example.load_config(config)
    config.write_bytes(b"x" * (example.MAX_CONFIG_BYTES + 1))
    with pytest.raises(ValueError):
        example.load_config(config)
    directory = tmp_path / "private"
    example.prepare_socket(directory / "control.sock")
    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    (directory / "control.sock").write_text("must not overwrite")
    with pytest.raises(ValueError):
        example.prepare_socket(directory / "control.sock")
    directory.chmod(0o755)
    with pytest.raises(ValueError):
        example.prepare_socket(directory / "other.sock")


def test_socket_recovery_preserves_active_listener_and_removes_only_stale_socket():
    with tempfile.TemporaryDirectory(prefix="pap-socket-", dir="/tmp") as directory:
        path = Path(directory) / "private" / "control.sock"
        example.prepare_socket(path)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(path))
            listener.listen(1)
            with pytest.raises(ValueError, match="another workload process"):
                example.prepare_socket(path)
            assert path.exists()
        example.prepare_socket(path)
        assert not path.exists()


@pytest.mark.parametrize("finish", ["success", "failure", "cancel"])
async def test_resource_admission_is_nonblocking_and_releases_every_exit(finish):
    entered, release = asyncio.Event(), asyncio.Event()

    class BlockedClient:
        store = MemoryProofStore()
        calls = 0

        async def authorize_request(self, _request):
            self.calls += 1
            entered.set()
            await release.wait()
            if finish == "failure" and self.calls == 1:
                raise WorkloadError("issuer_unavailable", 503)
            return {"tenant": "docker-example"}

        async def close(self):
            pass

    settings = json.loads((EXAMPLE / "config.public.json").read_text())
    settings.update(enabled=True, trustOriginDeployment=True)
    client = BlockedClient()
    app = example.create_app(WorkloadConfig.from_dict(settings), client=client, max_inflight=1)
    request = SimpleNamespace(app=app)
    first = asyncio.create_task(example.records(request))
    await asyncio.wait_for(entered.wait(), 1)
    overflow = await asyncio.wait_for(example.records(request), 0.1)
    assert overflow.status == 503 and overflow.headers["Retry-After"] == "1"
    assert client.calls == 1
    if finish == "cancel":
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        release.set()
    else:
        release.set()
        if finish == "failure":
            with pytest.raises(WorkloadError, match="issuer_unavailable"):
                await first
        else:
            assert (await first).status == 200
    assert (await asyncio.wait_for(example.records(request), 0.1)).status == 200
    assert client.calls == 2
