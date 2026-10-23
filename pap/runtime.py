"""Local host reference: private enrollment/admin sockets plus a native HTTPS resource API."""

import asyncio
import contextlib
import fcntl
import ipaddress
import json
import os
import socket
import ssl
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

from aiohttp import web
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from pydantic import Field

from .authority import Authority, Config
from .crypto import Denied, fresh_key, private_pem
from .local import LOG, StrictModel, body, clean_socket, errors, peer_uid, require_operation_key
from .storage import Store, private_directory


class Challenge(StrictModel):
    jwk: dict


class TokenRequest(Challenge):
    grant_id: Annotated[str, Field(min_length=1, max_length=80)]


class Note(StrictModel):
    message: Annotated[str, Field(min_length=1, max_length=1000)]


class Event(StrictModel):
    event_id: Annotated[str, Field(min_length=36, max_length=36)]
    kind: Annotated[str, Field(max_length=30)]
    subject: Annotated[str, Field(min_length=1, max_length=80)]
    reason: Annotated[str, Field(max_length=20)]


def atomic_private(path: Path, data: bytes):
    temp = path.with_suffix(path.suffix + ".next")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


class Runtime:
    def __init__(self, state: Path, config: Config | None = None):
        self.state, self.config = state, config or Config()
        self.runners = []
        self.task = None
        self.ready = False
        self.origin = ""
        self.tls_pem = ""
        self.tls_generation = 0
        self.last_tls = 0.0
        self.authority = None
        self.store = None
        self.lock = None
        self.failure = None

    async def start(self, port: int = 0):
        private_directory(self.state)
        # A host state directory has one lifecycle controller and one local socket owner.
        self.lock = os.open(self.state / "host.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            (self.state / "runtime.json.next").unlink(missing_ok=True)
            self.store = Store(self.state / "authority.sqlite")
            self.authority = Authority(self.store, self.config)
            self.authority.provision(os.getuid())
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.bind(("127.0.0.1", port))
            self.origin = "https://127.0.0.1:" + str(tcp.getsockname()[1])
            self.ssl = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ssl.minimum_version = ssl.TLSVersion.TLSv1_2
            self.rotate_tls()
            authority_app = web.Application(middlewares=[errors], client_max_size=8192)
            authority_app.router.add_get("/v0/bootstrap", self.bootstrap)
            authority_app.router.add_post("/v0/challenge", self.challenge)
            authority_app.router.add_post("/v0/token", self.token)
            admin_app = web.Application(middlewares=[errors], client_max_size=8192)
            admin_app.router.add_get("/v0/status", self.status)
            admin_app.router.add_get("/v0/audit", self.audit)
            admin_app.router.add_post("/v0/events", self.event)
            resource_app = web.Application(middlewares=[errors], client_max_size=8192)
            resource_app.router.add_get("/health", self.health)
            resource_app.router.add_get("/.well-known/jwks.json", self.jwks)
            resource_app.router.add_get("/v0/tenants/{tenant}/records", self.records)
            resource_app.router.add_post("/v0/tenants/{tenant}/notes", self.note)
            for app, filename in ((authority_app, "authority.sock"), (admin_app, "admin.sock")):
                path = self.state / filename
                clean_socket(path)
                runner = web.AppRunner(app, access_log=None, shutdown_timeout=2)
                await runner.setup()
                self.runners.append(runner)
                await web.UnixSite(runner, str(path)).start()
                path.chmod(0o600)
            runner = web.AppRunner(resource_app, access_log=None, shutdown_timeout=2)
            await runner.setup()
            self.runners.append(runner)
            await web.SockSite(runner, tcp, ssl_context=self.ssl).start()
            self.ready = True
            self.task = asyncio.create_task(self.lifecycle(), name="pap-host-lifecycle")
            atomic_private(self.state / "runtime.json", json.dumps({"origin": self.origin}).encode())
            return self
        except BaseException:
            await self.close()
            raise

    def rotate_tls(self):
        key = fresh_key()
        now = datetime.now(UTC)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PAP local endpoint")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(seconds=30))
            .not_valid_after(now + timedelta(seconds=max(60, self.config.tls_interval * 3)))
            .add_extension(
                x509.SubjectAlternativeName(
                    [x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.DNSName("localhost")]
                ),
                critical=False,
            )
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
        )
        pem = cert.public_bytes(serialization.Encoding.PEM)
        # Recover any incomplete temporary writes from our locked private directory.
        for filename in ("tls-cert.pem.next", "tls-key.pem.next"):
            (self.state / filename).unlink(missing_ok=True)
        atomic_private(self.state / "tls-cert.pem", pem)
        atomic_private(self.state / "tls-key.pem", private_pem(key).encode())
        self.ssl.load_cert_chain(self.state / "tls-cert.pem", self.state / "tls-key.pem")
        self.tls_pem = pem.decode()
        self.last_tls = time.time()
        self.tls_generation += 1
        self.store.audit("transport.rotated", {"generation": self.tls_generation})

    async def lifecycle(self):
        while True:
            try:
                self.authority.maintenance()
                if time.time() - self.last_tls >= self.config.tls_interval:
                    self.rotate_tls()
                self.failure = None
            except Exception:
                self.failure = "lifecycle_unavailable"
                LOG.error("lifecycle_unavailable")
            await asyncio.sleep(self.config.tick)

    def require_ready(self):
        if not self.ready or self.failure:
            raise Denied("lifecycle_unavailable", 503)

    def local_identity(self, request):
        self.require_ready()
        return peer_uid(request)

    def admin_identity(self, request):
        if peer_uid(request) != os.getuid():
            raise Denied("admin_not_authorized", 403)

    async def bootstrap(self, request):
        uid = self.local_identity(request)
        workload = self.authority.workload_for_uid(uid)
        return web.json_response(
            {
                "origin": self.origin,
                "tls_certificate": self.tls_pem,
                "tls_generation": self.tls_generation,
                "issuer": self.config.issuer,
                "audience": self.config.audience,
                "subject": workload["id"],
                "tenant": workload["tenant"],
                "environment": workload["environment"],
            }
        )

    async def challenge(self, request):
        uid = self.local_identity(request)
        payload = await body(request, Challenge)
        return web.json_response(self.authority.challenge(uid, payload.jwk))

    async def token(self, request):
        uid = self.local_identity(request)
        payload = await body(request, TokenRequest)
        return web.json_response(
            self.authority.issue(uid, payload.grant_id, payload.jwk, request.headers.get("DPoP", ""))
        )

    async def status(self, request):
        self.admin_identity(request)
        return web.json_response(
            {
                **self.authority.status(),
                "ready": self.ready and not self.failure,
                "tls_generation": self.tls_generation,
                "origin": self.origin,
            }
        )

    async def audit(self, request):
        self.admin_identity(request)
        rows = self.store.db.execute(
            "SELECT seq,at,event,details FROM audit ORDER BY seq DESC LIMIT 100"
        ).fetchall()
        return web.json_response({"events": [{**dict(r), "details": json.loads(r["details"])} for r in rows]})

    async def event(self, request):
        self.admin_identity(request)
        payload = await body(request, Event)
        # The UUID id is itself non-secret and ensures safely retried incident signals.
        from uuid import UUID

        try:
            if str(UUID(payload.event_id)) != payload.event_id:
                raise ValueError("noncanonical")
        except ValueError as exc:
            raise Denied("invalid_event_id", 400) from exc
        return web.json_response(self.authority.event(**payload.model_dump()))

    async def health(self, request):
        return web.json_response(
            {"ready": self.ready and not self.failure}, status=200 if not self.failure else 503
        )

    async def jwks(self, request):
        rows = self.store.db.execute(
            "SELECT kid,public FROM signing_keys WHERE state IN ('pending','active','draining')"
        ).fetchall()
        return web.json_response(
            {
                "keys": [
                    {**json.loads(r["public"]), "kid": r["kid"], "use": "sig", "alg": "ES256"} for r in rows
                ]
            }
        )

    def authorize(self, request, action):
        self.require_ready()
        # Fixed configured origin. Never use Host or forwarded headers to construct the DPoP target.
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("DPoP "):
            raise Denied("dpop_required")
        return self.authority.authorize(
            auth[5:],
            request.headers.get("DPoP", ""),
            request.method,
            self.origin + request.path,
            request.match_info["tenant"],
            action,
        )

    async def records(self, request):
        claims = self.authorize(request, "records.read")
        return web.json_response(
            {"tenant": claims["tenant"], "records": [{"id": "example-record", "value": "protected"}]}
        )

    async def note(self, request):
        payload = await body(request, Note)
        operation_key = require_operation_key(request)
        claims = self.authorize(request, "notes.create")
        return web.json_response(
            self.authority.create_note(claims, operation_key, payload.message), status=201
        )

    async def close(self):
        self.ready = False
        if self.task:
            self.task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.task
            self.task = None
        for runner in reversed(self.runners):
            await runner.cleanup()
        self.runners.clear()
        if self.store:
            self.store.close()
            self.store = None
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None
