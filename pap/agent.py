"""Credential-owning local agent. Its application socket returns operation results only."""

import asyncio
import contextlib
import os
import re
import secrets
import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path

import aiohttp
from aiohttp import web

from .authority import TOKEN_TARGET
from .crypto import Denied, fresh_key, proof, public_jwk
from .local import body, clean_socket, errors, peer_uid, require_operation_key
from .runtime import Note
from .storage import private_directory


@dataclass(repr=False)
class Credential:
    key: object = field(repr=False)
    token: str = field(repr=False)
    nonce: str = field(repr=False)
    expires: float
    tenant: str


class Agent:
    def __init__(self, state: Path, grant_id: str = "demo-grant"):
        self.state, self.grant_id = state, grant_id
        self.credential = None
        self.lock = asyncio.Lock()
        self.task = None
        self.runner = None
        self.session = None
        self.renewals = 0
        self.last_error = None
        self.terminal = False
        self.renew_at = 0
        self.socket_lock = None

    async def local(self, method: str, path: str, **kwargs):
        async with self.session.request(method, "http://authority" + path, **kwargs) as response:
            data = await response.json()
            if response.status != 200:
                raise Denied(data.get("error", "authority_unavailable"), response.status)
            return data

    async def refresh(self, *, force=False):
        async with self.lock:
            if self.terminal:
                raise Denied(self.last_error or "workload_not_authorized", 403)
            if not force and self.credential and time.time() < self.renew_at:
                return
            new_key = fresh_key()
            jwk = public_jwk(new_key)
            challenge = await self.local("POST", "/v0/challenge", json={"jwk": jwk})
            data = await self.local(
                "POST",
                "/v0/token",
                json={"jwk": jwk, "grant_id": self.grant_id},
                headers={"DPoP": proof(new_key, "POST", TOKEN_TARGET, challenge["nonce"])},
            )
            now = time.time()
            self.credential = Credential(
                new_key, data["access_token"], data["dpop_nonce"], data["expires_at"], data["tenant"]
            )
            self.renew_at = now + max(0.2, (data["expires_at"] - now) * 0.60)
            self.renewals += 1
            self.last_error = None

    async def maintain(self):
        backoff = 0.2
        while True:
            try:
                await self.refresh()
                backoff = 0.2
                await asyncio.sleep(0.15)
            except Denied as exc:
                self.last_error = exc.code
                if exc.status == 403:
                    self.terminal = True
                    self.credential = None
                    return
                await asyncio.sleep(backoff + secrets.randbelow(100) / 1000)
                backoff = min(8.0, backoff * 2)
            except (aiohttp.ClientError, TimeoutError, OSError):
                self.last_error = "authority_unavailable"
                await asyncio.sleep(backoff + secrets.randbelow(100) / 1000)
                backoff = min(8.0, backoff * 2)

    async def start(self):
        private_directory(self.state)
        import fcntl

        self.socket_lock = os.open(self.state / "agent.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.socket_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.session = aiohttp.ClientSession(
                connector=aiohttp.UnixConnector(path=str(self.state / "authority.sock")),
                timeout=aiohttp.ClientTimeout(total=5),
                trust_env=False,
            )
            await self.refresh()
            app = web.Application(middlewares=[errors], client_max_size=8192)
            app.router.add_get("/v0/status", self.status)
            app.router.add_get("/v0/records", self.records)
            app.router.add_post("/v0/notes", self.note)
            clean_socket(self.state / "agent.sock")
            self.runner = web.AppRunner(app, access_log=None, shutdown_timeout=2)
            await self.runner.setup()
            await web.UnixSite(self.runner, str(self.state / "agent.sock")).start()
            (self.state / "agent.sock").chmod(0o600)
            self.task = asyncio.create_task(self.maintain(), name="pap-credential-renewal")
            return self
        except BaseException:
            await self.close()
            raise

    def local_identity(self, request):
        if peer_uid(request) != os.getuid():
            raise Denied("local_application_not_authorized", 403)

    async def invoke(
        self, method: str, operation: str, *, data: dict | None = None, operation_key: str | None = None
    ):
        if operation not in ("records", "notes") or (method, operation) not in (
            ("GET", "records"),
            ("POST", "notes"),
        ):
            raise Denied("operation_not_supported", 400)
        for attempt in range(2):
            await self.refresh()
            credential = self.credential
            if credential is None or credential.expires <= time.time():
                raise Denied("credential_unavailable", 503)
            # Fetch public transport trust from the authenticated local host channel.
            bootstrap = await self.local("GET", "/v0/bootstrap")
            origin = bootstrap["origin"]
            if not re.fullmatch(r"https://127\.0\.0\.1:[0-9]{1,5}", origin):
                raise Denied("invalid_host_origin", 503)
            context = ssl.create_default_context(cadata=bootstrap["tls_certificate"])
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            url = origin + f"/v0/tenants/{credential.tenant}/{operation}"
            headers = {
                "Authorization": "DPoP " + credential.token,
                "DPoP": proof(credential.key, method, url, credential.nonce, credential.token),
            }
            if operation_key:
                headers["Idempotency-Key"] = operation_key
            try:
                async with aiohttp.ClientSession(
                    timeout=aiohttp.ClientTimeout(total=5), trust_env=False
                ) as session:
                    async with session.request(
                        method, url, json=data, headers=headers, ssl=context, allow_redirects=False
                    ) as response:
                        payload = await response.json()
                        if response.status == 401 and attempt == 0:
                            await self.refresh(force=True)
                            continue
                        if response.status not in (200, 201):
                            raise Denied(payload.get("error", "endpoint_unavailable"), response.status)
                        return payload
            except aiohttp.ClientConnectorCertificateError:
                # TLS failed before sending the request. Trust may have rotated since bootstrap.
                if attempt == 0:
                    continue
                raise Denied("transport_trust_unavailable", 503) from None
            except (aiohttp.ClientError, TimeoutError, OSError):
                raise Denied("endpoint_unavailable", 503) from None
        raise Denied("credential_unavailable", 503)

    async def records(self, request):
        self.local_identity(request)
        return web.json_response(await self.invoke("GET", "records"))

    async def note(self, request):
        self.local_identity(request)
        data = await body(request, Note)
        operation_key = require_operation_key(request)
        return web.json_response(
            await self.invoke("POST", "notes", data=data.model_dump(), operation_key=operation_key),
            status=201,
        )

    async def status(self, request):
        self.local_identity(request)
        return web.json_response(
            {
                "ready": self.credential is not None
                and self.credential.expires > time.time()
                and not self.terminal,
                "credential_renewals": self.renewals,
                "workload_key_rotations": max(0, self.renewals - 1),
                "expires_at": self.credential.expires if self.credential else None,
                "last_error": self.last_error,
            }
        )

    async def close(self):
        if self.task:
            self.task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.task
            self.task = None
        if self.runner:
            await self.runner.cleanup()
            self.runner = None
        if self.session:
            await self.session.close()
            self.session = None
        self.credential = None
        if self.socket_lock is not None:
            os.close(self.socket_lock)
            self.socket_lock = None


class Client:
    """Application SDK: an agent path is configuration, not an authentication secret."""

    def __init__(self, socket_path: Path):
        self.socket_path = socket_path

    async def request(self, method: str, path: str, **kwargs):
        async with aiohttp.ClientSession(
            connector=aiohttp.UnixConnector(path=str(self.socket_path)),
            timeout=aiohttp.ClientTimeout(total=8),
            trust_env=False,
        ) as session:
            async with session.request(method, "http://agent" + path, **kwargs) as response:
                payload = await response.json()
                if response.status not in (200, 201):
                    raise Denied(payload.get("error", "agent_unavailable"), response.status)
                return payload

    async def records(self):
        return await self.request("GET", "/v0/records")

    async def create_note(self, message: str, *, idempotency_key: str):
        return await self.request(
            "POST", "/v0/notes", json={"message": message}, headers={"Idempotency-Key": idempotency_key}
        )
