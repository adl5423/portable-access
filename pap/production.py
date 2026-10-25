"""Netlify origin-control profile with an isolated, externally backed authority.

Only the single actor thread touches SQLite or calls the synchronous KMS client.
No HTTP route can provision an identity or choose a signing provider.
"""

import asyncio
import contextlib
import fcntl
import json
import os
import signal
import socket
import stat
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Annotated, Literal

from aiohttp import web
from pydantic import Field, field_validator, model_validator

from . import __version__
from .authority import Authority, Config
from .certificates import CertificateManager
from .cloud import Site, SiteRegistry, fetch_site_record, validate_sites
from .configuration import parse_config_json
from .connectors import ConnectorConfig, ConnectorStore, CredentialRequest, generate
from .crypto import Denied
from .enrollment import UnixEnrollmentClient
from .identity_adapters import https_origin
from .local import LOG, StrictModel, body, errors, peer_uid
from .process_security import harden_secret_process
from .runtime import Event
from .signers import OpenBaoSigner, _trusted_file
from .storage import Store, private_directory


class KMSConfig(StrictModel):
    provider: Literal["openbao"]
    base_url: Annotated[str, Field(min_length=1, max_length=256)]
    role: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")]
    client_cert: str
    client_key: str
    ca_file: str
    client_ca_file: str
    pki_role: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")]
    common_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]{1,128}$")]
    enrollment_socket: str | None = None
    enrollment_uid: Annotated[int, Field(ge=1)] | None = None

    @field_validator("client_cert", "client_key", "ca_file", "client_ca_file")
    @classmethod
    def absolute(cls, value):
        if not Path(value).is_absolute() or ".." in Path(value).parts:
            raise ValueError("absolute credential paths required")
        return value

    @model_validator(mode="after")
    def generation_pair(self):
        cert, key = Path(self.client_cert), Path(self.client_key)
        if (
            cert.parent != key.parent
            or cert.parent.name != "current"
            or cert.name != "client-cert.pem"
            or key.name != "client-key.pem"
        ):
            raise ValueError("certificate pair must share the atomic current generation")
        if (self.enrollment_socket is None) != (self.enrollment_uid is None):
            raise ValueError("enrollment socket and peer UID must be configured together")
        if self.enrollment_socket is not None and (
            self.enrollment_socket != "/run/pap-enroller/enroll.sock"
            or self.base_url != "https://127.0.0.1:8200"
            or self.common_name != "pap-issuer"
            or self.pki_role != "pap-issuer"
        ):
            raise ValueError("local enrollment requires the fixed issuer and loopback KMS profile")
        return self


class SiteConfig(StrictModel):
    site_id: str
    origin: str
    subject: str
    tenant: str
    environment: Literal["production"]
    grant_id: str
    grant_expires_at: float
    trusted_site_contexts: Literal[True]
    resource_path: str = "/api/pap/records"
    resource_action: str = "records.read"
    identity_adapter: Literal["netlify", "https-origin"] = "netlify"

    @model_validator(mode="after")
    def validate_site(self):
        Site(**self.model_dump())
        return self


class ProductionConfig(StrictModel):
    issuer: Annotated[str, Field(min_length=1, max_length=256)]
    audience: Annotated[str, Field(min_length=1, max_length=200)]
    state_dir: str
    listen_host: Literal["127.0.0.1"] = "127.0.0.1"
    listen_port: Annotated[int, Field(ge=1024, le=65535)] = 9480
    admin_uid: Annotated[int, Field(ge=1)]
    signing_interval: Annotated[int, Field(ge=3600, le=31536000)] = 86400
    token_ttl: Annotated[int, Field(ge=4, le=300)] = 60
    kms: KMSConfig
    sites: Annotated[list[SiteConfig], Field(max_length=1000)]
    connectors: Annotated[list[ConnectorConfig], Field(max_length=3)] = Field(default_factory=list)

    @field_validator("issuer")
    @classmethod
    def public_origin(cls, value):
        return https_origin(value)

    @model_validator(mode="after")
    def bindings(self):
        validate_sites([Site(**site.model_dump()) for site in self.sites])
        state = Path(self.state_dir)
        if not state.is_absolute() or ".." in state.parts:
            raise ValueError("absolute state directory required")
        if Path(self.kms.client_cert).parent.parent != state / "credentials":
            raise ValueError("issuer credentials must be in its protected state directory")
        if self.admin_uid == os.getuid():
            raise ValueError("administration and issuer require different UIDs")
        if self.kms.enrollment_uid in {os.getuid(), self.admin_uid}:
            raise ValueError("enrollment, administration and issuer require different UIDs")
        if any(c.isspace() for c in self.audience):
            raise ValueError("invalid audience")
        if len({c.operation for c in self.connectors}) != len(self.connectors):
            raise ValueError("duplicate connector operation")
        if len({c.grant_id for c in self.connectors}) != len(self.connectors):
            raise ValueError("each connector requires its own grant")
        grants = {site.grant_id for site in self.sites}
        if any(c.enabled and c.grant_id not in grants for c in self.connectors):
            raise ValueError("enabled connector requires a configured site grant")
        return self


def load_config(path: Path) -> ProductionConfig:
    with _trusted_file(path, private=False) as descriptor:
        # The service can read policy but cannot silently change its own enrollment policy.
        root_owned = os.fstat(descriptor).st_uid == 0
        raw = os.read(descriptor, 1024 * 1024 + 1)
    if not root_owned:
        raise ValueError("production configuration must be owned by root")

    return ProductionConfig.model_validate(parse_config_json(raw, maximum_bytes=1024 * 1024))


def require_isolated_linux():
    if sys.platform != "linux" or os.getuid() == 0:
        raise ValueError("production requires an isolated non-root Linux service")
    if (
        len(set(os.getresuid())) != 1
        or 0 in os.getresuid()
        or len(set(os.getresgid())) != 1
        or 0 in os.getresgid()
        or not set(os.getgroups()) <= {os.getgid()}
    ):
        raise ValueError("production requires one unprivileged service identity without supplementary groups")
    fields = dict(
        line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line
    )
    if (
        fields.get("Uid", "").split() != [str(os.getuid())] * 4
        or fields.get("Gid", "").split() != [str(os.getgid())] * 4
    ):
        raise ValueError("production requires consistent filesystem and process identities")
    if fields.get("NoNewPrivs", "").strip() != "1" or any(
        int(fields.get(name, "1").strip(), 16) != 0 for name in ("CapEff", "CapPrm", "CapAmb", "CapInh")
    ):
        raise ValueError("production requires no-new-privileges and zero process capabilities")


def activated_admin_socket(admin_uid: int) -> socket.socket:
    """Accept exactly one systemd Unix listener; its on-disk ACL belongs to administration."""
    if (
        os.environ.get("LISTEN_PID") != str(os.getpid())
        or os.environ.get("LISTEN_FDS") != "1"
        or os.environ.get("LISTEN_FDNAMES") != "pap-admin"
    ):
        raise ValueError("systemd administrative socket activation required")
    listener = socket.socket(fileno=os.dup(3))
    try:
        if (
            listener.family != socket.AF_UNIX
            or listener.type != socket.SOCK_STREAM
            or not listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        ):
            raise ValueError("invalid administrative listener")
        path = Path(listener.getsockname())
        parent = path.parent.lstat()
        # The issuer intentionally cannot traverse this directory. systemd owns the
        # listener ACL; the directory and kernel peer UID are independently checked.
        if (
            str(path) != "/run/pap-admin/admin.sock"
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != admin_uid
            or stat.S_IMODE(parent.st_mode) != 0o700
        ):
            raise ValueError("administrative socket permissions are invalid")
        listener.setblocking(False)
        return listener
    except BaseException:
        listener.close()
        raise


class SiteChallenge(StrictModel):
    grant_id: Annotated[str, Field(min_length=1, max_length=80)]
    jwk: dict


class SiteToken(StrictModel):
    challenge_id: Annotated[str, Field(min_length=36, max_length=36)]
    jwk: dict


class Authorization(StrictModel):
    method: Literal["GET"]
    url: Annotated[str, Field(min_length=1, max_length=512)]
    tenant: Annotated[str, Field(min_length=1, max_length=80)]
    action: Annotated[str, Field(min_length=1, max_length=80)]
    audience: Annotated[str, Field(min_length=1, max_length=200)]


class CertificateManagedSigner:
    """Recheck wall-clock certificate expiry before each actual KMS operation."""

    def __init__(self, signer, certificates, on_renewal=None):
        self.signer, self.certificates = signer, certificates
        self.on_renewal = on_renewal or signer.reset_authentication

    def maintain(self):
        result = self.certificates.maintain()
        if result.get("renewed"):
            self.on_renewal()
        return result

    def prepare(self, generation_id):
        self.maintain()
        return self.signer.prepare(generation_id)

    def sign(self, reference, signing_input):
        self.maintain()
        return self.signer.sign(reference, signing_input)

    def retire(self, reference):
        return self.signer.retire(reference)

    def health(self):
        self.maintain()
        return self.signer.health()

    def encrypt_provider_credential(self, provider, credential):
        self.maintain()
        return self.signer.encrypt_provider_credential(provider, credential)

    def decrypt_provider_credential(self, provider, ciphertext):
        self.maintain()
        return self.signer.decrypt_provider_credential(provider, ciphertext)


class AuthorityActor:
    def __init__(self, config: ProductionConfig):
        self.config = config
        self.store = self.authority = self.registry = self.certificates = self.signer = self.connectors = None
        self.lock = None
        self.credentials_revalidation_pending = False

    def start(self):
        state = Path(self.config.state_dir)
        private_directory(state)
        self.lock = os.open(state / "authority.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        k = self.config.kms
        self.signer = OpenBaoSigner(
            k.base_url,
            role=k.role,
            client_cert=Path(k.client_cert),
            client_key=Path(k.client_key),
            ca_file=Path(k.ca_file),
        )
        recovery = (
            UnixEnrollmentClient(
                Path(k.enrollment_socket),
                Path(k.client_ca_file),
                k.enrollment_uid,
                issuer_uid=os.getuid(),
            )
            if k.enrollment_socket is not None
            else None
        )
        certificate_options = {"recovery_issuer": recovery} if recovery is not None else {}
        self.certificates = CertificateManager(
            self.signer,
            state / "credentials",
            Path(k.client_ca_file),
            k.pki_role,
            k.common_name,
            **certificate_options,
        )
        self.certificates.maintain()
        # A persisted active signing key does not prove current KMS readiness.
        # Legacy PKI renewal may also have cached a login bound to the old leaf.
        self.signer.reset_authentication()
        self.signer.health()
        self.store = Store(state / "authority.sqlite")
        self.authority = Authority(
            self.store,
            Config(
                issuer=self.config.issuer,
                audience=self.config.audience,
                token_ttl=self.config.token_ttl,
                signing_interval=self.config.signing_interval,
            ),
            signer=(
                CertificateManagedSigner(self.signer, self.certificates, self._certificate_changed)
                if recovery
                else self.signer
            ),
        )
        self.registry = SiteRegistry(self.authority, [Site(**s.model_dump()) for s in self.config.sites])
        self.connectors = ConnectorStore(
            self.store,
            CertificateManagedSigner(self.signer, self.certificates, self._certificate_changed),
            self.config.connectors,
        )

    def _certificate_changed(self):
        self.signer.reset_authentication()
        self.credentials_revalidation_pending = True

    def connector_admission(self, operation, token, encoded_proof, authorization):
        # One actor operation keeps revocation ordering explicit between proof
        # authorization, cached access and the durable generation claim.
        context = self.registry.authorize(token, encoded_proof, **authorization)
        return context, self.connectors.claim(operation, context)

    def maintain(self):
        result = self.certificates.maintain()
        if result.get("renewed"):
            self._certificate_changed()
        if self.credentials_revalidation_pending:
            # Keep readiness false until OpenBao has actually loaded the fresh
            # listener leaf and accepts the new client certificate. A cached
            # bearer token cannot establish this post-pause condition.
            self.signer.health()
            self.credentials_revalidation_pending = False
        self.authority.maintenance()

    def status(self):
        return {
            **self.authority.status(),
            "profile": "PAP-Netlify-Origin-0.2",
            "version": __version__,
            "key_custody": "openbao-transit",
            "client_certificate_expires_at": self.certificates.current_certificate().not_valid_after_utc.timestamp(),
        }

    def audit(self):
        rows = self.store.db.execute(
            "SELECT seq,at,event,details FROM audit ORDER BY seq DESC LIMIT 100"
        ).fetchall()
        return {"events": [{**dict(row), "details": json.loads(row["details"])} for row in rows]}

    def jwks(self):
        return {
            "keys": [
                {**json.loads(row["public"]), "kid": row["kid"], "use": "sig", "alg": "ES256"}
                for row in self.store.db.execute(
                    "SELECT kid,public FROM signing_keys WHERE state IN ('pending','active','draining')"
                )
            ]
        }

    def close(self):
        if self.store is not None:
            self.store.close()
            self.store = None
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None


class ProductionRuntime:
    def __init__(self, config: ProductionConfig):
        self.config = config
        self.actor = AuthorityActor(config)
        self.executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="pap-authority")
        self.pending = 0
        self.runners = []
        self.task = None
        self.ready = False
        self.failure = None
        self.last_maintenance = 0.0
        self.outbound = asyncio.Semaphore(4)
        self.connector_outbound = asyncio.Semaphore(2)
        self.closed = False

    async def call(self, function, *args, **kwargs):
        if self.pending >= 32:
            raise Denied("authority_busy", 503)
        try:
            future = asyncio.get_running_loop().run_in_executor(
                self.executor, lambda: function(*args, **kwargs)
            )
        except RuntimeError:
            raise Denied("authority_unavailable", 503) from None
        self.pending += 1

        def finished(completed):
            self.pending -= 1
            # A disconnected client still leaves an admitted operation to finish.
            # Retrieve its exception to avoid unhandled-future tracebacks with payloads.
            if not completed.cancelled():
                completed.exception()

        future.add_done_callback(finished)
        return await asyncio.shield(future)

    async def start(self, admin_listener: socket.socket):
        try:
            await self.call(self.actor.start)
            for application, listener in ((self.public_app(), None), (self.admin_app(), admin_listener)):
                runner = web.AppRunner(application, access_log=None, shutdown_timeout=2)
                await runner.setup()
                self.runners.append(runner)
                if listener is None:
                    await web.TCPSite(
                        runner, self.config.listen_host, self.config.listen_port, backlog=128
                    ).start()
                else:
                    await web.SockSite(runner, listener).start()
            self.last_maintenance = time.monotonic()
            self.ready = True
            self.task = asyncio.create_task(self.lifecycle(), name="pap-production-lifecycle")
            return self
        except BaseException:
            await self.close()
            raise

    def public_app(self):
        app = web.Application(middlewares=[errors], client_max_size=8192)
        app.router.add_get("/health", self.health)
        app.router.add_get("/.well-known/jwks.json", self.jwks)
        app.router.add_post("/v1/site/challenge", self.challenge)
        app.router.add_post("/v1/site/token", self.token)
        app.router.add_post("/v1/authorize", self.authorize)
        app.router.add_post("/v1/connectors/{operation}", self.connector)
        return app

    def admin_app(self):
        app = web.Application(middlewares=[errors], client_max_size=8192)
        app.router.add_get("/v0/status", self.status)
        app.router.add_get("/v0/audit", self.audit)
        app.router.add_post("/v0/events", self.event)
        app.router.add_post("/v0/connectors/credentials", self.credential)
        return app

    def require_ready(self):
        if (
            not self.ready
            or self.failure
            or self.actor.credentials_revalidation_pending
            or time.monotonic() - self.last_maintenance > 15
        ):
            raise Denied("lifecycle_unavailable", 503)

    def admin_identity(self, request):
        if peer_uid(request) != self.config.admin_uid:
            raise Denied("admin_not_authorized", 403)

    async def lifecycle(self):
        while True:
            try:
                await self.call(self.actor.maintain)
                self.last_maintenance = time.monotonic()
                self.failure = None
            except Exception:
                self.failure = "lifecycle_unavailable"
                LOG.error("production_lifecycle_unavailable")
            await asyncio.sleep(1)

    async def challenge(self, request):
        self.require_ready()
        payload = await body(request, SiteChallenge)
        return web.json_response(
            await self.call(self.actor.registry.challenge, payload.grant_id, payload.jwk)
        )

    async def token(self, request):
        self.require_ready()
        payload = await body(request, SiteToken)
        try:
            if str(uuid.UUID(payload.challenge_id)) != payload.challenge_id:
                raise ValueError("noncanonical challenge")
        except ValueError:
            raise Denied("invalid_challenge", 400) from None
        encoded = request.headers.get("DPoP", "")
        site, _ = await self.call(
            self.actor.registry.exchange_context, payload.challenge_id, payload.jwk, encoded
        )
        if self.outbound.locked():
            raise Denied("authority_busy", 503)
        async with self.outbound:
            if site.identity_adapter == "netlify":
                published = await fetch_site_record(site.origin, payload.challenge_id)
            else:
                published = await fetch_site_record(
                    site.origin, payload.challenge_id, identity_adapter=site.identity_adapter
                )
        self.require_ready()
        return web.json_response(
            await self.call(
                self.actor.registry.finish_exchange, payload.challenge_id, payload.jwk, encoded, published
            )
        )

    async def authorize(self, request):
        self.require_ready()
        authorization = request.headers.get("Authorization", "")
        if not authorization.startswith("DPoP ") or len(authorization) > 4101:
            raise Denied("dpop_required")
        payload = await body(request, Authorization)
        return web.json_response(
            await self.call(
                self.actor.registry.authorize,
                authorization[5:],
                request.headers.get("DPoP", ""),
                **payload.model_dump(),
            )
        )

    async def health(self, request):
        try:
            self.require_ready()
            return web.json_response({"ready": True})
        except Denied:
            return web.json_response({"ready": False}, status=503)

    async def connector(self, request):
        self.require_ready()
        operation = request.match_info["operation"]
        await self.call(self.actor.connectors.configuration, operation)
        authorization = request.headers.get("Authorization", "")
        if not authorization.startswith("DPoP ") or len(authorization) > 4101:
            raise Denied("dpop_required")
        payload = await body(request, Authorization)
        if self.connector_outbound.locked():
            raise Denied("connector_busy", 503)
        async with self.connector_outbound:
            context, claim = await self.call(
                self.actor.connector_admission,
                operation,
                authorization[5:],
                request.headers.get("DPoP", ""),
                payload.model_dump(),
            )
            if "cached" in claim:
                return web.json_response(claim["cached"])
            try:
                async with asyncio.timeout(25):
                    result = await generate(operation, claim["credentials"], claim["key"][2])
                self.require_ready()
                result = await self.call(
                    self.actor.connectors.complete,
                    claim,
                    result,
                    context,
                    self.actor.registry,
                )
                return web.json_response(result)
            except BaseException as error:
                await self.call(self.actor.connectors.fail, claim["key"])
                if isinstance(error, asyncio.CancelledError):
                    raise
                if isinstance(error, Denied):
                    raise
                raise Denied("connector_upstream_unavailable", 503) from None
            finally:
                # Python strings cannot promise zeroization. This bounded scope
                # reduces their lifetime; host memory is an explicit trust boundary.
                claim["credentials"].clear()

    async def credential(self, request):
        self.admin_identity(request)
        self.require_ready()
        payload = await body(request, CredentialRequest)
        return web.json_response(await self.call(self.actor.connectors.credential, payload))

    async def jwks(self, request):
        self.require_ready()
        return web.json_response(await self.call(self.actor.jwks))

    async def status(self, request):
        self.admin_identity(request)
        return web.json_response(
            {**await self.call(self.actor.status), "ready": self.ready and not self.failure}
        )

    async def audit(self, request):
        self.admin_identity(request)
        return web.json_response(await self.call(self.actor.audit))

    async def event(self, request):
        self.admin_identity(request)
        payload = await body(request, Event)
        try:
            if str(uuid.UUID(payload.event_id)) != payload.event_id:
                raise ValueError("noncanonical event")
        except ValueError:
            raise Denied("invalid_event_id", 400) from None
        return web.json_response(await self.call(self.actor.authority.event, **payload.model_dump()))

    async def close(self):
        if self.closed:
            return
        self.ready = False
        if self.task:
            self.task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.task
            self.task = None
        for runner in reversed(self.runners):
            await runner.cleanup()
        self.runners.clear()
        # Shutdown is an actor control operation and must remain possible when the
        # bounded public admission queue is saturated.
        await asyncio.get_running_loop().run_in_executor(self.executor, self.actor.close)
        self.executor.shutdown(wait=True, cancel_futures=True)
        self.closed = True


async def serve(config_path: Path):
    require_isolated_linux()
    harden_secret_process()
    config = load_config(config_path)
    listener = activated_admin_socket(config.admin_uid)
    runtime = ProductionRuntime(config)
    try:
        await runtime.start(listener)
        LOG.warning("production_ready profile=PAP-Netlify-Origin-0.2")
        stopped = asyncio.Event()
        loop = asyncio.get_running_loop()
        for signum in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(signum, stopped.set)
        await stopped.wait()
    finally:
        await runtime.close()
        listener.close()
