"""HTTPS origin workload SDK. Configuration is public; private keys remain in RAM.

An origin adapter proves control of the whole registered production origin. It
does not attest to a cloud account, container, process, or hardware identity.
Use one proof store shared by the SDK and its callback handler. The in-memory
implementation supports one process; multiple workers require a shared store.
"""

import asyncio
import base64
import json
import logging
import math
import re
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Protocol
from urllib.parse import urlsplit

import aiohttp
from aiohttp import web

from .cloud import PublicResolver
from .crypto import fresh_key, proof, public_jwk, thumbprint
from .identity_adapters import https_origin

PROOF_PATH = "/.well-known/pap/site-proof/"
MAX_JSON_BYTES = 16_384
LOG = logging.getLogger(__name__)
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}\Z")
_COMPACT_JWT = re.compile(r"[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\Z")
_NO_CACHE = {
    "Cache-Control": "no-store, private, max-age=0",
    "CDN-Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
}


class WorkloadError(Exception):
    """A bounded error code, safe to return without upstream bodies or tokens."""

    def __init__(self, code: str, status: int = 401):
        self.code, self.status = code, status
        super().__init__(code)


def _object(value: Any, fields: set[str]) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise WorkloadError("invalid_schema", 502)
    return value


def _text(value: Any, minimum: int = 1, maximum: int = 128) -> str:
    if (
        not isinstance(value, str)
        or not minimum <= len(value) <= maximum
        or re.search(r"[\x00-\x20\x7f]", value)
    ):
        raise WorkloadError("invalid_schema", 502)
    return value


def _uuid(value: Any) -> str:
    value = _text(value, 36, 36)
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError("noncanonical UUID")
    except ValueError:
        raise WorkloadError("invalid_identifier", 502) from None
    return value


def _identifier(value: Any) -> str:
    value = _text(value, 1, 80)
    if not _IDENTIFIER.fullmatch(value):
        raise WorkloadError("invalid_identifier", 502)
    return value


def _number(value: Any) -> float:
    if type(value) not in (int, float) or not math.isfinite(value):
        raise WorkloadError("invalid_schema", 502)
    return value


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _json(raw: bytes) -> Any:
    try:
        return json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("nonfinite JSON")),
        )
    except (UnicodeError, ValueError, RecursionError):
        raise WorkloadError("invalid_json", 502) from None


@dataclass(frozen=True, slots=True)
class WorkloadConfig:
    """Strict, public-only configuration. Construct with :meth:`from_dict`."""

    issuer_url: str
    workload_id: str
    grant_id: str
    resource_origin: str
    resource_path: str
    resource_action: str
    tenant: str
    environment: str
    audience: str
    enabled: bool = False
    trust_origin_deployment: bool = False

    @classmethod
    def from_dict(cls, value: Any) -> "WorkloadConfig":
        value = _object(value, {
            "enabled", "issuerURL", "workloadID", "grantID", "resourceOrigin",
            "resourcePath", "resourceAction", "tenant", "environment", "audience",
            "trustOriginDeployment",
        })
        if value["enabled"] is not True or value["trustOriginDeployment"] is not True:
            raise WorkloadError("adapter_not_configured", 503)
        if value["environment"] != "production":
            raise WorkloadError("production_required", 503)
        path, action = _text(value["resourcePath"], 1, 256), _text(value["resourceAction"], 1, 64)
        if not re.fullmatch(r"/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+", path):
            raise WorkloadError("invalid_resource_path", 503)
        if not re.fullmatch(r"[a-z][a-z0-9._-]*", action):
            raise WorkloadError("invalid_resource_action", 503)
        try:
            issuer, origin = https_origin(value["issuerURL"]), https_origin(value["resourceOrigin"])
        except (ValueError, TypeError):
            raise WorkloadError("invalid_origin", 503) from None
        return cls(
            issuer, _uuid(value["workloadID"]), _identifier(value["grantID"]), origin, path,
            action, _identifier(value["tenant"]), "production", _text(value["audience"], 1, 200), True, True,
        )

    def __post_init__(self):
        # Direct dataclass construction must not bypass the public-config checks.
        if self.enabled is not True or self.trust_origin_deployment is not True:
            raise WorkloadError("adapter_not_configured", 503)
        try:
            https_origin(self.issuer_url)
            https_origin(self.resource_origin)
        except (ValueError, TypeError):
            raise WorkloadError("invalid_origin", 503) from None
        _uuid(self.workload_id)
        for value in (self.grant_id, self.tenant):
            _identifier(value)
        _text(self.audience, 1, 200)
        if (
            self.environment != "production"
            or not isinstance(self.resource_path, str)
            or len(self.resource_path) > 256
            or not re.fullmatch(r"/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+", self.resource_path)
            or not isinstance(self.resource_action, str)
            or not re.fullmatch(r"[a-z][a-z0-9._-]{0,63}", self.resource_action)
        ):
            raise WorkloadError("invalid_configuration", 503)


def _record(value: Any, now: float) -> dict:
    value = _object(value, {"challenge_id", "nonce", "jkt", "issuer", "site_id", "expires_at"})
    result = {
        "challenge_id": _uuid(value["challenge_id"]),
        "nonce": _text(value["nonce"], 16, 128),
        "jkt": _text(value["jkt"], 43, 43),
        "issuer": _text(value["issuer"], 1, 256),
        "site_id": _uuid(value["site_id"]),
        "expires_at": _number(value["expires_at"]),
    }
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", result["jkt"]):
        raise WorkloadError("invalid_challenge", 502)
    try:
        https_origin(result["issuer"])
    except ValueError:
        raise WorkloadError("invalid_challenge", 502) from None
    if not now < result["expires_at"] <= now + 120:
        raise WorkloadError("challenge_expired", 401)
    return result


class ProofStore(Protocol):
    """Only the trusted local SDK publishes; expose reads through the GET handler."""

    async def publish(self, record: Mapping[str, Any]) -> None: ...
    async def read(self, challenge_id: str) -> dict | None: ...
    async def remove(self, challenge_id: str) -> None: ...


class MemoryProofStore:
    """Bounded public challenge records, for a single application process only."""

    def __init__(self, *, max_records: int = 32, now: Callable[[], float] = time.time):
        if type(max_records) is not int or not 1 <= max_records <= 1024:
            raise ValueError("max_records must be between 1 and 1024")
        self._limit, self._now = max_records, now
        self._records: dict[str, dict] = {}
        self._lock = asyncio.Lock()

    def _expire(self):
        now = self._now()
        self._records = {k: v for k, v in self._records.items() if v["expires_at"] > now}

    async def publish(self, record: Mapping[str, Any]) -> None:
        value = _record(dict(record), self._now())
        async with self._lock:
            self._expire()
            previous = self._records.get(value["challenge_id"])
            if previous is not None and previous != value:
                raise WorkloadError("proof_record_conflict", 409)
            if previous is None and len(self._records) >= self._limit:
                raise WorkloadError("proof_store_full", 503)
            self._records[value["challenge_id"]] = value

    async def read(self, challenge_id: str) -> dict | None:
        _uuid(challenge_id)
        async with self._lock:
            self._expire()
            result = self._records.get(challenge_id)
            return dict(result) if result is not None else None

    async def remove(self, challenge_id: str) -> None:
        _uuid(challenge_id)
        async with self._lock:
            self._records.pop(challenge_id, None)


def proof_handler(store: ProofStore):
    """GET-only callback. It never accepts a JWK or a publication request."""

    async def handler(request: web.Request) -> web.Response:
        challenge_id = request.match_info.get("challenge_id", "")
        if request.method != "GET":
            return web.json_response(
                {"error": "method_not_allowed"}, status=405, headers={**_NO_CACHE, "Allow": "GET"},
            )
        try:
            _uuid(challenge_id)
            if (
                request.raw_path != PROOF_PATH + challenge_id
                or request.can_read_body
                or request.headers.get("Transfer-Encoding")
            ):
                raise WorkloadError("invalid_proof_path", 400)
            async with asyncio.timeout(2):
                record = await store.read(challenge_id)
            if record is None:
                raise WorkloadError("proof_not_found", 404)
            record = _record(record, time.time())
            return web.json_response(record, headers=_NO_CACHE)
        except WorkloadError as exc:
            return web.json_response({"error": exc.code}, status=exc.status, headers=_NO_CACHE)
        except Exception:  # noqa: BLE001 -- A backend exception may contain secret values.
            return web.json_response({"error": "proof_store_unavailable"}, status=503, headers=_NO_CACHE)

    return handler


def install_proof_route(app: web.Application, store: ProofStore) -> None:
    """Register the fixed callback path; no POST publisher is installed."""
    app.router.add_route("*", PROOF_PATH + "{challenge_id}", proof_handler(store))


@dataclass(frozen=True, slots=True)
class JSONResponse:
    status: int
    value: Any = field(repr=False)


class JSONTransport(Protocol):
    """Explicit test/infrastructure seam, not user-controlled configuration."""

    async def request(self, method: str, url: str, *, body: dict | None, headers: dict) -> JSONResponse: ...
    async def close(self) -> None: ...


class HTTPSJSONTransport:
    """TLS verified, DNS pinned public origins; no proxies, cookies or redirects."""

    def __init__(self, origins: set[str]):
        self._origins = frozenset(https_origin(origin) for origin in origins)
        self._sessions: dict[str, aiohttp.ClientSession] = {}
        self._closed = False

    async def request(self, method: str, url: str, *, body: dict | None, headers: dict) -> JSONResponse:
        parsed = urlsplit(url)
        origin = "https://" + (parsed.hostname or "")
        if (
            self._closed or method not in {"GET", "POST"} or origin not in self._origins
            or parsed.netloc != parsed.hostname or parsed.scheme != "https"
            or parsed.query or parsed.fragment
        ):
            raise WorkloadError("unregistered_destination", 503)
        session = self._sessions.get(origin)
        if session is None:
            session = aiohttp.ClientSession(
                connector=aiohttp.TCPConnector(
                    resolver=PublicResolver(parsed.hostname), use_dns_cache=False, limit=8,
                ),
                trust_env=False, auto_decompress=False, cookie_jar=aiohttp.DummyCookieJar(),
                skip_auto_headers={"Accept-Encoding"},
                timeout=aiohttp.ClientTimeout(total=30, connect=3, sock_read=30),
            )
            self._sessions[origin] = session
        try:
            async with session.request(
                method, url, json=body, headers={
                    "Accept": "application/json", "Cache-Control": "no-store", **headers,
                    "Accept-Encoding": "identity",
                },
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(
                    total=30 if method == "GET" else 8, connect=3,
                    sock_read=30 if method == "GET" else 8,
                ),
            ) as response:
                if response.status != 200:
                    # Never retain or display error pages, which can contain secrets.
                    return JSONResponse(response.status, None)
                if response.content_type != "application/json" or response.headers.get("Content-Encoding"):
                    raise WorkloadError("invalid_upstream_response", 502)
                if response.content_length is not None and response.content_length > MAX_JSON_BYTES:
                    raise WorkloadError("response_too_large", 502)
                raw = bytearray()
                async for chunk in response.content.iter_chunked(4096):
                    raw.extend(chunk)
                    if len(raw) > MAX_JSON_BYTES:
                        raise WorkloadError("response_too_large", 502)
                return JSONResponse(200, _json(bytes(raw)))
        except WorkloadError:
            raise
        except (aiohttp.ClientError, OSError, TimeoutError):
            raise WorkloadError("upstream_unavailable", 503) from None

    async def close(self) -> None:
        self._closed = True
        await asyncio.gather(*(session.close() for session in self._sessions.values()))
        self._sessions.clear()


@dataclass(slots=True, repr=False)
class _Credential:
    key: Any
    token: str
    nonce: str
    expires_at: float


def _credential(value: Any, config: WorkloadConfig, jkt: str, key: Any, now: float) -> _Credential:
    value = _object(value, {"access_token", "token_type", "expires_at", "expires_in", "dpop_nonce", "tenant", "environment"})
    token, nonce = _text(value["access_token"], 16, 4096), _text(value["dpop_nonce"], 16, 128)
    expires, ttl = _number(value["expires_at"]), _number(value["expires_in"])
    if (
        value["token_type"] != "DPoP" or value["tenant"] != config.tenant
        or value["environment"] != config.environment or not now < expires <= now + 3600
        or not 0 < ttl <= 3600 or abs(expires - now - ttl) > 10 or not _COMPACT_JWT.fullmatch(token)
    ):
        raise WorkloadError("invalid_credential_response", 502)
    try:
        header, payload, _signature = token.split(".")
        header = _json(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)))
        claims = _json(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        _object(header, {"alg", "typ", "kid"})
        _object(claims, {
            "iss", "aud", "sub", "client_id", "iat", "exp", "jti", "cnf", "tenant", "environment",
            "grant_id", "epoch", "scope",
        })
        _identifier(claims["sub"])
        _uuid(claims["jti"])
        _text(header["kid"], 1, 128)
        if (
            header["alg"] != "ES256" or header["typ"] != "at+jwt"
            or claims["iss"] != config.issuer_url or claims["aud"] != config.audience
            or claims["tenant"] != config.tenant or claims["environment"] != config.environment
            or claims["grant_id"] != config.grant_id or claims["cnf"] != {"jkt": jkt}
            or claims["client_id"] != claims["sub"] or type(claims["iat"]) is not int
            or not now - 10 <= claims["iat"] <= now + 2 or type(claims["exp"]) is not int
            or claims["exp"] != expires or type(claims["epoch"]) is not int or claims["epoch"] < 0
            or not isinstance(claims["scope"], str) or len(claims["scope"]) > 1024
            or config.resource_action not in claims["scope"].split(" ")
        ):
            raise ValueError("credential binding mismatch")
    except (ValueError, TypeError, KeyError, WorkloadError):
        raise WorkloadError("credential_binding_mismatch", 502) from None
    # TLS authenticates the issuer response; the resource verifies the JWT signature
    # online. These checks prevent caching a misbound response, not local JWT auth.
    return _Credential(key, token, nonce, expires)


class WorkloadClient:
    """Fixed GET operation with automatic, single-flight renewal when used.

    No provider key or bearer token can be supplied through public configuration.
    Network failures never resubmit the resource operation; its outcome may be
    unknown. A definitive 401 permits one renewal and one new proof attempt.
    """

    def __init__(
        self, config: WorkloadConfig | dict, *, store: ProofStore | None = None,
        transport: JSONTransport | None = None, now: Callable[[], float] = time.time,
    ):
        self.config = config if isinstance(config, WorkloadConfig) else WorkloadConfig.from_dict(config)
        self.store = store if store is not None else MemoryProofStore(now=now)
        self._transport = transport if transport is not None else HTTPSJSONTransport({
            self.config.issuer_url, self.config.resource_origin,
        })
        self._now = now
        self._cached: _Credential | None = None
        self._renewing: asyncio.Task | None = None
        self._inflight: set[asyncio.Task] = set()
        self._closed = False

    def _open(self):
        if self._closed:
            raise WorkloadError("client_closed", 503)

    async def __aenter__(self):
        self._open()
        return self

    async def __aexit__(self, *_exc):
        await self.close()

    async def _request(self, method, url, body=None, headers=None, *, issuer=True):
        self._open()
        task = asyncio.create_task(self._transport.request(method, url, body=body, headers=headers or {}))
        self._inflight.add(task)
        try:
            async with asyncio.timeout(8 if method == "POST" else 30):
                response = await task
            self._open()
            if not isinstance(response, JSONResponse) or type(response.status) is not int:
                raise WorkloadError("invalid_upstream_response", 502)
            if response.status != 200:
                if response.status in (401, 403):
                    raise WorkloadError("access_denied", response.status)
                raise WorkloadError("issuer_unavailable" if issuer else "resource_unavailable", 503)
            return response.value
        except asyncio.CancelledError:
            self._open()
            raise
        except WorkloadError as exc:
            if exc.code == "upstream_unavailable":
                raise WorkloadError("issuer_unavailable" if issuer else "resource_unavailable", 503) from None
            raise
        except Exception:  # noqa: BLE001 -- Never expose transport exception text.
            raise WorkloadError("issuer_unavailable" if issuer else "resource_unavailable", 503) from None
        finally:
            self._inflight.discard(task)

    async def _renew(self):
        self._open()
        key = fresh_key()
        jwk = public_jwk(key)
        expected_jkt = thumbprint(jwk)
        challenge = _record(await self._request(
            "POST", self.config.issuer_url + "/v1/site/challenge",
            {"grant_id": self.config.grant_id, "jwk": jwk},
        ), self._now())
        if (
            challenge["jkt"] != expected_jkt or challenge["issuer"] != self.config.issuer_url
            or challenge["site_id"] != self.config.workload_id
        ):
            raise WorkloadError("challenge_binding_mismatch", 502)
        published = False
        try:
            self._open()
            try:
                async with asyncio.timeout(5):
                    await self.store.publish(challenge)
                    published = True
                    if await self.store.read(challenge["challenge_id"]) != challenge:
                        raise WorkloadError("proof_publication_mismatch", 503)
            except WorkloadError:
                raise
            except Exception:  # noqa: BLE001 -- Custom store errors must be redacted.
                raise WorkloadError("proof_publication_failed", 503) from None
            self._open()
            target = self.config.issuer_url + "/v1/site/token"
            encoded = proof(key, "POST", target, challenge["nonce"], now=self._now())
            credential = _credential(await self._request(
                "POST", target, {"challenge_id": challenge["challenge_id"], "jwk": jwk}, {"DPoP": encoded},
            ), self.config, expected_jkt, key, self._now())
            self._open()
            self._cached = credential
            return credential
        finally:
            if published:
                try:
                    async with asyncio.timeout(2):
                        await self.store.remove(challenge["challenge_id"])
                except Exception:  # noqa: BLE001 -- Log a fixed code, never store error text.
                    # The record is public and expires; preserve the original issuance result.
                    LOG.warning("workload_proof_cleanup_failed", extra={"event": "proof_cleanup_failed"})

    async def _renew_with_recovery(self):
        try:
            return await self._renew()
        except WorkloadError as exc:
            if exc.code != "issuer_unavailable":
                raise
        self._open()
        deadline = asyncio.get_running_loop().time() + 20
        ready = False
        for attempt in range(8):
            try:
                async with asyncio.timeout(max(0.01, deadline - asyncio.get_running_loop().time())):
                    health = await self._request("GET", self.config.issuer_url + "/health")
                if isinstance(health, dict) and set(health) == {"ready"} and health["ready"] is True:
                    ready = True
                    break
            except WorkloadError as exc:
                if exc.code in {"access_denied", "client_closed"}:
                    raise
            except TimeoutError:
                break
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0 or attempt == 7:
                break
            await asyncio.sleep(min(remaining, 0.25 * 2 ** min(attempt, 3)))
        if ready:
            # At most one retry after an uncertain POST, with fresh key/challenge.
            return await self._renew()
        raise WorkloadError("issuer_unavailable", 503)

    async def _active(self):
        self._open()
        if self._cached is not None and self._cached.expires_at - self._now() > 10:
            return self._cached
        if self._renewing is None:
            self._renewing = asyncio.create_task(self._renew_with_recovery())
        task = self._renewing
        try:
            result = await asyncio.shield(task)
            self._open()
            return result
        except asyncio.CancelledError:
            self._open()
            raise
        finally:
            if task.done() and self._renewing is task:
                self._renewing = None

    async def get_json(self) -> Any:
        """Execute only the configured GET operation; return resource JSON only."""
        for attempt in range(2):
            credential = await self._active()
            url = self.config.resource_origin + self.config.resource_path
            encoded = proof(
                credential.key, "GET", url, credential.nonce, credential.token, now=self._now(),
            )
            try:
                return await self._request("GET", url, headers={
                    "Authorization": "DPoP " + credential.token, "DPoP": encoded,
                }, issuer=False)
            except WorkloadError as exc:
                if attempt or exc.status != 401:
                    raise
                if self._cached is credential:
                    self._cached = None
        raise WorkloadError("access_denied", 401)

    async def authorize_request(self, request: web.Request) -> dict:
        """Online resource verification: validates route and consumes the proof once.

        Build the authorization URL from registered configuration, never Host or
        forwarding headers. Do not call this before a connector that itself
        authorizes the same request; DPoP proofs are deliberately single-use.
        """
        self._open()
        if (
            request.method != "GET" or request.raw_path != self.config.resource_path
            or request.can_read_body or request.headers.get("Transfer-Encoding")
        ):
            raise WorkloadError("unsupported_operation", 400)
        if len(request.headers.getall("Authorization", [])) != 1 or len(request.headers.getall("DPoP", [])) != 1:
            raise WorkloadError("invalid_proof", 401)
        authorization, encoded = request.headers["Authorization"], request.headers["DPoP"]
        if (
            not authorization.startswith("DPoP ") or len(authorization) > 4101
            or not _COMPACT_JWT.fullmatch(authorization[5:]) or len(encoded) > 4096
            or not _COMPACT_JWT.fullmatch(encoded)
        ):
            raise WorkloadError("invalid_proof", 401)
        value = _object(await self._request("POST", self.config.issuer_url + "/v1/authorize", {
            "method": "GET", "url": self.config.resource_origin + self.config.resource_path,
            "tenant": self.config.tenant, "action": self.config.resource_action, "audience": self.config.audience,
        }, {"Authorization": authorization, "DPoP": encoded}), {
            "subject", "tenant", "environment", "grant_id", "action", "expires_at",
        })
        _identifier(value["subject"])
        if (
            value["tenant"] != self.config.tenant or value["environment"] != self.config.environment
            or value["grant_id"] != self.config.grant_id or value["action"] != self.config.resource_action
            or not self._now() < _number(value["expires_at"]) <= self._now() + 3600
        ):
            raise WorkloadError("authorization_binding_mismatch", 403)
        return dict(value)

    async def close(self) -> None:
        """Cancel pending HTTP/renewal, discard private credentials, close sockets."""
        if self._closed:
            return
        self._closed = True
        self._cached = None
        pending = set(self._inflight)
        if self._renewing is not None:
            pending.add(self._renewing)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        self._renewing = None
        await self._transport.close()
