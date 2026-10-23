"""Registered-origin verification. This is site control, not platform attestation."""

import asyncio
import base64
import hashlib
import hmac
import json
import re
import secrets
import socket
import time
import uuid
from dataclasses import dataclass
from urllib.parse import urlsplit

import aiohttp
from aiohttp.abc import AbstractResolver

from .crypto import Denied, b64, thumbprint, verify_proof
from .identity_adapters import identity_adapter as get_identity_adapter
from .identity_adapters import netlify_origin as netlify_origin
from .identity_adapters import public_destination


class PublicResolver(AbstractResolver):
    """Resolve only the registered host and pin checked public IPs into the connector."""

    def __init__(self, hostname: str):
        self.hostname = hostname

    async def resolve(self, host, port=0, family=socket.AF_INET):
        if host != self.hostname or port != 443:
            raise OSError("unregistered destination")
        records = await asyncio.get_running_loop().getaddrinfo(
            host, port, family=family, type=socket.SOCK_STREAM
        )
        results = []
        for af, _socktype, protocol, _canonname, address in records:
            try:
                ip = public_destination(address[0])
            except ValueError:
                raise OSError("nonpublic destination") from None
            results.append(
                {"hostname": host, "host": str(ip), "port": port, "family": af, "proto": protocol, "flags": 0}
            )
        if not results:
            raise OSError("unavailable destination")
        return results

    async def close(self):
        pass


async def fetch_site_record(origin: str, challenge_id: str, *, identity_adapter: str = "netlify") -> dict:
    get_identity_adapter(identity_adapter).validate_origin(origin)
    try:
        if str(uuid.UUID(challenge_id)) != challenge_id:
            raise ValueError("noncanonical challenge")
    except (ValueError, TypeError, AttributeError):
        raise Denied("invalid_challenge", 400) from None
    connector = aiohttp.TCPConnector(
        resolver=PublicResolver(urlsplit(origin).hostname), use_dns_cache=False, limit=2
    )
    try:
        async with aiohttp.ClientSession(
            connector=connector,
            trust_env=False,
            auto_decompress=False,
            timeout=aiohttp.ClientTimeout(total=5, connect=3, sock_read=2),
        ) as session:
            async with session.get(
                origin + "/.well-known/pap/site-proof/" + challenge_id,
                headers={"Accept": "application/json", "Accept-Encoding": "identity"},
                allow_redirects=False,
            ) as response:
                if response.status != 200 or response.content_type != "application/json":
                    raise Denied("site_proof_unavailable", 503)
                if getattr(response, "headers", {}).get("Content-Encoding", "identity").lower() != "identity":
                    raise Denied("site_proof_invalid", 403)
                chunks, total = [], 0
                while True:
                    chunk = await response.content.read(16385 - total)
                    if not chunk:
                        break
                    chunks.append(chunk)
                    total += len(chunk)
                    if total > 16384:
                        raise Denied("site_proof_invalid", 403)
                raw = b"".join(chunks)

                def unique(pairs):
                    result = {}
                    for k, v in pairs:
                        if k in result:
                            raise ValueError("duplicate member")
                        result[k] = v
                    return result

                result = json.loads(raw, object_pairs_hook=unique)
                if not isinstance(result, dict):
                    raise Denied("site_proof_invalid", 403)
                return result
    except Denied:
        raise
    except (OSError, ValueError, RecursionError, aiohttp.ClientError, TimeoutError):
        raise Denied("site_proof_unavailable", 503) from None


@dataclass(frozen=True)
class Site:
    site_id: str
    origin: str
    subject: str
    tenant: str
    environment: str
    grant_id: str
    grant_expires_at: float
    trusted_site_contexts: bool
    resource_path: str = "/api/pap/records"
    resource_action: str = "records.read"
    identity_adapter: str = "netlify"

    def __post_init__(self):
        if str(uuid.UUID(self.site_id)) != self.site_id:
            raise ValueError("canonical site UUID required")
        get_identity_adapter(self.identity_adapter).validate_origin(self.origin)
        for value in (self.subject, self.tenant, self.environment, self.grant_id):
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", value):
                raise ValueError("invalid site binding identifier")
        if self.environment != "production" or self.trusted_site_contexts is not True:
            raise ValueError("dedicated trusted production site must be explicitly acknowledged")
        if type(self.grant_expires_at) not in (int, float) or not 0 < self.grant_expires_at < 4102444800:
            raise ValueError("explicit absolute grant expiry required")
        if (
            not re.fullmatch(r"/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+", self.resource_path)
            or len(self.resource_path) > 256
        ):
            raise ValueError("canonical resource path required")
        if not re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", self.resource_action):
            raise ValueError("invalid resource action")

    @property
    def uid(self):
        # A stable negative namespace never represents a kernel UID.
        return -1 - int.from_bytes(hashlib.sha256(self.subject.encode()).digest()[:7])


class SiteRegistry:
    def __init__(self, authority, sites: list[Site]):
        self.authority, self.store = authority, authority.store
        if any(
            len({getattr(s, k) for s in sites}) != len(sites)
            for k in ("site_id", "origin", "subject", "grant_id")
        ):
            raise ValueError("site bindings must be unique")
        self.sites = {s.grant_id: s for s in sites}
        # Initial challenges are deliberately stateless: an unauthenticated
        # caller must not reserve another site's issuance slots or quota.
        self._nonce_key = secrets.token_bytes(32)
        self._selectors = {self._selector(s.grant_id): s for s in sites}
        if len(self._selectors) != len(sites):
            raise ValueError("site challenge selectors must be unique")
        self.store.db.execute("""CREATE TABLE IF NOT EXISTS site_challenges (
            id TEXT PRIMARY KEY, grant_id TEXT NOT NULL, record TEXT NOT NULL, expires REAL NOT NULL, consumed INTEGER NOT NULL DEFAULT 0)""")
        for site in sites:
            binding = {k: v for k, v in vars(site).items() if k != "grant_expires_at"}
            previous = self.store.setting("site:" + site.grant_id)
            if isinstance(previous, dict) and "identity_adapter" not in previous:
                # Older releases only implemented Netlify. Absence is a legacy
                # Netlify binding, never permission to select a new trust method.
                previous = {**previous, "identity_adapter": "netlify"}
            if previous is not None and previous != binding:
                raise ValueError("existing site binding cannot be silently rebound")
            existed = self.store.db.execute("SELECT 1 FROM workloads WHERE id=?", (site.subject,)).fetchone()
            self.authority.provision(
                site.uid,
                subject=site.subject,
                tenant=site.tenant,
                environment=site.environment,
                grant_id=site.grant_id,
                actions={site.resource_action},
            )
            with self.store.transaction() as db:
                if not existed:
                    db.execute(
                        "UPDATE grants SET expires=? WHERE id=?", (site.grant_expires_at, site.grant_id)
                    )
                self.store.set_setting("site:" + site.grant_id, binding)

    def site_for_grant(self, grant_id: str):
        site = self.sites.get(grant_id)
        if site is None:
            raise Denied("site_not_authorized", 403)
        self.authority.workload_for_uid(site.uid)
        self.authority.grant_for(site.subject, grant_id)
        return site

    @staticmethod
    def _selector(grant_id: str) -> bytes:
        return hashlib.sha256(grant_id.encode()).digest()[:16]

    def _challenge_mac(self, site: Site, challenge_id: str, jkt: str, expires: int) -> bytes:
        binding = json.dumps(
            [
                "PAP-site-challenge-v1",
                site.identity_adapter,
                self.authority.config.issuer,
                site.site_id,
                site.origin,
                site.grant_id,
                jkt,
                challenge_id,
                expires,
            ],
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        return hmac.digest(self._nonce_key, binding, "sha256")

    def challenge(self, grant_id: str, jwk: dict):
        site = self.site_for_grant(grant_id)
        challenge_id, jkt = str(uuid.uuid4()), thumbprint(jwk)
        expires = min(int(time.time()) + 15, int(site.grant_expires_at))
        if expires <= time.time():
            raise Denied("grant_not_authorized", 403)
        encoded = b"\x01" + expires.to_bytes(4, "big") + self._selector(grant_id)
        nonce = b64(encoded + self._challenge_mac(site, challenge_id, jkt, expires))
        record = {
            "challenge_id": challenge_id,
            "nonce": nonce,
            "jkt": jkt,
            "issuer": self.authority.config.issuer,
            "site_id": site.site_id,
            "expires_at": expires,
        }
        return record

    def exchange_context(self, challenge_id: str, jwk: dict, encoded_proof: str):
        jkt = thumbprint(jwk)
        p, _ = verify_proof(
            encoded_proof,
            "POST",
            self.authority.config.issuer + "/v1/site/token",
            expected_jkt=jkt,
            max_age=self.authority.config.proof_age,
            skew=self.authority.config.skew,
        )
        nonce = p["nonce"]
        try:
            if str(uuid.UUID(challenge_id)) != challenge_id:
                raise ValueError("invalid challenge identity")
            if re.fullmatch(r"[A-Za-z0-9_-]{71}", nonce) is None:
                raise ValueError("invalid nonce encoding")
            decoded = base64.b64decode(nonce + "=", altchars=b"-_", validate=True)
            if len(decoded) != 53 or b64(decoded) != nonce or decoded[0] != 1:
                raise ValueError("invalid nonce format")
            expires = int.from_bytes(decoded[1:5], "big")
            site = self._selectors.get(decoded[5:21])
            if site is None or not hmac.compare_digest(
                decoded[21:], self._challenge_mac(site, challenge_id, jkt, expires)
            ):
                raise ValueError("invalid nonce binding")
        except (ValueError, TypeError, AttributeError):
            raise Denied("invalid_nonce") from None
        if not time.time() < expires <= time.time() + 15:
            raise Denied("challenge_not_authorized", 403)
        site = self.site_for_grant(site.grant_id)
        record = {
            "challenge_id": challenge_id,
            "nonce": nonce,
            "jkt": jkt,
            "issuer": self.authority.config.issuer,
            "site_id": site.site_id,
            "expires_at": expires,
        }
        row = self.store.db.execute("SELECT * FROM site_challenges WHERE id=?", (challenge_id,)).fetchone()
        if row is not None and (
            row["consumed"]
            or row["expires"] <= time.time()
            or row["grant_id"] != site.grant_id
            or json.loads(row["record"]) != record
        ):
            raise Denied("challenge_not_authorized", 403)
        return site, record

    def finish_exchange(self, challenge_id, jwk, encoded_proof, published):
        site, record = self.exchange_context(challenge_id, jwk, encoded_proof)
        if not isinstance(published, dict) or set(published) != set(record) or published != record:
            raise Denied("site_proof_mismatch", 403)
        with self.store.transaction() as db:
            # This budget is charged only after proof of control of the enrolled
            # origin. Anonymous initial challenges cannot consume it.
            self.authority.rate_limit("site-verified:" + site.grant_id, 30)
            existing = db.execute("SELECT 1 FROM site_challenges WHERE id=?", (challenge_id,)).fetchone()
            if existing is None:
                db.execute(
                    "INSERT INTO site_challenges(id,grant_id,record,expires) VALUES (?,?,?,?)",
                    (challenge_id, site.grant_id, json.dumps(record), record["expires_at"]),
                )
                db.execute(
                    "INSERT INTO nonces VALUES (?,?,?,?,?)",
                    (
                        hashlib.sha256(record["nonce"].encode()).hexdigest(),
                        record["jkt"],
                        site.subject,
                        "issuance",
                        record["expires_at"],
                    ),
                )
            # An existing pending record with a missing nonce may mean a process
            # stopped after issuance committed. Never recreate that consumed nonce.
            db.execute("DELETE FROM site_challenges WHERE expires<?", (time.time() - 60,))
        result = self.authority.issue(
            site.uid,
            site.grant_id,
            jwk,
            encoded_proof,
            token_target=self.authority.config.issuer + "/v1/site/token",
        )
        with self.store.transaction() as db:
            db.execute("UPDATE site_challenges SET consumed=1 WHERE id=?", (challenge_id,))
            self.store.audit(
                "site.verified",
                {
                    "subject": site.subject,
                    "site_id": site.site_id,
                    "identity_adapter": site.identity_adapter,
                    "attestation": get_identity_adapter(site.identity_adapter).attestation,
                },
            )
        return result

    def authorize(self, token, encoded_proof, method, url, tenant, action, audience):
        claims = self.authority.verify_token(token)
        site = self.site_for_grant(claims["grant_id"])
        if (
            audience != self.authority.config.audience
            or tenant != site.tenant
            or action != site.resource_action
            or method != "GET"
            or url != site.origin + site.resource_path
        ):
            raise Denied("resource_not_authorized", 403)
        context = self.authority.authorize(token, encoded_proof, method, url, tenant, action)
        return {
            "subject": context["sub"],
            "tenant": context["tenant"],
            "environment": context["environment"],
            "grant_id": context["grant_id"],
            "action": action,
            "expires_at": context["exp"],
        }
