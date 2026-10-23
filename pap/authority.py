"""Online authorization authority and durable automatic lifecycle controller."""

import hashlib
import json
import re
import secrets
import sqlite3
import time
import uuid
from dataclasses import dataclass

import jwt

from .crypto import (
    Denied,
    external_jwt,
    fresh_key,
    parse_public,
    private_pem,
    public_jwk,
    read_private,
    thumbprint,
    verify_proof,
)
from .storage import Store

TOKEN_TARGET = "http://authority/v0/token"
ACTIONS = {"records.read", "notes.create"}


@dataclass(frozen=True)
class Config:
    issuer: str = "https://pap.local/issuer"
    audience: str = "urn:pap:records-api"
    token_ttl: int = 30
    signing_interval: float = 90
    tls_interval: float = 120
    grant_ttl: float = 3600
    requests_per_minute: int = 120
    proof_age: int = 10
    skew: int = 2
    tick: float = 0.25

    def __post_init__(self):
        if not 4 <= self.token_ttl <= 300 or self.signing_interval < 2 or self.tls_interval < 2:
            raise ValueError("invalid lifecycle interval")
        if self.grant_ttl < 1 or self.requests_per_minute < 1 or not 0.05 <= self.tick <= 5:
            raise ValueError("invalid policy settings")
        if not 1 <= self.proof_age <= 30 or not 0 <= self.skew <= 5:
            raise ValueError("invalid proof timing")


class Authority:
    def __init__(self, store: Store, config: Config, *, signer=None):
        self.store, self.config = store, config
        self.signer = signer
        if (
            signer is not None
            and store.db.execute("SELECT 1 FROM signing_keys WHERE private IS NOT NULL").fetchone()
        ):
            raise ValueError("production signer refuses a database containing local issuer private keys")
        self.maintenance()

    def provision(
        self,
        uid: int,
        *,
        subject: str = "demo-service",
        tenant: str = "demo",
        environment: str = "development",
        grant_id: str = "demo-grant",
        actions: set[str] | None = None,
    ):
        actions = ACTIONS if actions is None else actions
        if not actions or any(not re.fullmatch(r"[a-z][a-z0-9_.:-]{0,79}", action) for action in actions):
            raise ValueError("explicit nonempty action set required")
        # Initialization is insert-only. Restarting never restores a revoked/expired grant.
        with self.store.transaction() as db:
            existing = db.execute("SELECT * FROM workloads WHERE id=? OR uid=?", (subject, uid)).fetchall()
            if existing:
                if len(existing) != 1 or any(
                    existing[0][k] != v
                    for k, v in {
                        "id": subject,
                        "uid": uid,
                        "tenant": tenant,
                        "environment": environment,
                    }.items()
                ):
                    raise ValueError("existing workload binding differs; refusing to rebind")
                return
            db.execute(
                "INSERT INTO workloads(id,uid,tenant,environment) VALUES (?,?,?,?)",
                (subject, uid, tenant, environment),
            )
            db.execute(
                "INSERT INTO grants(id,workload,actions,expires) VALUES (?,?,?,?)",
                (grant_id, subject, json.dumps(sorted(actions)), time.time() + self.config.grant_ttl),
            )
            self.store.audit("workload.provisioned", {"subject": subject, "tenant": tenant})

    def active_key(self):
        return self.store.db.execute("SELECT * FROM signing_keys WHERE state='active'").fetchone()

    def rotate(self, *, force: bool = False):
        if self.signer is not None:
            return self._rotate_external(force=force)
        now = time.time()
        active = self.active_key()
        pending = self.store.db.execute(
            "SELECT * FROM signing_keys WHERE state='pending' ORDER BY created LIMIT 1"
        ).fetchone()
        if not pending and active and not force and now - active["created"] < self.config.signing_interval:
            return
        if pending is None:
            key = fresh_key()
            kid = str(uuid.uuid4())
            # A durable pending entry permits recovery if the process stops before activation.
            with self.store.transaction() as db:
                db.execute(
                    "INSERT INTO signing_keys(kid,private,public,state,created) VALUES (?,?,?,?,?)",
                    (kid, private_pem(key), json.dumps(public_jwk(key)), "pending", now),
                )
                self.store.audit("issuer.prepared", {"kid": kid})
            pending = self.store.db.execute("SELECT * FROM signing_keys WHERE kid=?", (kid,)).fetchone()
        check = jwt.encode({"sub": "readiness"}, read_private(pending["private"]), algorithm="ES256")
        jwt.decode(check, parse_public(json.loads(pending["public"])), algorithms=["ES256"])
        with self.store.transaction() as db:
            # Retain old verification keys at least until the latest issued token expires.
            db.execute(
                "UPDATE signing_keys SET state='draining',retire=MAX(last_exp,?)+? WHERE state='active'",
                (now, self.config.skew),
            )
            db.execute(
                "UPDATE signing_keys SET state='active' WHERE kid=? AND state='pending'", (pending["kid"],)
            )
            self.store.audit("issuer.activated", {"kid": pending["kid"]})

    def _rotate_external(self, *, force: bool = False):
        now = time.time()
        active = self.active_key()
        candidate = self.store.db.execute(
            "SELECT * FROM signing_keys WHERE state IN ('preparing','pending') ORDER BY created LIMIT 1"
        ).fetchone()
        if (
            candidate is None
            and active
            and not force
            and now - active["created"] < self.config.signing_interval
        ):
            return
        if candidate is None:
            kid = str(uuid.uuid4())
            with self.store.transaction() as db:
                db.execute(
                    "INSERT INTO signing_keys(kid,private,public,state,created) VALUES (?,NULL,'{}','preparing',?)",
                    (kid, now),
                )
                self.store.audit("issuer.prepare_requested", {"kid": kid})
            candidate = self.store.db.execute("SELECT * FROM signing_keys WHERE kid=?", (kid,)).fetchone()
        if candidate["state"] == "preparing":
            # Deterministic generation identity makes recovery safe after an uncertain KMS result.
            prepared = self.signer.prepare(candidate["kid"])
            parse_public(prepared.public_jwk)
            with self.store.transaction() as db:
                db.execute(
                    "UPDATE signing_keys SET public=?,provider_ref=?,state='pending' WHERE kid=?",
                    (json.dumps(prepared.public_jwk), prepared.reference, candidate["kid"]),
                )
                self.store.audit("issuer.prepared", {"kid": candidate["kid"], "custody": "external"})
            candidate = self.store.db.execute(
                "SELECT * FROM signing_keys WHERE kid=?", (candidate["kid"],)
            ).fetchone()
        check = external_jwt({"sub": "readiness"}, candidate["kid"], self.signer, candidate["provider_ref"])
        jwt.decode(check, parse_public(json.loads(candidate["public"])), algorithms=["ES256"])
        with self.store.transaction() as db:
            db.execute(
                "UPDATE signing_keys SET state='draining',retire=MAX(last_exp,?)+? WHERE state='active'",
                (now, self.config.skew),
            )
            db.execute(
                "UPDATE signing_keys SET state='active' WHERE kid=? AND state='pending'", (candidate["kid"],)
            )
            self.store.audit("issuer.activated", {"kid": candidate["kid"], "custody": "external"})

    def maintenance(self):
        self.rotate()
        now = time.time()
        with self.store.transaction() as db:
            expired = db.execute("SELECT id FROM grants WHERE enabled=1 AND expires<=?", (now,)).fetchall()
            for row in expired:
                db.execute("UPDATE grants SET enabled=0 WHERE id=?", (row["id"],))
                self.store.audit("grant.expired", {"grant_id": row["id"]})
            retiring = db.execute(
                "SELECT kid FROM signing_keys WHERE state='draining' AND retire<=?", (now,)
            ).fetchall()
            for row in retiring:
                db.execute("UPDATE signing_keys SET state='retired',private=NULL WHERE kid=?", (row["kid"],))
                self.store.audit("issuer.retired", {"kid": row["kid"]})
            db.execute("DELETE FROM nonces WHERE expires<?", (now,))
            db.execute("DELETE FROM proofs WHERE expires<?", (now,))
            db.execute("DELETE FROM buckets WHERE bucket<?", (int(now // 60) - 1,))
        if self.signer is not None:
            for row in self.store.db.execute(
                "SELECT provider_ref FROM signing_keys WHERE state IN ('retired','revoked') AND provider_ref IS NOT NULL"
            ):
                self.signer.retire(row["provider_ref"])

    def workload_for_uid(self, uid: int):
        row = self.store.db.execute("SELECT * FROM workloads WHERE uid=?", (uid,)).fetchone()
        if row is None or not row["enabled"]:
            raise Denied("workload_not_authorized", 403)
        return row

    def grant_for(self, subject: str, grant_id: str):
        row = self.store.db.execute(
            "SELECT * FROM grants WHERE id=? AND workload=?", (grant_id, subject)
        ).fetchone()
        if row is None or not row["enabled"] or row["expires"] <= time.time():
            raise Denied("grant_not_authorized", 403)
        return row

    def new_nonce(self, jkt: str, subject: str, kind: str, lifetime: float):
        value = secrets.token_urlsafe(32)
        self.store.db.execute(
            "INSERT INTO nonces VALUES (?,?,?,?,?)",
            (hashlib.sha256(value.encode()).hexdigest(), jkt, subject, kind, time.time() + lifetime),
        )
        return value

    def challenge(self, uid: int, jwk: dict):
        workload = self.workload_for_uid(uid)
        # Fail before minting nonces for a workload without a usable grant.
        if not self.store.db.execute(
            "SELECT 1 FROM grants WHERE workload=? AND enabled=1 AND expires>?", (workload["id"], time.time())
        ).fetchone():
            raise Denied("grant_not_authorized", 403)
        jkt = thumbprint(jwk)
        count = self.store.db.execute(
            "SELECT count(*) FROM nonces WHERE kind='issuance' AND subject=? AND expires>?",
            (workload["id"], time.time()),
        ).fetchone()[0]
        if count >= 20:
            raise Denied("too_many_challenges", 429)
        return {"nonce": self.new_nonce(jkt, workload["id"], "issuance", 15)}

    def consume(self, claims: dict, jkt: str, subject: str, kind: str):
        now = time.time()
        nonce = self.store.db.execute(
            "SELECT * FROM nonces WHERE digest=?", (hashlib.sha256(claims["nonce"].encode()).hexdigest(),)
        ).fetchone()
        if (
            nonce is None
            or nonce["expires"] <= now
            or any(nonce[k] != v for k, v in {"jkt": jkt, "subject": subject, "kind": kind}.items())
        ):
            raise Denied("invalid_nonce")
        try:
            self.store.db.execute(
                "INSERT INTO proofs VALUES (?,?,?)",
                (jkt, claims["jti"], max(now, claims["iat"]) + self.config.proof_age + self.config.skew + 1),
            )
        except sqlite3.IntegrityError as exc:
            raise Denied("proof_replayed") from exc
        if kind == "issuance":
            self.store.db.execute("DELETE FROM nonces WHERE digest=?", (nonce["digest"],))

    def issue(
        self, uid: int, grant_id: str, jwk: dict, encoded_proof: str, *, token_target: str = TOKEN_TARGET
    ):
        jkt = thumbprint(jwk)
        claims, _ = verify_proof(
            encoded_proof,
            "POST",
            token_target,
            expected_jkt=jkt,
            max_age=self.config.proof_age,
            skew=self.config.skew,
        )
        with self.store.transaction() as db:
            workload = self.workload_for_uid(uid)
            grant = self.grant_for(workload["id"], grant_id)
            self.consume(claims, jkt, workload["id"], "issuance")
            self.rate_limit("issue:" + workload["id"], 30)
            now = int(time.time())
            exp = min(now + self.config.token_ttl, int(grant["expires"]))
            if exp <= now:
                raise Denied("grant_not_authorized", 403)
            key = self.active_key()
            if key is None:
                raise Denied("issuer_unavailable", 503)
            token_claims = {
                "iss": self.config.issuer,
                "aud": self.config.audience,
                "sub": workload["id"],
                "client_id": workload["id"],
                "iat": now,
                "exp": exp,
                "jti": str(uuid.uuid4()),
                "cnf": {"jkt": jkt},
                "tenant": workload["tenant"],
                "environment": workload["environment"],
                "grant_id": grant["id"],
                "epoch": workload["epoch"],
                "scope": " ".join(json.loads(grant["actions"])),
            }
            if self.signer is not None:
                if key["private"] is not None or not key["provider_ref"]:
                    raise Denied("signer_custody_invalid", 503)
                token = external_jwt(token_claims, key["kid"], self.signer, key["provider_ref"])
                jwt.decode(
                    token,
                    parse_public(json.loads(key["public"])),
                    algorithms=["ES256"],
                    audience=self.config.audience,
                    issuer=self.config.issuer,
                )
            else:
                token = jwt.encode(
                    token_claims,
                    read_private(key["private"]),
                    algorithm="ES256",
                    headers={"typ": "at+jwt", "kid": key["kid"]},
                )
            db.execute("UPDATE signing_keys SET last_exp=MAX(last_exp,?) WHERE kid=?", (exp, key["kid"]))
            nonce = self.new_nonce(
                jkt, workload["id"], "resource", self.config.token_ttl + self.config.skew + 1
            )
            self.store.audit("credential.issued", {"subject": workload["id"], "kid": key["kid"], "jkt": jkt})
        return {
            "access_token": token,
            "token_type": "DPoP",
            "expires_at": exp,
            "expires_in": exp - time.time(),
            "dpop_nonce": nonce,
            "tenant": workload["tenant"],
            "environment": workload["environment"],
        }

    def verify_token(self, token: str):
        if not isinstance(token, str) or len(token) > 4096:
            raise Denied("invalid_token")
        try:
            header = jwt.get_unverified_header(token)
            if set(header) != {"alg", "typ", "kid"} or header["alg"] != "ES256" or header["typ"] != "at+jwt":
                raise Denied("invalid_token_header")
            if not isinstance(header["kid"], str) or len(header["kid"]) > 64:
                raise Denied("invalid_token_header")
            key = self.store.db.execute("SELECT * FROM signing_keys WHERE kid=?", (header["kid"],)).fetchone()
            now = time.time()
            if (
                key is None
                or key["state"] not in ("active", "draining")
                or (key["state"] == "draining" and key["retire"] <= now)
            ):
                raise Denied("issuer_key_not_authorized")
            fields = {
                "iss",
                "aud",
                "sub",
                "client_id",
                "iat",
                "exp",
                "jti",
                "cnf",
                "tenant",
                "environment",
                "grant_id",
                "epoch",
                "scope",
            }
            claims = jwt.decode(
                token,
                parse_public(json.loads(key["public"])),
                algorithms=["ES256"],
                issuer=self.config.issuer,
                audience=self.config.audience,
                options={"require": sorted(fields), "strict_aud": True},
            )
            if set(claims) != fields or any(
                not isinstance(claims[k], str)
                for k in (
                    "iss",
                    "aud",
                    "sub",
                    "client_id",
                    "jti",
                    "tenant",
                    "environment",
                    "grant_id",
                    "scope",
                )
            ):
                raise Denied("invalid_token_claims")
            if any(type(claims[k]) is not int for k in ("iat", "exp", "epoch")):
                raise Denied("invalid_token_claims")
            if not 0 < claims["exp"] - claims["iat"] <= self.config.token_ttl:
                raise Denied("invalid_token_lifetime")
            if claims["iat"] < key["created"] - 1 or (
                key["state"] == "draining" and claims["exp"] > key["last_exp"]
            ):
                raise Denied("invalid_token_lifetime")
            if not isinstance(claims["cnf"], dict) or set(claims["cnf"]) != {"jkt"}:
                raise Denied("invalid_token_binding")
            jkt = claims["cnf"]["jkt"]
            if not isinstance(jkt, str) or len(jkt) != 43:
                raise Denied("invalid_token_binding")
            uuid.UUID(claims["jti"])
            return claims
        except (jwt.PyJWTError, KeyError, ValueError, TypeError) as exc:
            raise Denied("invalid_token") from exc

    def authorize(self, token: str, encoded_proof: str, method: str, url: str, tenant: str, action: str):
        claims = self.verify_token(token)
        p, jkt = verify_proof(
            encoded_proof,
            method,
            url,
            token=token,
            expected_jkt=claims["cnf"]["jkt"],
            max_age=self.config.proof_age,
            skew=self.config.skew,
        )
        with self.store.transaction():
            # Recheck issuer status under the admission lock after cryptographic validation.
            # A concurrent revocation must commit either before this decision or after it.
            claims = self.verify_token(token)
            workload = self.store.db.execute(
                "SELECT * FROM workloads WHERE id=?", (claims["sub"],)
            ).fetchone()
            if workload is None or not workload["enabled"] or workload["epoch"] != claims["epoch"]:
                raise Denied("workload_not_authorized", 403)
            grant = self.grant_for(workload["id"], claims["grant_id"])
            for field in ("tenant", "environment"):
                if claims[field] != workload[field]:
                    raise Denied("policy_mismatch", 403)
            if claims["client_id"] != workload["id"] or tenant != workload["tenant"]:
                raise Denied("tenant_not_authorized", 403)
            if action not in claims["scope"].split() or action not in json.loads(grant["actions"]):
                raise Denied("action_not_authorized", 403)
            self.consume(p, jkt, workload["id"], "resource")
            self.rate_limit(workload["id"], self.config.requests_per_minute)
        # Internal authorization metadata, never part of the wire JWT.
        claims["_issuer_kid"] = jwt.get_unverified_header(token)["kid"]
        return claims

    def rate_limit(self, subject: str, maximum: int):
        bucket = int(time.time() // 60)
        self.store.db.execute(
            "INSERT INTO buckets VALUES (?,?,1) ON CONFLICT(subject,bucket) DO UPDATE SET used=used+1",
            (subject, bucket),
        )
        count = self.store.db.execute(
            "SELECT used FROM buckets WHERE subject=? AND bucket=?", (subject, bucket)
        ).fetchone()[0]
        if count > maximum:
            raise Denied("rate_limited", 429)

    def event(self, event_id: str, kind: str, subject: str, reason: str):
        if kind not in ("revoke_workload", "revoke_issuer_key") or reason not in ("operator", "compromised"):
            raise Denied("invalid_event", 400)
        digest = hashlib.sha256(json.dumps([kind, subject, reason]).encode()).hexdigest()
        with self.store.transaction() as db:
            prior = db.execute("SELECT * FROM events WHERE id=?", (event_id,)).fetchone()
            if prior:
                if prior["digest"] != digest:
                    raise Denied("event_conflict", 409)
                return json.loads(prior["response"])
            if kind == "revoke_workload":
                row = db.execute("SELECT enabled FROM workloads WHERE id=?", (subject,)).fetchone()
                if row is None:
                    raise Denied("unknown_workload", 404)
                db.execute(
                    "UPDATE workloads SET enabled=0,epoch=epoch+1 WHERE id=? AND enabled=1", (subject,)
                )
                db.execute("UPDATE grants SET enabled=0 WHERE workload=?", (subject,))
            else:
                row = db.execute("SELECT kid FROM signing_keys WHERE kid=?", (subject,)).fetchone()
                if row is None:
                    raise Denied("unknown_issuer_key", 404)
                db.execute("UPDATE signing_keys SET state='revoked',private=NULL WHERE kid=?", (subject,))
            response = {"event_id": event_id, "status": "revoked", "kind": kind, "subject": subject}
            db.execute("INSERT INTO events VALUES (?,?,?)", (event_id, digest, json.dumps(response)))
            self.store.audit("access.revoked", {"kind": kind, "subject": subject, "reason": reason})
        if kind == "revoke_issuer_key":
            self.rotate()
        return response

    def create_note(self, claims: dict, operation_key: str, message: str):
        digest = hashlib.sha256(message.encode()).hexdigest()
        subject, tenant = claims["sub"], claims["tenant"]
        with self.store.transaction() as db:
            signer = db.execute(
                "SELECT * FROM signing_keys WHERE kid=?", (claims.get("_issuer_kid"),)
            ).fetchone()
            if (
                signer is None
                or signer["state"] not in ("active", "draining")
                or (signer["state"] == "draining" and signer["retire"] <= time.time())
            ):
                raise Denied("issuer_key_not_authorized")
            live = db.execute("SELECT * FROM workloads WHERE id=?", (subject,)).fetchone()
            if live is None or not live["enabled"] or live["epoch"] != claims["epoch"]:
                raise Denied("workload_not_authorized", 403)
            grant = self.grant_for(subject, claims["grant_id"])
            if (
                tenant != live["tenant"]
                or claims["environment"] != live["environment"]
                or "notes.create" not in json.loads(grant["actions"])
                or "notes.create" not in claims["scope"].split()
            ):
                raise Denied("action_not_authorized", 403)
            # Check both admission and commit. A revocation between them must prevent the mutation.
            self.verify_token_expiry(claims)
            prior = db.execute(
                "SELECT * FROM operations WHERE subject=? AND tenant=? AND operation_key=?",
                (subject, tenant, operation_key),
            ).fetchone()
            if prior:
                if prior["digest"] != digest:
                    raise Denied("idempotency_conflict", 409)
                return json.loads(prior["response"])
            note_id = str(uuid.uuid4())
            response = {"id": note_id, "tenant": tenant, "created": True}
            db.execute(
                "INSERT INTO notes VALUES (?,?,?,?,?)", (note_id, tenant, subject, message, time.time())
            )
            db.execute(
                "INSERT INTO operations VALUES (?,?,?,?,?)",
                (subject, tenant, operation_key, digest, json.dumps(response)),
            )
            self.store.audit("note.created", {"subject": subject, "tenant": tenant, "note_id": note_id})
        return response

    @staticmethod
    def verify_token_expiry(claims: dict):
        if claims["exp"] <= time.time():
            raise Denied("invalid_token")

    def status(self):
        db = self.store.db
        return {
            "profile": "PAP-local-0.1",
            "version": "0.1-experimental",
            "issuer": self.config.issuer,
            "audience": self.config.audience,
            "token_ttl_seconds": self.config.token_ttl,
            "workloads": [
                dict(r) for r in db.execute("SELECT id,uid,tenant,environment,enabled,epoch FROM workloads")
            ],
            "grants": [dict(r) for r in db.execute("SELECT id,workload,expires,enabled FROM grants")],
            "signing_keys": [
                dict(r) for r in db.execute("SELECT kid,state,created,retire FROM signing_keys")
            ],
            "audit_events": db.execute("SELECT count(*) FROM audit").fetchone()[0],
        }
