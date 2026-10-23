"""Adversarial checks against credential theft, replay, and lifecycle bypasses."""

import copy
import json
import os
import ssl
import tempfile
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

import aiohttp
import jwt
import pytest

from pap.agent import Agent, Client
from pap.authority import TOKEN_TARGET, Authority, Config
from pap.crypto import (
    Denied,
    fresh_key,
    private_pem,
    proof,
    public_jwk,
    read_private,
    thumbprint,
    verify_proof,
)
from pap.local import clean_socket
from pap.runtime import Runtime
from pap.storage import Store

API_URL = "https://api.example.test/v1/notes"
NONCE = "server-issued-nonce-for-tests"


def signed_proof(key, claims, **header_changes):
    headers = {"typ": "dpop+jwt", "jwk": public_jwk(key)}
    headers.update(header_changes)
    return jwt.encode(claims, key, algorithm="ES256", headers=headers)


def proof_claims(now=None):
    return {
        "jti": "unique-request-id-for-tests",
        "htm": "POST",
        "htu": API_URL,
        "iat": int(time.time() if now is None else now),
        "nonce": NONCE,
    }


def test_stolen_token_cannot_be_used_with_attacker_proof_key():
    legitimate, attacker = fresh_key(), fresh_key()
    token = "stolen-access-token"
    encoded = proof(attacker, "POST", API_URL, NONCE, token)
    with pytest.raises(Denied, match="proof_key_mismatch"):
        verify_proof(
            encoded,
            "POST",
            API_URL,
            token=token,
            expected_jkt=thumbprint(public_jwk(legitimate)),
        )


def test_proof_cannot_be_rebound_to_another_access_token():
    key = fresh_key()
    encoded = proof(key, "POST", API_URL, NONCE, "original-token")
    with pytest.raises(Denied, match="token_hash_mismatch"):
        verify_proof(encoded, "POST", API_URL, token="different-token")


@pytest.mark.parametrize(
    "method,url",
    [
        ("GET", API_URL),
        ("POST", "https://attacker.example.test/v1/notes"),
        ("POST", "https://api.example.test/v1/admin"),
        ("POST", "http://api.example.test/v1/notes"),
    ],
)
def test_proof_cannot_be_rebound_to_another_request(method, url):
    encoded = proof(fresh_key(), "POST", API_URL, NONCE)
    with pytest.raises(Denied, match="proof_target_mismatch"):
        verify_proof(encoded, method, url)


@pytest.mark.parametrize("offset", [-11, 3])
def test_expired_and_future_dated_proofs_are_rejected(offset):
    now = 2_000_000_000
    encoded = proof(fresh_key(), "POST", API_URL, NONCE, now=now + offset)
    with pytest.raises(Denied, match="stale_proof"):
        verify_proof(encoded, "POST", API_URL, now=now)


@pytest.mark.parametrize(
    "extra",
    [
        {"jku": "https://attacker.example.test/jwks"},
        {"x5u": "https://attacker.example.test/cert"},
        {"crit": ["injected"]},
        {"kid": "../../private-key.pem"},
        {"typ": "JWT"},
    ],
)
def test_proof_rejects_unrecognized_or_unsafe_jose_headers(extra):
    key = fresh_key()
    encoded = signed_proof(key, proof_claims(), **extra)
    with pytest.raises(Denied, match="invalid_proof"):
        verify_proof(encoded, "POST", API_URL)


def test_proof_rejects_symmetric_algorithm_confusion():
    key = fresh_key()
    encoded = jwt.encode(
        proof_claims(),
        "attacker-controlled-hmac-key-at-least-32-bytes",
        algorithm="HS256",
        headers={"typ": "dpop+jwt", "jwk": public_jwk(key)},
    )
    with pytest.raises(Denied, match="invalid_proof_header"):
        verify_proof(encoded, "POST", API_URL)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda jwk: {**jwk, "d": "private-key-material"},
        lambda jwk: {**jwk, "crv": "P-384"},
        lambda jwk: {**jwk, "kty": "oct", "k": "c2VjcmV0"},
        lambda jwk: {**jwk, "x": "A" * 43, "y": "A" * 43},
        lambda jwk: {**jwk, "x": jwk["x"] + "="},
        lambda jwk: {**jwk, "x": None},
        lambda jwk: {**jwk, "x": "!" * 43},
    ],
)
def test_proof_rejects_hostile_jwk(mutation):
    key = fresh_key()
    jwk = mutation(copy.deepcopy(public_jwk(key)))
    encoded = signed_proof(key, proof_claims(), jwk=jwk)
    with pytest.raises(Denied, match="invalid_public_key"):
        verify_proof(encoded, "POST", API_URL)


@pytest.mark.parametrize(
    "claim,value",
    [
        ("iat", True),
        ("iat", str(int(time.time()))),
        ("nonce", "short"),
        ("jti", "short"),
        ("jti", ["not", "a", "string"]),
    ],
)
def test_proof_rejects_invalid_claim_types_or_lengths(claim, value):
    key = fresh_key()
    claims = proof_claims()
    claims[claim] = value
    with pytest.raises(Denied):
        verify_proof(signed_proof(key, claims), "POST", API_URL)


def test_proof_rejects_oversized_input_before_jwt_parsing():
    with pytest.raises(Denied, match="invalid_proof"):
        verify_proof("A" * 4097, "POST", API_URL)


@pytest.fixture
def authority(tmp_path):
    state = tmp_path / "authority"
    state.mkdir(mode=0o700)
    store = Store(state / "state.sqlite")
    instance = Authority(store, Config())
    instance.provision(os.getuid())
    try:
        yield instance
    finally:
        store.close()


def issue(authority, key=None, uid=None):
    key = key or fresh_key()
    uid = os.getuid() if uid is None else uid
    jwk = public_jwk(key)
    challenge = authority.challenge(uid, jwk)
    credential = authority.issue(
        uid,
        "demo-grant",
        jwk,
        proof(key, "POST", TOKEN_TARGET, challenge["nonce"]),
    )
    return key, credential


def authorize(authority, key, credential, *, token=None, tenant="demo", action="records.read"):
    token = credential["access_token"] if token is None else token
    return authority.authorize(
        token,
        proof(key, "GET", API_URL, credential["dpop_nonce"], token),
        "GET",
        API_URL,
        tenant,
        action,
    )


def mint_altered_token(authority, credential, **changes):
    claims = jwt.decode(credential["access_token"], options={"verify_signature": False})
    claims.update(changes)
    active = authority.active_key()
    return jwt.encode(
        claims,
        read_private(active["private"]),
        algorithm="ES256",
        headers={"typ": "at+jwt", "kid": active["kid"]},
    )


def test_legitimate_access_then_replayed_proof_is_rejected(authority):
    key, credential = issue(authority)
    token = credential["access_token"]
    encoded = proof(key, "GET", API_URL, credential["dpop_nonce"], token)
    claims = authority.authorize(token, encoded, "GET", API_URL, "demo", "records.read")
    assert claims["sub"] == "demo-service"
    with pytest.raises(Denied, match="proof_replayed"):
        authority.authorize(token, encoded, "GET", API_URL, "demo", "records.read")


def test_concurrent_replay_admits_exactly_one_request(authority):
    key, credential = issue(authority)
    token = credential["access_token"]
    encoded = proof(key, "GET", API_URL, credential["dpop_nonce"], token)
    database = authority.store.db.execute("PRAGMA database_list").fetchone()[2]
    ready = threading.Barrier(2)

    def attempt():
        local = Store(Path(database))
        try:
            instance = Authority(local, authority.config)
            ready.wait(timeout=5)
            try:
                instance.authorize(token, encoded, "GET", API_URL, "demo", "records.read")
                return "accepted"
            except Denied as exc:
                return exc.code
        finally:
            local.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: attempt(), range(2)))
    assert sorted(results) == ["accepted", "proof_replayed"]


def test_issuance_nonce_is_single_use(authority):
    key = fresh_key()
    jwk = public_jwk(key)
    nonce = authority.challenge(os.getuid(), jwk)["nonce"]
    authority.issue(os.getuid(), "demo-grant", jwk, proof(key, "POST", TOKEN_TARGET, nonce))
    with pytest.raises(Denied, match="invalid_nonce"):
        authority.issue(os.getuid(), "demo-grant", jwk, proof(key, "POST", TOKEN_TARGET, nonce))


def test_nonce_cannot_be_used_by_another_proof_key(authority):
    legitimate, attacker = fresh_key(), fresh_key()
    nonce = authority.challenge(os.getuid(), public_jwk(legitimate))["nonce"]
    with pytest.raises(Denied, match="invalid_nonce"):
        authority.issue(
            os.getuid(),
            "demo-grant",
            public_jwk(attacker),
            proof(attacker, "POST", TOKEN_TARGET, nonce),
        )


def test_unknown_os_identity_cannot_enroll(authority):
    with pytest.raises(Denied, match="workload_not_authorized"):
        authority.challenge(os.getuid() + 1, public_jwk(fresh_key()))


@pytest.mark.parametrize(
    "changes",
    [
        {"tenant": "other-customer"},
        {"environment": "production"},
        {"client_id": "other-service"},
        {"sub": "other-service"},
        {"aud": "urn:attacker:api"},
        {"aud": ["urn:pap:records-api", "urn:attacker:api"]},
        {"iss": "https://attacker.example.test/issuer"},
        {"epoch": 0},
        {"grant_id": "different-grant"},
        {"scope": "administrator"},
        {"exp": int(time.time()) - 1},
        {"iat": int(time.time()) + 60, "exp": int(time.time()) + 90},
        {"iat": True},
        {"epoch": True},
        {"cnf": {"jkt": "short"}},
    ],
)
def test_signed_tokens_still_require_strict_policy_claims(authority, changes):
    key, credential = issue(authority)
    token = mint_altered_token(authority, credential, **changes)
    with pytest.raises(Denied):
        authorize(authority, key, credential, token=token)


def test_route_tenant_must_match_authorized_tenant(authority):
    key, credential = issue(authority)
    with pytest.raises(Denied, match="tenant_not_authorized"):
        authorize(authority, key, credential, tenant="other-customer")


def test_revoked_workload_cannot_use_existing_token_or_renew(authority):
    key, credential = issue(authority)
    next_nonce = authority.challenge(os.getuid(), public_jwk(key))["nonce"]
    authority.event(str(uuid.uuid4()), "revoke_workload", "demo-service", "compromised")
    with pytest.raises(Denied, match="workload_not_authorized"):
        authorize(authority, key, credential)
    with pytest.raises(Denied, match="workload_not_authorized"):
        authority.issue(
            os.getuid(),
            "demo-grant",
            public_jwk(key),
            proof(key, "POST", TOKEN_TARGET, next_nonce),
        )
    with pytest.raises(Denied, match="workload_not_authorized"):
        authority.challenge(os.getuid(), public_jwk(fresh_key()))


def test_reprovisioning_cannot_restore_revoked_workload(authority):
    authority.event(str(uuid.uuid4()), "revoke_workload", "demo-service", "operator")
    authority.provision(os.getuid())
    with pytest.raises(Denied, match="workload_not_authorized"):
        authority.challenge(os.getuid(), public_jwk(fresh_key()))


def test_restart_preserves_revocation_and_event_deduplication(authority):
    key, credential = issue(authority)
    event_id = str(uuid.uuid4())
    expected = authority.event(event_id, "revoke_workload", "demo-service", "compromised")
    database = authority.store.db.execute("PRAGMA database_list").fetchone()[2]
    restarted_store = Store(Path(database))
    try:
        restarted = Authority(restarted_store, authority.config)
        restarted.provision(os.getuid())
        assert restarted.event(event_id, "revoke_workload", "demo-service", "compromised") == expected
        with pytest.raises(Denied, match="workload_not_authorized"):
            authorize(restarted, key, credential)
        with pytest.raises(Denied, match="workload_not_authorized"):
            restarted.challenge(os.getuid(), public_jwk(fresh_key()))
    finally:
        restarted_store.close()


def test_event_id_reuse_with_different_payload_is_rejected(authority):
    event_id = str(uuid.uuid4())
    authority.event(event_id, "revoke_workload", "demo-service", "operator")
    with pytest.raises(Denied, match="event_conflict") as error:
        authority.event(event_id, "revoke_workload", "demo-service", "compromised")
    assert error.value.status == 409
    epoch = authority.store.db.execute("SELECT epoch FROM workloads WHERE id='demo-service'").fetchone()[0]
    assert epoch == 2


def test_rotation_preserves_valid_old_tokens_until_retirement(authority, monkeypatch):
    key, credential = issue(authority)
    old_kid = jwt.get_unverified_header(credential["access_token"])["kid"]
    authority.rotate(force=True)
    assert authority.active_key()["kid"] != old_kid
    authorize(authority, key, credential)
    old = authority.store.db.execute("SELECT * FROM signing_keys WHERE kid=?", (old_kid,)).fetchone()
    assert old["state"] == "draining"
    assert old["retire"] >= credential["expires_at"]
    monkeypatch.setattr("pap.authority.time.time", lambda: old["retire"] + 1)
    authority.maintenance()
    retired = authority.store.db.execute(
        "SELECT state,private FROM signing_keys WHERE kid=?", (old_kid,)
    ).fetchone()
    assert tuple(retired) == ("retired", None)
    with pytest.raises(Denied, match="issuer_key_not_authorized"):
        authority.verify_token(credential["access_token"])


def test_compromised_signing_key_is_rejected_immediately_and_replaced(authority):
    key, credential = issue(authority)
    compromised = dict(authority.active_key())
    authority.event(str(uuid.uuid4()), "revoke_issuer_key", compromised["kid"], "compromised")
    assert authority.active_key()["kid"] != compromised["kid"]
    with pytest.raises(Denied, match="issuer_key_not_authorized"):
        authorize(authority, key, credential)
    claims = jwt.decode(credential["access_token"], options={"verify_signature": False})
    claims["jti"] = str(uuid.uuid4())
    forged = jwt.encode(
        claims,
        read_private(compromised["private"]),
        algorithm="ES256",
        headers={"typ": "at+jwt", "kid": compromised["kid"]},
    )
    with pytest.raises(Denied, match="issuer_key_not_authorized"):
        authorize(authority, key, credential, token=forged)
    replacement_key, replacement = issue(authority)
    authorize(authority, replacement_key, replacement)


def test_restart_recovers_prepared_signing_key_before_issuing_tokens(authority):
    prepared = fresh_key()
    pending_id = str(uuid.uuid4())
    authority.store.db.execute(
        "INSERT INTO signing_keys(kid,private,public,state,created) VALUES (?,?,?,?,?)",
        (pending_id, private_pem(prepared), json.dumps(public_jwk(prepared)), "pending", time.time()),
    )
    restarted = Authority(authority.store, authority.config)
    assert restarted.active_key()["kid"] == pending_id
    key, credential = issue(restarted)
    assert jwt.get_unverified_header(credential["access_token"])["kid"] == pending_id
    authorize(restarted, key, credential)


def test_idempotent_write_reuses_response_and_rejects_different_payload(authority):
    key, credential = issue(authority)
    claims = authorize(authority, key, credential, action="notes.create")
    operation = str(uuid.uuid4())
    first = authority.create_note(claims, operation, "approved note")
    assert authority.create_note(claims, operation, "approved note") == first
    with pytest.raises(Denied, match="idempotency_conflict") as error:
        authority.create_note(claims, operation, "different note")
    assert error.value.status == 409
    assert authority.store.db.execute("SELECT count(*) FROM notes").fetchone()[0] == 1


def test_revocation_between_authorization_and_write_prevents_commit(authority):
    key, credential = issue(authority)
    claims = authorize(authority, key, credential, action="notes.create")
    authority.event(str(uuid.uuid4()), "revoke_workload", "demo-service", "compromised")
    with pytest.raises(Denied):
        authority.create_note(claims, str(uuid.uuid4()), "must not be committed")
    assert authority.store.db.execute("SELECT count(*) FROM notes").fetchone()[0] == 0


def test_expired_grant_between_authorization_and_write_prevents_commit(authority):
    key, credential = issue(authority)
    claims = authorize(authority, key, credential, action="notes.create")
    authority.store.db.execute("UPDATE grants SET expires=? WHERE id='demo-grant'", (time.time() - 1,))
    with pytest.raises(Denied):
        authority.create_note(claims, str(uuid.uuid4()), "must not be committed")
    assert authority.store.db.execute("SELECT count(*) FROM notes").fetchone()[0] == 0


def test_expired_grant_blocks_current_access_and_fresh_enrollment(authority):
    key, credential = issue(authority)
    pending = authority.challenge(os.getuid(), public_jwk(key))["nonce"]
    authority.store.db.execute("UPDATE grants SET expires=?", (time.time() - 1,))
    with pytest.raises(Denied, match="grant_not_authorized"):
        authorize(authority, key, credential)
    with pytest.raises(Denied, match="grant_not_authorized"):
        authority.issue(
            os.getuid(),
            "demo-grant",
            public_jwk(key),
            proof(key, "POST", TOKEN_TARGET, pending),
        )
    authority.maintenance()
    authority.provision(os.getuid())
    with pytest.raises(Denied, match="grant_not_authorized"):
        authority.challenge(os.getuid(), public_jwk(fresh_key()))


def test_parallel_idempotent_writes_commit_only_one_note(authority):
    key, credential = issue(authority)
    claims = authorize(authority, key, credential, action="notes.create")
    database = authority.store.db.execute("PRAGMA database_list").fetchone()[2]
    operation_key = str(uuid.uuid4())
    ready = threading.Barrier(2)

    def attempt():
        local = Store(Path(database))
        try:
            instance = Authority(local, authority.config)
            ready.wait(timeout=5)
            return instance.create_note(claims, operation_key, "same operation")
        finally:
            local.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: attempt(), range(2)))
    assert results[0] == results[1]
    assert authority.store.db.execute("SELECT count(*) FROM notes").fetchone()[0] == 1


def test_parallel_requests_cannot_exceed_authorization_quota(authority):
    key, credential = issue(authority)
    token = credential["access_token"]
    proofs = [proof(key, "GET", API_URL, credential["dpop_nonce"], token) for _ in range(2)]
    database = authority.store.db.execute("PRAGMA database_list").fetchone()[2]
    config = replace(authority.config, requests_per_minute=1)
    ready = threading.Barrier(2)

    def attempt(encoded):
        local = Store(Path(database))
        try:
            instance = Authority(local, config)
            ready.wait(timeout=5)
            try:
                instance.authorize(token, encoded, "GET", API_URL, "demo", "records.read")
                return "accepted"
            except Denied as exc:
                return exc.code
        finally:
            local.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(attempt, proofs))
    assert sorted(results) == ["accepted", "rate_limited"]


@pytest.fixture
async def running():
    with tempfile.TemporaryDirectory(prefix="pap-security-", dir="/private/tmp") as name:
        state = Path(name)
        runtime = await Runtime(state).start()
        agent = Agent(state)
        try:
            await agent.start()
            yield runtime, agent
        finally:
            await agent.close()
            await runtime.close()


@pytest.mark.parametrize("path", ["/v0/bootstrap", "/v0/challenge", "/v0/token"])
async def test_authority_rejects_unprovisioned_peer_uid(running, monkeypatch, path):
    runtime, _ = running
    monkeypatch.setattr("pap.runtime.peer_uid", lambda request: os.getuid() + 1)
    headers = {"X-UID": str(os.getuid()), "X-Workload-ID": "demo-service"}
    key = fresh_key()
    payload = {"jwk": public_jwk(key)}
    if path == "/v0/token":
        payload["grant_id"] = "demo-grant"
        headers["DPoP"] = proof(key, "POST", TOKEN_TARGET, NONCE)
    async with aiohttp.ClientSession(
        connector=aiohttp.UnixConnector(path=str(runtime.state / "authority.sock")),
        trust_env=False,
    ) as session:
        method = "GET" if path == "/v0/bootstrap" else "POST"
        async with session.request(
            method, "http://authority" + path, json=payload, headers=headers
        ) as response:
            data = await response.json()
            assert response.status == 403
            assert data["error"] == "workload_not_authorized"


@pytest.mark.parametrize("path", ["/v0/status", "/v0/audit", "/v0/events"])
async def test_admin_socket_rejects_different_peer_uid(running, monkeypatch, path):
    runtime, _ = running
    monkeypatch.setattr("pap.runtime.peer_uid", lambda request: os.getuid() + 1)
    async with aiohttp.ClientSession(
        connector=aiohttp.UnixConnector(path=str(runtime.state / "admin.sock")),
        trust_env=False,
    ) as session:
        method = "POST" if path == "/v0/events" else "GET"
        async with session.request(method, "http://admin" + path, json={}) as response:
            assert response.status == 403
            assert (await response.json())["error"] == "admin_not_authorized"


@pytest.mark.parametrize("path", ["/v0/status", "/v0/records", "/v0/notes"])
async def test_agent_socket_rejects_different_peer_uid(running, monkeypatch, path):
    runtime, _ = running
    monkeypatch.setattr("pap.agent.peer_uid", lambda request: os.getuid() + 1)
    async with aiohttp.ClientSession(
        connector=aiohttp.UnixConnector(path=str(runtime.state / "agent.sock")),
        trust_env=False,
    ) as session:
        method = "POST" if path == "/v0/notes" else "GET"
        async with session.request(
            method,
            "http://agent" + path,
            json={"message": "should be denied"},
            headers={"Idempotency-Key": str(uuid.uuid4()), "X-UID": str(os.getuid())},
        ) as response:
            assert response.status == 403
            assert (await response.json())["error"] == "local_application_not_authorized"


async def test_agent_rejects_caller_supplied_targets_and_credentials(running):
    runtime, agent = running
    client = Client(runtime.state / "agent.sock")
    with pytest.raises(Denied, match="invalid_request"):
        await client.request(
            "POST",
            "/v0/notes",
            headers={"Idempotency-Key": str(uuid.uuid4())},
            json={
                "message": "note",
                "url": "https://attacker.example.test/",
                "headers": {"Authorization": "secret"},
            },
        )
    with pytest.raises(Denied, match="operation_not_supported"):
        await agent.invoke("GET", "https://attacker.example.test/")
    assert runtime.store.db.execute("SELECT count(*) FROM notes").fetchone()[0] == 0


async def test_agent_rejects_remote_or_unencrypted_bootstrap_origin(running, monkeypatch):
    _, agent = running
    original = agent.local

    async def substituted(method, path, **kwargs):
        result = await original(method, path, **kwargs)
        if path == "/v0/bootstrap":
            result["origin"] = "http://attacker.example.test:80"
        return result

    monkeypatch.setattr(agent, "local", substituted)
    with pytest.raises(Denied, match="invalid_host_origin"):
        await agent.invoke("GET", "records")


async def test_host_headers_cannot_rebind_resource_proof_target(running):
    runtime, _ = running
    key, credential = issue(runtime.authority)
    token = credential["access_token"]
    url = runtime.origin + "/v0/tenants/demo/records"
    context = ssl.create_default_context(cadata=runtime.tls_pem)
    async with aiohttp.ClientSession(trust_env=False) as session:
        headers = {
            "Authorization": "DPoP " + token,
            "DPoP": proof(key, "GET", url, credential["dpop_nonce"], token),
            "Host": "attacker.example.test",
            "X-Forwarded-Host": "attacker.example.test",
            "X-Forwarded-Proto": "http",
        }
        async with session.get(url, headers=headers, ssl=context) as response:
            assert response.status == 200
        headers["DPoP"] = proof(
            key,
            "GET",
            "https://attacker.example.test/v0/tenants/demo/records",
            credential["dpop_nonce"],
            token,
        )
        async with session.get(url, headers=headers, ssl=context) as response:
            assert response.status == 401
            assert (await response.json())["error"] == "proof_target_mismatch"


async def test_endpoint_errors_and_application_status_never_return_credentials(running, caplog):
    runtime, agent = running
    sentinel = "SENSITIVE_SENTINEL_MUST_NOT_BE_RETURNED"
    url = runtime.origin + "/v0/tenants/demo/records"
    context = ssl.create_default_context(cadata=runtime.tls_pem)
    async with (
        aiohttp.ClientSession(trust_env=False) as session,
        session.get(url, headers={"Authorization": "Bearer " + sentinel}, ssl=context) as response,
    ):
        data = await response.text()
        assert response.status == 401
        assert sentinel not in data
        assert response.headers["Cache-Control"] == "no-store"
    status = await Client(runtime.state / "agent.sock").request("GET", "/v0/status")
    encoded = json.dumps(status)
    assert agent.credential.token not in encoded
    assert agent.credential.nonce not in encoded
    assert "PRIVATE KEY" not in encoded
    assert sentinel not in caplog.text


def test_private_state_rejects_public_permissions(tmp_path):
    state = tmp_path / "public-state"
    state.mkdir(mode=0o755)
    with pytest.raises(ValueError, match="0700"):
        Store(state / "authority.sqlite")


def test_state_database_symlink_is_never_followed(tmp_path):
    state = tmp_path / "private-state"
    state.mkdir(mode=0o700)
    target = tmp_path / "victim"
    target.write_text("do not overwrite")
    (state / "authority.sqlite").symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        Store(state / "authority.sqlite")
    assert target.read_text() == "do not overwrite"


def test_socket_cleanup_never_removes_regular_file(tmp_path):
    victim = tmp_path / "agent.sock"
    victim.write_text("preserve this file")
    with pytest.raises(ValueError, match="non-socket"):
        clean_socket(victim)
    assert victim.read_text() == "preserve this file"
