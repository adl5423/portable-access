"""Durable authority behavior with a signing service outside its private state."""

import json
import os
import time
import uuid

import jwt
import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from pap.authority import TOKEN_TARGET, Authority, Config
from pap.crypto import Denied, fresh_key, proof, public_jwk
from pap.signers import PreparedKey, SignerError
from pap.storage import Store


class RemoteSigner:
    """Test service whose private keys survive authority/provider restarts only remotely."""

    def __init__(self, keys=None):
        self.keys = {} if keys is None else keys
        self.prepared = []
        self.retired = set()
        self.fail_after_prepare = False
        self.fail_sign = False
        self.corrupt_sign = False

    def prepare(self, generation):
        reference = "remote:" + generation
        self.prepared.append(generation)
        self.keys.setdefault(reference, fresh_key())
        if self.fail_after_prepare:
            raise SignerError("simulated_uncertain_prepare")
        return PreparedKey(reference, public_jwk(self.keys[reference]))

    def sign(self, reference, signing_input):
        if self.fail_sign:
            raise SignerError("simulated_signer_unavailable")
        if reference in self.retired:
            raise SignerError("signer_key_retired")
        if self.corrupt_sign:
            return b"\x00" * 64
        der = self.keys[reference].sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def retire(self, reference):
        self.retired.add(reference)

    def health(self):
        return {"provider": "test-remote"}


def create(tmp_path, provider=None):
    store = Store(tmp_path / "state" / "authority.db")
    provider = RemoteSigner() if provider is None else provider
    authority = Authority(store, Config(signing_interval=86400), signer=provider)
    authority.provision(os.getuid())
    return store, authority, provider


def issue(authority):
    key = fresh_key()
    jwk = public_jwk(key)
    challenge = authority.challenge(os.getuid(), jwk)
    return authority.issue(
        os.getuid(), "demo-grant", jwk, proof(key, "POST", TOKEN_TARGET, challenge["nonce"])
    )["access_token"]


def test_external_mode_never_calls_local_signing_or_persists_private_material(tmp_path, monkeypatch):
    import pap.authority as authority_module

    def forbidden(*args, **kwargs):
        raise AssertionError("local issuer key access must never happen in external mode")

    for name in ("fresh_key", "private_pem", "read_private"):
        monkeypatch.setattr(authority_module, name, forbidden)
    store, authority, provider = create(tmp_path)
    token = issue(authority)
    assert authority.verify_token(token)["sub"] == "demo-service"
    authority.rotate(force=True)
    rows = store.db.execute("SELECT * FROM signing_keys").fetchall()
    assert len(rows) == 2
    assert all(row["private"] is None and row["provider_ref"].startswith("remote:") for row in rows)
    assert all("PRIVATE KEY" not in row["public"] for row in rows)
    audit = "\n".join(row[0] for row in store.db.execute("SELECT details FROM audit"))
    assert token not in audit and "PRIVATE KEY" not in audit
    assert len(provider.keys) == 2


def test_external_mode_refuses_existing_local_private_keys(tmp_path):
    store = Store(tmp_path / "state" / "authority.db")
    Authority(store, Config())
    with pytest.raises(ValueError, match="refuses a database containing local issuer private keys"):
        Authority(store, Config(), signer=RemoteSigner())


def test_uncertain_remote_prepare_recovers_same_generation_after_restart(tmp_path):
    store = Store(tmp_path / "state" / "authority.db")
    first = RemoteSigner()
    first.fail_after_prepare = True
    with pytest.raises(SignerError, match="simulated_uncertain_prepare"):
        Authority(store, Config(), signer=first)
    row = store.db.execute("SELECT * FROM signing_keys").fetchone()
    assert row["state"] == "preparing" and row["private"] is None
    generation = row["kid"]
    assert len(first.keys) == 1
    store.close()
    restored_store = Store(tmp_path / "state" / "authority.db")
    restored_provider = RemoteSigner(first.keys)
    restored = Authority(restored_store, Config(), signer=restored_provider)
    assert restored.active_key()["kid"] == generation
    assert restored_provider.prepared == [generation]
    assert len(restored_provider.keys) == 1
    assert restored_store.db.execute("SELECT count(*) FROM signing_keys").fetchone()[0] == 1


def test_failed_readiness_preserves_old_active_key_and_recovers_candidate(tmp_path):
    store, authority, provider = create(tmp_path)
    original = authority.active_key()["kid"]
    provider.fail_sign = True
    with pytest.raises(SignerError):
        authority.rotate(force=True)
    candidate = store.db.execute("SELECT * FROM signing_keys WHERE state='pending'").fetchone()
    assert candidate is not None and candidate["private"] is None
    assert authority.active_key()["kid"] == original
    store.close()
    restored_store = Store(tmp_path / "state" / "authority.db")
    restored_provider = RemoteSigner(provider.keys)
    restored = Authority(restored_store, Config(signing_interval=86400), signer=restored_provider)
    assert restored.active_key()["kid"] == candidate["kid"]
    assert restored_provider.prepared == []
    assert len(provider.keys) == 2


def test_invalid_readiness_signature_never_activates_candidate(tmp_path):
    store, authority, provider = create(tmp_path)
    original = authority.active_key()["kid"]
    provider.corrupt_sign = True
    with pytest.raises(jwt.InvalidSignatureError):
        authority.rotate(force=True)
    assert authority.active_key()["kid"] == original
    assert store.db.execute("SELECT count(*) FROM signing_keys WHERE state='pending'").fetchone()[0] == 1


def test_signer_outage_cannot_fall_back_to_a_local_key(tmp_path):
    store, authority, provider = create(tmp_path)
    provider.fail_sign = True
    with pytest.raises(SignerError):
        issue(authority)
    assert store.db.execute("SELECT count(*) FROM signing_keys WHERE private IS NOT NULL").fetchone()[0] == 0
    assert store.db.execute("SELECT count(*) FROM audit WHERE event='credential.issued'").fetchone()[0] == 0


def test_rotation_retains_old_verification_until_issued_token_drain_boundary(tmp_path):
    store, authority, provider = create(tmp_path)
    token = issue(authority)
    old_kid = jwt.get_unverified_header(token)["kid"]
    expiry = jwt.decode(token, options={"verify_signature": False})["exp"]
    authority.rotate(force=True)
    old = store.db.execute("SELECT * FROM signing_keys WHERE kid=?", (old_kid,)).fetchone()
    assert old["state"] == "draining"
    assert old["retire"] >= expiry + authority.config.skew
    assert authority.verify_token(token)["sub"] == "demo-service"
    store.db.execute("UPDATE signing_keys SET retire=? WHERE kid=?", (time.time() - 1, old_kid))
    authority.maintenance()
    assert old["provider_ref"] in provider.retired
    with pytest.raises(Denied, match="issuer_key_not_authorized"):
        authority.verify_token(token)


def test_issuer_revocation_remains_effective_with_a_fresh_provider_after_restart(tmp_path):
    store, authority, provider = create(tmp_path)
    token = issue(authority)
    revoked_kid = jwt.get_unverified_header(token)["kid"]
    revoked_ref = authority.active_key()["provider_ref"]
    event_id = str(uuid.uuid4())
    receipt = authority.event(event_id, "revoke_issuer_key", revoked_kid, "compromised")
    assert receipt["status"] == "revoked"
    assert authority.active_key()["kid"] != revoked_kid
    with pytest.raises(Denied, match="issuer_key_not_authorized"):
        authority.verify_token(token)
    store.close()
    restored_store = Store(tmp_path / "state" / "authority.db")
    restored_provider = RemoteSigner(provider.keys)
    restored = Authority(restored_store, Config(signing_interval=86400), signer=restored_provider)
    with pytest.raises(Denied, match="issuer_key_not_authorized"):
        restored.verify_token(token)
    assert revoked_ref in restored_provider.retired
    assert restored.event(event_id, "revoke_issuer_key", revoked_kid, "compromised") == receipt
    assert restored.verify_token(issue(restored))["sub"] == "demo-service"
    state = restored_store.db.execute(
        "SELECT state,private FROM signing_keys WHERE kid=?", (revoked_kid,)
    ).fetchone()
    assert tuple(state) == ("revoked", None)
    assert all(json.loads(row[0]) for row in restored_store.db.execute("SELECT public FROM signing_keys"))


def test_revocation_commits_before_replacement_outage_and_recovers_on_restart(tmp_path):
    store, authority, provider = create(tmp_path)
    token = issue(authority)
    revoked_kid = authority.active_key()["kid"]
    event_id = str(uuid.uuid4())
    provider.fail_sign = True
    with pytest.raises(SignerError):
        authority.event(event_id, "revoke_issuer_key", revoked_kid, "compromised")
    assert authority.active_key() is None
    with pytest.raises(Denied, match="issuer_key_not_authorized"):
        authority.verify_token(token)
    assert store.db.execute("SELECT 1 FROM events WHERE id=?", (event_id,)).fetchone() is not None
    candidate = store.db.execute("SELECT kid FROM signing_keys WHERE state='pending'").fetchone()[0]
    store.close()
    restored_store = Store(tmp_path / "state" / "authority.db")
    restored = Authority(restored_store, Config(signing_interval=86400), signer=RemoteSigner(provider.keys))
    assert restored.active_key()["kid"] == candidate
    assert restored.event(event_id, "revoke_issuer_key", revoked_kid, "compromised")["status"] == "revoked"
    with pytest.raises(Denied, match="issuer_key_not_authorized"):
        restored.verify_token(token)
