"""Regression checks from independent review of the first implementation."""

import os
import tempfile
import uuid
from pathlib import Path

import pytest

from pap.authority import TOKEN_TARGET, Authority, Config
from pap.crypto import Denied, fresh_key, proof, public_jwk
from pap.runtime import Runtime
from pap.storage import Store


@pytest.fixture
def issued(tmp_path):
    state = tmp_path / "private"
    store = Store(state / "state.sqlite")
    authority = Authority(store, Config())
    authority.provision(os.getuid())
    key = fresh_key()
    jwk = public_jwk(key)
    challenge = authority.challenge(os.getuid(), jwk)
    credential = authority.issue(
        os.getuid(), "demo-grant", jwk, proof(key, "POST", TOKEN_TARGET, challenge["nonce"])
    )
    try:
        yield authority, key, credential
    finally:
        store.close()


def authorize(authority, key, credential):
    token = credential["access_token"]
    url = "https://api.example/v0/tenants/demo/notes"
    return authority.authorize(
        token, proof(key, "POST", url, credential["dpop_nonce"], token), "POST", url, "demo", "notes.create"
    )


def test_issuer_revocation_between_crypto_check_and_admission_is_rechecked(issued, monkeypatch):
    authority, key, credential = issued
    original = authority.verify_token
    calls = 0

    def verify_then_revoke(token):
        nonlocal calls
        claims = original(token)
        calls += 1
        if calls == 1:
            authority.event(
                str(uuid.uuid4()), "revoke_issuer_key", authority.active_key()["kid"], "compromised"
            )
        return claims

    monkeypatch.setattr(authority, "verify_token", verify_then_revoke)
    with pytest.raises(Denied, match="issuer_key_not_authorized"):
        authorize(authority, key, credential)


def test_signer_revoked_after_admission_cannot_commit_mutation(issued):
    authority, key, credential = issued
    claims = authorize(authority, key, credential)
    authority.event(str(uuid.uuid4()), "revoke_issuer_key", authority.active_key()["kid"], "compromised")
    with pytest.raises(Denied, match="issuer_key_not_authorized"):
        authority.create_note(claims, str(uuid.uuid4()), "must not commit")
    assert authority.store.db.execute("SELECT count(*) FROM notes").fetchone()[0] == 0


async def test_abandoned_runtime_metadata_write_does_not_block_restart():
    with tempfile.TemporaryDirectory(
        prefix="pap-recovery-", dir="/private/tmp" if Path("/private/tmp").exists() else "/tmp"
    ) as directory:
        state = Path(directory)
        state.chmod(0o700)
        (state / "runtime.json.next").write_text("incomplete public metadata")
        runtime = Runtime(state)
        try:
            await runtime.start()
            assert runtime.ready
            assert not (state / "runtime.json.next").exists()
        finally:
            await runtime.close()
