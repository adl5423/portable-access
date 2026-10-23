import asyncio
import hashlib
import json
import os
import shutil
import ssl
import stat
import subprocess
import sys
import uuid
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from pap import boot as b

PLAIN = hashlib.sha256(b"synthetic-static-seal-test-key").digest()
assert len(PLAIN) == 32
KEY_ID = hashlib.sha256(PLAIN).hexdigest()
BOOT_ID = "c5d988b6-fd40-426b-91c3-b7d620f3bdf0"


@pytest.fixture(scope="module")
def recipient():
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


@pytest.fixture
def config():
    return b.BootConfig(
        seal_origin="https://portable-access-seal.netlify.app",
        proof_origin="https://8080-abcdefghijklmnop.instabox.tech",
        machine_id="m_abcdefghijklmnopqrstuvwxyz",
        deployment_id="example-deployment",
        key_id=KEY_ID,
        proxy_gid=1001,
    )


def response(value, key, *, plain=PLAIN, label=None):
    ciphertext = key.public_key().encrypt(
        plain,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=hashlib.sha256(b.canonical(value)).digest() if label is None else label,
        ),
    )
    return {
        "v": 1,
        "request_id": value["request_id"],
        "key_id": value["key_id"],
        "wrapped_key": b._b64(ciphertext),
    }


def test_canonical_request_and_rsa_wrapping(config, recipient):
    value = b.request(config, BOOT_ID, recipient, 1792706600)
    assert set(value) == b._REQUEST_FIELDS
    assert value["exp"] - value["iat"] == 120
    assert uuid.UUID(value["request_id"]).version == 4
    assert b._decode(value["nonce"], 32)
    assert len(b._decode(value["recipient_jwk"]["n"], 512)) == 512
    assert value["recipient_jwk"]["e"] == "AQAB"
    assert b.canonical(value) == json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    assert b.unwrap(config, value, response(value, recipient), recipient, 1792706601) == PLAIN


@pytest.mark.parametrize(
    "field,value",
    [
        ("seal_origin", "http://portable-access-seal.netlify.app"),
        ("seal_origin", "https://private.example.com"),
        ("seal_origin", "https://preview--portable-access-seal.netlify.app"),
        ("seal_origin", "https://portable-access-seal.netlify.app/"),
        ("proof_origin", "http://8080-abcdefghijklmnop.instabox.tech"),
        ("proof_origin", "https://127.0.0.1"),
        ("proof_origin", "https://authority.example.com.evil.org"),
        ("key_id", KEY_ID.upper()),
        ("key_id", "a" * 63),
        ("machine_id", "m_a/b"),
        ("deployment_id", ""),
        ("proxy_gid", 0),
        ("proxy_gid", True),
    ],
)
def test_configuration_rejects_untrusted_bindings(config, field, value):
    with pytest.raises(b.BootError):
        replace(config, **{field: value})


@pytest.mark.parametrize(
    "raw",
    [b'{"v":1,"v":1}', b'{"x":{"v":1,"v":1}}', b"[]", b"null", b"", b"\xff", b'{"v":NaN}', b'{"v":Infinity}'],
)
def test_json_rejects_duplicates_and_nonobjects(raw):
    with pytest.raises(b.BootError, match="boot_json_invalid"):
        b._json(raw, 4096)


@pytest.mark.parametrize(
    "field,value",
    [
        ("v", True),
        ("v", 1.0),
        ("v", 2),
        ("request_id", BOOT_ID),
        ("key_id", "a" * 64),
        ("wrapped_key", "a" * 683 + "="),
        ("extra", "unexpected"),
    ],
)
def test_response_requires_exact_request_binding(config, recipient, field, value):
    request = b.request(config, BOOT_ID, recipient, 1792706600)
    reply = response(request, recipient)
    reply[field] = value
    with pytest.raises(b.BootError, match="boot_release_invalid"):
        b.unwrap(config, request, reply, recipient, 1792706601)


@pytest.mark.parametrize("now", [1792706599, 1792706720, 1792706721, float("nan"), float("inf")])
def test_release_cannot_outlive_request_or_time_move_backwards(config, recipient, now):
    request = b.request(config, BOOT_ID, recipient, 1792706600)
    with pytest.raises(b.BootError, match="boot_release_invalid"):
        b.unwrap(config, request, response(request, recipient), recipient, now)


@pytest.mark.parametrize("plain,label", [(b"x" * 31, None), (b"x" * 32, None), (PLAIN, b"wrong-domain")])
def test_seal_key_requires_length_pin_and_oaep_request_label(config, recipient, plain, label):
    request = b.request(config, BOOT_ID, recipient, 1792706600)
    with pytest.raises(b.BootError, match="boot_release_invalid"):
        b.unwrap(
            config, request, response(request, recipient, plain=plain, label=label), recipient, 1792706601
        )


def test_request_requires_rsa4096(config):
    with pytest.raises(b.BootError, match="boot_request_invalid"):
        b.request(config, BOOT_ID, rsa.generate_private_key(public_exponent=65537, key_size=2048), 1792706600)


def test_tmpfs_check_uses_longest_covering_mount_and_rejects_persistent_overlay():
    mounts = "1 0 0:1 / / rw - ext4 /dev/vda rw\n2 1 0:2 / /run rw,nosuid,nodev - tmpfs tmpfs rw\n"
    assert b._tmpfs(Path("/run/pap-boot"), mounts)
    assert not b._tmpfs(Path("/data/pap"), mounts)
    assert not b._tmpfs(Path("/run/pap-boot"), mounts + "3 2 0:1 /seal /run/pap-boot rw - ext4 /dev/vda rw\n")
    assert not b._tmpfs(Path("/run/pap-boot"), mounts.replace("/run rw", "/run ro"))


class Content:
    def __init__(self, chunks):
        self.chunks = list(chunks)

    async def read(self, size):
        if not self.chunks:
            return b""
        value = self.chunks.pop(0)
        if len(value) > size:
            self.chunks.insert(0, value[size:])
        return value[:size]


class HTTPResponse:
    def __init__(self, chunks, status=200, *, content_type="application/json", encoding=None):
        self.content, self.status, self.content_type = Content(chunks), status, content_type
        self.headers = {} if encoding is None else {"Content-Encoding": encoding}

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False


def http_fixture(monkeypatch, result):
    observed = {}

    def connector(**kwargs):
        observed["connector"] = kwargs
        return object()

    class Session:
        def __init__(self, **kwargs):
            observed["session"] = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return False

        def post(self, url, **kwargs):
            observed["post"] = {"url": url, **kwargs}
            if isinstance(result, Exception):
                raise result
            return result

    monkeypatch.setattr(b.aiohttp, "TCPConnector", connector)
    monkeypatch.setattr(b.aiohttp, "ClientSession", Session)
    return observed


async def test_http_transport_pins_dns_tls_origin_and_collects_fragmented_json(config, monkeypatch):
    observed = http_fixture(monkeypatch, HTTPResponse([b'{"v":', b"1}"]))
    assert await b.ReleaseTransport(config)({"request": "public"}) == {"v": 1}
    assert observed["session"]["trust_env"] is False
    assert observed["session"]["auto_decompress"] is False
    assert observed["session"]["timeout"].total == 15
    assert observed["connector"]["resolver"].hostname == "portable-access-seal.netlify.app"
    assert observed["connector"]["use_dns_cache"] is False
    assert observed["connector"]["ssl"].verify_mode == ssl.CERT_REQUIRED
    assert observed["connector"]["ssl"].check_hostname is True
    assert observed["post"]["url"] == config.seal_origin + "/v1/boot/release"
    assert observed["post"]["allow_redirects"] is False
    assert observed["post"]["data"] == b'{"request":"public"}'
    assert "Authorization" not in observed["post"]["headers"]


@pytest.mark.parametrize(
    "status,retryable",
    [
        (301, False),
        (302, False),
        (400, False),
        (401, False),
        (403, False),
        (404, False),
        (409, True),
        (429, True),
        (500, True),
        (502, True),
        (503, True),
        (504, True),
    ],
)
async def test_http_error_policy_is_explicit(config, monkeypatch, status, retryable):
    http_fixture(monkeypatch, HTTPResponse([], status))
    with pytest.raises(b.BootError) as raised:
        await b.ReleaseTransport(config)({})
    assert raised.value.retryable is retryable


@pytest.mark.parametrize(
    "response",
    [
        HTTPResponse([b"x" * 4097]),
        HTTPResponse([b"{}"], content_type="text/plain"),
        HTTPResponse([b"{}"], encoding="gzip"),
        HTTPResponse([b'{"v":1,"v":2}']),
    ],
)
async def test_transport_rejects_oversized_encoded_and_ambiguous_responses(config, monkeypatch, response):
    http_fixture(monkeypatch, response)
    with pytest.raises(b.BootError) as raised:
        await b.ReleaseTransport(config)({})
    assert raised.value.retryable is False


async def test_network_timeout_is_temporary_without_leaking_exception(config, monkeypatch):
    http_fixture(monkeypatch, TimeoutError("sensitive-upstream-detail"))
    with pytest.raises(b.BootError, match="boot_release_unavailable") as raised:
        await b.ReleaseTransport(config)({})
    assert raised.value.retryable is True
    assert "sensitive" not in str(raised.value)


@pytest.mark.parametrize(
    "body,retryable",
    [
        (b'{"error":"proof_expired"}', True),
        (b'{"error":"access_denied"}', False),
        (b'{"error":"proof_expired","extra":true}', False),
        (b"{}", False),
        (b"invalid", False),
    ],
)
async def test_only_explicit_expired_request_401_can_generate_fresh_proof(
    config, monkeypatch, body, retryable
):
    http_fixture(monkeypatch, HTTPResponse([body], 401))
    with pytest.raises(b.BootError) as raised:
        await b.ReleaseTransport(config)({})
    assert raised.value.retryable is retryable


def client_for_attempt(config, recipient, tmp_path, transport, *, ready=lambda: True):
    client = b.BootClient(
        config,
        _runtime=tmp_path,
        _incident_lock=tmp_path / "incident.lock",
        _transport=transport,
        _key_factory=lambda: recipient,
        _clock=lambda: 1792706600,
        _clock_ready=ready,
        _boot_id=lambda: BOOT_ID,
    )
    client.public.mkdir()
    client.private.mkdir()
    client._atomic = lambda path, raw, mode, gid: path.write_bytes(raw)
    return client


async def test_attempt_publishes_exact_proof_and_removes_it_after_success(config, recipient, tmp_path):
    async def transport(value):
        assert (client.public / (value["request_id"] + ".json")).read_bytes() == b.canonical(value)
        assert not client.key_path.exists()
        return response(value, recipient)

    client = client_for_attempt(config, recipient, tmp_path, transport)
    await client.attempt()
    assert client.key_path.read_bytes() == PLAIN
    assert not list(client.public.iterdir())


@pytest.mark.parametrize(
    "failure", [b.BootError("boot_release_unavailable", retryable=True), asyncio.CancelledError()]
)
async def test_attempt_removes_public_proof_on_failure_or_cancellation(config, recipient, tmp_path, failure):
    async def transport(value):
        raise failure

    client = client_for_attempt(config, recipient, tmp_path, transport)
    with pytest.raises(type(failure)):
        await client.attempt()
    assert not list(client.public.iterdir())
    assert not client.key_path.exists()


async def test_clock_must_be_trusted_before_request_and_before_key_acceptance(config, recipient, tmp_path):
    calls = []
    states = iter([True, False])

    async def transport(value):
        calls.append(value)
        return response(value, recipient)

    client = client_for_attempt(config, recipient, tmp_path, transport, ready=lambda: next(states))
    with pytest.raises(b.BootError, match="boot_clock_untrusted") as raised:
        await client.attempt()
    assert raised.value.retryable and len(calls) == 1
    assert not client.key_path.exists() and not list(client.public.iterdir())
    client.clock_ready = lambda: False
    with pytest.raises(b.BootError, match="boot_clock_untrusted"):
        await client.attempt()
    assert len(calls) == 1


def create_latch(path, kind):
    if kind == "regular":
        path.write_bytes(b"")
    elif kind == "directory":
        path.mkdir()
    else:
        path.symlink_to("missing-incident-target")


@pytest.mark.parametrize("kind", ["regular", "directory", "broken_symlink"])
async def test_incident_lock_blocks_attempt_before_clock_key_generation_or_network(
    config, recipient, tmp_path, kind
):
    async def transport(value):
        pytest.fail("a locked host must not call custody")

    client = client_for_attempt(
        config, recipient, tmp_path, transport, ready=lambda: pytest.fail("locked clock call")
    )
    client.key_factory = lambda: pytest.fail("a locked host must not generate a recipient")
    create_latch(client.incident_lock, kind)
    with pytest.raises(b.BootError, match="boot_locked") as raised:
        await client.attempt()
    assert raised.value.retryable is False
    assert not client.key_path.exists() and not list(client.public.iterdir())


@pytest.mark.parametrize("kind", ["regular", "directory", "broken_symlink"])
async def test_incident_lock_set_during_release_blocks_runtime_key_write(config, recipient, tmp_path, kind):
    async def transport(value):
        create_latch(client.incident_lock, kind)
        return response(value, recipient)

    client = client_for_attempt(config, recipient, tmp_path, transport)
    with pytest.raises(b.BootError, match="boot_locked") as raised:
        await client.attempt()
    assert raised.value.retryable is False
    assert not client.key_path.exists() and not list(client.public.iterdir())


NATIVE_ROOT = sys.platform == "linux" and os.geteuid() == 0
native = pytest.mark.skipif(
    not NATIVE_ROOT, reason="requires native Linux root and /run tmpfs; run container acceptance"
)


@pytest.fixture
def runtime():
    if not NATIVE_ROOT:
        pytest.skip("requires native Linux root")
    parent = Path("/run/pap-boot-tests")
    parent.mkdir(mode=0o755, exist_ok=True)
    path = parent / uuid.uuid4().hex
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@native
async def test_native_runtime_permissions_and_no_network_on_same_boot_reuse(config, recipient, runtime):
    calls = []

    async def transport(value):
        calls.append(value)
        proof = runtime / "public" / (value["request_id"] + ".json")
        assert b._read_file(proof, mode=0o440, gid=config.proxy_gid, limit=4096) == b.canonical(value)
        return response(value, recipient)

    client = b.BootClient(
        config,
        _runtime=runtime,
        _incident_lock=runtime / "incident.lock",
        _transport=transport,
        _key_factory=lambda: recipient,
        _clock_ready=lambda: True,
        _clock=lambda: 1792706600,
        _boot_id=lambda: BOOT_ID,
    )
    assert (await client.run())["runtime_key_reused"] is False
    assert (await client.run())["runtime_key_reused"] is True
    assert len(calls) == 1
    assert stat.S_IMODE(client.private.stat().st_mode) == 0o700
    assert stat.S_IMODE(client.key_path.stat().st_mode) == 0o400
    assert client.key_path.stat().st_uid == client.key_path.stat().st_gid == 0
    assert b._read_file(client.key_path, mode=0o400, gid=0, limit=32) == PLAIN
    assert not list(client.public.iterdir())


@native
async def test_native_transient_outage_recovers_beyond_previous_restart_limit(config, recipient, runtime):
    elapsed, calls, requests = [0.0], [], []

    async def sleep(delay):
        elapsed[0] += delay

    async def transport(value):
        requests.append(value)
        if elapsed[0] < 129:
            raise b.BootError("boot_release_unavailable", retryable=True)
        return response(value, recipient)

    def factory():
        calls.append(True)
        return recipient

    client = b.BootClient(
        config,
        _runtime=runtime,
        _incident_lock=runtime / "incident.lock",
        _transport=transport,
        _key_factory=factory,
        _clock_ready=lambda: True,
        _clock=lambda: 1792706600 + elapsed[0],
        _boot_id=lambda: BOOT_ID,
        _sleep=sleep,
        _jitter=lambda: 1,
    )
    assert (await client.run())["ready"] is True
    assert elapsed[0] >= 129 and len(calls) == len(requests) > 5
    assert len({value["request_id"] for value in requests}) == len(requests)
    assert len({value["nonce"] for value in requests}) == len(requests)
    assert not list(client.public.iterdir())


@native
async def test_native_waits_for_prolonged_trusted_time_without_publishing(config, recipient, runtime):
    elapsed, calls = [0.0], []

    async def sleep(delay):
        elapsed[0] += delay
        assert not list(client.public.iterdir())
        assert not client.key_path.exists()

    async def transport(value):
        calls.append(value)
        assert elapsed[0] >= 194
        return response(value, recipient)

    client = b.BootClient(
        config,
        _runtime=runtime,
        _incident_lock=runtime / "incident.lock",
        _transport=transport,
        _key_factory=lambda: recipient,
        _clock_ready=lambda: elapsed[0] >= 194,
        _clock=lambda: 1792706600 + elapsed[0],
        _boot_id=lambda: BOOT_ID,
        _sleep=sleep,
        _jitter=lambda: 1,
    )
    assert (await client.run())["ready"] is True
    assert elapsed[0] >= 194 and len(calls) == 1


@native
async def test_native_denial_does_not_retry_or_write_key(config, recipient, runtime):
    async def transport(value):
        raise b.BootError("boot_release_denied")

    async def sleep(delay):
        pytest.fail("denial must not retry")

    client = b.BootClient(
        config,
        _runtime=runtime,
        _incident_lock=runtime / "incident.lock",
        _transport=transport,
        _key_factory=lambda: recipient,
        _clock_ready=lambda: True,
        _clock=lambda: 1792706600,
        _boot_id=lambda: BOOT_ID,
        _sleep=sleep,
    )
    with pytest.raises(b.BootError, match="boot_release_denied"):
        await client.run()
    assert not client.key_path.exists() and not list(client.public.iterdir())


@native
async def test_native_rejects_symlink_existing_key_and_unsafe_directory(config, recipient, runtime):
    client = b.BootClient(
        config, _runtime=runtime, _incident_lock=runtime / "incident.lock", _clock_ready=lambda: True
    )
    client.prepare()
    client.key_path.symlink_to("/etc/passwd")
    with pytest.raises((b.BootError, OSError)):
        await client.run()
    client.key_path.unlink()
    client.public.chmod(0o777)
    with pytest.raises(b.BootError, match="boot_directory_untrusted"):
        client.prepare()


@native
@pytest.mark.parametrize("kind", ["regular", "directory", "broken_symlink"])
async def test_native_incident_lock_blocks_cached_same_boot_key(config, runtime, kind):
    async def transport(value):
        pytest.fail("cached key on locked host must not contact custody")

    client = b.BootClient(
        config, _runtime=runtime, _incident_lock=runtime / "incident.lock", _transport=transport
    )
    client.prepare()
    client._atomic(client.key_path, PLAIN, 0o400, 0)
    create_latch(client.incident_lock, kind)
    with pytest.raises(b.BootError, match="boot_locked") as raised:
        await client.run()
    assert raised.value.retryable is False
    assert client.key_path.read_bytes() == PLAIN
    assert client.incident_lock.lstat()
    if kind == "broken_symlink":
        assert not client.incident_lock.exists()
        assert (
            subprocess.run(["/usr/bin/test", "!", "-L", str(client.incident_lock)], check=False).returncode
            == 1
        )


def test_new_units_have_no_caddy_authority_boot_order_cycle():
    root = Path(__file__).parents[1] / "deploy/linux"
    service = (root / "systemd/pap-boot.service").read_text()
    gateway = (root / "systemd/pap-caddy.service").read_text()
    gateway_profile = (root / "systemd/pap-caddy.service.d/boot-origin.conf").read_text()
    kms = (root / "systemd/pap-openbao.service.d/boot-static-seal.conf").read_text()
    assert "After=network-online.target time-sync.target pap-caddy.service" in service
    assert "Before=pap-openbao.service" in service
    assert "StartLimitIntervalSec=0" in service and "RestartPreventExitStatus=78" in service
    assert "TimeoutStartSec=infinity" in service and "MemorySwapMax=0" in service
    assert "ProcSubset=pid" not in service
    dependency_lines = [
        line
        for line in (gateway + gateway_profile).splitlines()
        if line.startswith(("After=", "Before=", "Wants=", "Requires="))
    ]
    assert all("pap-authority.service" not in line for line in dependency_lines)
    assert all("pap-openbao.service" not in line for line in dependency_lines)
    assert "After=network-online.target" in dependency_lines
    assert "Wants=network-online.target" in dependency_lines
    assert "After=" not in dependency_lines and "Wants=" not in dependency_lines
    assert "After=pap-boot.service" in kms
    assert "LoadCredential=seal-current:/run/pap-boot/private/current.key" in kms
    assert "ConditionPathExists=!/etc/pap/boot.locked" in kms
    assert "ExecStartPre=/usr/bin/test ! -L /etc/pap/boot.locked" in kms
    for name in ("pap-authority", "pap-enroller"):
        assert (
            "StartLimitIntervalSec=0" in (root / f"systemd/{name}.service.d/boot-recovery.conf").read_text()
        )
    assert "sys/unseal" not in (root.parents[1] / "pap/boot.py").read_text()
