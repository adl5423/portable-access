"""Executable, redacted lifecycle acceptance scenario using real local HTTPS and Unix sockets."""

import asyncio
import json
import ssl
import tempfile
import time
import uuid
from pathlib import Path

import aiohttp

from .agent import Agent, Client
from .authority import Config
from .crypto import Denied, fresh_key, proof
from .runtime import Runtime


async def scenario(report_path: Path | None = None) -> dict:
    with tempfile.TemporaryDirectory(
        prefix="pap-demo-", dir="/private/tmp" if Path("/private/tmp").exists() else "/tmp"
    ) as directory:
        state = Path(directory)
        state.chmod(0o700)
        config = Config(token_ttl=6, signing_interval=3, tls_interval=4, grant_ttl=60)
        runtime, agent = Runtime(state, config), Agent(state)
        started = time.monotonic()
        checks = {}
        try:
            await runtime.start()
            await agent.start()
            client = Client(state / "agent.sock")
            first = await client.records()
            checks["authorized_https_request"] = first["tenant"] == "demo"
            first_credential = agent.credential
            first_kid = runtime.authority.active_key()["kid"]
            ssl_context = ssl.create_default_context(cadata=runtime.tls_pem)
            url = runtime.origin + "/v0/tenants/demo/records"
            async with aiohttp.ClientSession(trust_env=False) as session:
                async with session.get(url, ssl=ssl_context) as response:
                    checks["unauthenticated_request_rejected"] = response.status == 401
                stolen = {
                    "Authorization": "DPoP " + first_credential.token,
                    "DPoP": proof(fresh_key(), "GET", url, first_credential.nonce, first_credential.token),
                }
                async with session.get(url, headers=stolen, ssl=ssl_context) as response:
                    checks["stolen_token_wrong_key_rejected"] = response.status == 401
            operation_key = str(uuid.uuid4())
            note = await client.create_note("Synthetic acceptance note", idempotency_key=operation_key)
            again = await client.create_note("Synthetic acceptance note", idempotency_key=operation_key)
            checks["retried_write_has_one_effect"] = (
                note == again and runtime.store.db.execute("SELECT count(*) FROM notes").fetchone()[0] == 1
            )
            # The application is idle. Background tasks, not requests, must renew and rotate.
            await asyncio.sleep(9)
            checks["idle_background_credential_renewal"] = agent.renewals >= 3
            checks["workload_private_key_rotated"] = agent.credential.key is not first_credential.key
            checks["issuer_key_automatically_rotated"] = runtime.authority.active_key()["kid"] != first_kid
            checks["old_issuer_key_retired"] = (
                runtime.store.db.execute(
                    "SELECT state FROM signing_keys WHERE kid=?", (first_kid,)
                ).fetchone()[0]
                == "retired"
            )
            checks["tls_identity_automatically_rotated"] = runtime.tls_generation >= 3
            checks["request_after_all_rotations"] = (await client.records())["tenant"] == "demo"
            event_id = str(uuid.uuid4())
            event = {
                "event_id": event_id,
                "kind": "revoke_workload",
                "subject": "demo-service",
                "reason": "compromised",
            }
            async with aiohttp.ClientSession(
                connector=aiohttp.UnixConnector(path=str(state / "admin.sock")), trust_env=False
            ) as session:
                async with session.post("http://admin/v0/events", json=event) as response:
                    checks["authenticated_revocation_event_applied"] = response.status == 200
            try:
                await client.records()
                checks["revoked_workload_rejected"] = False
            except Denied as exc:
                checks["revoked_workload_rejected"] = exc.status == 403
            renewal_denied = False
            try:
                await agent.refresh(force=True)
            except Denied as exc:
                renewal_denied = exc.status == 403
            checks["revoked_workload_cannot_renew"] = renewal_denied
            renewals, tls_generations = agent.renewals, runtime.tls_generation
            await agent.close()
            await runtime.close()
            # Restart against the same durable authority database. Provisioning is insert-only.
            runtime = Runtime(state, config)
            await runtime.start()
            checks["revocation_survives_host_restart"] = (
                runtime.authority.status()["workloads"][0]["enabled"] == 0
            )
            result = {
                "profile": "PAP-local-0.1",
                "passed": all(checks.values()),
                "checks": checks,
                "credential_issuances": renewals,
                "tls_generations": tls_generations,
                "elapsed_seconds": round(time.monotonic() - started, 2),
                "scope": "Local OS trust domain; synthetic data; no cloud providers or external credentials",
                "environment_secret_inputs": 0,
            }
            if report_path:
                report_path.parent.mkdir(parents=True, exist_ok=True)
                report_path.write_text(json.dumps(result, indent=2) + "\n")
            return result
        finally:
            await agent.close()
            await runtime.close()
