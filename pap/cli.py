"""Human CLI. No command accepts or prints application authentication credentials."""

import argparse
import asyncio
import json
import logging
import os
import signal
import sys
import uuid
from pathlib import Path

import aiohttp

from .agent import Agent, Client
from .authority import Config
from .crypto import Denied
from .demo import scenario
from .runtime import Runtime
from .signers import SignerError


def parser():
    root = argparse.ArgumentParser(
        description="Portable Access reference: local demonstration and isolated Linux/OpenBao authority."
    )
    commands = root.add_subparsers(dest="command", required=True)
    default_state = (
        Path("/private/tmp" if Path("/private/tmp").exists() else "/tmp") / f"pap-reference-{os.getuid()}"
    )
    for name in ("serve", "host", "agent", "request", "note", "status", "audit", "revoke"):
        sub = commands.add_parser(name)
        sub.add_argument(
            "--state",
            type=Path,
            default=default_state,
            help="private persistent local state, use a short Unix socket path",
        )
        if name in ("serve", "host"):
            sub.add_argument("--port", type=int, default=0)
            sub.add_argument(
                "--accelerated",
                action="store_true",
                help="6 second credentials, 3 second issuer rotation, 4 second TLS rotation",
            )
            sub.add_argument(
                "--grant-ttl", type=float, default=3600, help="seconds before access is automatically revoked"
            )
        if name == "note":
            sub.add_argument("message")
            sub.add_argument("--idempotency-key", required=True, help="reuse this UUID when retrying a write")
        if name == "revoke":
            sub.add_argument("--subject", default="demo-service")
            sub.add_argument("--reason", choices=["operator", "compromised"], default="operator")
            sub.add_argument(
                "--event-id", default=None, help="reuse this UUID when retrying an incident signal"
            )
    sub = commands.add_parser("demo")
    sub.add_argument("--report", type=Path)
    commands.add_parser("conformance")
    sub = commands.add_parser("production", help="isolated Linux authority with external OpenBao signer")
    sub.add_argument("--config", type=Path, required=True)
    sub = commands.add_parser("enrollment", help="isolated local certificate enrollment service")
    sub.add_argument("--config", type=Path, required=True)
    return root


async def admin(state: Path, method: str, path: str, data=None):
    async with aiohttp.ClientSession(
        connector=aiohttp.UnixConnector(path=str(state / "admin.sock")),
        timeout=aiohttp.ClientTimeout(total=5),
        trust_env=False,
    ) as session:
        async with session.request(method, "http://admin" + path, json=data) as response:
            payload = await response.json()
            if response.status != 200:
                raise Denied(payload.get("error", "admin_unavailable"), response.status)
            return payload


async def run(args):
    if args.command == "enrollment":
        import threading

        from .enrollment import EnrollmentServer, load_enrollment_config

        server = EnrollmentServer(load_enrollment_config(args.config))
        stopped = threading.Event()
        loop = asyncio.get_running_loop()
        for signum in (signal.SIGTERM, signal.SIGINT):
            loop.add_signal_handler(signum, stopped.set)
        try:
            await asyncio.to_thread(server.serve_forever, stopped)
        finally:
            server.close()
        return 0
    if args.command == "production":
        from .production import serve

        await serve(args.config)
        return 0
    if args.command == "demo":
        result = await scenario(args.report)
        print(json.dumps(result, indent=2))
        return 0 if result["passed"] else 1
    if args.command in ("serve", "host", "agent"):
        runtime, agent = None, None
        try:
            if args.command != "agent":
                config = Config(
                    grant_ttl=args.grant_ttl,
                    **(
                        {"token_ttl": 6, "signing_interval": 3, "tls_interval": 4} if args.accelerated else {}
                    ),
                )
                runtime = Runtime(args.state, config)
                await runtime.start(args.port)
            if args.command != "host":
                agent = Agent(args.state)
                await agent.start()
            print(
                json.dumps(
                    {
                        "ready": True,
                        "state": str(args.state),
                        "origin": runtime.origin if runtime else None,
                        "profile": "PAP-local-0.1",
                        "warning": "same-UID local demonstration; not a production identity provider",
                    }
                ),
                flush=True,
            )
            stopped = asyncio.Event()
            loop = asyncio.get_running_loop()
            for signum in (signal.SIGTERM, signal.SIGINT):
                loop.add_signal_handler(signum, stopped.set)
            await stopped.wait()
        finally:
            if agent:
                await agent.close()
            if runtime:
                await runtime.close()
        return 0
    if args.command == "request":
        result = await Client(args.state / "agent.sock").records()
    elif args.command == "note":
        key = args.idempotency_key
        result = {
            **await Client(args.state / "agent.sock").create_note(args.message, idempotency_key=key),
            "idempotency_key": key,
        }
    elif args.command == "status":
        result = await admin(args.state, "GET", "/v0/status")
    elif args.command == "audit":
        result = await admin(args.state, "GET", "/v0/audit")
    elif args.command == "revoke":
        result = await admin(
            args.state,
            "POST",
            "/v0/events",
            {
                "event_id": args.event_id or str(uuid.uuid4()),
                "kind": "revoke_workload",
                "subject": args.subject,
                "reason": args.reason,
            },
        )
    else:
        raise ValueError("unknown command")
    print(json.dumps(result, indent=2))
    return 0


def main():
    inherited_umask = os.umask(0o077)
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s %(message)s")
    args = parser().parse_args()
    if args.command == "conformance":
        # Permission tests set deliberate fixture modes. Preserve the invoking
        # operator mask for the test subprocess instead of the service mask.
        os.umask(inherited_umask)
        import subprocess

        tests = Path(__file__).resolve().parent.parent / "tests"
        if not tests.is_dir():
            print(json.dumps({"error": "run_conformance_from_source_checkout"}), file=sys.stderr)
            raise SystemExit(2)
        raise SystemExit(
            subprocess.run([sys.executable, "-m", "pytest", "-q", str(tests)], check=False).returncode
        )
    try:
        raise SystemExit(asyncio.run(run(args)))
    except Denied as exc:
        print(json.dumps({"error": exc.code, "status": exc.status}), file=sys.stderr)
        raise SystemExit(1) from None
    except SignerError as exc:
        print(json.dumps({"error": exc.code, "status": 503}), file=sys.stderr)
        raise SystemExit(1) from None
    except (OSError, ValueError, aiohttp.ClientError):
        print(json.dumps({"error": "local_runtime_unavailable_or_invalid_configuration"}), file=sys.stderr)
        raise SystemExit(1) from None
