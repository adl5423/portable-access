"""One-process HTTPS origin adapter example. No long-lived workload secret."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import os
import signal
import socket
import stat
from pathlib import Path

from aiohttp import ClientSession, ClientTimeout, UnixConnector, web

from pap.workload import MemoryProofStore, WorkloadClient, WorkloadConfig, WorkloadError, install_proof_route

LOGGER = logging.getLogger("pap.docker-example")
CLIENT = web.AppKey("workload_client", object)
CONFIGURED = web.AppKey("configured", bool)
CHECK_LOCK = web.AppKey("check_lock", asyncio.Lock)
ADMISSION = web.AppKey("resource_admission", asyncio.BoundedSemaphore)
CONTROL_TIMEOUT = 100
MAX_CONFIG_BYTES = 16_384
MAX_INFLIGHT = 32


def event(name: str, **fields: str | int | bool) -> None:
    # Deliberately exclude requests, URLs, proof records, tokens and exception strings.
    LOGGER.info(json.dumps({"event": name, **fields}, separators=(",", ":")))


def load_config(path: Path) -> WorkloadConfig | None:
    with path.open("rb") as source:
        raw = source.read(MAX_CONFIG_BYTES + 1)
    if len(raw) > MAX_CONFIG_BYTES:
        raise ValueError("public configuration exceeds the size limit")

    def unique(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError("duplicate public configuration member")
            result[name] = value
        return result

    value = json.loads(raw, object_pairs_hook=unique)
    if isinstance(value, dict) and value.get("enabled") is False:
        return None
    return WorkloadConfig.from_dict(value)


@web.middleware
async def response_headers(request: web.Request, handler):
    try:
        response = await handler(request)
    except WorkloadError as error:
        response = web.json_response({"error": error.code}, status=error.status)
    except web.HTTPException as error:
        response = web.json_response({"error": "route_unavailable"}, status=error.status)
    response.headers.update({"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
    return response


async def readiness(request: web.Request) -> web.Response:
    enabled = request.app[CONFIGURED]
    return web.json_response({"ready": enabled}, status=200 if enabled else 503)


async def liveness(_request: web.Request) -> web.Response:
    return web.json_response({"alive": True})


async def records(request: web.Request) -> web.Response:
    if not request.app[CONFIGURED]:
        return web.json_response({"error": "workload_disabled"}, status=503)
    admission = request.app[ADMISSION]
    if admission.locked():
        return web.json_response({"error": "resource_busy"}, status=503, headers={"Retry-After": "1"})
    # asyncio.acquire does not yield when a slot is free. There is no waiting queue between this
    # event-loop-local capacity check and acquisition. Proof callbacks have their own route.
    await admission.acquire()
    try:
        binding = await request.app[CLIENT].authorize_request(request)
        # Authorization uses the configured canonical HTTPS origin, never forwarded headers.
        return web.json_response({"records": [{"id": "example-1", "message": "Authorized by PAP"}], "access": binding})
    finally:
        admission.release()


def create_app(config: WorkloadConfig | None, *, client: WorkloadClient | None = None,
               max_inflight: int = MAX_INFLIGHT) -> web.Application:
    if type(max_inflight) is not int or not 1 <= max_inflight <= 128:
        raise ValueError("invalid resource concurrency limit")
    store = client.store if client is not None else MemoryProofStore()
    app = web.Application(middlewares=[response_headers], client_max_size=1024)
    app[CONFIGURED] = config is not None
    app[CLIENT] = client or (WorkloadClient(config, store=store) if config is not None else None)
    app[ADMISSION] = asyncio.BoundedSemaphore(max_inflight)
    install_proof_route(app, store)
    app.router.add_get("/health/live", liveness, allow_head=False)
    app.router.add_get("/health/ready", readiness, allow_head=False)
    app.router.add_get(config.resource_path if config is not None else "/api/pap/records", records, allow_head=False)

    async def close_client(application):
        if application[CLIENT] is not None:
            await application[CLIENT].close()

    app.on_cleanup.append(close_client)
    return app


async def local_check(request: web.Request) -> web.Response:
    # This handler exists only on a permission-restricted Unix socket, never the public listener.
    client = request.app[CLIENT]
    if not request.app[CONFIGURED]:
        return web.json_response({"error": "workload_disabled"}, status=503)
    if request.query_string or request.content_type != "application/json" or request.content_length != 0:
        return web.json_response({"error": "invalid_check_request"}, status=400)
    lock = request.app[CHECK_LOCK]
    if lock.locked():
        return web.json_response({"error": "check_in_progress"}, status=409)
    async with lock:
        try:
            result = await client.get_json()
            if not isinstance(result, dict) or "records" not in result:
                return web.json_response({"error": "unexpected_resource_response"}, status=502)
        except WorkloadError as error:
            event("check_failed", code=error.code)
            return web.json_response({"error": error.code}, status=error.status)
        except (OSError, TimeoutError):
            event("check_failed", code="check_unavailable")
            return web.json_response({"error": "check_unavailable"}, status=503)
    event("authorized_read_completed")
    return web.json_response({"ok": True})


def control_app(app: web.Application) -> web.Application:
    control = web.Application(middlewares=[response_headers], client_max_size=0)
    control[CLIENT] = app[CLIENT]
    control[CONFIGURED] = app[CONFIGURED]
    control[CHECK_LOCK] = asyncio.Lock()
    control.router.add_post("/check", local_check)
    return control


def prepare_socket(path: Path) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.parent.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("control directory must be owned by this user and private")
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if info.st_uid != os.getuid() or not stat.S_ISSOCK(info.st_mode):
            raise ValueError("refusing to replace an unsafe control socket")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as existing:
            existing.settimeout(0.5)
            try:
                existing.connect(str(path))
            except ConnectionRefusedError:
                pass  # A terminated process can leave a stale socket inode.
            else:
                raise ValueError("another workload process owns the control socket")
        path.unlink()


async def serve(config: WorkloadConfig | None, host: str, port: int, socket_path: Path) -> None:
    prepare_socket(socket_path)
    app = create_app(config)
    public_runner = web.AppRunner(app, access_log=None, shutdown_timeout=10)
    local_runner = web.AppRunner(control_app(app), access_log=None, shutdown_timeout=10)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(signum, stop.set)
    try:
        await public_runner.setup()
        await web.TCPSite(public_runner, host, port).start()
        # The control socket becomes available only after the public listener accepts callbacks.
        await local_runner.setup()
        await web.UnixSite(local_runner, str(socket_path)).start()
        socket_path.chmod(0o600)
        event("workload_listening", configured=config is not None)
        await stop.wait()
    finally:
        await local_runner.cleanup()
        await public_runner.cleanup()
        with contextlib.suppress(FileNotFoundError):
            socket_path.unlink()
        for signum in (signal.SIGINT, signal.SIGTERM):
            loop.remove_signal_handler(signum)
        event("workload_stopped")


async def check(socket_path: Path, repeat_after: int) -> int:
    # Execute inside the same container/UID. The private socket invokes the server's proof store.
    info = socket_path.lstat()
    if info.st_uid != os.getuid() or not stat.S_ISSOCK(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("control socket must be owned by this user and private")
    async with ClientSession(connector=UnixConnector(path=str(socket_path)), trust_env=False,
                             timeout=ClientTimeout(total=CONTROL_TIMEOUT)) as session:
        count = 2 if repeat_after else 1
        for index in range(count):
            if index:
                await asyncio.sleep(repeat_after)
            async with session.post("http://localhost/check", headers={"Content-Type": "application/json"},
                                    data=b"", allow_redirects=False) as response:
                raw = await response.content.read(1025)
                if response.status != 200 or len(raw) > 1024 or json.loads(raw) != {"ok": True}:
                    event("acceptance_failed", status=response.status)
                    return 1
    event("acceptance_passed", authorized_reads=count)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("/etc/pap-workload/config.public.json"))
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, default=8080)
    parser.add_argument("--control-socket", type=Path, default=Path("/run/pap-workload/control.sock"))
    parser.add_argument("--check", action="store_true", help="ask the running process for an authorized read")
    parser.add_argument("--repeat-after", type=int, choices=(0, 65), default=0,
                        help="perform a second read after the default 60-second credential lifetime")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    try:
        if args.check:
            return asyncio.run(check(args.control_socket, args.repeat_after))
        if args.repeat_after:
            parser.error("--repeat-after requires --check")
        if not 1 <= args.listen_port <= 65535:
            parser.error("invalid listener port")
        asyncio.run(serve(load_config(args.config), args.listen_host, args.listen_port, args.control_socket))
        return 0
    except (OSError, ValueError, WorkloadError):
        event("startup_or_check_failed")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
