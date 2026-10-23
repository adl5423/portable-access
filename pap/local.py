"""Kernel-derived Unix peer identity, protected paths and redacted HTTP errors."""

import ctypes
import json
import logging
import os
import socket
import sqlite3
import stat
import struct
import sys
import uuid
from pathlib import Path

from aiohttp import web
from pydantic import BaseModel, ConfigDict, ValidationError

from .crypto import Denied
from .signers import SignerError

LOG = logging.getLogger("pap")


def peer_uid(request: web.Request) -> int:
    transport = request.transport
    sock = transport.get_extra_info("socket") if transport else None
    if sock is None or sock.family != socket.AF_UNIX:
        raise Denied("local_identity_required", 403)
    if sys.platform == "darwin":
        libc = ctypes.CDLL(None, use_errno=True)
        fn = libc.getpeereid
        fn.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint), ctypes.POINTER(ctypes.c_uint)]
        fn.restype = ctypes.c_int
        uid, gid = ctypes.c_uint(), ctypes.c_uint()
        if fn(sock.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
            raise Denied("local_identity_unavailable", 503)
        return uid.value
    if hasattr(socket, "SO_PEERCRED"):
        _, uid, _ = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        return uid
    raise Denied("unsupported_peer_identity", 503)


def clean_socket(path: Path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError("refusing to remove a non-socket or foreign socket")
    path.unlink()


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


async def body(request: web.Request, model):
    if request.content_type != "application/json":
        raise Denied("json_required", 415)
    try:

        def unique(pairs):
            value = {}
            for key, member in pairs:
                if key in value:
                    raise ValueError("duplicate JSON member")
                value[key] = member
            return value

        payload = json.loads(
            await request.read(),
            object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid number")),
        )
        return model.model_validate(payload)
    except (ValueError, ValidationError, TypeError) as exc:
        raise Denied("invalid_request", 400) from exc


def require_operation_key(request: web.Request) -> str:
    value = request.headers.get("Idempotency-Key", "")
    try:
        if str(uuid.UUID(value)) != value:
            raise ValueError("noncanonical id")
    except (ValueError, AttributeError) as exc:
        raise Denied("idempotency_key_required", 400) from exc
    return value


@web.middleware
async def errors(request, handler):
    request_id = str(uuid.uuid4())
    try:
        if request.headers.get("Origin") is not None:
            raise Denied("browser_origin_not_supported", 403)
        if request.query_string:
            raise Denied("query_not_supported", 400)
        response = await handler(request)
    except Denied as exc:
        response = web.json_response({"error": exc.code, "request_id": request_id}, status=exc.status)
        if exc.status == 401:
            response.headers["WWW-Authenticate"] = 'DPoP error="invalid_token"'
        if exc.status == 429:
            response.headers["Retry-After"] = "60"
    except web.HTTPException as exc:
        response = web.json_response({"error": "http_error", "request_id": request_id}, status=exc.status)
    except SignerError as exc:
        LOG.error("signer_unavailable request_id=%s", request_id)
        response = web.json_response({"error": exc.code, "request_id": request_id}, status=503)
    except sqlite3.Error:
        LOG.error("state_unavailable request_id=%s", request_id)
        response = web.json_response({"error": "state_unavailable", "request_id": request_id}, status=503)
    except Exception:
        # No exception text/traceback: libraries can include URLs or request headers in exceptions.
        LOG.error("internal_error request_id=%s", request_id)
        response = web.json_response({"error": "internal_error", "request_id": request_id}, status=500)
    response.headers.update(
        {"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "X-Request-ID": request_id}
    )
    return response
