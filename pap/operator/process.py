"""Prevent operator secrets from being persisted by ordinary process dumps."""

import ctypes
import resource
import sys

from .custody import CustodyError


def harden_process() -> None:
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if sys.platform == "linux":
            libc = ctypes.CDLL(None, use_errno=True)
            libc.prctl.argtypes = [
                ctypes.c_int,
                ctypes.c_ulong,
                ctypes.c_ulong,
                ctypes.c_ulong,
                ctypes.c_ulong,
            ]
            libc.prctl.restype = ctypes.c_int
            if libc.prctl(4, 0, 0, 0, 0) != 0:  # PR_SET_DUMPABLE
                raise CustodyError("Cannot disable operator process inspection and dumps")
    except (OSError, ValueError, AttributeError) as exc:
        raise CustodyError("Cannot enforce operator process dump protection") from exc
