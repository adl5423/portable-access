"""Disable ordinary process dumps before loading service or operator secrets."""

import ctypes
import sys

try:
    import resource
except ImportError:  # Configuration-only commands can still import on non-POSIX hosts.
    resource = None

_PR_GET_DUMPABLE = 3
_PR_SET_DUMPABLE = 4
_FAILURE = "Cannot enforce secret process dump protection"


def harden_secret_process() -> None:
    """Fail closed if the current process can still produce ordinary core dumps.

    Linux dumpability also restricts same-UID process inspection. Host root and
    debuggers with sufficient capabilities remain trusted. These controls do
    not lock Python's copies of private material in physical memory.
    """
    try:
        if resource is None:
            raise ValueError(_FAILURE)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        if resource.getrlimit(resource.RLIMIT_CORE) != (0, 0):
            raise ValueError(_FAILURE)
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
            if libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
                raise ValueError(_FAILURE)
            if libc.prctl(_PR_GET_DUMPABLE, 0, 0, 0, 0) != 0:
                raise ValueError(_FAILURE)
    except (OSError, ValueError, AttributeError, TypeError, OverflowError) as exc:
        raise ValueError(_FAILURE) from exc
