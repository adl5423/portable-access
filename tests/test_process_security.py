"""Secret-bearing processes must fail before loading keys if dump protection fails."""

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from pap import process_security as security


def fake_limits(monkeypatch, result=(0, 0)):
    calls = []
    monkeypatch.setattr(
        security,
        "resource",
        SimpleNamespace(
            RLIMIT_CORE=4,
            setrlimit=lambda name, limits: calls.append((name, limits)),
            getrlimit=lambda name: result,
        ),
    )
    return calls


class Prctl:
    def __init__(self, results):
        self.results = iter(results)
        self.calls = []

    def __call__(self, *arguments):
        self.calls.append(arguments)
        return next(self.results)


def fake_linux(monkeypatch, results=(0, 0)):
    monkeypatch.setattr(security, "sys", SimpleNamespace(platform="linux"))
    prctl = Prctl(results)
    monkeypatch.setattr(security.ctypes, "CDLL", lambda *_args, **_kwargs: SimpleNamespace(prctl=prctl))
    return prctl


def test_linux_requires_both_core_limit_and_verified_nondumpability(monkeypatch):
    limits = fake_limits(monkeypatch)
    prctl = fake_linux(monkeypatch)
    security.harden_secret_process()
    assert limits == [(4, (0, 0))]
    assert prctl.calls == [(4, 0, 0, 0, 0), (3, 0, 0, 0, 0)]


@pytest.mark.parametrize("results", [(-1,), (0, 1), (0, -1)])
def test_linux_rejects_failed_set_or_failed_readback(monkeypatch, results):
    fake_limits(monkeypatch)
    fake_linux(monkeypatch, results)
    with pytest.raises(ValueError, match="^Cannot enforce secret process dump protection$"):
        security.harden_secret_process()


def test_unenforced_core_limit_is_rejected_before_linux_calls(monkeypatch):
    fake_limits(monkeypatch, result=(0, -1))
    prctl = fake_linux(monkeypatch)
    with pytest.raises(ValueError, match="dump protection"):
        security.harden_secret_process()
    assert prctl.calls == []


@pytest.mark.parametrize("failure", [OSError, ValueError, AttributeError])
def test_enforcement_errors_do_not_expose_library_details(monkeypatch, failure):
    def reject(*_args):
        raise failure("synthetic-private-detail")

    fake_limits(monkeypatch)
    monkeypatch.setattr(security.resource, "setrlimit", reject)
    with pytest.raises(ValueError) as caught:
        security.harden_secret_process()
    assert str(caught.value) == "Cannot enforce secret process dump protection"


def test_nonlinux_posix_still_disables_core_files(monkeypatch):
    limits = fake_limits(monkeypatch)
    monkeypatch.setattr(security, "sys", SimpleNamespace(platform="darwin"))

    def unexpected(*_args, **_kwargs):
        raise AssertionError("Linux-only process control called on another platform")

    monkeypatch.setattr(security.ctypes, "CDLL", unexpected)
    security.harden_secret_process()
    assert limits == [(4, (0, 0))]


def test_unsupported_dump_control_fails_before_secret_dispatch(monkeypatch):
    monkeypatch.setattr(security, "resource", None)
    with pytest.raises(ValueError, match="^Cannot enforce secret process dump protection$"):
        security.harden_secret_process()


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux prctl in an isolated child")
def test_linux_kernel_confirms_child_has_no_core_limit_or_dumpability(tmp_path):
    root = Path(__file__).resolve().parents[1]
    code = """
import ctypes,json,resource
from pap.process_security import harden_secret_process
harden_secret_process()
libc=ctypes.CDLL(None,use_errno=True)
print(json.dumps({'core':resource.getrlimit(resource.RLIMIT_CORE),'dumpable':libc.prctl(3,0,0,0,0)}))
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=root,
        env={
            "PATH": os.defpath,
            "HOME": str(tmp_path),
            "PYTHONPATH": str(root),
            "PYTHONDONTWRITEBYTECODE": "1",
        },
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == {"core": [0, 0], "dumpable": 0}
