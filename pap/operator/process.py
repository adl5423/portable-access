"""Prevent operator secrets from being persisted by ordinary process dumps."""

from ..process_security import harden_secret_process
from ..process_security import resource as resource
from .custody import CustodyError


def harden_process() -> None:
    try:
        harden_secret_process()
    except ValueError as exc:
        raise CustodyError("Cannot enforce operator process dump protection") from exc
