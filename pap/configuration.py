"""Strict, bounded configuration parsing without returning input in errors."""

from __future__ import annotations

import json
import math
from typing import Any

MAX_CONFIGURATION_BYTES = 1024 * 1024
MAX_CONFIGURATION_DEPTH = 64
MAX_CONFIGURATION_NODES = 100_000


class ConfigurationError(ValueError):
    """A fixed diagnostic code safe to include in operator output."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _unique_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for name, item in pairs:
        if name in value:
            raise ConfigurationError("configuration_duplicate_member")
        value[name] = item
    return value


def _reject_constant(_value: str) -> None:
    raise ConfigurationError("configuration_nonfinite_number")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ConfigurationError("configuration_nonfinite_number")
    return number


def parse_config_json(raw: bytes, *, maximum_bytes: int = MAX_CONFIGURATION_BYTES) -> dict[str, Any]:
    """Parse one UTF-8 JSON object; never normalize ambiguous policy silently.

    Paths, ownership and schema validation remain the caller's responsibility.
    Configuration values are deliberately excluded from every failure message.
    """
    if type(raw) is not bytes:
        raise ConfigurationError("configuration_bytes_required")
    if type(maximum_bytes) is not int or not 1 <= maximum_bytes <= MAX_CONFIGURATION_BYTES:
        raise ConfigurationError("configuration_limit_invalid")
    if len(raw) > maximum_bytes:
        raise ConfigurationError("configuration_too_large")
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_members,
            parse_constant=_reject_constant,
            parse_float=_finite_float,
        )
    except ConfigurationError:
        raise
    except (UnicodeError, ValueError, RecursionError, OverflowError):
        raise ConfigurationError("configuration_json_invalid") from None
    if not isinstance(value, dict):
        raise ConfigurationError("configuration_object_required")
    stack = [(value, 1)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if depth > MAX_CONFIGURATION_DEPTH or nodes > MAX_CONFIGURATION_NODES:
            raise ConfigurationError("configuration_structure_too_large")
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, list):
            stack.extend((child, depth + 1) for child in item)
    return value
