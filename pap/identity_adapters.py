"""Closed registered-origin identity adapters.

These adapters establish control of an enrolled HTTPS origin. They do not
attest a cloud account, deployment, machine, or provider-issued identity.
Adapters are selected by operator configuration, never by a token request.
"""

import ipaddress
import re
from collections.abc import Callable
from dataclasses import dataclass
from types import MappingProxyType
from urllib.parse import urlsplit


def https_origin(value: str) -> str:
    """Accept one canonical DNS HTTPS origin; connection-time DNS is checked separately."""
    valid = False
    if isinstance(value, str) and len(value) <= 260:
        try:
            parsed = urlsplit(value)
            hostname = parsed.hostname or ""
            valid = (
                value == "https://" + hostname
                and parsed.scheme == "https"
                and parsed.netloc == hostname
                and not parsed.path
                and not parsed.query
                and not parsed.fragment
                and not parsed.username
                and not parsed.password
                and re.fullmatch(
                    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",
                    hostname,
                )
                is not None
                and not hostname.endswith((".localhost", ".local", ".internal", ".home.arpa"))
            )
        except (ValueError, TypeError):
            pass
    if not valid:
        raise ValueError("a canonical public DNS https://HOST origin is required")
    return value


def netlify_origin(value: str) -> str:
    """Keep the production-only Netlify enrollment policy independent of generic origins."""
    try:
        https_origin(value)
        hostname = urlsplit(value).hostname or ""
        valid = (
            len(value) <= 256
            and "--" not in hostname
            and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.netlify\.app", hostname)
        )
    except (ValueError, TypeError):
        valid = False
    if not valid:
        raise ValueError("a canonical production https://SITE.netlify.app origin is required")
    return value


@dataclass(frozen=True)
class IdentityAdapter:
    identifier: str
    validate_origin: Callable[[str], str]
    attestation: str = "origin-control"


# Configuration cannot load Python modules, specify discovery URLs, or register
# arbitrary remote issuers. Adding a trust method requires a reviewed implementation.
IDENTITY_ADAPTERS = MappingProxyType(
    {
        "netlify": IdentityAdapter("netlify", netlify_origin),
        "https-origin": IdentityAdapter("https-origin", https_origin),
    }
)


def identity_adapter(identifier: str = "netlify") -> IdentityAdapter:
    if not isinstance(identifier, str) or identifier not in IDENTITY_ADAPTERS:
        raise ValueError("unknown identity adapter")
    return IDENTITY_ADAPTERS[identifier]


# Supplement ipaddress's public-address classification across supported Python
# versions. Azure's virtual service IP is globally numbered but is not a public
# application destination. Transition prefixes can tunnel a private IPv4 target.
_DENIED_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (
        "168.63.129.16/32",
        "192.0.0.0/24",
        "192.88.99.0/24",
        "::/96",
        "::ffff:0:0/96",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "2001::/23",
        "2002::/16",
    )
)


def public_destination(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """Reject private, special-use, mapped and transition addresses before connecting."""
    if not isinstance(value, str) or "%" in value:
        raise ValueError("nonpublic destination")
    address = ipaddress.ip_address(value)
    if (
        not address.is_global
        or address.is_multicast
        or address.is_unspecified
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or any(address.version == network.version and address in network for network in _DENIED_NETWORKS)
    ):
        raise ValueError("nonpublic destination")
    return address
