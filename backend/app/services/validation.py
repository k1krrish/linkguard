"""Target validation - the SSRF guard for every live diagnostic.

Rules (applied before any socket is opened):
1. Host must be a syntactically valid ASCII domain name or an IP literal.
2. IP literals (and every address a domain resolves to) must be globally
   routable: loopback, private, link-local, multicast, reserved, unspecified
   and IPv4-mapped IPv6 forms of those are rejected.
3. TCP ports must be on a small allow-list; HTTP(S) only on web ports.
4. Only http/https URLs without embedded credentials are accepted.

``LINKGUARD_ALLOW_PRIVATE_TARGETS=1`` relaxes rules 2 and 3 for local,
controlled tests only (see config.py).
"""

import ipaddress
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

from app.config import Settings

SAFE_TCP_PORTS = frozenset({22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 8080, 8443})
SAFE_HTTP_PORTS = frozenset({80, 443, 8080, 8443})

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_BLOCKED_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".lan",
    ".home",
    ".home.arpa",
    ".localdomain",
    ".intranet",
    ".corp",
)


class TargetRejected(ValueError):
    """Raised when a target fails validation. The message is safe to show users."""

    def __init__(self, message: str, code: str = "target_rejected"):
        super().__init__(message)
        self.message = message
        self.code = code


@dataclass(frozen=True)
class Host:
    name: str  # normalized host (lower-case, no trailing dot)
    ip: Optional[str] = None  # set when the host is an IP literal

    @property
    def is_ip(self) -> bool:
        return self.ip is not None


def is_public_ip(ip: "ipaddress.IPv4Address | ipaddress.IPv6Address") -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return False
    return bool(ip.is_global)


def check_ip_allowed(ip_text: str, settings: Settings) -> None:
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError as exc:  # pragma: no cover - defensive
        raise TargetRejected("Not a valid IP address.") from exc
    if not settings.allow_private_targets and not is_public_ip(ip):
        raise TargetRejected(
            "Destination is not a public address (loopback, private, link-local, "
            "multicast and reserved ranges are blocked)."
        )


def parse_host(raw: str, settings: Settings) -> Host:
    value = (raw or "").strip().lower()
    if not value:
        raise TargetRejected("Target is empty.")
    if any(ch.isspace() for ch in value) or any(c in value for c in "/\\@?#%"):
        raise TargetRejected("Target must be a bare domain name or IP address (no paths or credentials).")

    bare = value[1:-1] if value.startswith("[") and value.endswith("]") else value
    try:
        ip = ipaddress.ip_address(bare)
    except ValueError:
        ip = None
    if ip is not None:
        check_ip_allowed(str(ip), settings)
        return Host(name=str(ip), ip=str(ip))

    if ":" in value:
        raise TargetRejected("Target must not include a port; use the port field.")
    name = value.rstrip(".")
    if not name.isascii():
        raise TargetRejected("Use the punycode (xn--) form for internationalized names.")
    if len(name) > 253:
        raise TargetRejected("Domain name is too long.")
    labels = name.split(".")
    if any(not _LABEL.match(label) for label in labels):
        raise TargetRejected("Not a valid domain name.")
    if labels[-1].isdigit():
        raise TargetRejected("Not a valid domain name (numeric top-level label).")
    if not settings.allow_private_targets:
        if name == "localhost" or name.endswith(_BLOCKED_SUFFIXES):
            raise TargetRejected("Local and internal host names are not allowed.")
        if len(labels) < 2:
            raise TargetRejected("Use a fully qualified domain name such as example.com.")
    return Host(name=name)


def check_tcp_port(port: int, settings: Settings) -> None:
    if not 1 <= port <= 65535:
        raise TargetRejected("Port must be between 1 and 65535.", code="port_rejected")
    if not settings.allow_private_targets and port not in SAFE_TCP_PORTS:
        allowed = ", ".join(str(p) for p in sorted(SAFE_TCP_PORTS))
        raise TargetRejected(f"Port {port} is not allowed. Allowed ports: {allowed}.", code="port_rejected")


@dataclass(frozen=True)
class ParsedUrl:
    scheme: str
    host: Host
    port: int
    path: str  # path + query, always starts with "/"


def parse_http_url(url: str, settings: Settings) -> ParsedUrl:
    try:
        parts = urlsplit(url.strip())
        port = parts.port
    except ValueError as exc:
        raise TargetRejected("Not a valid URL.") from exc
    if parts.scheme not in ("http", "https"):
        raise TargetRejected("URL must start with http:// or https://.")
    if parts.username or parts.password:
        raise TargetRejected("URLs with embedded credentials are not allowed.")
    if not parts.hostname:
        raise TargetRejected("URL has no host.")
    host = parse_host(parts.hostname, settings)
    effective = port or (443 if parts.scheme == "https" else 80)
    if not settings.allow_private_targets and effective not in SAFE_HTTP_PORTS:
        allowed = ", ".join(str(p) for p in sorted(SAFE_HTTP_PORTS))
        raise TargetRejected(f"Port {effective} is not allowed for HTTP checks. Allowed: {allowed}.", code="port_rejected")
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return ParsedUrl(scheme=parts.scheme, host=host, port=effective, path=path)
