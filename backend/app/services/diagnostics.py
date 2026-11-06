"""Live DNS, TCP and HTTP(S) checks.

Every check:
* validates its target first (see validation.py),
* is bounded by a timeout (socket timeouts plus a wall-clock guard),
* returns a ``CheckResult`` with an honest status:
    success      - the check did what it was asked
    failure      - the remote side gave a definite negative answer
    inconclusive - no answer in time; cause cannot be told from this host
    unavailable  - this host could not perform the check (resolver/route problem)
* never invents data: a result is only built from what the OS/network returned.

A single failed check never says "the network is down" - it only describes
what happened to this one attempt from this one machine.
"""

import errno
import http.client
import ipaddress
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from typing import Any, Callable, Optional

from app.config import Settings, get_settings
from app.schemas.models import CheckResult, utcnow
from app.services.validation import (
    Host,
    TargetRejected,
    check_tcp_port,
    is_public_ip,
    parse_host,
    parse_http_url,
)

USER_AGENT = "LinkGuard/2.0 (educational network diagnostics)"
_executor = ThreadPoolExecutor(max_workers=16, thread_name_prefix="linkguard-check")

# Indirection so tests can replace name resolution without touching the network.
_getaddrinfo: Callable[..., list] = socket.getaddrinfo

_FAMILY = {"A": socket.AF_INET, "AAAA": socket.AF_INET6, "BOTH": socket.AF_UNSPEC}
_UNREACHABLE_ERRNOS = {
    errno.ENETUNREACH,
    errno.EHOSTUNREACH,
    errno.ENETDOWN,
    getattr(errno, "EADDRNOTAVAIL", -1),
    getattr(errno, "EAFNOSUPPORT", -1),
}


class _ResolveError(Exception):
    def __init__(self, status: str, kind: str, message: str):
        super().__init__(message)
        self.status, self.kind, self.message = status, kind, message


def _bounded(fn: Callable[[], Any], timeout: float) -> Any:
    """Run ``fn`` in a worker thread and give up waiting after ``timeout`` seconds."""
    future = _executor.submit(fn)
    try:
        return future.result(timeout=timeout)
    except FutureTimeout as exc:
        raise TimeoutError("operation exceeded its time budget") from exc


def _resolve(name: str, family: int, timeout: float) -> list[str]:
    """Resolve with the system resolver. Returns unique addresses in resolver order."""

    def work() -> list[str]:
        infos = _getaddrinfo(name, None, family, socket.SOCK_STREAM)
        seen: list[str] = []
        for info in infos:
            addr = info[4][0]
            if addr not in seen:
                seen.append(addr)
        return seen

    try:
        return _bounded(work, timeout)
    except TimeoutError as exc:
        raise _ResolveError(
            "inconclusive", "timeout", f"No answer from the system resolver within {timeout:g} s."
        ) from exc
    except socket.gaierror as exc:
        code = exc.errno
        if code in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -5)):
            raise _ResolveError(
                "failure",
                "name_not_found",
                "The resolver reported that the name could not be resolved (no such name, or no record of the requested type).",
            ) from exc
        if code == socket.EAI_AGAIN:
            raise _ResolveError(
                "unavailable",
                "resolver_unavailable",
                "Temporary failure in name resolution: the resolver could not be reached or did not answer usefully.",
            ) from exc
        if code == socket.EAI_FAIL:
            raise _ResolveError(
                "failure", "resolver_error", "The resolver reported a non-recoverable error for this name."
            ) from exc
        raise _ResolveError(
            "unavailable", "resolver_error", f"Name resolution could not be completed ({exc.strerror or 'error'})."
        ) from exc
    except OSError as exc:
        raise _ResolveError("unavailable", "resolver_error", "Name resolution could not be performed on this host.") from exc


def _result(
    check: str,
    target: str,
    status: str,
    started,
    t0: float,
    message: str,
    error_kind: Optional[str] = None,
    details: Optional[dict[str, Any]] = None,
) -> CheckResult:
    return CheckResult(
        check=check,  # type: ignore[arg-type]
        target=target,
        status=status,  # type: ignore[arg-type]
        started_at=started,
        elapsed_ms=round((time.perf_counter() - t0) * 1000, 1),
        error_kind=error_kind,
        message=message,
        details=details or {},
    )


def _connect_addresses(host: Host, family: int, timeout: float, settings: Settings) -> list[str]:
    """Addresses to connect to. Rejects the target if ANY resolved address is non-public."""
    if host.ip:
        return [host.ip]
    addrs = _resolve(host.name, family, timeout)
    if not settings.allow_private_targets:
        for addr in addrs:
            if not is_public_ip(ipaddress.ip_address(addr)):
                raise TargetRejected(
                    f"{host.name} resolves to a non-public address; connecting to it is blocked.",
                    code="target_rejected",
                )
    return addrs


# --------------------------------------------------------------------------
# DNS
# --------------------------------------------------------------------------
def dns_check(target: str, record_type: str = "A", timeout: Optional[float] = None) -> CheckResult:
    settings = get_settings()
    timeout = min(timeout or settings.default_timeout, settings.max_timeout)
    host = parse_host(target, settings)
    if host.is_ip:
        raise TargetRejected("A DNS lookup needs a domain name, not an IP address.")
    started, t0 = utcnow(), time.perf_counter()
    base = {"record_type": record_type, "resolver": "system resolver of the host running LinkGuard"}
    try:
        addrs = _resolve(host.name, _FAMILY[record_type], timeout)
    except _ResolveError as err:
        return _result("dns", host.name, err.status, started, t0, err.message, err.kind, base)
    non_public = any(not is_public_ip(ipaddress.ip_address(a)) for a in addrs)
    details = {**base, "addresses": addrs, "contains_non_public_address": non_public}
    return _result("dns", host.name, "success", started, t0, f"Resolved to {len(addrs)} address(es).", None, details)


# --------------------------------------------------------------------------
# TCP
# --------------------------------------------------------------------------
def _tcp_attempt(ip: str, port: int, timeout: float) -> tuple[str, str, Optional[str]]:
    """One connection attempt. Returns (status, error_kind|'', os_message)."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except ConnectionRefusedError:
        return "failure", "connection_refused", "Connection actively refused by the destination or a device on the path."
    except (TimeoutError, socket.timeout):
        return "inconclusive", "timeout", f"No reply within {timeout:g} s."
    except ConnectionResetError:
        return "failure", "connection_reset", "Connection was reset during setup."
    except OSError as exc:
        if exc.errno in _UNREACHABLE_ERRNOS:
            return "unavailable", "network_unreachable", "This host has no usable route to the destination."
        return "unavailable", "os_error", f"Connection could not be attempted ({exc.strerror or 'OS error'})."
    sock.close()
    return "success", "", None


def tcp_check(target: str, port: int, timeout: Optional[float] = None) -> CheckResult:
    settings = get_settings()
    timeout = min(timeout or settings.default_timeout, settings.max_timeout)
    host = parse_host(target, settings)
    check_tcp_port(port, settings)
    started, t0 = utcnow(), time.perf_counter()
    label = f"{host.name}:{port}"
    try:
        addrs = _connect_addresses(host, socket.AF_UNSPEC, timeout, settings)
    except _ResolveError as err:
        return _result(
            "tcp",
            label,
            "unavailable",
            started,
            t0,
            f"No connection was attempted because the name could not be resolved ({err.kind}).",
            "resolution_failed",
            {"port": port, "resolution_status": err.status},
        )

    attempts: list[dict[str, Any]] = []
    final = ("unavailable", "no_address", "No address available to connect to.")
    for ip in addrs[:2]:  # bounded: at most two addresses per check
        remaining = timeout - (time.perf_counter() - t0)
        if remaining <= 0.05:
            break
        a0 = time.perf_counter()
        status, kind, msg = _tcp_attempt(ip, port, remaining)
        attempts.append(
            {"ip": ip, "status": status, "error_kind": kind or None, "ms": round((time.perf_counter() - a0) * 1000, 1)}
        )
        if status == "success":
            final = (status, "", f"TCP handshake with {ip}:{port} completed; the connection was closed immediately.")
            break
        if final[1] == "no_address" or len(attempts) == 1:
            final = (status, kind, msg or "")
    status, kind, msg = final
    return _result("tcp", label, status, started, t0, msg, kind or None, {"port": port, "attempts": attempts})


# --------------------------------------------------------------------------
# HTTP / HTTPS
# --------------------------------------------------------------------------
class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Connects to an already-validated IP while keeping the original Host header."""

    def __init__(self, host: str, port: int, ip: str, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._ip, self.port), timeout=self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, ip: str, timeout: float):
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._ip = ip

    def connect(self) -> None:
        raw = socket.create_connection((self._ip, self.port), timeout=self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)  # type: ignore[attr-defined]


_KEEP_HEADERS = ("server", "content-type", "content-length", "location", "retry-after", "via")


def http_check(url: str, method: str = "GET", timeout: Optional[float] = None) -> CheckResult:
    settings = get_settings()
    timeout = min(timeout or settings.default_timeout, settings.max_timeout)
    parsed = parse_http_url(url, settings)
    started, t0 = utcnow(), time.perf_counter()
    label = f"{parsed.scheme}://{parsed.host.name}" + ("" if parsed.port in (80, 443) else f":{parsed.port}") + parsed.path
    base = {"method": method, "redirects_followed": False}

    try:
        addrs = _connect_addresses(parsed.host, socket.AF_UNSPEC, timeout, settings)
    except _ResolveError as err:
        return _result(
            "http", label, "unavailable", started, t0,
            f"No request was sent because the name could not be resolved ({err.kind}).",
            "resolution_failed", {**base, "resolution_status": err.status},
        )

    ip = addrs[0]
    conn_cls = _PinnedHTTPSConnection if parsed.scheme == "https" else _PinnedHTTPConnection
    conn = conn_cls(parsed.host.name, parsed.port, ip, max(timeout - (time.perf_counter() - t0), 0.1))
    details: dict[str, Any] = {**base, "connected_ip": ip}
    try:
        conn.request(method, parsed.path, headers={"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"})
        resp = conn.getresponse()
        code = resp.status
        details.update(
            status_code=code,
            reason=resp.reason,
            http_version="1.1" if resp.version == 11 else "1.0",
            headers={h: resp.getheader(h) for h in _KEEP_HEADERS if resp.getheader(h)},
        )
        if parsed.scheme == "https" and conn.sock is not None:
            details["tls_version"] = conn.sock.version()  # type: ignore[union-attr]
        resp.close()
    except ssl.SSLCertVerificationError as exc:
        return _result("http", label, "failure", started, t0,
                       "TLS certificate verification failed.", "tls_verification_failed",
                       {**details, "tls_error": getattr(exc, "verify_message", "certificate verify failed")})
    except ssl.SSLError as exc:
        return _result("http", label, "failure", started, t0, "TLS handshake failed.", "tls_error",
                       {**details, "tls_error": exc.reason or "ssl error"})
    except ConnectionRefusedError:
        return _result("http", label, "failure", started, t0,
                       "Connection actively refused by the destination or a device on the path.", "connection_refused", details)
    except ConnectionResetError:
        return _result("http", label, "failure", started, t0, "Connection was reset before a response arrived.", "connection_reset", details)
    except (TimeoutError, socket.timeout):
        return _result("http", label, "inconclusive", started, t0, f"No complete response within {timeout:g} s.", "timeout", details)
    except http.client.HTTPException as exc:
        return _result("http", label, "failure", started, t0,
                       f"The server sent a malformed HTTP response ({type(exc).__name__}).", "protocol_error", details)
    except OSError as exc:
        kind = "network_unreachable" if exc.errno in _UNREACHABLE_ERRNOS else "os_error"
        return _result("http", label, "unavailable", started, t0,
                       f"The request could not be performed from this host ({exc.strerror or 'OS error'}).", kind, details)
    finally:
        conn.close()

    reason = f"HTTP {code} {details['reason']}".strip()
    if code < 400:
        note = " (redirect not followed)" if 300 <= code < 400 else ""
        return _result("http", label, "success", started, t0, f"{reason}{note}", None, details)
    kind = "http_4xx" if code < 500 else "http_5xx"
    details["transport_ok"] = True
    return _result("http", label, "failure", started, t0, f"{reason} - the server answered with an error status.", kind, details)
