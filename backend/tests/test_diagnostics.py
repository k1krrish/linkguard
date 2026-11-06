"""Live-check tests use ONLY local, controlled servers or patched resolvers - never the internet."""

import http.server
import socket
import threading
import time

import pytest

from app.services import diagnostics
from app.services.validation import TargetRejected


@pytest.fixture
def allow_local(monkeypatch):
    monkeypatch.setenv("LINKGUARD_ALLOW_PRIVATE_TARGETS", "1")


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        code = {"/ok": 200, "/missing": 404, "/boom": 503, "/moved": 302}.get(self.path, 200)
        self.send_response(code)
        if code == 302:
            self.send_header("Location", "/ok")
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_HEAD = do_GET

    def log_message(self, *a):
        pass


@pytest.fixture
def web():
    srv = http.server.HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# -- TCP ------------------------------------------------------------------------
def test_tcp_success_local(allow_local, web):
    r = diagnostics.tcp_check("127.0.0.1", web, 2)
    assert r.status == "success" and r.elapsed_ms is not None and r.check == "tcp"


def test_tcp_refused_local(allow_local):
    r = diagnostics.tcp_check("127.0.0.1", _closed_port(), 2)
    assert r.status == "failure" and r.error_kind == "connection_refused"


def test_tcp_timeout_is_inconclusive(allow_local, monkeypatch):
    def slow(*a, **k):
        raise TimeoutError("timed out")
    monkeypatch.setattr(diagnostics.socket, "create_connection", slow)
    r = diagnostics.tcp_check("127.0.0.1", 9, 1)
    assert r.status == "inconclusive" and r.error_kind == "timeout"


def test_tcp_no_route_is_unavailable(allow_local, monkeypatch):
    import errno
    def unreachable(*a, **k):
        raise OSError(errno.ENETUNREACH, "Network is unreachable")
    monkeypatch.setattr(diagnostics.socket, "create_connection", unreachable)
    r = diagnostics.tcp_check("127.0.0.1", 9, 1)
    assert r.status == "unavailable" and r.error_kind == "network_unreachable"


def test_tcp_rejects_private_by_default():
    with pytest.raises(TargetRejected):
        diagnostics.tcp_check("127.0.0.1", 80, 1)
    with pytest.raises(TargetRejected):
        diagnostics.tcp_check("example.com", 3306, 1)


def test_tcp_blocks_domain_resolving_to_private(monkeypatch):
    monkeypatch.setattr(diagnostics, "_getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("10.1.2.3", 0))])
    with pytest.raises(TargetRejected):
        diagnostics.tcp_check("rebind.example.com", 443, 1)


def test_tcp_unresolvable_reports_unavailable_not_failure(monkeypatch):
    def nx(*a, **k):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
    monkeypatch.setattr(diagnostics, "_getaddrinfo", nx)
    r = diagnostics.tcp_check("nope.example.com", 443, 1)
    assert r.status == "unavailable" and r.error_kind == "resolution_failed"


# -- DNS ------------------------------------------------------------------------
def test_dns_success_patched(monkeypatch):
    monkeypatch.setattr(diagnostics, "_getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("198.51.100.7", 0)), (2, 1, 6, "", ("198.51.100.7", 0)), (2, 1, 6, "", ("198.51.100.8", 0))])
    r = diagnostics.dns_check("example.com", "A", 2)
    assert r.status == "success" and r.details["addresses"] == ["198.51.100.7", "198.51.100.8"]


@pytest.mark.parametrize("code,status,kind", [
    (socket.EAI_NONAME, "failure", "name_not_found"),
    (socket.EAI_AGAIN, "unavailable", "resolver_unavailable"),
    (socket.EAI_FAIL, "failure", "resolver_error"),
])
def test_dns_errors_map_to_honest_status(monkeypatch, code, status, kind):
    def boom(*a, **k):
        raise socket.gaierror(code, "x")
    monkeypatch.setattr(diagnostics, "_getaddrinfo", boom)
    r = diagnostics.dns_check("example.com", "A", 2)
    assert (r.status, r.error_kind) == (status, kind)


def test_dns_timeout_is_bounded_and_inconclusive(monkeypatch):
    monkeypatch.setattr(diagnostics, "_getaddrinfo", lambda *a, **k: time.sleep(2) or [])
    t0 = time.perf_counter()
    r = diagnostics.dns_check("example.com", "A", 0.3)
    assert r.status == "inconclusive" and r.error_kind == "timeout"
    assert time.perf_counter() - t0 < 1.5


def test_dns_rejects_ip_and_localhost():
    with pytest.raises(TargetRejected):
        diagnostics.dns_check("8.8.8.8")
    with pytest.raises(TargetRejected):
        diagnostics.dns_check("localhost")


def test_timeout_is_capped_by_settings(monkeypatch):
    seen = {}
    def fake(name, family, timeout):
        seen["t"] = timeout
        return ["198.51.100.1"]
    monkeypatch.setattr(diagnostics, "_resolve", fake)
    diagnostics.dns_check("example.com", "A", 999)
    assert seen["t"] == 10.0


# -- HTTP -----------------------------------------------------------------------
def test_http_200(allow_local, web):
    r = diagnostics.http_check(f"http://127.0.0.1:{web}/ok", "GET", 2)
    assert r.status == "success" and r.details["status_code"] == 200


def test_http_503_is_failure_with_transport_ok(allow_local, web):
    r = diagnostics.http_check(f"http://127.0.0.1:{web}/boom", "GET", 2)
    assert r.status == "failure" and r.error_kind == "http_5xx" and r.details["transport_ok"] is True


def test_http_404_is_4xx(allow_local, web):
    r = diagnostics.http_check(f"http://127.0.0.1:{web}/missing", "HEAD", 2)
    assert r.error_kind == "http_4xx"


def test_http_redirect_not_followed(allow_local, web):
    r = diagnostics.http_check(f"http://127.0.0.1:{web}/moved", "GET", 2)
    assert r.status == "success" and r.details["status_code"] == 302 and "not followed" in r.message


def test_http_refused(allow_local):
    r = diagnostics.http_check(f"http://127.0.0.1:{_closed_port()}/", "GET", 2)
    assert r.status == "failure" and r.error_kind == "connection_refused"


def test_http_timeout_inconclusive(allow_local):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)  # accepts connections but never answers
    try:
        r = diagnostics.http_check(f"http://127.0.0.1:{srv.getsockname()[1]}/", "GET", 0.4)
        assert r.status == "inconclusive" and r.error_kind == "timeout"
    finally:
        srv.close()


def test_http_rejects_private_by_default():
    for url in ("http://127.0.0.1/", "http://169.254.169.254/", "ftp://example.com/"):
        with pytest.raises(TargetRejected):
            diagnostics.http_check(url)
