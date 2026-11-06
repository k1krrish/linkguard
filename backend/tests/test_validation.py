import pytest

from app.config import get_settings
from app.services.validation import TargetRejected, check_tcp_port, parse_host, parse_http_url

S = get_settings()


@pytest.mark.parametrize("value", ["example.com", "Sub.Example.COM.", "xn--bcher-kva.example", "a-b.example.org"])
def test_valid_domains(value):
    assert parse_host(value, S).name == value.lower().rstrip(".")


@pytest.mark.parametrize("value,ip", [("8.8.8.8", "8.8.8.8"), ("[2606:4700:4700::1111]", "2606:4700:4700::1111")])
def test_valid_public_ips(value, ip):
    assert parse_host(value, S).ip == ip


@pytest.mark.parametrize("value", [
    "127.0.0.1", "10.0.0.5", "172.16.3.4", "192.168.1.1", "169.254.169.254", "224.0.0.1", "0.0.0.0",
    "240.0.0.1", "100.64.0.1", "::1", "fe80::1", "fc00::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
    "192.0.2.1",
])
def test_non_public_ips_rejected(value):
    with pytest.raises(TargetRejected):
        parse_host(value, S)


@pytest.mark.parametrize("value", [
    "", "   ", "localhost", "foo.localhost", "printer.local", "db.internal", "intranet", "exa mple.com",
    "example.com/path", "user@example.com", "example.com:80", "-bad.example.com", "bad-.example.com",
    "a..b.com", "bücher.example", "example.123", "x" * 64 + ".com", "http://example.com", "a;b.com", "$(id).com",
])
def test_bad_hosts_rejected(value):
    with pytest.raises(TargetRejected):
        parse_host(value, S)


def test_overlong_name_rejected():
    with pytest.raises(TargetRejected):
        parse_host(".".join(["a" * 60] * 5) + ".com", S)


@pytest.mark.parametrize("port", [22, 53, 80, 443, 8443])
def test_safe_ports(port):
    check_tcp_port(port, S)


@pytest.mark.parametrize("port", [0, 21, 23, 3306, 6379, 9200, 65536, -1])
def test_unsafe_ports_rejected(port):
    with pytest.raises(TargetRejected):
        check_tcp_port(port, S)


def test_url_parsing():
    p = parse_http_url("https://Example.com/a?b=1", S)
    assert (p.scheme, p.host.name, p.port, p.path) == ("https", "example.com", 443, "/a?b=1")
    assert parse_http_url("http://example.com", S).port == 80


@pytest.mark.parametrize("url", [
    "ftp://example.com", "file:///etc/passwd", "gopher://example.com", "http://user:pw@example.com/",
    "http://127.0.0.1/", "http://[::1]/", "http://169.254.169.254/latest/meta-data", "https://example.com:6379/",
    "http://", "not a url", "http://localhost:8080/", "javascript:alert(1)",
])
def test_bad_urls_rejected(url):
    with pytest.raises(TargetRejected):
        parse_http_url(url, S)


def test_private_override_is_explicit(monkeypatch):
    monkeypatch.setenv("LINKGUARD_ALLOW_PRIVATE_TARGETS", "1")
    s = get_settings()
    assert parse_host("127.0.0.1", s).ip == "127.0.0.1"
    check_tcp_port(5000, s)
    assert parse_host("localhost", s).name == "localhost"
