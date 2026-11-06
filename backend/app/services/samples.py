"""Clearly labelled SIMULATED demonstration scenarios.

Nothing here is observed on a real network. Captures are built by
``fixtures.py`` from documentation-range addresses; "live" check results that
accompany a sample are hand-written and flagged ``simulated=True`` so the UI
and reports always label them as simulated.
"""

from datetime import datetime, timezone
from typing import Callable, Optional

from app.schemas.models import CheckResult, SampleInfo, Symptom

_T0 = datetime(2023, 11, 14, 22, 13, 20, tzinfo=timezone.utc)  # matches fixtures.BASE_TIME


class Sample:
    def __init__(self, id: str, title: str, description: str, teaches: str, symptom: Symptom,
                 target: Optional[str], fixture: Optional[str], checks: Callable[[], list[CheckResult]]):
        self.info = SampleInfo(id=id, title=title, description=description, teaches=teaches, symptom=symptom)
        self.target, self.fixture, self.checks = target, fixture, checks


def _chk(check: str, target: str, status: str, ms: float, message: str, kind: str | None, details: dict) -> CheckResult:
    return CheckResult(check=check, target=target, status=status, started_at=_T0, elapsed_ms=ms,  # type: ignore[arg-type]
                       error_kind=kind, message=message, details={**details, "simulated_note": "Synthetic result - not a live observation."},
                       simulated=True)


SAMPLES: dict[str, Sample] = {s.info.id: s for s in [
    Sample(
        "dns-unanswered", "DNS queries that get no answer",
        "A capture in which one name is queried three times without any matching response, while a second name is answered normally.",
        "Why an unanswered query is not proof that the DNS server failed.",
        "dns_resolution_failure", "unreachable.example.test", "dns_unanswered",
        lambda: [_chk("dns", "unreachable.example.test", "inconclusive", 5003.0,
                      "No answer from the system resolver within 5 s.", "timeout",
                      {"record_type": "A", "resolver": "simulated resolver"})],
    ),
    Sample(
        "tcp-refused", "TCP connection refused (RST)",
        "A capture where a SYN to port 8081 is answered by a reset while another connection to port 443 completes normally.",
        "What a reset means - and what it cannot tell you about the cause.",
        "connection_failure", "service.example.test", "tcp_refused",
        lambda: [_chk("tcp", "service.example.test:8081", "failure", 31.2, "Connection actively refused by the destination or a device on the path.",
                      "connection_refused", {"port": 8081, "attempts": [{"ip": "198.51.100.20", "status": "failure", "error_kind": "connection_refused", "ms": 31.2}]}),
                 _chk("tcp", "service.example.test:443", "success", 24.8, "TCP handshake with 198.51.100.20:443 completed; the connection was closed immediately.",
                      None, {"port": 443, "attempts": [{"ip": "198.51.100.20", "status": "success", "error_kind": None, "ms": 24.8}]})],
    ),
    Sample(
        "http-503", "HTTP 503 from a reachable server",
        "Simulated live checks: DNS and TCP succeed, but the HTTPS request returns 503 Service Unavailable. No capture is attached.",
        "A server-side error status is not a network failure.",
        "http_error", "shop.example.test", None,
        lambda: [
            _chk("dns", "shop.example.test", "success", 18.4, "Resolved to 1 address(es).", None,
                 {"record_type": "A", "addresses": ["198.51.100.20"], "resolver": "simulated resolver"}),
            _chk("tcp", "shop.example.test:443", "success", 26.1, "TCP handshake with 198.51.100.20:443 completed; the connection was closed immediately.",
                 None, {"port": 443, "attempts": [{"ip": "198.51.100.20", "status": "success", "error_kind": None, "ms": 26.1}]}),
            _chk("http", "https://shop.example.test/checkout", "failure", 143.7, "HTTP 503 Service Unavailable - the server answered with an error status.",
                 "http_5xx", {"method": "GET", "status_code": 503, "reason": "Service Unavailable", "http_version": "1.1",
                              "headers": {"retry-after": "30", "content-type": "text/html"}, "transport_ok": True}),
        ],
    ),
    Sample(
        "insufficient", "Too little evidence to conclude",
        "A three-packet capture: a mid-connection ACK, one unrelated UDP datagram and a DNS query sent just before the capture ends.",
        "When a tool should say 'inconclusive' instead of guessing.",
        "unknown", None, "insufficient", lambda: [],
    ),
    Sample(
        "dns-nxdomain", "DNS domain does not exist (NXDOMAIN)",
        "DNS lookup returns RCODE 3 (Non-Existent Domain), proving the resolver is functional but the name is unmapped.",
        "Resolver reachability does not equal domain registration.",
        "dns_resolution_failure", "missing.example.test", "dns_nxdomain",
        lambda: [_chk("dns", "missing.example.test", "failure", 32.5, "DNS query returned NXDOMAIN (Non-Existent Domain).",
                      "nxdomain", {"record_type": "A", "rcode": 3, "resolver": "192.0.2.53"})],
    ),
    Sample(
        "tcp-retrans", "TCP retransmissions & segment drops",
        "A capture showing repeated unacknowledged TCP segments and handshake drops across multiple attempts.",
        "Packet drops and retransmissions cause application timeouts without socket resets.",
        "slow_or_intermittent", "slow.example.test", "tcp_retransmission",
        lambda: [_chk("tcp", "slow.example.test:443", "failure", 5002.1, "TCP connection timed out after repeated retransmission attempts.",
                      "timeout", {"port": 443, "attempts": [{"ip": "203.0.113.30", "status": "timeout", "error_kind": "timeout", "ms": 5002.1}]})],
    ),
    Sample(
        "dns-servfail", "DNS Server Failure (SERVFAIL / DNSSEC)",
        "DNS lookup returns RCODE 2 (Server Failure), indicating an upstream recursive failure or DNSSEC cryptographic validation breakdown.",
        "Why SERVFAIL points to upstream authoritative nameservers rather than local network failure.",
        "dns_resolution_failure", "upstream-auth.example.test", "dns_servfail",
        lambda: [_chk("dns", "upstream-auth.example.test", "failure", 42.1, "DNS query returned SERVFAIL (Server Failure - upstream resolver error).",
                      "name_not_found", {"record_type": "A", "rcode": 2, "resolver": "192.0.2.53"})],
    ),
    Sample(
        "tls-cert-expired", "TLS Certificate Verification Failure",
        "DNS and TCP handshakes succeed, but the HTTPS session aborts during TLS negotiation because the remote certificate has expired.",
        "Transport layer connectivity does not guarantee security/session negotiation.",
        "connection_failure", "secure-vault.example.test", "tcp_midstream_rst",
        lambda: [
            _chk("dns", "secure-vault.example.test", "success", 16.2, "Resolved to 1 address(es).", None,
                 {"record_type": "A", "addresses": ["198.51.100.20"], "resolver": "simulated resolver"}),
            _chk("tcp", "secure-vault.example.test:443", "success", 22.4, "TCP handshake with 198.51.100.20:443 completed.", None,
                 {"port": 443, "attempts": [{"ip": "198.51.100.20", "status": "success", "error_kind": None, "ms": 22.4}]}),
            _chk("http", "https://secure-vault.example.test/api", "failure", 88.5,
                 "Certificate verification failed: certificate has expired (SSL error: CERTIFICATE_VERIFY_FAILED).",
                 "tls_verification_failed", {"method": "GET", "transport_ok": True, "ssl_error": "CERTIFICATE_VERIFY_FAILED"}),
        ],
    ),
    Sample(
        "http-504", "HTTP 504 Gateway Timeout",
        "The reverse proxy accepted the TCP connection, but the upstream application service failed to return an HTTP response before timeout.",
        "Gateway timeouts identify backend application stalls behind healthy reverse proxies.",
        "http_error", "api-gateway.example.test", None,
        lambda: [
            _chk("dns", "api-gateway.example.test", "success", 14.1, "Resolved to 1 address(es).", None,
                 {"record_type": "A", "addresses": ["198.51.100.20"], "resolver": "simulated resolver"}),
            _chk("tcp", "api-gateway.example.test:443", "success", 19.8, "TCP handshake with 198.51.100.20:443 completed.", None,
                 {"port": 443, "attempts": [{"ip": "198.51.100.20", "status": "success", "error_kind": None, "ms": 19.8}]}),
            _chk("http", "https://api-gateway.example.test/v1/data", "failure", 5002.3,
                 "HTTP 504 Gateway Timeout - the reverse proxy timed out waiting for upstream origin.",
                 "http_5xx", {"method": "GET", "status_code": 504, "reason": "Gateway Timeout", "http_version": "1.1",
                              "headers": {"retry-after": "60", "content-type": "text/html"}, "transport_ok": True}),
        ],
    ),
    Sample(
        "tcp-syn-blackhole", "TCP SYN Drop (Firewall Blackhole)",
        "Connection attempts (SYN) receive neither SYN-ACK nor RST; packets are silently dropped by a security perimeter or firewall.",
        "Silent packet dropping (DROP) vs active rejection (REJECT/RST).",
        "connection_failure", "firewall-drop.example.test", "tcp_syn_no_reply",
        lambda: [
            _chk("dns", "firewall-drop.example.test", "success", 20.3, "Resolved to 1 address(es).", None,
                 {"record_type": "A", "addresses": ["203.0.113.30"], "resolver": "simulated resolver"}),
            _chk("tcp", "firewall-drop.example.test:443", "inconclusive", 5001.2,
                 "Connection attempt timed out: no answer from destination within 5 s (SYN retransmissions unacknowledged).",
                 "timeout", {"port": 443, "attempts": [{"ip": "203.0.113.30", "status": "timeout", "error_kind": "timeout", "ms": 5001.2}]}),
        ],
    ),
    Sample(
        "http-403-waf", "HTTP 403 Forbidden (WAF Security Block)",
        "The client request reached the application edge, where a Web Application Firewall inspected request signatures and blocked access.",
        "Network delivery succeeded end-to-end, but layer 7 WAF policy rejected the request.",
        "http_error", "portal.example.test", None,
        lambda: [
            _chk("dns", "portal.example.test", "success", 12.0, "Resolved to 1 address(es).", None,
                 {"record_type": "A", "addresses": ["198.51.100.20"], "resolver": "simulated resolver"}),
            _chk("tcp", "portal.example.test:443", "success", 18.5, "TCP handshake completed.", None,
                 {"port": 443, "attempts": [{"ip": "198.51.100.20", "status": "success", "error_kind": None, "ms": 18.5}]}),
            _chk("http", "https://portal.example.test/admin", "failure", 65.2,
                 "HTTP 403 Forbidden - access denied by WAF security policy rules.",
                 "http_4xx", {"method": "GET", "status_code": 403, "reason": "Forbidden", "http_version": "1.1",
                              "headers": {"server": "CloudShield-WAF", "x-waf-block": "rule-40392"}, "transport_ok": True}),
        ],
    ),
    Sample(
        "http-502", "HTTP 502 Bad Gateway (Upstream Crash)",
        "The reverse proxy received an invalid or truncated HTTP response header from the backend daemon.",
        "Identifies origin backend process failure versus reverse proxy routing problems.",
        "http_error", "billing.example.test", None,
        lambda: [
            _chk("dns", "billing.example.test", "success", 15.3, "Resolved to 1 address(es).", None,
                 {"record_type": "A", "addresses": ["198.51.100.20"], "resolver": "simulated resolver"}),
            _chk("tcp", "billing.example.test:443", "success", 21.0, "TCP handshake completed.", None,
                 {"port": 443, "attempts": [{"ip": "198.51.100.20", "status": "success", "error_kind": None, "ms": 21.0}]}),
            _chk("http", "https://billing.example.test/invoices", "failure", 120.1,
                 "HTTP 502 Bad Gateway - backend service returned an invalid or empty response.",
                 "http_5xx", {"method": "GET", "status_code": 502, "reason": "Bad Gateway", "http_version": "1.1", "transport_ok": True}),
        ],
    ),
    Sample(
        "icmp-unreachable", "ICMP Destination Unreachable (Policy Filter)",
        "Packets directed to an internal subnet are met with ICMP Type 3 Code 13 (Administratively Prohibited) from a transit router.",
        "ICMP control messages reveal route and access-list filtering between network segments.",
        "connection_failure", "internal-router.example.test", "icmp_unreachable",
        lambda: [
            _chk("dns", "internal-router.example.test", "success", 25.0, "Resolved to 1 address(es).", None,
                 {"record_type": "A", "addresses": ["203.0.113.30"], "resolver": "simulated resolver"}),
            _chk("tcp", "internal-router.example.test:443", "failure", 35.4,
                 "Connection rejected: Host administratively prohibited by intermediate gateway router (ICMP type 3 code 13).",
                 "connection_refused", {"port": 443, "attempts": [{"ip": "203.0.113.30", "status": "failure", "error_kind": "connection_refused", "ms": 35.4}]}),
        ],
    ),
    Sample(
        "high-jitter", "Severe Latency Jitter & Bufferbloat",
        "Packet transit time varies wildly between 40ms and 850ms, causing out-of-order delivery and spurious TCP retransmissions.",
        "How bufferbloat and high jitter mimic packet loss and stall TCP windows.",
        "slow_or_intermittent", "latency-spike.example.test", "tcp_retransmission",
        lambda: [
            _chk("dns", "latency-spike.example.test", "success", 18.0, "Resolved to 1 address(es).", None,
                 {"record_type": "A", "addresses": ["203.0.113.30"], "resolver": "simulated resolver"}),
            _chk("tcp", "latency-spike.example.test:443", "failure", 5002.5,
                 "TCP connection timed out during handshake after multiple retransmission attempts (extreme queue delay).",
                 "timeout", {"port": 443, "attempts": [{"ip": "203.0.113.30", "status": "timeout", "error_kind": "timeout", "ms": 5002.5}]}),
        ],
    ),
    Sample(
        "mtu-blackhole", "Path MTU Blackhole (DF Bit Dropped)",
        "TCP handshake completes normally with small packets, but large data packets exceeding tunnel MTU are silently dropped.",
        "Why a connection can open cleanly but freeze as soon as large data payloads or certificates are sent.",
        "slow_or_intermittent", "tunnel-mtu.example.test", "tcp_retransmission",
        lambda: [
            _chk("dns", "tunnel-mtu.example.test", "success", 18.4, "Resolved to 1 address(es).", None,
                 {"record_type": "A", "addresses": ["198.51.100.20"], "resolver": "simulated resolver"}),
            _chk("tcp", "tunnel-mtu.example.test:443", "success", 24.1, "TCP handshake completed (small SYN/ACK frames fit within tunnel MTU).", None,
                 {"port": 443, "attempts": [{"ip": "198.51.100.20", "status": "success", "error_kind": None, "ms": 24.1}]}),
            _chk("http", "https://tunnel-mtu.example.test/payload", "inconclusive", 5004.8,
                 "Request stalled waiting for server response: large segments dropped by intermediate router with DF bit set.",
                 "timeout", {"method": "GET", "transport_ok": True, "pmtu_stall": True}),
        ],
    ),
    Sample(
        "ipv6-unanswered", "IPv6 Dual-Stack Failure (Fallback Delay)",
        "DNS AAAA queries for an IPv6 destination receive no response, forcing clients into Happy Eyeballs fallback delay.",
        "How IPv6 path breaks stall application launch even when IPv4 works.",
        "dns_resolution_failure", "v6.example.test", "ipv6_dns_unanswered",
        lambda: [
            _chk("dns", "v6.example.test", "inconclusive", 5001.0,
                 "No answer for AAAA query from IPv6 resolver within 5 s.", "timeout",
                 {"record_type": "AAAA", "resolver": "2001:db8::53"}),
        ],
    ),
]}


def sample_infos() -> list[SampleInfo]:
    return [s.info for s in SAMPLES.values()]
