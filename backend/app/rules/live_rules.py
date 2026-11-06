"""Rules that read evidence from live DNS / TCP / HTTP checks.

Each check is one attempt from one machine at one moment. Failures are never
generalized to "the network is down".
"""

from app.rules.base import Rule, RuleContext
from app.schemas.models import Evidence, Finding

ONE_ATTEMPT = "This is a single attempt from the host running LinkGuard at one moment; it says nothing about other hosts, networks or times."
STATUS_MAP = {"success": "ok", "failure": "issue", "unavailable": "inconclusive", "inconclusive": "inconclusive"}


def _ms(e: Evidence) -> str:
    return f"{e.data['elapsed_ms']:g} ms" if e.data.get("elapsed_ms") is not None else "unknown time"


class LiveDnsRule(Rule):
    rule_id = "LIVE-DNS-001"
    title = "Live DNS lookup"
    source = "live_check"
    description = "Interprets the outcome of a DNS lookup made with the host's system resolver."
    triggers = "A live DNS check is part of the investigation."
    does_not_prove = "That DNS is broken everywhere. Only the host's configured resolver was asked, once."

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for e in ctx.of_kind("dns_check"):
            status, kind, target = e.data["status"], e.data.get("error_kind"), e.data["target"]
            base = dict(evidence=[e])
            if status == "success":
                addrs = e.data.get("addresses", [])
                out.append(self.finding(
                    [e], title="DNS lookup succeeded", severity="info", status="ok",
                    observed=f"{target} resolved to {len(addrs)} address(es) ({', '.join(addrs[:4])}) in {_ms(e)}.",
                    interpretation="The host's resolver returned an answer for this name at this moment.",
                    limitations=[ONE_ATTEMPT, "Other resolvers or cached answers may differ; a correct lookup does not show the service is reachable."],
                    next_test="If the application still fails, run a TCP check to one of the returned addresses.",
                ))
            elif status == "failure":
                out.append(self.finding(
                    [e], title="DNS lookup failed", severity="medium", status="issue",
                    observed=f"{target}: {e.data['message']} ({_ms(e)}).",
                    interpretation="The configured resolver gave a negative answer for this name from this host.",
                    limitations=[ONE_ATTEMPT, "The system resolver interface does not expose the exact DNS RCODE, so NXDOMAIN and 'no data' look alike."],
                    alternatives=["Mistyped or non-existent name", "No record of the requested type (A vs AAAA)", "Resolver policy or upstream failure"],
                    next_test="Check the spelling, try the other record type, and compare against a different resolver or a known-good name.",
                ))
            else:  # unavailable or inconclusive
                out.append(self.finding(
                    [e], title="DNS lookup could not be completed", severity="low", status="inconclusive",
                    observed=f"{target}: {e.data['message']} ({_ms(e)}).",
                    interpretation="The lookup did not return a usable answer, and the cause cannot be told from this single attempt. This does not show the name is invalid.",
                    limitations=[ONE_ATTEMPT, "A timeout or temporary failure can mean an unreachable resolver, a slow upstream, or a local network problem."],
                    alternatives=["Resolver unreachable from this host", "Local connectivity problem", "Slow upstream resolution"],
                    next_test="Repeat the lookup, then try a name known to exist; if both fail, check the host's network and resolver configuration.",
                ))
        return out


_TCP_FAILURES = {
    "connection_refused": (
        "The destination (or a device on the path) actively refused the connection.",
        ["No service listening on that port", "Firewall rejecting the connection", "Service restarting"],
    ),
    "connection_reset": (
        "The connection was reset while it was being set up.",
        ["Service or load balancer rejecting the client", "Middlebox policy", "Service crashing"],
    ),
}


class LiveTcpRule(Rule):
    rule_id = "LIVE-TCP-001"
    title = "Live TCP connection check"
    source = "live_check"
    description = "Interprets a TCP connect() attempt to a host and port."
    triggers = "A live TCP check is part of the investigation."
    does_not_prove = "That the host or whole network is down. One refused or timed-out attempt is one observation."

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for e in ctx.of_kind("tcp_check"):
            status, kind, target = e.data["status"], e.data.get("error_kind"), e.data["target"]
            if status == "success":
                out.append(self.finding(
                    [e], title="TCP connection succeeded", severity="info", status="ok",
                    observed=f"TCP handshake to {target} completed in {_ms(e)}.",
                    interpretation="Something accepted a TCP connection on this port from this host, so a network path existed at this moment.",
                    limitations=[ONE_ATTEMPT, "Says nothing about TLS, HTTP or the application behind the port."],
                    next_test="Run an HTTP check to confirm the application responds correctly.",
                ))
            elif status == "failure":
                meaning, alts = _TCP_FAILURES.get(kind, ("The connection attempt failed.", ["Unknown"]))
                out.append(self.finding(
                    [e], title="TCP connection failed", severity="medium", status="issue",
                    observed=f"Connection to {target} failed: {e.data['message']} ({_ms(e)}).",
                    interpretation=f"{meaning} A host or device answered, so complete loss of connectivity is not indicated.",
                    limitations=[ONE_ATTEMPT, "A refusal or reset cannot tell you which device produced it or why."],
                    alternatives=alts,
                    next_test="Check that the service is running on the expected port, try a second known-open port on the same host, and capture packets while repeating the check.",
                ))
            else:
                out.append(self.finding(
                    [e], title="TCP connection check inconclusive", severity="low", status="inconclusive",
                    observed=f"Connection to {target}: {e.data['message']} ({_ms(e)}).",
                    interpretation="No definite answer was obtained. Silence and local failures can have many causes, so no conclusion is drawn about the destination or the network.",
                    limitations=[ONE_ATTEMPT, "A timeout can be packet loss, a firewall that drops packets, a slow path, or a host that is off."],
                    alternatives=["Firewall silently dropping packets", "Host or path unavailable", "Packet loss or a slow path", "No route from this host (e.g. IPv6)"],
                    next_test="Retry with a longer timeout (max 10 s), try another port or address family, and run a DNS check if the name did not resolve.",
                ))
        return out


class LiveHttpRule(Rule):
    rule_id = "LIVE-HTTP-001"
    title = "Live HTTP(S) request"
    source = "live_check"
    description = "Interprets the status line (or failure) of one HTTP(S) request."
    triggers = "A live HTTP check is part of the investigation."
    does_not_prove = "A network fault. An HTTP error status means the server answered, so the path worked well enough to get a reply."

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for e in ctx.of_kind("http_check"):
            status, kind, target = e.data["status"], e.data.get("error_kind"), e.data["target"]
            code = e.data.get("status_code")
            if status == "success":
                note = " The redirect was not followed." if code and 300 <= code < 400 else ""
                out.append(self.finding(
                    [e], title="HTTP request succeeded", severity="info", status="ok",
                    observed=f"{target} answered HTTP {code} {e.data.get('reason', '')} in {_ms(e)}.{note}",
                    interpretation="DNS, TCP and (for https) TLS worked for this request, and the server returned a non-error status.",
                    limitations=[ONE_ATTEMPT, "One URL and method only; other paths, clients or times may behave differently."],
                    next_test="If users still report problems, compare timings across repeated checks or capture a failing session.",
                ))
            elif kind in ("http_4xx", "http_5xx"):
                server_side = kind == "http_5xx"
                out.append(self.finding(
                    [e], title="HTTP server-side error response" if server_side else "HTTP client-error response",
                    severity="medium" if server_side else "low", status="issue",
                    observed=f"{target} answered HTTP {code} {e.data.get('reason', '')} in {_ms(e)}.",
                    interpretation=(
                        "The server returned an error status. It was reachable and spoke HTTP, so this points at the server or application, not necessarily at the network."
                        if server_side else
                        "The server rejected or could not find the request. It was reachable and spoke HTTP, so this is not a connectivity failure."
                    ),
                    limitations=[ONE_ATTEMPT, "An HTTP status does not by itself show a network failure.", "A transient error may disappear on retry."],
                    alternatives=(["Application bug or overload", "Upstream or database failure", "Maintenance or deployment in progress"] if server_side
                                  else ["Wrong URL or removed resource", "Authentication or permission requirement", "Bot or rate-limit policy"]),
                    next_test="Repeat the request a few times and compare; check server or application logs for the failing request." if server_side
                    else "Verify the URL, then try with the credentials or headers the real client sends.",
                ))
            elif status == "failure":
                out.append(self.finding(
                    [e], title="HTTP request failed", severity="medium", status="issue",
                    observed=f"{target}: {e.data['message']} ({_ms(e)}).",
                    interpretation={
                        "tls_verification_failed": "The TLS certificate was not accepted, so no HTTP exchange took place. This points at the certificate or the name used, not at connectivity.",
                        "tls_error": "The TLS handshake failed before HTTP could be exchanged.",
                    }.get(kind or "", "The request failed before a normal HTTP response was received."),
                    limitations=[ONE_ATTEMPT, "The failing layer is named, but not necessarily its root cause."],
                    alternatives=["Expired, mismatched or untrusted certificate" if (kind or "").startswith("tls") else "Service refusing or resetting connections",
                                  "Middlebox interference", "Server misconfiguration"],
                    next_test="Run DNS and TCP checks against the same host to see which stage fails, and inspect the certificate chain." if (kind or "").startswith("tls")
                    else "Run DNS and TCP checks against the same host to find the failing stage.",
                ))
            else:
                out.append(self.finding(
                    [e], title="HTTP request inconclusive", severity="low", status="inconclusive",
                    observed=f"{target}: {e.data['message']} ({_ms(e)}).",
                    interpretation="No complete HTTP response was obtained, and the stage that stalled cannot be identified from this single attempt.",
                    limitations=[ONE_ATTEMPT, "A timeout can occur at DNS, TCP, TLS or the server."],
                    alternatives=["Slow or overloaded server", "Packet loss or a slow path", "Local connectivity problem"],
                    next_test="Run separate DNS and TCP checks to see how far the request gets, then retry with a longer timeout.",
                ))
        return out
