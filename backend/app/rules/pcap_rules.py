"""Rules that read evidence extracted from a packet capture.

Wording policy: say what was OBSERVED IN THE CAPTURE. Absence from a capture
is never reported as "did not happen". Each finding lists limitations and
alternative explanations.
"""

from app.rules.base import Rule, RuleContext
from app.schemas.models import Finding

END_OF_CAPTURE_GRACE_S = 2.0  # a query this close to the end may simply have been cut off
MIN_PACKETS = 6
_ANOMALY_KINDS = ("dns_unanswered_query", "dns_error_response", "tcp_reset", "tcp_retransmission", "tcp_syn_no_reply")
CAPTURE_POINT = (
    "A capture only shows traffic that crossed the capture point; where it was taken (client, server, or a mirror port) "
    "changes what can be seen."
)


def _names(items: list[str], limit: int = 4) -> str:
    shown = ", ".join(items[:limit])
    return shown + (f" (+{len(items) - limit} more)" if len(items) > limit else "")


class DnsUnansweredRule(Rule):
    rule_id = "DNS-001"
    title = "DNS query with no matching response in the capture"
    source = "pcap"
    description = "Matches each DNS query to a response by client address/port, DNS ID, name and type."
    triggers = "A query has no matching response later in the same capture."
    does_not_prove = "That the DNS server failed. The response may have been lost, filtered or simply not captured."

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        txns = ctx.capture.dns_transactions if ctx.capture else []
        if not txns:
            return []
        unanswered = ctx.of_kind("dns_unanswered_query")
        if not unanswered:
            summary = ctx.of_kind("capture_summary")
            return [self.finding(
                summary, title="All DNS queries in the capture have a matching response", severity="info", status="ok",
                observed=f"{len(txns)} DNS query transaction(s) observed; each has a matching response in the capture.",
                interpretation="Within this capture, name resolution traffic was answered. Response codes are checked separately by DNS-002.",
                limitations=[CAPTURE_POINT, "Matching uses client address/port, DNS ID, name and type; unusual setups (NAT, DNS proxies) can defeat matching."],
                next_test="If the symptom persists, look at the TCP/HTTP stage: run a live TCP check to the resolved address.",
            )]
        settled = [e for e in unanswered if e.data["seconds_before_capture_end"] >= END_OF_CAPTURE_GRACE_S]
        retried = [e for e in unanswered if e.data["attempts"] >= 2]
        names = [f"{e.data['qname']} ({e.data['attempts']} attempt{'s' if e.data['attempts'] != 1 else ''})" for e in unanswered]
        status = "issue" if settled else "inconclusive"
        severity = "medium" if retried and settled else "low"
        limits = [
            "Not observed in this capture is not the same as did not happen: the response may have been dropped, filtered, or missed by the capture point.",
            CAPTURE_POINT,
            "Responses are matched on client address/port, DNS ID, name and type; a response that differs in any of these would not be matched.",
        ]
        if not settled:
            limits.insert(0, f"Every unanswered query was sent within {END_OF_CAPTURE_GRACE_S:g} s of the end of the capture, so the capture may have ended before a response could arrive.")
        return [self.finding(
            unanswered, title=self.title, severity=severity, status=status,
            observed=f"{len(unanswered)} DNS query transaction(s) had no matching response in this capture: {_names(names)}.",
            interpretation=(
                "The resolver's answer was not seen in this capture. That is consistent with an unreachable or unresponsive resolver, "
                "but it is equally consistent with the other explanations below." + (" Repeated attempts show the client retried." if retried else "")
            ),
            limitations=limits,
            alternatives=[
                "Resolver is down, overloaded or rate-limiting",
                "Query or response was dropped on the path (firewall, packet loss)",
                "Response bypassed this capture point (asymmetric routing, capture filter)",
                "Capture started late or ended early",
            ],
            next_test="Run a live DNS check for the same name, then re-capture with a filter that keeps both directions of port 53 for longer than the client's resolver timeout.",
        )]


class DnsErrorRule(Rule):
    rule_id = "DNS-002"
    title = "DNS response with an error code"
    source = "pcap"
    description = "Looks at the RCODE of matched DNS responses."
    triggers = "A matched response has an RCODE other than NOERROR (for example NXDOMAIN, SERVFAIL, REFUSED)."
    does_not_prove = "That the network is faulty. A response arrived, so the resolver was reachable."

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        errs = ctx.of_kind("dns_error_response")
        if not errs:
            return []
        codes = sorted({e.data["rcode_name"] for e in errs})
        hard = any(c in ("SERVFAIL", "REFUSED", "FORMERR", "NOTIMP") or c.startswith("RCODE") for c in codes)
        meaning = {
            "NXDOMAIN": "the resolver said the name does not exist",
            "SERVFAIL": "the resolver could not complete the lookup",
            "REFUSED": "the server declined to answer (policy or access control)",
            "FORMERR": "the server could not parse the query",
            "NOTIMP": "the server does not support the request type",
        }
        detail = "; ".join(f"{c}: {meaning.get(c, 'non-standard error code')}" for c in codes)
        return [self.finding(
            errs, title=self.title, severity="medium" if hard else "low", status="issue",
            observed=f"{len(errs)} DNS response(s) carried an error code ({', '.join(codes)}) for: {_names([e.data['qname'] for e in errs])}.",
            interpretation=f"A response was received, so the resolver was reachable. In these responses, {detail}.",
            limitations=[
                "NXDOMAIN can be a normal outcome (typos, search-domain expansion, probing for optional names).",
                "The error comes from the resolver that answered; other resolvers may answer differently.",
                CAPTURE_POINT,
            ],
            alternatives=["Mistyped or expired name", "Missing record for the requested type", "Resolver policy, filtering or upstream failure"],
            next_test="Look up the same name through a different resolver and compare results; check spelling and the zone's records.",
        )]


class TcpResetRule(Rule):
    rule_id = "TCP-001"
    title = "TCP reset observed"
    source = "pcap"
    description = "Finds packets with the RST flag and records whether the handshake preceded them."
    triggers = "At least one TCP segment with the RST flag set."
    does_not_prove = "Which device sent the reset or why. Many normal stacks use resets."

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        resets = ctx.of_kind("tcp_reset")
        if not resets:
            return []
        total = sum(e.data["reset_count"] for e in resets)
        syn_rst = [e for e in resets if e.data["context"] == "syn_answered_by_rst"]
        flows = [f"{e.data['client']} -> {e.data['server']}" for e in resets]
        if syn_rst:
            interp = (
                "In at least one flow a connection attempt (SYN) was answered by a reset instead of a SYN/ACK. "
                "This is what a closed port typically produces, but a firewall or other device on the path can send the same reply."
            )
        else:
            interp = (
                "A reset abruptly ends a TCP connection. Endpoints send resets for many reasons, "
                "so a reset alone does not identify the underlying cause."
            )
        return [self.finding(
            resets, title=self.title, severity="medium" if syn_rst else "low", status="issue",
            observed=f"{total} TCP reset(s) in {len(resets)} flow(s): {_names(flows)}.",
            interpretation=interp,
            limitations=[
                "A reset does not uniquely identify its cause or its sender; a middlebox can send resets on behalf of an endpoint.",
                "Client/server roles are inferred from the direction of the first SYN seen in the capture.",
                CAPTURE_POINT,
            ],
            alternatives=[
                "No process listening on the destination port",
                "Firewall or load balancer rejecting the connection",
                "Application closed the socket abruptly (for example with unread data)",
                "Connection state expired on a stateful device",
            ],
            next_test="Run a live TCP check to the same host and port; verify a service is listening and check firewall logs. Comparing the IP TTL of the reset with other packets from that server can hint whether it came from a different device.",
        )]


class TcpRetransmissionRule(Rule):
    rule_id = "TCP-002"
    title = "TCP retransmission indicators observed"
    source = "pcap"
    description = "Flags an exact repeat of a segment (same flow, direction, sequence number and payload length) or a repeated SYN/SYN-ACK."
    triggers = "The same segment appears again in the same direction within the capture."
    does_not_prove = "Congestion. Retransmissions show that a sender re-sent data, not why."

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        rtx = ctx.of_kind("tcp_retransmission")
        if not rtx:
            return []
        hs = sum(e.data["handshake_repeats"] for e in rtx)
        data = sum(e.data["data_repeats"] for e in rtx)
        total = hs + data
        return [self.finding(
            rtx, title=self.title, severity="medium" if hs or total >= 3 else "low", status="issue",
            observed=f"{total} repeated TCP segment(s) across {len(rtx)} flow(s): {data} data segment(s), {hs} handshake segment(s).",
            interpretation=(
                "A segment with the same sequence number (and length) was sent again in the same direction, which is how TCP behaves "
                "when it does not see a timely acknowledgment. Repeated handshake segments mean connection setup was retried."
            ),
            limitations=[
                "Retransmissions alone do not prove congestion or loss; they show only that the sender repeated a segment.",
                "Detection is conservative: only exact repeats are flagged, so partial overlaps and out-of-order delivery are not counted.",
                "Identical packets can also come from capture or link-layer duplication, especially on mirror ports.",
                CAPTURE_POINT,
            ],
            alternatives=[
                "Packet loss in either direction",
                "ACKs delayed or lost on the return path",
                "High latency relative to the sender's retransmission timer",
                "Receiver overloaded or not reading data",
                "Duplicated frames at the capture point",
            ],
            next_test="Repeat live TCP checks at different times to see whether setup delays or failures recur, and capture at the other end of the path to compare which copies arrive.",
        )]


class TcpSynNoReplyRule(Rule):
    rule_id = "TCP-003"
    title = "SYN sent with no reply observed in the capture"
    source = "pcap"
    description = "Finds connection attempts for which neither SYN/ACK nor RST appears in the capture."
    triggers = "A flow has a SYN but no SYN/ACK or RST observed later."
    does_not_prove = "That no reply was sent. It only says no reply was observed here."

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        syns = ctx.of_kind("tcp_syn_no_reply")
        if not syns:
            return []
        flows = [f"{e.data['client']} -> {e.data['server']} ({e.data['syn_count']} SYN)" for e in syns]
        return [self.finding(
            syns, title=self.title, severity="low", status="inconclusive",
            observed=f"{len(syns)} flow(s) show a SYN with no SYN/ACK or RST observed in this capture: {_names(flows)}.",
            interpretation="The destination's reply was not seen here. That is consistent with a dropped or filtered connection attempt, but the evidence is not enough to say which.",
            limitations=[
                "Not observed in this capture is not the same as did not happen.",
                "The capture may have ended before a reply arrived, or the reply may have bypassed the capture point.",
                CAPTURE_POINT,
            ],
            alternatives=["Firewall silently dropping the SYN", "Destination host down or unreachable", "Packet loss", "Reply not captured"],
            next_test="Run a live TCP check to the same host and port, then capture on both ends of the path to see whether the SYN arrives.",
        )]


def capture_gaps(ctx: RuleContext) -> list[str]:
    cap = ctx.capture
    if cap is None:
        return []
    gaps: list[str] = []
    if cap.total_packets == 0:
        gaps.append("The capture contains no packets.")
    elif cap.total_packets < MIN_PACKETS:
        gaps.append(f"Only {cap.total_packets} packet(s) were captured, which is too few to judge a connection or name-resolution problem.")
    if cap.total_packets and cap.dns_packets == 0 and cap.tcp_packets == 0:
        gaps.append("No DNS or TCP packets were found, so the DNS/TCP rules had nothing to examine.")
    if cap.truncated:
        gaps.append("Analysis was limited before the end of the file; later packets were not examined.")
    gaps.extend(cap.warnings)
    if cap.unparsed_packets:
        gaps.append(f"{cap.unparsed_packets} packet(s) could not be fully dissected.")
    return gaps


class EvidenceGapRule(Rule):
    rule_id = "EVID-001"
    title = "Insufficient or incomplete packet evidence"
    source = "pcap"
    description = "Checks whether the capture is large and complete enough for the other rules to be meaningful."
    triggers = "Empty or very small capture, no DNS/TCP traffic, truncated file or limited analysis."
    does_not_prove = "That anything is wrong. It only says the evidence cannot support a conclusion."

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        gaps = capture_gaps(ctx)
        if not gaps:
            return []
        return [self.finding(
            ctx.of_kind("capture_summary"), title=self.title, severity="low", status="inconclusive",
            observed=" ".join(gaps),
            interpretation="The capture does not contain enough evidence to support a conclusion about the reported symptom.",
            limitations=["Any finding drawn from such a capture would rest on very little data.",
                         "Flows whose handshake is missing from the capture cannot be classified reliably."],
            alternatives=["Capture started after the problem began", "Capture filter excluded relevant traffic", "Wrong interface or capture point"],
            next_test="Start the capture before reproducing the problem, capture on the correct interface for long enough to include the failure, and upload it again.",
        )]


class CaptureNoMatchRule(Rule):
    rule_id = "CAP-001"
    title = "No packet rule matched in the capture"
    source = "pcap"
    description = "Reports when a capture of reasonable size produced no DNS/TCP anomaly indicators."
    triggers = "Capture has enough packets and none of the other capture rules produced evidence."
    does_not_prove = "That the network is healthy. This tool only looks for a few DNS/TCP indicators."

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        if ctx.capture is None or capture_gaps(ctx) or ctx.of_kind(*_ANOMALY_KINDS):
            return []
        cap = ctx.capture
        return [self.finding(
            ctx.of_kind("capture_summary"), title=self.title, severity="info", status="ok",
            observed=f"None of this tool's packet rules matched in the {cap.total_packets} packets examined.",
            interpretation="Within the captured window and capture point, no unanswered DNS queries, DNS error responses, TCP resets, repeated segments or unanswered SYNs were observed.",
            limitations=[
                "Only a few DNS/TCP indicators are checked; problems at other layers or outside the captured period would not appear.",
                CAPTURE_POINT,
            ],
            next_test="If the symptom persists, capture again while reproducing it, or run live DNS/TCP/HTTP checks.",
        )]
