"""Turn raw results (live checks, parsed capture) into normalized ``Evidence``.

The rule engine reads ONLY this normalized form. That keeps rules small and
lets one rule work for evidence from any source.
"""

from typing import Optional

from app.schemas.models import CheckResult, Evidence
from app.services.pcap import _RESET_PHRASES, ParsedCapture

KIND_BY_CHECK = {"dns": "dns_check", "tcp": "tcp_check", "http": "http_check"}


def build_evidence(checks: list[CheckResult], parsed: Optional[ParsedCapture]) -> list[Evidence]:
    out: list[Evidence] = []
    for n, chk in enumerate(checks, 1):
        out.append(
            Evidence(
                id=f"E-CHK-{n}",
                kind=KIND_BY_CHECK[chk.check],
                source="live_check",
                summary=f"{chk.check.upper()} check of {chk.target}: {chk.status} - {chk.message}",
                observed_at=chk.started_at,
                simulated=chk.simulated,
                data={
                    "target": chk.target,
                    "status": chk.status,
                    "error_kind": chk.error_kind,
                    "elapsed_ms": chk.elapsed_ms,
                    "message": chk.message,
                    **chk.details,
                },
            )
        )
    if parsed is not None:
        out.extend(_capture_evidence(parsed))
    return out


def _capture_evidence(parsed: ParsedCapture) -> list[Evidence]:
    cap, pkts = parsed.summary, parsed.packets
    sim = cap.simulated
    last_ts = cap.last_timestamp or 0.0
    out: list[Evidence] = [
        Evidence(
            id="E-CAP-1",
            kind="capture_summary",
            source="pcap",
            simulated=sim,
            summary=f"Capture of {cap.total_packets} packets over {cap.duration_seconds:.2f} s "
            f"({cap.dns_packets} DNS, {cap.tcp_packets} TCP).",
            data={
                "total_packets": cap.total_packets,
                "dns_packets": cap.dns_packets,
                "tcp_packets": cap.tcp_packets,
                "duration_seconds": cap.duration_seconds,
                "truncated": cap.truncated,
                "warnings": cap.warnings,
                "unparsed_packets": cap.unparsed_packets,
                "file_format": cap.file_format,
                "flows_without_handshake": sum(1 for f in cap.tcp_flows if not f.syn_seen),
            },
        )
    ]
    for t in cap.dns_transactions:
        if not t.answered:
            out.append(
                Evidence(
                    id=f"E-DNS-{t.id}", kind="dns_unanswered_query", source="pcap", simulated=sim,
                    summary=f"{t.attempts} DNS quer{'y' if t.attempts == 1 else 'ies'} for {t.qname} ({t.qtype}) "
                    f"from {t.client} to {t.server}; no matching response observed in the capture.",
                    data={"qname": t.qname, "qtype": t.qtype, "client": t.client, "server": t.server,
                          "attempts": t.attempts, "seconds_before_capture_end": t.seconds_before_capture_end},
                    packet_refs=t.query_packets,
                )
            )
        elif t.rcode_name not in (None, "NOERROR"):
            out.append(
                Evidence(
                    id=f"E-DNSERR-{t.id}", kind="dns_error_response", source="pcap", simulated=sim,
                    summary=f"DNS response {t.rcode_name} for {t.qname} ({t.qtype}) from {t.responder}.",
                    data={"qname": t.qname, "qtype": t.qtype, "rcode_name": t.rcode_name, "responder": t.responder,
                          "client": t.client},
                    packet_refs=t.response_packets,
                )
            )
    for f in cap.tcp_flows:
        if f.reset_packets:
            out.append(
                Evidence(
                    id=f"E-RST-{f.id}", kind="tcp_reset", source="pcap", simulated=sim,
                    summary=f"{len(f.reset_packets)} TCP reset(s) in flow {f.client} -> {f.server}: "
                    f"{_RESET_PHRASES.get(f.reset_context or '', 'context unknown')}.",
                    data={"flow_id": f.id, "client": f.client, "server": f.server, "reset_count": len(f.reset_packets),
                          "context": f.reset_context, "syn_seen": f.syn_seen, "synack_seen": f.synack_seen},
                    packet_refs=f.reset_packets,
                )
            )
        if f.retransmission_packets:
            handshake = sum(1 for i in f.retransmission_packets if "SYN" in (pkts[i - 1].tcp_flags or ""))
            data_count = len(f.retransmission_packets) - handshake
            out.append(
                Evidence(
                    id=f"E-RTX-{f.id}", kind="tcp_retransmission", source="pcap", simulated=sim,
                    summary=f"{len(f.retransmission_packets)} repeated segment(s) in flow {f.client} -> {f.server} "
                    f"({handshake} handshake, {data_count} data).",
                    data={"flow_id": f.id, "client": f.client, "server": f.server,
                          "handshake_repeats": handshake, "data_repeats": data_count},
                    packet_refs=f.retransmission_packets,
                )
            )
        if f.syn_seen and not f.synack_seen and not f.reset_packets:
            last_syn = pkts[f.syn_packets[-1] - 1].timestamp if f.syn_packets else last_ts
            out.append(
                Evidence(
                    id=f"E-SYN-{f.id}", kind="tcp_syn_no_reply", source="pcap", simulated=sim,
                    summary=f"SYN sent {f.syn_count} time(s) from {f.client} to {f.server}; "
                    "no SYN/ACK or RST observed in the capture.",
                    data={"flow_id": f.id, "client": f.client, "server": f.server, "syn_count": f.syn_count,
                          "seconds_before_capture_end": round(max(last_ts - last_syn, 0.0), 6)},
                    packet_refs=f.syn_packets,
                )
            )
    return out
