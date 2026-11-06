"""PCAP / PCAPNG analyzer (Scapy).

Design notes
------------
* The upload is parsed from memory (``io.BytesIO``); nothing is written to disk
  and the raw bytes are dropped as soon as parsing finishes.
* Only metadata is kept: addresses, ports, TCP flags/sequence numbers, DNS
  names and rcodes. Payload bytes are never stored or returned.
* The analyzer reports what is *observed in the capture*. It never states that
  something did not happen - only that it was "not observed in this capture".
* Retransmission detection is deliberately conservative: only an exact repeat
  of (flow, direction, seq, payload length) - or a repeated SYN/SYN-ACK with
  the same sequence number - is flagged. Duplicate ACKs and out-of-order
  segments are NOT flagged, so absence of a flag is not proof of no loss.
"""

import io
import logging
import struct
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Optional

from scapy.layers.dns import DNS, dnsqtypes
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP
from scapy.packet import NoPayload, Packet, Padding, Raw
from scapy.utils import PcapReader

from app.config import get_settings
from app.schemas.models import (
    CaptureSummary,
    DnsInfo,
    DnsTransaction,
    EndpointCount,
    LayerInfo,
    PacketDetail,
    TcpFlow,
    TimeBucket,
    TimelineEvent,
)

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

PCAP_MAGICS = {
    bytes.fromhex("a1b2c3d4"): ("pcap", ">"),
    bytes.fromhex("d4c3b2a1"): ("pcap", "<"),
    bytes.fromhex("a1b23c4d"): ("pcap", ">"),  # nanosecond resolution
    bytes.fromhex("4d3cb2a1"): ("pcap", "<"),
}
PCAPNG_MAGIC = bytes.fromhex("0a0d0d0a")

MAX_EVENTS = 300
MAX_LIST = 200
PARSE_TIME_BUDGET_S = 20.0
_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
_ICMP_TYPES = {0: "Echo reply", 3: "Destination unreachable", 5: "Redirect", 8: "Echo request", 11: "Time exceeded"}
_TCP_BITS = [(0x02, "SYN"), (0x10, "ACK"), (0x01, "FIN"), (0x04, "RST"), (0x08, "PSH"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR")]
_LAYER_FIELDS = {
    "Ether": ["type"],
    "IP": ["version", "ihl", "tos", "len", "id", "flags", "frag", "ttl", "proto"],
    "IPv6": ["tc", "fl", "plen", "nh", "hlim"],
    "TCP": ["sport", "dport", "seq", "ack", "dataofs", "flags", "window", "urgptr"],
    "UDP": ["sport", "dport", "len"],
    "ICMP": ["type", "code"],
    "ARP": ["op"],
    "DNS": ["id", "qr", "opcode", "rcode", "qdcount", "ancount", "nscount", "arcount"],
}
_RESET_PHRASES = {
    "syn_answered_by_rst": "a SYN was answered by a reset (no SYN/ACK observed first)",
    "reset_after_handshake": "reset sent after the handshake was observed",
    "no_handshake_observed": "reset on a connection whose handshake is not in this capture",
    "other_before_handshake": "reset sent by the initiating side before a SYN/ACK was observed",
}


class CaptureError(ValueError):
    """Capture could not be analyzed. ``message`` is safe to show to users."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code, self.message = code, message


@dataclass
class ParsedCapture:
    summary: CaptureSummary
    packets: list[PacketDetail] = field(default_factory=list)


# --------------------------------------------------------------------------
# Format detection / integrity
# --------------------------------------------------------------------------
def detect_format(data: bytes) -> str:
    if len(data) < 12:
        raise CaptureError("not_a_capture", "File is too small to be a PCAP/PCAPNG capture.")
    head = data[:4]
    if head in PCAP_MAGICS:
        return "pcap"
    if head == PCAPNG_MAGIC:
        return "pcapng"
    raise CaptureError("not_a_capture", "File is not a PCAP or PCAPNG capture (unrecognized file signature).")


def _pcap_integrity_warning(data: bytes) -> Optional[str]:
    """Walk classic-pcap record headers; report if the last record is cut off."""
    endian = PCAP_MAGICS[data[:4]][1]
    pos, size = 24, len(data)
    while pos < size:
        if pos + 16 > size:
            return "Capture file is truncated: the last record header is incomplete."
        incl_len = struct.unpack(endian + "I", data[pos + 8 : pos + 12])[0]
        pos += 16 + incl_len
        if pos > size:
            return "Capture file is truncated: the last packet record is incomplete."
    return None


# --------------------------------------------------------------------------
# Per-packet dissection
# --------------------------------------------------------------------------
def _flag_names(value: int) -> list[str]:
    return [name for bit, name in _TCP_BITS if value & bit]


def _plain(value: Any) -> Any:
    return value if isinstance(value, (int, str, bool)) or value is None else str(value)


def _layers(pkt: Packet) -> list[LayerInfo]:
    out: list[LayerInfo] = []
    layer: Any = pkt
    for _ in range(12):
        if layer is None or isinstance(layer, NoPayload):
            break
        cls = type(layer).__name__
        if isinstance(layer, (Raw, Padding)):
            label = "Payload (bytes not displayed)" if isinstance(layer, Raw) else "Padding"
            out.append(LayerInfo(name=label, fields={"length": len(bytes(layer))}))
        else:
            fields = {f: _plain(getattr(layer, f, None)) for f in _LAYER_FIELDS.get(cls, [])}
            out.append(LayerInfo(name=layer.name, fields={k: v for k, v in fields.items() if v is not None}))
        layer = layer.payload
    return out


def _transport(net: Packet) -> Any:
    layer = net.payload
    for _ in range(8):
        if getattr(layer, "name", "").startswith("IPv6 Extension Header"):
            layer = layer.payload
        else:
            break
    return layer


def _first(value: Any) -> Any:
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def _text(value: Any) -> str:
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)


def _dns_info(dns: DNS) -> Optional[DnsInfo]:
    if getattr(dns, "opcode", 0) != 0:
        return None
    question = _first(dns.qd)
    qname = _text(question.qname).rstrip(".") if question is not None and hasattr(question, "qname") else None
    qtype = None
    if question is not None and hasattr(question, "qtype"):
        qtype = dnsqtypes.get(question.qtype, str(question.qtype))
    is_response = bool(dns.qr)
    answers: list[str] = []
    for rr in (dns.an if isinstance(dns.an, (list, tuple)) else []):
        if len(answers) >= 8:
            break
        rtype = dnsqtypes.get(getattr(rr, "type", None), None)
        if rtype in ("A", "AAAA", "CNAME"):
            answers.append(f"{rtype} {_text(getattr(rr, 'rdata', ''))}".rstrip("."))
    rcode = int(dns.rcode) if is_response else None
    return DnsInfo(
        id=int(dns.id),
        is_response=is_response,
        qname=qname,
        qtype=qtype,
        rcode=rcode,
        rcode_name=(_RCODES.get(rcode, f"RCODE{rcode}") if rcode is not None else None),
        answer_count=int(dns.ancount or 0),
        answers=answers,
    )


def _tcp_payload_len(net: Packet, tcp: TCP, version: int) -> Optional[int]:
    """Segment payload length from header fields (immune to Ethernet padding/snaplen)."""
    try:
        header = int(tcp.dataofs) * 4
        if version == 4:
            total = int(net.len or 0)
            length = total - int(net.ihl) * 4 - header if total else None
        else:
            length = int(net.plen) - header if net.nh == 6 and net.plen else None
    except (TypeError, ValueError):
        return None
    return length if length is not None and length >= 0 else None


def _dissect(pkt: Packet, index: int, t0: float) -> PacketDetail:
    ts = float(pkt.time)
    length = int(getattr(pkt, "wirelen", None) or len(pkt))
    d = PacketDetail(index=index, timestamp=ts, rel_time=round(ts - t0, 6), protocol="Other", length=length)
    d.layers = _layers(pkt)

    arp = pkt.getlayer(ARP)
    ip4 = pkt.getlayer(IP)
    ip6 = pkt.getlayer(IPv6) if ip4 is None else None
    net = ip4 if ip4 is not None else ip6

    if net is None:
        if arp is not None:
            d.protocol, d.src, d.dst = "ARP", arp.psrc, arp.pdst
            d.info = f"Who has {arp.pdst}? Tell {arp.psrc}" if arp.op == 1 else f"{arp.psrc} replies (op {arp.op})"
        else:
            d.info = "No IP layer found"
        return d

    d.ip_version = 4 if ip4 is not None else 6
    d.src, d.dst = net.src, net.dst
    d.ttl = int(net.ttl if ip4 is not None else net.hlim)
    if ip4 is not None and int(net.frag or 0) > 0:
        d.info = f"IPv4 fragment (offset {int(net.frag) * 8}); transport header not in this fragment"
        return d

    t = _transport(net)
    if isinstance(t, TCP):
        d.protocol = "TCP"
        d.src_port, d.dst_port = int(t.sport), int(t.dport)
        names = _flag_names(int(t.flags))
        d.tcp_flags = ",".join(names) if names else "NONE"
        d.tcp_seq, d.tcp_ack, d.tcp_window = int(t.seq), int(t.ack), int(t.window)
        d.tcp_payload_len = _tcp_payload_len(net, t, d.ip_version)
        plen = "?" if d.tcp_payload_len is None else d.tcp_payload_len
        d.info = f"{d.src_port} -> {d.dst_port} [{d.tcp_flags}] Seq={d.tcp_seq} Ack={d.tcp_ack} Len={plen}"
        if 53 in (d.src_port, d.dst_port) and d.tcp_payload_len and d.tcp_payload_len >= 14:
            raw = bytes(t.payload)
            if len(raw) >= 14 and int.from_bytes(raw[:2], "big") == len(raw) - 2:
                try:
                    d.dns = _dns_info(DNS(raw[2:]))
                except Exception:  # noqa: BLE001 - malformed DNS is simply not decoded
                    d.dns = None
                if d.dns:
                    d.protocol = "DNS"
    elif isinstance(t, UDP):
        d.protocol = "UDP"
        d.src_port, d.dst_port = int(t.sport), int(t.dport)
        d.info = f"{d.src_port} -> {d.dst_port} Len={int(t.len or 0)}"
        if isinstance(t.payload, DNS):
            if 53 in (d.src_port, d.dst_port):
                d.dns = _dns_info(t.payload)
                if d.dns:
                    d.protocol = "DNS"
            elif 5353 in (d.src_port, d.dst_port):
                d.protocol = "mDNS"
    elif isinstance(t, ICMP):
        d.protocol = "ICMP"
        d.info = f"{_ICMP_TYPES.get(int(t.type), 'ICMP')} (type {int(t.type)}, code {int(t.code)})"
    elif getattr(t, "name", "").startswith("ICMPv6"):
        d.protocol, d.info = "ICMPv6", t.name
    else:
        proto = net.proto if ip4 is not None else net.nh
        d.info = f"IP protocol {proto}"

    if d.dns:
        q = d.dns
        what = f"{q.qname or '?'} {q.qtype or ''}".strip()
        d.info = (f"Response {q.rcode_name} {what}" + (f" -> {', '.join(q.answers)}" if q.answers else "")) if q.is_response else f"Query {what}"
    return d


# --------------------------------------------------------------------------
# Cross-packet analysis (DNS transactions, TCP flows, events)
# --------------------------------------------------------------------------
@dataclass
class _Txn:
    client: str
    server: str
    qname: str
    qtype: str
    packets: list[int] = field(default_factory=list)
    times: list[float] = field(default_factory=list)
    first_rel: float = 0.0
    responses: list[int] = field(default_factory=list)
    rcode_name: Optional[str] = None
    responder: Optional[str] = None


@dataclass
class _Flow:
    id: str
    client: Optional[tuple] = None
    server: Optional[tuple] = None
    packets: int = 0
    first: int = 0
    last: int = 0
    syn_count: int = 0
    syn_seen: bool = False
    synack_seen: bool = False
    handshake_ack: bool = False
    resets: list[tuple[int, str]] = field(default_factory=list)  # (packet, context)
    retrans: list[int] = field(default_factory=list)
    syn_packets: list[int] = field(default_factory=list)
    seen: set = field(default_factory=set)


def _ep(ip: Optional[str], port: Optional[int]) -> str:
    return f"[{ip}]:{port}" if ip and ":" in ip else f"{ip}:{port}"


class _Analyzer:
    def __init__(self) -> None:
        self.txns: dict[tuple, _Txn] = {}
        self.flows: dict[tuple, _Flow] = {}
        self.events: list[TimelineEvent] = []
        self.events_truncated = False

    def _event(self, d: PacketDetail, kind: str, level: str, text: str) -> None:
        if len(self.events) >= MAX_EVENTS:
            self.events_truncated = True
            return
        self.events.append(TimelineEvent(packet=d.index, rel_time=d.rel_time, kind=kind, level=level, description=text))  # type: ignore[arg-type]

    def feed(self, d: PacketDetail) -> None:
        if d.dns is not None and d.src_port is not None:
            self._dns(d)
        if d.tcp_flags is not None and d.src and d.dst:
            self._tcp(d)

    # -- DNS ----------------------------------------------------------------
    def _dns(self, d: PacketDetail) -> None:
        q = d.dns
        if q is None or not q.qname or not q.qtype:
            return
        name = q.qname.lower()
        if not q.is_response:
            key = (d.src, d.src_port, q.id, name, q.qtype)
            txn = self.txns.get(key)
            if txn is None:
                txn = self.txns[key] = _Txn(_ep(d.src, d.src_port), _ep(d.dst, d.dst_port), q.qname, q.qtype, first_rel=d.rel_time)
                self._event(d, "dns_query", "info", f"DNS query for {q.qname} ({q.qtype}) from {txn.client} to {txn.server}")
            else:
                self._event(d, "dns_query_repeat", "notable", f"DNS query for {q.qname} repeated (attempt {len(txn.packets) + 1})")
            txn.packets.append(d.index)
            txn.times.append(d.timestamp)
        else:
            txn = self.txns.get((d.dst, d.dst_port, q.id, name, q.qtype))
            if txn is None or d.index < txn.packets[0]:
                return  # response without a query seen earlier in this capture: not matched
            txn.responses.append(d.index)
            if txn.rcode_name is None:
                txn.rcode_name, txn.responder = q.rcode_name, _ep(d.src, d.src_port)
            level = "info" if q.rcode_name == "NOERROR" else "warning"
            self._event(d, "dns_response", level, f"DNS response {q.rcode_name} for {q.qname} ({q.qtype})")

    # -- TCP ----------------------------------------------------------------
    def _tcp(self, d: PacketDetail) -> None:
        a, b = (d.src, d.src_port), (d.dst, d.dst_port)
        key = (min(a, b), max(a, b))
        flow = self.flows.get(key)
        if flow is None:
            flow = self.flows[key] = _Flow(id=f"F{len(self.flows) + 1}", first=d.index)
        flow.packets += 1
        flow.last = d.index
        flags = set((d.tcp_flags or "").split(","))
        syn, ack, rst = "SYN" in flags, "ACK" in flags, "RST" in flags
        sender = a

        if syn and not ack:
            flow.syn_count += 1
            flow.syn_seen = True
            flow.syn_packets.append(d.index)
            if flow.client is None:
                flow.client, flow.server = a, b
            if flow.syn_count == 1:
                self._event(d, "tcp_syn", "info", f"TCP SYN {_ep(*a)} -> {_ep(*b)}")
        elif syn and ack:
            if not flow.synack_seen:
                self._event(d, "tcp_synack", "info", f"TCP SYN/ACK {_ep(*a)} -> {_ep(*b)}")
            flow.synack_seen = True
            if flow.client is None:
                flow.client, flow.server = b, a
        elif ack and not rst and flow.synack_seen and sender == flow.client:
            flow.handshake_ack = True
        if flow.client is None:
            flow.client, flow.server = a, b  # capture started mid-connection: roles are a guess

        # Retransmission indicator: exact repeat of an earlier segment in the same direction.
        signature = None
        if syn:
            signature = ("SYN", sender, d.tcp_seq, ack)
        elif d.tcp_payload_len and not rst:
            signature = ("DATA", sender, d.tcp_seq, d.tcp_payload_len)
        if signature is not None:
            if signature in flow.seen:
                flow.retrans.append(d.index)
                d.markers.append("retransmission")
                kind = "handshake segment" if syn else f"{d.tcp_payload_len}-byte data segment"
                self._event(d, "tcp_retransmission", "warning", f"Repeated {kind} (Seq={d.tcp_seq}) from {_ep(*a)}: retransmission indicator")
            flow.seen.add(signature)

        if rst:
            if not flow.syn_seen:
                ctx = "no_handshake_observed"
            elif flow.synack_seen:
                ctx = "reset_after_handshake"
            elif sender != flow.client:
                ctx = "syn_answered_by_rst"
            else:
                ctx = "other_before_handshake"
            flow.resets.append((d.index, ctx))
            d.markers.append("reset")
            self._event(d, "tcp_reset", "warning", f"TCP RST from {_ep(*a)} to {_ep(*b)}: {_RESET_PHRASES[ctx]}")

    # -- results --------------------------------------------------------------
    def dns_transactions(self, last_ts: float, packets: list[PacketDetail]) -> list[DnsTransaction]:
        out: list[DnsTransaction] = []
        for i, txn in enumerate(self.txns.values(), 1):
            answered = bool(txn.responses)
            if not answered:
                for idx in txn.packets:
                    packets[idx - 1].markers.append("dns_unanswered")
            elif txn.rcode_name not in (None, "NOERROR"):
                for idx in txn.responses:
                    packets[idx - 1].markers.append("dns_error")
            out.append(
                DnsTransaction(
                    id=f"D{i}", qname=txn.qname, qtype=txn.qtype, client=txn.client, server=txn.server,
                    attempts=len(txn.packets), query_packets=txn.packets, response_packets=txn.responses,
                    answered=answered, rcode_name=txn.rcode_name, responder=txn.responder,
                    first_query_rel_time=txn.first_rel,
                    seconds_before_capture_end=round(max(last_ts - max(txn.times), 0.0), 6),
                )
            )
        return out

    def tcp_flows(self, packets: list[PacketDetail]) -> list[TcpFlow]:
        out: list[TcpFlow] = []
        for flow in self.flows.values():
            handshake = flow.syn_seen and flow.synack_seen and flow.handshake_ack
            if flow.resets:
                outcome = "Reset observed: " + _RESET_PHRASES[flow.resets[0][1]]
            elif handshake:
                outcome = "Three-way handshake observed"
            elif flow.syn_seen and not flow.synack_seen:
                outcome = "SYN observed; no reply observed in this capture"
                for idx in flow.syn_packets:
                    packets[idx - 1].markers.append("syn_no_reply")
            elif flow.syn_seen:
                outcome = "SYN and SYN/ACK observed; final ACK not observed in this capture"
            else:
                outcome = "Capture starts mid-connection (handshake not in this capture)"
            out.append(
                TcpFlow(
                    id=flow.id, client=_ep(*flow.client), server=_ep(*flow.server), packets=flow.packets,
                    first_packet=flow.first, last_packet=flow.last, syn_count=flow.syn_count, syn_packets=flow.syn_packets,
                    syn_seen=flow.syn_seen, synack_seen=flow.synack_seen, handshake_observed=handshake,
                    reset_packets=[p for p, _ in flow.resets], reset_context=flow.resets[0][1] if flow.resets else None,
                    retransmission_packets=flow.retrans, outcome=outcome,
                )
            )
        return out


def _buckets(packets: list[PacketDetail], max_buckets: int = 30) -> list[TimeBucket]:
    """Packet counts over time (equal-width buckets) for the activity chart."""
    if not packets:
        return []
    duration = packets[-1].rel_time if packets[-1].rel_time >= packets[0].rel_time else max(p.rel_time for p in packets)
    n = max(1, min(max_buckets, len(packets)))
    width = (duration / n) if duration > 0 else 1.0
    counts, flagged = [0] * n, [0] * n
    for p in packets:
        i = min(int(max(p.rel_time, 0) / width), n - 1) if duration > 0 else 0
        counts[i] += 1
        flagged[i] += 1 if p.markers else 0
    return [TimeBucket(start=round(i * width, 3), packets=counts[i], flagged=flagged[i]) for i in range(n)]


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
def analyze_capture(data: bytes, filename: Optional[str] = None, simulated: bool = False) -> ParsedCapture:
    settings = get_settings()
    if len(data) > settings.max_upload_bytes:
        raise CaptureError("file_too_large", f"Capture exceeds the {settings.max_upload_bytes // (1024 * 1024)} MB limit.")
    fmt = detect_format(data)
    warnings: list[str] = []
    if fmt == "pcap":
        note = _pcap_integrity_warning(data)
        if note:
            warnings.append(note)
    try:
        reader = PcapReader(io.BytesIO(data))
    except Exception as exc:  # noqa: BLE001
        raise CaptureError("unreadable_capture", "The capture header could not be read; the file may be corrupt.") from exc

    analyzer = _Analyzer()
    packets: list[PacketDetail] = []
    unparsed, truncated, t0 = 0, False, 0.0
    started = time.monotonic()
    try:
        for raw in reader:
            if len(packets) >= settings.max_packets:
                truncated = True
                warnings.append(f"Analysis stopped after the first {settings.max_packets:,} packets (configured limit).")
                break
            if time.monotonic() - started > PARSE_TIME_BUDGET_S:
                truncated = True
                warnings.append(f"Analysis stopped after {PARSE_TIME_BUDGET_S:g} s (time budget); later packets were not analyzed.")
                break
            index = len(packets) + 1
            try:
                if index == 1:
                    t0 = float(raw.time)
                detail = _dissect(raw, index, t0)
            except Exception:  # noqa: BLE001 - one bad packet must not abort the capture
                unparsed += 1
                ts = float(getattr(raw, "time", t0) or t0)
                detail = PacketDetail(index=index, timestamp=ts, rel_time=round(ts - t0, 6), protocol="Other",
                                      length=len(raw), info="Packet could not be dissected")
            packets.append(detail)
            try:
                analyzer.feed(detail)
            except Exception:  # noqa: BLE001
                unparsed += 1
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Reading stopped early ({type(exc).__name__}); packets read so far were analyzed.")
    finally:
        try:
            reader.close()
        except Exception:  # noqa: BLE001
            pass

    last_ts = max((p.timestamp for p in packets), default=0.0)
    first_ts = packets[0].timestamp if packets else None
    protocol_counts = Counter(p.protocol for p in packets)
    endpoint_counts: Counter = Counter()
    for p in packets:
        for ip in {p.src, p.dst}:
            if ip:
                endpoint_counts[ip] += 1

    dns_txns = analyzer.dns_transactions(last_ts, packets)
    flows = analyzer.tcp_flows(packets)  # both calls add packet markers, so buckets are built after them

    summary = CaptureSummary(
        filename=filename,
        file_format=fmt,  # type: ignore[arg-type]
        file_size_bytes=len(data),
        total_packets=len(packets),
        unparsed_packets=unparsed,
        truncated=truncated,
        warnings=warnings,
        first_timestamp=first_ts,
        last_timestamp=last_ts if packets else None,
        duration_seconds=round(last_ts - first_ts, 6) if packets and first_ts is not None else 0.0,
        protocol_counts=dict(protocol_counts.most_common()),
        ip_versions=dict(Counter(f"IPv{p.ip_version}" for p in packets if p.ip_version)),
        top_endpoints=[EndpointCount(endpoint=e, packets=n) for e, n in endpoint_counts.most_common(8)],
        dns_packets=sum(1 for p in packets if p.dns is not None),
        tcp_packets=sum(1 for p in packets if p.tcp_flags is not None),
        dns_transactions=dns_txns[:MAX_LIST],
        tcp_flows=flows[:MAX_LIST],
        events=analyzer.events,
        events_truncated=analyzer.events_truncated,
        time_buckets=_buckets(packets),
        simulated=simulated,
    )
    return ParsedCapture(summary=summary, packets=packets)
