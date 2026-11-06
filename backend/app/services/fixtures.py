"""Deterministic, synthetic packet captures for demos and tests.

All addresses come from the documentation ranges (RFC 5737 / RFC 3849) and all
names use reserved TLDs (.test), so these captures cannot refer to real hosts.
They are SYNTHETIC: built with Scapy, never observed on a real network.
"""

import io
import os
import struct
import tempfile
from typing import Callable

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw
from scapy.utils import PcapNgWriter, PcapWriter

BASE_TIME = 1_700_000_000.0
CLIENT, RESOLVER, WEB, ALT = "192.0.2.10", "192.0.2.53", "198.51.100.20", "203.0.113.30"
MAC_A, MAC_B = "02:00:00:00:00:01", "02:00:00:00:00:02"


def _at(pkt: Packet, t: float) -> Packet:
    pkt.time = BASE_TIME + t
    return pkt


def _eth(src: str = CLIENT) -> Ether:
    return Ether(src=MAC_A if src == CLIENT else MAC_B, dst=MAC_B if src == CLIENT else MAC_A)


def dns_query(t: float, name: str, dns_id: int, sport: int = 40000, src: str = CLIENT, dst: str = RESOLVER) -> Packet:
    pkt = _eth(src) / IP(src=src, dst=dst) / UDP(sport=sport, dport=53) / DNS(id=dns_id, rd=1, qd=DNSQR(qname=name))
    return _at(pkt, t)


def dns_response(t: float, name: str, dns_id: int, dport: int = 40000, rcode: int = 0, answer: str = WEB,
                 src: str = RESOLVER, dst: str = CLIENT) -> Packet:
    an = DNSRR(rrname=name, type="A", rdata=answer, ttl=60) if rcode == 0 else None
    dns = DNS(id=dns_id, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=name), an=an, ancount=1 if an else 0)
    return _at(_eth(src) / IP(src=src, dst=dst) / UDP(sport=53, dport=dport) / dns, t)


def tcp(t: float, src: str, dst: str, sport: int, dport: int, flags: str, seq: int, ack: int = 0, payload: bytes = b"") -> Packet:
    pkt = _eth(src) / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=64240)
    if payload:
        pkt = pkt / Raw(payload)
    return _at(pkt, t)


def _handshake(t: float, sport: int, dport: int = 443, server: str = WEB, cseq: int = 1000, sseq: int = 5000) -> list[Packet]:
    return [
        tcp(t, CLIENT, server, sport, dport, "S", cseq),
        tcp(t + 0.02, server, CLIENT, dport, sport, "SA", sseq, cseq + 1),
        tcp(t + 0.03, CLIENT, server, sport, dport, "A", cseq + 1, sseq + 1),
    ]


# --------------------------------------------------------------------------
# Scenario captures
# --------------------------------------------------------------------------
def dns_unanswered() -> list[Packet]:
    """One name is queried three times and never answered; another name is answered."""
    name = "unreachable.example.test."
    pkts = [
        dns_query(0.0, name, 0x1111),
        dns_query(1.0, name, 0x1111),
        dns_query(3.0, name, 0x1111),
        dns_query(0.5, "ok.example.test.", 0x2222, sport=40001),
        dns_response(0.52, "ok.example.test.", 0x2222, dport=40001),
    ]
    pkts += _handshake(10.0, 50000)
    pkts.append(tcp(20.0, CLIENT, WEB, 50000, 443, "A", 1001, 5001))
    return sorted(pkts, key=lambda p: p.time)


def dns_answered() -> list[Packet]:
    """Negative case: every query has a matching response."""
    pkts = [
        dns_query(0.0, "a.example.test.", 0x0A01),
        dns_response(0.02, "a.example.test.", 0x0A01),
        dns_query(0.1, "b.example.test.", 0x0A02, sport=40001),
        dns_response(0.13, "b.example.test.", 0x0A02, dport=40001),
    ]
    pkts += _handshake(1.0, 50000)
    pkts.append(tcp(2.0, CLIENT, WEB, 50000, 443, "A", 1001, 5001))
    return sorted(pkts, key=lambda p: p.time)


def dns_nxdomain() -> list[Packet]:
    pkts = [dns_query(0.0, "missing.example.test.", 0x0B01), dns_response(0.03, "missing.example.test.", 0x0B01, rcode=3)]
    pkts += _handshake(1.0, 50000)
    pkts.append(tcp(2.0, CLIENT, WEB, 50000, 443, "A", 1001, 5001))
    return sorted(pkts, key=lambda p: p.time)


def dns_servfail() -> list[Packet]:
    """DNS query answered with SERVFAIL (rcode 2)."""
    pkts = [
        dns_query(0.0, "upstream-auth.example.test.", 0x0C05),
        dns_response(0.04, "upstream-auth.example.test.", 0x0C05, rcode=2),
    ]
    pkts += _handshake(1.0, 50000)
    pkts.append(tcp(2.0, CLIENT, WEB, 50000, 443, "A", 1001, 5001))
    return sorted(pkts, key=lambda p: p.time)


def tcp_syn_no_reply() -> list[Packet]:
    """Client sends repeated SYN to port 443 with no reply received (firewall blackhole)."""
    pkts = [
        tcp(0.0, CLIENT, WEB, 50500, 443, "S", 1000),
        tcp(1.0, CLIENT, WEB, 50500, 443, "S", 1000),
        tcp(3.0, CLIENT, WEB, 50500, 443, "S", 1000),
    ]
    return sorted(pkts, key=lambda p: p.time)


def icmp_unreachable() -> list[Packet]:
    """TCP SYN met with ICMP Destination Unreachable / Administratively Prohibited."""
    syn = tcp(0.0, CLIENT, ALT, 50600, 443, "S", 2000)
    icmp_pkt = _eth(RESOLVER) / IP(src=RESOLVER, dst=CLIENT) / ICMP(type=3, code=13) / syn[IP]
    return sorted([syn, _at(icmp_pkt, 0.05)], key=lambda p: p.time)


def tcp_refused() -> list[Packet]:
    """A SYN to port 8081 is answered by RST/ACK; a different connection works."""
    pkts = [
        dns_query(0.0, "service.example.test.", 0x0C01),
        dns_response(0.02, "service.example.test.", 0x0C01),
        tcp(0.10, CLIENT, WEB, 50100, 8081, "S", 7000),
        tcp(0.13, WEB, CLIENT, 8081, 50100, "RA", 0, 7001),
    ]
    pkts += _handshake(1.0, 50101)
    pkts.append(tcp(1.5, CLIENT, WEB, 50101, 443, "PA", 1001, 5001, b"X" * 60))
    pkts.append(tcp(1.6, WEB, CLIENT, 443, 50101, "A", 5001, 1061))
    return sorted(pkts, key=lambda p: p.time)


def tcp_retransmission() -> list[Packet]:
    """Same 100-byte segment sent three times; plus a SYN repeated with no reply."""
    pkts = _handshake(0.0, 50200)
    pkts += [
        tcp(0.10, CLIENT, WEB, 50200, 443, "PA", 1001, 5001, b"X" * 100),
        tcp(0.40, CLIENT, WEB, 50200, 443, "PA", 1001, 5001, b"X" * 100),
        tcp(1.00, CLIENT, WEB, 50200, 443, "PA", 1001, 5001, b"X" * 100),
        tcp(1.20, WEB, CLIENT, 443, 50200, "A", 5001, 1101),
        tcp(2.0, CLIENT, ALT, 50201, 443, "S", 9000),
        tcp(3.0, CLIENT, ALT, 50201, 443, "S", 9000),
        tcp(5.0, CLIENT, ALT, 50201, 443, "S", 9000),
        tcp(9.0, CLIENT, WEB, 50200, 443, "A", 1101, 5001),
    ]
    return sorted(pkts, key=lambda p: p.time)


def tcp_midstream_rst() -> list[Packet]:
    """Capture starts mid-connection and later shows a reset."""
    return [
        tcp(0.0, CLIENT, WEB, 50300, 443, "PA", 4000, 8000, b"X" * 40),
        tcp(0.05, WEB, CLIENT, 443, 50300, "A", 8000, 4040),
        tcp(0.5, WEB, CLIENT, 443, 50300, "R", 8000),
        tcp(1.0, CLIENT, WEB, 50301, 443, "S", 100),
        tcp(1.02, WEB, CLIENT, 443, 50301, "SA", 200, 101),
        tcp(1.03, CLIENT, WEB, 50301, 443, "A", 101, 201),
        tcp(1.5, WEB, CLIENT, 443, 50301, "RA", 201, 101),
        tcp(2.0, CLIENT, WEB, 50302, 443, "S", 300),
        tcp(2.02, WEB, CLIENT, 443, 50302, "SA", 400, 301),
        tcp(2.03, CLIENT, WEB, 50302, 443, "A", 301, 401),
        tcp(3.0, CLIENT, WEB, 50302, 443, "A", 301, 401),
        tcp(4.0, CLIENT, WEB, 50302, 443, "A", 301, 401),
        tcp(5.0, CLIENT, WEB, 50302, 443, "A", 301, 401),
        tcp(6.0, CLIENT, WEB, 50302, 443, "A", 301, 401),
        tcp(7.0, CLIENT, WEB, 50302, 443, "A", 301, 401),
        tcp(8.0, CLIENT, WEB, 50302, 443, "A", 301, 401),
    ]


def insufficient() -> list[Packet]:
    """Tiny capture: a mid-stream ACK, an unrelated UDP datagram, and a DNS query at the very end."""
    return [
        tcp(0.0, CLIENT, WEB, 50400, 443, "A", 4000, 8000),
        _at(_eth() / IP(src=CLIENT, dst=ALT) / UDP(sport=45000, dport=9999) / Raw(b"ping"), 0.3),
        dns_query(0.6, "late.example.test.", 0x0D01),
    ]


def ipv6_dns_unanswered() -> list[Packet]:
    c, r = "2001:db8::10", "2001:db8::53"
    pkts = [
        _at(_eth() / IPv6(src=c, dst=r) / UDP(sport=41000, dport=53) / DNS(id=0x0E01, rd=1, qd=DNSQR(qname="v6.example.test.")), 0.0),
        _at(_eth() / IPv6(src=c, dst=r) / UDP(sport=41000, dport=53) / DNS(id=0x0E01, rd=1, qd=DNSQR(qname="v6.example.test.")), 1.0),
    ]
    pkts += [
        _at(_eth() / IPv6(src=c, dst="2001:db8::80") / TCP(sport=51000, dport=443, flags="S", seq=1), 8.0),
        _at(_eth("x") / IPv6(src="2001:db8::80", dst=c) / TCP(sport=443, dport=51000, flags="SA", seq=9, ack=2), 8.02),
        _at(_eth() / IPv6(src=c, dst="2001:db8::80") / TCP(sport=51000, dport=443, flags="A", seq=2, ack=10), 12.0),
    ]
    return pkts


def mixed_layers() -> list[Packet]:
    """Odd packets that lack the usual layers; the analyzer must not fail on them."""
    return [
        _at(Ether(src=MAC_A, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc=CLIENT, pdst=RESOLVER), 0.0),
        _at(_eth() / IP(src=CLIENT, dst=WEB) / ICMP(type=8, code=0), 0.1),
        _at(_eth() / IP(src=CLIENT, dst=WEB, frag=10, proto=6) / Raw(b"fragment-body"), 0.2),
        _at(_eth() / IP(src=CLIENT, dst=ALT, proto=89) / Raw(b"\x00" * 8), 0.3),
        _at(Ether(src=MAC_A, dst=MAC_B, type=0x1234) / Raw(b"\x01\x02\x03\x04"), 0.4),
        _at(_eth() / IP(src=CLIENT, dst=ALT) / UDP(sport=5000, dport=5001) / Raw(b"hello"), 0.5),
    ]


FIXTURES: dict[str, Callable[[], list[Packet]]] = {
    "dns_unanswered": dns_unanswered,
    "dns_answered": dns_answered,
    "dns_nxdomain": dns_nxdomain,
    "dns_servfail": dns_servfail,
    "tcp_refused": tcp_refused,
    "tcp_retransmission": tcp_retransmission,
    "tcp_midstream_rst": tcp_midstream_rst,
    "tcp_syn_no_reply": tcp_syn_no_reply,
    "icmp_unreachable": icmp_unreachable,
    "insufficient": insufficient,
    "ipv6_dns_unanswered": ipv6_dns_unanswered,
    "mixed_layers": mixed_layers,
}


# --------------------------------------------------------------------------
# Serialization helpers
# --------------------------------------------------------------------------
def to_pcap_bytes(packets: list[Packet]) -> bytes:
    buf = io.BytesIO()
    writer = PcapWriter(buf, sync=True)
    for pkt in packets:
        writer.write(pkt)
    writer.flush()
    return buf.getvalue()


def to_pcapng_bytes(packets: list[Packet]) -> bytes:
    fd, path = tempfile.mkstemp(suffix=".pcapng")
    os.close(fd)
    try:
        writer = PcapNgWriter(path)
        for pkt in packets:
            writer.write(pkt)
        writer.close()
        with open(path, "rb") as fh:
            return fh.read()
    finally:
        os.unlink(path)


def build_pcap(name: str) -> bytes:
    return to_pcap_bytes(FIXTURES[name]())


def empty_pcap() -> bytes:
    """A valid classic-pcap file that contains a header but zero packets."""
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def truncated_pcap() -> bytes:
    data = build_pcap("tcp_refused")
    return data[:-25]  # cut inside the last record


def malformed_bytes() -> bytes:
    return b"This is not a packet capture. " * 10
