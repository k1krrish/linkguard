import pytest

from app.config import get_settings
from app.services import fixtures as F
from app.services.pcap import CaptureError, analyze_capture


def cap(name):
    return analyze_capture(F.build_pcap(name), f"{name}.pcap")


def test_totals_and_protocols():
    s = cap("dns_unanswered").summary
    assert s.total_packets == 9 and s.protocol_counts == {"DNS": 5, "TCP": 4}
    assert s.file_format == "pcap" and s.duration_seconds == pytest.approx(20.0)
    assert s.ip_versions == {"IPv4": 9}


def test_unanswered_vs_answered_dns():
    t = {x.qname: x for x in cap("dns_unanswered").summary.dns_transactions}
    assert not t["unreachable.example.test"].answered and t["unreachable.example.test"].attempts == 3
    assert t["ok.example.test"].answered and t["ok.example.test"].rcode_name == "NOERROR"
    assert all(x.answered for x in cap("dns_answered").summary.dns_transactions)


def test_nxdomain_is_answered_with_rcode():
    (t,) = cap("dns_nxdomain").summary.dns_transactions
    assert t.answered and t.rcode_name == "NXDOMAIN"


def test_response_with_wrong_id_does_not_match():
    pk = [F.dns_query(0, "x.example.test.", 1), F.dns_response(0.1, "x.example.test.", 2)]
    (t,) = analyze_capture(F.to_pcap_bytes(pk)).summary.dns_transactions
    assert not t.answered


def test_response_before_query_is_not_matched():
    pk = [F.dns_response(0, "x.example.test.", 1), F.dns_query(0.1, "x.example.test.", 1)]
    (t,) = analyze_capture(F.to_pcap_bytes(pk)).summary.dns_transactions
    assert not t.answered


def test_tcp_reset_contexts():
    flows = {f.client.split(":")[-1]: f for f in cap("tcp_midstream_rst").summary.tcp_flows}
    assert flows["50300"].reset_context == "no_handshake_observed"
    assert flows["50301"].reset_context == "reset_after_handshake"
    assert not flows["50302"].reset_packets
    refused = {f.server.split(":")[-1]: f for f in cap("tcp_refused").summary.tcp_flows}
    assert refused["8081"].reset_context == "syn_answered_by_rst"
    assert refused["443"].handshake_observed


def test_retransmission_only_exact_repeats():
    flows = cap("tcp_retransmission").summary.tcp_flows
    data_flow = next(f for f in flows if f.server.endswith(":443") and "198.51" in f.server)
    assert len(data_flow.retransmission_packets) == 2          # 3 identical sends -> 2 repeats
    syn_flow = next(f for f in flows if "203.0.113.30" in f.server)
    assert len(syn_flow.retransmission_packets) == 2 and not syn_flow.synack_seen


def test_no_retransmission_flagged_for_distinct_segments():
    pk = [F.tcp(0, F.CLIENT, F.WEB, 1, 80, "PA", 100, 1, b"a" * 10), F.tcp(0.1, F.CLIENT, F.WEB, 1, 80, "PA", 110, 1, b"a" * 10),
          F.tcp(0.2, F.CLIENT, F.WEB, 1, 80, "A", 120, 1), F.tcp(0.3, F.CLIENT, F.WEB, 1, 80, "A", 120, 1)]  # pure ACKs repeat
    (f,) = analyze_capture(F.to_pcap_bytes(pk)).summary.tcp_flows
    assert f.retransmission_packets == []


def test_midstream_capture_not_called_handshake():
    (f,) = cap("insufficient").summary.tcp_flows
    assert not f.syn_seen and "mid-connection" in f.outcome


def test_ipv6_is_parsed():
    s = cap("ipv6_dns_unanswered").summary
    assert s.ip_versions == {"IPv6": 5}
    assert s.dns_transactions[0].client.startswith("[2001:db8::10]")
    assert s.tcp_flows[0].handshake_observed


def test_packets_missing_layers_do_not_crash():
    r = cap("mixed_layers")
    assert [p.protocol for p in r.packets] == ["ARP", "ICMP", "Other", "Other", "Other", "UDP"]
    assert r.packets[4].src is None and "No IP layer" in r.packets[4].info


def test_pcapng_supported():
    r = analyze_capture(F.to_pcapng_bytes(F.tcp_refused()), "a.pcapng")
    assert r.summary.file_format == "pcapng" and r.summary.total_packets == 9


def test_payload_bytes_not_exposed():
    r = cap("tcp_refused")
    blob = "".join(p.model_dump_json() for p in r.packets)
    assert "XXXXXXXX" not in blob
    assert any(l.name.startswith("Payload") for p in r.packets for l in p.layers)


def test_empty_valid_capture():
    s = analyze_capture(F.empty_pcap()).summary
    assert s.total_packets == 0 and s.duration_seconds == 0 and s.first_timestamp is None


def test_truncated_capture_warns():
    s = analyze_capture(F.truncated_pcap()).summary
    assert any("truncated" in w for w in s.warnings) and s.total_packets >= 1


@pytest.mark.parametrize("blob", [b"", b"abc", F.malformed_bytes(), b"\x00" * 100])
def test_not_a_capture_rejected(blob):
    with pytest.raises(CaptureError) as e:
        analyze_capture(blob)
    assert e.value.code == "not_a_capture"


def test_corrupt_pcapng_body_does_not_crash():
    data = F.to_pcapng_bytes(F.tcp_refused())
    try:
        analyze_capture(data[:60] + b"\xff" * 80)
    except CaptureError:
        pass  # a clean CaptureError is acceptable


def test_oversized_rejected(monkeypatch):
    monkeypatch.setenv("LINKGUARD_MAX_UPLOAD_MB", "1")
    with pytest.raises(CaptureError) as e:
        analyze_capture(b"\xd4\xc3\xb2\xa1" + b"\0" * (1024 * 1024 + 1))
    assert e.value.code == "file_too_large"


def test_packet_limit(monkeypatch):
    monkeypatch.setenv("LINKGUARD_MAX_PACKETS", "3")
    s = cap("dns_unanswered").summary
    assert s.total_packets == 3 and s.truncated and any("stopped" in w for w in s.warnings)


def test_markers_set():
    r = cap("tcp_refused")
    assert any("reset" in p.markers for p in r.packets)
    assert any("dns_unanswered" in p.markers for p in cap("dns_unanswered").packets)
    assert any("retransmission" in p.markers for p in cap("tcp_retransmission").packets)


def test_events_timeline_ordered_and_bounded():
    ev = cap("tcp_midstream_rst").summary.events
    assert ev and [e.rel_time for e in ev] == sorted(e.rel_time for e in ev)
    assert any(e.kind == "tcp_reset" for e in ev)


def test_time_buckets_cover_every_packet_and_flag_markers():
    s = cap("dns_unanswered").summary
    assert sum(b.packets for b in s.time_buckets) == s.total_packets == 9
    assert sum(b.flagged for b in s.time_buckets) == 3          # the three unanswered queries
    assert analyze_capture(F.empty_pcap()).summary.time_buckets == []
