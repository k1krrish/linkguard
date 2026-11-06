"""Every rule: positive, negative and inconclusive cases, plus wording checks."""

import re

import pytest

from app.rules.base import Rule, RuleContext
from app.rules.engine import RULES, run_rules
from app.rules.live_rules import LiveDnsRule, LiveHttpRule, LiveTcpRule
from app.rules.pcap_rules import (CaptureNoMatchRule, DnsErrorRule, DnsUnansweredRule, EvidenceGapRule,
                                  TcpResetRule, TcpRetransmissionRule, TcpSynNoReplyRule)
from app.schemas.models import CheckResult, utcnow
from app.services import fixtures as F
from app.services.evidence import build_evidence
from app.services.pcap import analyze_capture


def ctx_for(name=None, checks=(), pk=None):
    parsed = analyze_capture(F.to_pcap_bytes(pk) if pk is not None else F.build_pcap(name)) if (name or pk is not None) else None
    ev = build_evidence(list(checks), parsed)
    return RuleContext(evidence=ev, capture=parsed.summary if parsed else None)


def chk(kind, status, err=None, **details):
    return CheckResult(check=kind, target="example.com", status=status, started_at=utcnow(), elapsed_ms=12.5,
                       error_kind=err, message=f"{kind} {status}", details=details)


def big_clean(n=12):
    pk = []
    for i in range(n // 2):
        pk += [F.dns_query(i, f"n{i}.example.test.", 100 + i, sport=41000 + i), F.dns_response(i + 0.01, f"n{i}.example.test.", 100 + i, dport=41000 + i)]
    return pk


# -- DNS-001 ----------------------------------------------------------------------
def test_dns001_positive():
    (f,) = [f for f in DnsUnansweredRule().evaluate(ctx_for("dns_unanswered")) if f.status == "issue"]
    assert f.rule_id == "DNS-001" and f.severity == "medium" and f.packet_refs and "unreachable.example.test" in f.observed


def test_dns001_negative():
    (f,) = DnsUnansweredRule().evaluate(ctx_for("dns_answered"))
    assert f.status == "ok"


def test_dns001_inconclusive_when_query_at_end_of_capture():
    (f,) = DnsUnansweredRule().evaluate(ctx_for("insufficient"))
    assert f.status == "inconclusive" and "end of the capture" in " ".join(f.limitations)


def test_dns001_not_applicable_without_dns():
    assert DnsUnansweredRule().evaluate(ctx_for("tcp_refused", pk=[F.tcp(0, F.CLIENT, F.WEB, 1, 80, "S", 1)])) == []


# -- DNS-002 ----------------------------------------------------------------------
def test_dns002_positive_nxdomain_low():
    (f,) = DnsErrorRule().evaluate(ctx_for("dns_nxdomain"))
    assert f.status == "issue" and f.severity == "low" and "NXDOMAIN" in f.observed and "reachable" in f.interpretation


def test_dns002_servfail_is_medium():
    pk = [F.dns_query(0, "a.example.test.", 1), F.dns_response(0.1, "a.example.test.", 1, rcode=2)]
    (f,) = DnsErrorRule().evaluate(ctx_for(pk=pk))
    assert f.severity == "medium"


def test_dns002_negative():
    assert DnsErrorRule().evaluate(ctx_for("dns_answered")) == []


# -- TCP-001 ----------------------------------------------------------------------
def test_tcp001_positive_syn_rst():
    (f,) = TcpResetRule().evaluate(ctx_for("tcp_refused"))
    assert f.status == "issue" and f.severity == "medium" and "closed port" in f.interpretation


def test_tcp001_midstream_is_low_and_multi_flow():
    (f,) = TcpResetRule().evaluate(ctx_for("tcp_midstream_rst"))
    assert f.severity == "low" and "2 TCP reset" in f.observed


def test_tcp001_negative():
    assert TcpResetRule().evaluate(ctx_for("dns_answered")) == []


# -- TCP-002 / TCP-003 --------------------------------------------------------------
def test_tcp002_positive():
    (f,) = TcpRetransmissionRule().evaluate(ctx_for("tcp_retransmission"))
    assert f.status == "issue" and "do not prove congestion" in " ".join(f.limitations)


def test_tcp002_negative():
    assert TcpRetransmissionRule().evaluate(ctx_for("tcp_refused")) == []


def test_tcp003_inconclusive_status():
    (f,) = TcpSynNoReplyRule().evaluate(ctx_for("tcp_retransmission"))
    assert f.status == "inconclusive"


def test_tcp003_not_raised_for_reset_or_handshake():
    assert TcpSynNoReplyRule().evaluate(ctx_for("tcp_refused")) == []


# -- EVID-001 / CAP-001 -------------------------------------------------------------
def test_evid001_small_capture():
    (f,) = EvidenceGapRule().evaluate(ctx_for("insufficient"))
    assert f.status == "inconclusive" and "3 packet" in f.observed


def test_evid001_empty_capture():
    parsed = analyze_capture(F.empty_pcap())
    (f,) = EvidenceGapRule().evaluate(RuleContext(evidence=build_evidence([], parsed), capture=parsed.summary))
    assert "no packets" in f.observed


def test_evid001_truncated_file():
    parsed = analyze_capture(F.truncated_pcap())
    assert EvidenceGapRule().evaluate(RuleContext(evidence=build_evidence([], parsed), capture=parsed.summary))


def test_evid001_negative_for_adequate_capture():
    assert EvidenceGapRule().evaluate(ctx_for(pk=big_clean())) == []


def test_cap001_clean_capture_is_ok_not_healthy_claim():
    (f,) = CaptureNoMatchRule().evaluate(ctx_for(pk=big_clean()))
    assert f.status == "ok" and "does not" not in f.title and "healthy" not in f.interpretation.lower()


def test_cap001_not_raised_with_anomaly_or_gap():
    assert CaptureNoMatchRule().evaluate(ctx_for("dns_unanswered")) == []
    assert CaptureNoMatchRule().evaluate(ctx_for("insufficient")) == []


# -- live rules ---------------------------------------------------------------------
def run(rule, *checks):
    return rule.evaluate(ctx_for(checks=checks))


def test_live_dns():
    assert run(LiveDnsRule(), chk("dns", "success", addresses=["198.51.100.1"]))[0].status == "ok"
    f = run(LiveDnsRule(), chk("dns", "failure", "name_not_found"))[0]
    assert f.status == "issue" and "single attempt" in f.limitations[0]
    f = run(LiveDnsRule(), chk("dns", "inconclusive", "timeout"))[0]
    assert f.status == "inconclusive" and "does not show the name is invalid" in f.interpretation
    assert run(LiveDnsRule(), chk("dns", "unavailable", "resolver_unavailable"))[0].status == "inconclusive"
    assert run(LiveDnsRule()) == []


def test_live_tcp():
    assert run(LiveTcpRule(), chk("tcp", "success", port=443))[0].status == "ok"
    f = run(LiveTcpRule(), chk("tcp", "failure", "connection_refused"))[0]
    assert f.status == "issue" and "does not uniquely" not in f.interpretation and "complete loss of connectivity is not indicated" in f.interpretation
    f = run(LiveTcpRule(), chk("tcp", "inconclusive", "timeout"))[0]
    assert f.status == "inconclusive" and "no conclusion is drawn" in f.interpretation
    assert run(LiveTcpRule(), chk("tcp", "unavailable", "network_unreachable"))[0].status == "inconclusive"


def test_live_http():
    assert run(LiveHttpRule(), chk("http", "success", status_code=200, reason="OK"))[0].status == "ok"
    f = run(LiveHttpRule(), chk("http", "failure", "http_5xx", status_code=503, reason="Service Unavailable"))[0]
    assert f.status == "issue" and "not necessarily at the network" in f.interpretation and f.severity == "medium"
    f = run(LiveHttpRule(), chk("http", "failure", "http_4xx", status_code=404, reason="Not Found"))[0]
    assert f.severity == "low" and "not a connectivity failure" in f.interpretation
    f = run(LiveHttpRule(), chk("http", "failure", "tls_verification_failed"))[0]
    assert f.status == "issue" and "certificate" in f.interpretation
    assert run(LiveHttpRule(), chk("http", "inconclusive", "timeout"))[0].status == "inconclusive"


def test_one_failed_check_never_claims_network_down():
    ctx = ctx_for(checks=[chk("tcp", "failure", "connection_refused"), chk("dns", "inconclusive", "timeout")])
    text = " ".join(f.interpretation + f.observed for f in run_rules(ctx)).lower()
    assert "network is down" not in text and "network down" not in text


# -- engine -------------------------------------------------------------------------
def test_every_finding_is_complete_and_honest():
    contexts = [ctx_for(n) for n in F.FIXTURES] + [ctx_for(checks=[chk("tcp", "failure", "connection_refused"),
                chk("http", "failure", "http_5xx", status_code=500, reason="x"), chk("dns", "failure", "name_not_found")])]
    for ctx in contexts:
        for f in run_rules(ctx):
            assert re.fullmatch(r"[A-Z]+(-[A-Z]+)?-\d{3}", f.rule_id)
            assert f.title and f.observed and f.interpretation and f.next_test and f.limitations
            assert f.severity in ("info", "low", "medium") and f.status in ("issue", "ok", "inconclusive")
            assert f.evidence_refs, f.rule_id
            assert not re.search(r"confidence|\d+\s?%|root cause (is|was)|proves? that", f.interpretation + f.observed, re.I), f.rule_id
            if f.source == "pcap" and f.status != "ok" and f.rule_id != "EVID-001":
                assert any("not observed" in l.lower() or "capture point" in l.lower() or "capture" in l.lower() for l in f.limitations)


def test_rule_ids_unique_and_documented():
    ids = [r.rule_id for r in RULES]
    assert len(ids) == len(set(ids)) >= 10
    for r in RULES:
        assert r.title and r.description and r.triggers and r.does_not_prove


def test_failing_rule_becomes_inconclusive_finding():
    class Boom(Rule):
        rule_id, title, source = "TEST-001", "Boom", "pcap"
        def evaluate(self, ctx):
            raise RuntimeError("secret internal detail")
    (f,) = run_rules(RuleContext(evidence=[]), [Boom()])
    assert f.status == "inconclusive" and "secret" not in f.observed and "RuntimeError" in f.observed


def test_findings_sorted_issues_first():
    statuses = [f.status for f in run_rules(ctx_for("dns_unanswered"))]
    assert statuses == sorted(statuses, key={"issue": 0, "inconclusive": 1, "ok": 2}.get)


def test_simulated_flag_propagates():
    parsed = analyze_capture(F.build_pcap("tcp_refused"), simulated=True)
    ctx = RuleContext(evidence=build_evidence([], parsed), capture=parsed.summary)
    assert all(f.simulated for f in run_rules(ctx))
