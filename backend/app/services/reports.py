"""Investigation reports and JSON / CSV export. Everything is derived from stored backend data."""

import csv
import io

from app.schemas.models import Investigation, Report, ReportCapture, ReportTest, utcnow
from app.services.investigations import SYMPTOM_LABELS

GENERAL_LIMITATIONS = [
    "Live checks are single attempts from the machine running LinkGuard; they describe that vantage point and moment only.",
    "A capture shows only traffic that crossed the capture point. Not observed in a capture is not the same as did not happen.",
    "Findings list indicators and possible explanations, not confirmed root causes. No confidence scores are produced.",
]


def build_report(inv: Investigation) -> Report:
    counts = {s: sum(1 for f in inv.findings if f.status == s) for s in ("issue", "inconclusive", "ok")}
    cap = inv.capture
    capture = None
    if cap:
        capture = ReportCapture(
            filename=cap.filename, file_format=cap.file_format, total_packets=cap.total_packets,
            duration_seconds=cap.duration_seconds, protocol_counts=cap.protocol_counts,
            dns_transactions=len(cap.dns_transactions), dns_unanswered=sum(1 for t in cap.dns_transactions if not t.answered),
            tcp_flows=len(cap.tcp_flows), tcp_flows_with_reset=sum(1 for f in cap.tcp_flows if f.reset_packets),
            tcp_retransmission_packets=sum(len(f.retransmission_packets) for f in cap.tcp_flows),
            notable_events=[e for e in cap.events if e.level != "info"][:25], warnings=cap.warnings, simulated=cap.simulated,
        )
    limitations = list(GENERAL_LIMITATIONS)
    if inv.simulated:
        limitations.insert(0, "SIMULATED: this investigation uses synthetic data from a bundled demonstration scenario, not a live network observation.")
    for f in inv.findings:
        for lim in f.limitations[:1]:
            if lim not in limitations:
                limitations.append(lim)
    return Report(
        investigation_id=inv.id, title=inv.title, generated_at=utcnow(), symptom=inv.symptom,
        symptom_label=SYMPTOM_LABELS[inv.symptom], target=inv.target, source=inv.source, simulated=inv.simulated,
        summary=_summary(inv, counts), status_counts=counts,
        test_outcomes=[ReportTest(check=c.check, target=c.target, status=c.status, elapsed_ms=c.elapsed_ms, message=c.message, simulated=c.simulated)
                       for c in inv.checks],
        packet_evidence=capture, findings=inv.findings, evidence_index=inv.evidence, limitations=limitations[:10],
        next_steps=inv.next_actions,
    )


def _summary(inv: Investigation, counts: dict[str, int]) -> str:
    parts = []
    if inv.simulated:
        parts.append("SIMULATED DEMONSTRATION - synthetic data, not a live observation.")
    what = f"Reported symptom: {SYMPTOM_LABELS[inv.symptom].lower()}" + (f" (target {inv.target})." if inv.target else ".")
    parts.append(what)
    ev = []
    if inv.checks:
        ev.append(f"{len(inv.checks)} live check(s)")
    if inv.capture:
        ev.append(f"a capture of {inv.capture.total_packets} packet(s)")
    parts.append(("Evidence examined: " + " and ".join(ev) + ".") if ev else "No evidence has been attached yet; findings will appear once checks run or a capture is uploaded.")
    parts.append(f"Rules produced {counts['issue']} issue indicator(s), {counts['inconclusive']} inconclusive result(s) and {counts['ok']} normal observation(s).")
    if counts["issue"] == 0 and counts["inconclusive"] == 0 and inv.findings:
        parts.append("No issue was indicated by the available evidence; this does not prove the network is healthy.")
    elif counts["issue"]:
        parts.append("Indicators are observations with possible explanations; none is a confirmed root cause.")
    return " ".join(parts)


# --------------------------------------------------------------------------
def _cell(value) -> str:
    """Neutralize spreadsheet formula injection: cells starting with = + - @ are prefixed with a quote."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


COLUMNS = ["section", "id", "name", "status", "severity", "source", "simulated", "detail", "interpretation",
           "limitations", "next_step", "evidence_refs", "packet_refs"]


def to_csv(report: Report) -> str:
    """One flat CSV; the ``section`` column says what each row is (report, test, capture, finding, evidence, next_step)."""
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(COLUMNS)

    def row(**v) -> None:
        w.writerow([_cell(v.get(c, "")) for c in COLUMNS])

    row(section="report", id=report.investigation_id, name=report.title, status=report.symptom_label, source=report.source,
        simulated=report.simulated, detail=report.summary)
    for n, t in enumerate(report.test_outcomes, 1):
        row(section="test", id=f"T{n}", name=f"{t.check.upper()} {t.target}", status=t.status, simulated=t.simulated,
            source="simulated" if t.simulated else "live_check", detail=t.message)
    c = report.packet_evidence
    if c:
        row(section="capture", id=c.filename or "", name=f"{c.file_format} capture", simulated=c.simulated, source="pcap",
            detail=(f"{c.total_packets} packets over {c.duration_seconds:.2f} s; protocols " + ", ".join(f"{k}={v}" for k, v in c.protocol_counts.items())
                    + f"; DNS transactions {c.dns_transactions} ({c.dns_unanswered} unanswered); TCP flows {c.tcp_flows} "
                    f"({c.tcp_flows_with_reset} with reset); repeated segments {c.tcp_retransmission_packets}"))
    for f in report.findings:
        row(section="finding", id=f.rule_id, name=f.title, status=f.status, severity=f.severity, source=f.source, simulated=f.simulated,
            detail=f.observed, interpretation=f.interpretation, limitations=" | ".join(f.limitations), next_step=f.next_test,
            evidence_refs=" ".join(f.evidence_refs), packet_refs=" ".join(map(str, f.packet_refs)))
    for e in report.evidence_index:
        row(section="evidence", id=e.id, name=e.kind, source=e.source, simulated=e.simulated, detail=e.summary,
            packet_refs=" ".join(map(str, e.packet_refs[:50])))
    for n, step in enumerate(report.next_steps, 1):
        row(section="next_step", id=f"N{n}", next_step=step)
    return buf.getvalue()
