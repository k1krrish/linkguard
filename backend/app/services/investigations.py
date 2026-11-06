"""Investigation workflow and in-memory store.

Deliberately simple: investigations live in process memory (no database, per the
MVP scope) and are lost on restart. Uploaded capture bytes are never stored -
only the extracted metadata (per-packet summaries) is kept.
"""

import threading
import uuid
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Optional

from app.config import get_settings
from app.rules.base import RuleContext
from app.rules.engine import run_rules
from app.schemas.models import (
    ActivityEntry,
    CheckResult,
    Investigation,
    InvestigationCreate,
    InvestigationListItem,
    PacketDetail,
    PacketPage,
    PacketSummary,
    utcnow,
)
from app.services import diagnostics, fixtures
from app.services.evidence import build_evidence
from app.services.pcap import ParsedCapture, analyze_capture
from app.services.samples import SAMPLES
from app.services.validation import TargetRejected, parse_host

SYMPTOM_LABELS = {
    "dns_resolution_failure": "Names do not resolve",
    "connection_failure": "Cannot connect to a service",
    "http_error": "Web page returns an error",
    "slow_or_intermittent": "Slow or intermittent connectivity",
    "unknown": "Unspecified problem",
}


@dataclass
class Entry:
    investigation: Investigation
    parsed: Optional[ParsedCapture] = None


class Store:
    def __init__(self) -> None:
        self._items: "OrderedDict[str, Entry]" = OrderedDict()
        self._lock = threading.Lock()

    def add(self, entry: Entry) -> None:
        with self._lock:
            self._items[entry.investigation.id] = entry
            while len(self._items) > get_settings().max_investigations:
                self._items.popitem(last=False)

    def get(self, inv_id: str) -> Optional[Entry]:
        with self._lock:
            return self._items.get(inv_id)

    def delete(self, inv_id: str) -> bool:
        with self._lock:
            return self._items.pop(inv_id, None) is not None

    def all(self) -> list[Entry]:
        with self._lock:
            return list(reversed(self._items.values()))

    def clear(self) -> None:
        with self._lock:
            self._items.clear()


store = Store()


def reset_store() -> None:
    """Drop every investigation (used by tests and for a clean demo)."""
    store.clear()


class NotFound(LookupError):
    pass


def _get(inv_id: str) -> Entry:
    entry = store.get(inv_id)
    if entry is None:
        raise NotFound(f"Investigation {inv_id} was not found (investigations are kept in memory and cleared when the server restarts).")
    return entry


# --------------------------------------------------------------------------
def _recompute(entry: Entry) -> None:
    inv = entry.investigation
    inv.evidence = build_evidence(inv.checks, entry.parsed)
    ctx = RuleContext(evidence=inv.evidence, capture=inv.capture)
    inv.findings = run_rules(ctx)
    inv.next_actions = _next_actions(inv)
    inv.updated_at = utcnow()
    inv.activity.append(ActivityEntry(at=utcnow(), kind="rules", label=f"Rules evaluated: {len(inv.findings)} finding(s)"))


def _next_actions(inv: Investigation) -> list[str]:
    actions: list[str] = []
    if inv.status == "awaiting_capture":
        actions.append("Upload a PCAP/PCAPNG capture to continue the investigation.")
    for f in inv.findings:
        if f.status != "ok" and f.next_test not in actions:
            actions.append(f.next_test)
    if not actions:
        actions.append("No issue was indicated by the available evidence. If the symptom persists, repeat the checks while it is happening.")
    return actions[:6]


def _run_live(inv_target: str, plan) -> list[CheckResult]:
    """Run the requested live checks in parallel, each bounded by the timeout."""
    jobs: list[tuple[str, tuple]] = []
    if plan.dns:
        jobs.append(("dns", (inv_target, "A", plan.timeout)))
    for port in plan.tcp_ports:
        jobs.append(("tcp", (inv_target, port, plan.timeout)))
    if plan.http:
        jobs.append(("http", (f"{plan.http_scheme}://{inv_target}/", "GET", plan.timeout)))
    fns = {"dns": diagnostics.dns_check, "tcp": diagnostics.tcp_check, "http": diagnostics.http_check}
    with ThreadPoolExecutor(max_workers=max(len(jobs), 1)) as pool:
        futures = [pool.submit(fns[kind], *args) for kind, args in jobs]
        return [f.result() for f in futures]


def create(req: InvestigationCreate) -> Investigation:
    settings = get_settings()
    target: Optional[str] = None
    if req.target and req.target.strip():
        target = parse_host(req.target, settings).name  # raises TargetRejected
    wants_live = req.source in ("live", "both")
    if wants_live and not target:
        raise TargetRejected("A target domain or IP is required for live checks.", code="target_required")
    if wants_live and not (req.live.dns or req.live.tcp_ports or req.live.http):
        raise TargetRejected("Select at least one live check.", code="no_checks_selected")
    if wants_live and req.live.dns and target and parse_host(target, settings).is_ip:
        req.live.dns = False  # a DNS lookup of an IP address is meaningless
    for port in req.live.tcp_ports if wants_live else []:
        diagnostics.check_tcp_port(port, settings)

    now = utcnow()
    title = (req.title or "").strip() or f"{SYMPTOM_LABELS[req.symptom]}{' - ' + target if target else ''}"
    inv = Investigation(
        id=uuid.uuid4().hex[:10], title=title, symptom=req.symptom, target=target, source=req.source,
        status="completed" if req.source == "live" else "awaiting_capture", created_at=now, updated_at=now,
        activity=[ActivityEntry(at=now, kind="created", label=f"Investigation created ({req.source})")],
    )
    entry = Entry(inv)
    if wants_live and target:
        inv.checks = _run_live(target, req.live)
        for c in inv.checks:
            inv.activity.append(ActivityEntry(at=c.started_at, kind="check", label=f"{c.check.upper()} {c.target}", status=c.status))
    _recompute(entry)
    store.add(entry)
    return inv


def attach_capture(inv_id: str, data: bytes, filename: Optional[str]) -> Investigation:
    entry = _get(inv_id)
    inv = entry.investigation
    if inv.simulated:
        raise TargetRejected("Sample scenarios are fixed demonstrations; create a new investigation to upload your own capture.", code="sample_locked")
    if inv.source == "live":
        raise TargetRejected("This investigation was created for live checks only; create one with a capture source to upload evidence.", code="capture_not_expected")
    parsed = analyze_capture(data, _safe_name(filename))  # raises CaptureError; nothing is stored on failure
    entry.parsed, inv.capture = parsed, parsed.summary
    inv.status = "completed"
    inv.activity.append(ActivityEntry(at=utcnow(), kind="capture", label=f"Capture analyzed: {parsed.summary.total_packets} packets"))
    _recompute(entry)
    return inv


def load_sample(sample_id: str) -> Investigation:
    sample = SAMPLES.get(sample_id)
    if sample is None:
        raise NotFound(f"Unknown sample '{sample_id}'.")
    now = utcnow()
    inv = Investigation(
        id=uuid.uuid4().hex[:10], title=f"[SIMULATED] {sample.info.title}", symptom=sample.info.symptom, target=sample.target,
        source="sample", status="completed", simulated=True, sample_id=sample_id, created_at=now, updated_at=now,
        activity=[ActivityEntry(at=now, kind="sample", label="Simulated sample scenario loaded", simulated=True)],
    )
    entry = Entry(inv)
    inv.checks = sample.checks()
    for c in inv.checks:
        inv.activity.append(ActivityEntry(at=now, kind="check", label=f"{c.check.upper()} {c.target}", status=c.status, simulated=True))
    if sample.fixture:
        parsed = analyze_capture(fixtures.build_pcap(sample.fixture), f"sample-{sample.fixture}.pcap", simulated=True)
        entry.parsed, inv.capture = parsed, parsed.summary
        inv.activity.append(ActivityEntry(at=now, kind="capture", label=f"Synthetic capture analyzed: {parsed.summary.total_packets} packets", simulated=True))
    _recompute(entry)
    store.add(entry)
    return inv


def _safe_name(name: Optional[str]) -> Optional[str]:
    if not name:
        return None
    cleaned = "".join(ch for ch in name.replace("\\", "/").split("/")[-1] if ch.isprintable())
    return cleaned[:120] or None


# --------------------------------------------------------------------------
def get(inv_id: str) -> Investigation:
    return _get(inv_id).investigation


def resolve(inv_id: str) -> Investigation:
    entry = _get(inv_id)
    inv = entry.investigation
    inv.status = "resolved" if inv.status != "resolved" else "completed"
    now = utcnow()
    inv.updated_at = now
    if inv.status == "resolved":
        inv.activity.insert(0, ActivityEntry(at=now, kind="rules", label="Incident resolved: queries verified and remediated", status="success"))
    else:
        inv.activity.insert(0, ActivityEntry(at=now, kind="rules", label="Incident reopened for diagnostic investigation", status="inconclusive"))
    return inv


def delete(inv_id: str) -> None:
    if not store.delete(inv_id):
        raise NotFound(f"Investigation {inv_id} was not found.")


def list_items() -> list[InvestigationListItem]:
    out = []
    for e in store.all():
        i = e.investigation
        counts = {s: sum(1 for f in i.findings if f.status == s) for s in ("issue", "inconclusive", "ok")}
        out.append(InvestigationListItem(
            id=i.id, title=i.title, symptom=i.symptom, target=i.target, source=i.source, status=i.status, simulated=i.simulated,
            sample_id=i.sample_id,
            created_at=i.created_at, issue_count=counts["issue"], inconclusive_count=counts["inconclusive"], ok_count=counts["ok"],
            packet_total=i.capture.total_packets if i.capture else None,
        ))
    return out


# --------------------------------------------------------------------------
# Packet queries (metadata only; no raw bytes ever leave the server)
# --------------------------------------------------------------------------
def query_packets(inv_id: str, offset: int = 0, limit: int = 100, *, protocol: Optional[str] = None, ip: Optional[str] = None,
                  port: Optional[int] = None, flag: Optional[str] = None, marker: Optional[str] = None,
                  q: Optional[str] = None, dns_name: Optional[str] = None) -> PacketPage:
    entry = _get(inv_id)
    packets = entry.parsed.packets if entry.parsed else []
    needle = (q or "").strip().lower()
    proto = (protocol or "").strip().upper()
    ip_f = (ip or "").strip().lower()
    flag_f = (flag or "").strip().upper()
    marker_f = (marker or "").strip().lower()
    name_f = (dns_name or "").strip().lower().rstrip(".")

    def keep(p: PacketDetail) -> bool:
        if proto and p.protocol.upper() != proto:
            return False
        if ip_f and ip_f not in (p.src or "").lower() and ip_f not in (p.dst or "").lower():
            return False
        if port is not None and port not in (p.src_port, p.dst_port):
            return False
        if flag_f and flag_f not in (p.tcp_flags or "").split(","):
            return False
        if marker_f and marker_f not in p.markers:
            return False
        if name_f and name_f not in ((p.dns.qname or "").lower() if p.dns else ""):
            return False
        if needle:
            hay = f"{p.index} {p.src} {p.dst} {p.src_port} {p.dst_port} {p.protocol} {p.tcp_flags} {p.info}".lower()
            return needle in hay
        return True

    matched = [p for p in packets if keep(p)]
    page = matched[offset: offset + limit]
    fields = set(PacketSummary.model_fields)
    return PacketPage(total=len(matched), offset=offset, limit=limit, items=[PacketSummary(**p.model_dump(include=fields)) for p in page])


def packet_detail(inv_id: str, index: int) -> PacketDetail:
    entry = _get(inv_id)
    packets = entry.parsed.packets if entry.parsed else []
    if not 1 <= index <= len(packets):
        raise NotFound(f"Packet {index} was not found in this capture.")
    return packets[index - 1]
