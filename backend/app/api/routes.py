"""REST API. Routes stay thin: validate, call a service, return a model."""

import json
from typing import Optional

from fastapi import APIRouter, File, HTTPException, Query, Request, Response, UploadFile

from app.config import get_settings
from app.rules.engine import catalogue
from app.schemas.models import (
    CheckResult,
    DnsCheckRequest,
    HttpCheckRequest,
    Investigation,
    InvestigationCreate,
    InvestigationListItem,
    PacketDetail,
    PacketPage,
    Report,
    RuleInfo,
    SampleInfo,
    TcpCheckRequest,
)
from app.services import diagnostics, investigations, reports, samples
from app.services.pcap import CaptureError

router = APIRouter(prefix="/api")

ERR = {400: {"description": "Rejected input"}, 404: {"description": "Not found"}, 413: {"description": "Upload too large"}}


@router.get("/health", tags=["system"])
def health() -> dict:
    s = get_settings()
    return {
        "status": "ok",
        "version": "2.0.0",
        "limits": {"max_upload_mb": s.max_upload_bytes // (1024 * 1024), "max_packets": s.max_packets, "max_timeout_s": s.max_timeout},
        "private_targets_allowed": s.allow_private_targets,
    }


# -- live checks -------------------------------------------------------------
@router.post("/checks/dns", response_model=CheckResult, tags=["live checks"], responses=ERR)
def check_dns(body: DnsCheckRequest) -> CheckResult:
    return diagnostics.dns_check(body.target, body.record_type, body.timeout)


@router.post("/checks/tcp", response_model=CheckResult, tags=["live checks"], responses=ERR)
def check_tcp(body: TcpCheckRequest) -> CheckResult:
    return diagnostics.tcp_check(body.target, body.port, body.timeout)


@router.post("/checks/http", response_model=CheckResult, tags=["live checks"], responses=ERR)
def check_http(body: HttpCheckRequest) -> CheckResult:
    return diagnostics.http_check(body.url, body.method, body.timeout)


# -- samples and rules ---------------------------------------------------------
@router.get("/samples", response_model=list[SampleInfo], tags=["samples"])
def list_samples() -> list[SampleInfo]:
    return samples.sample_infos()


@router.post("/samples/{sample_id}/load", response_model=Investigation, status_code=201, tags=["samples"], responses=ERR)
def load_sample(sample_id: str) -> Investigation:
    return investigations.load_sample(sample_id)


@router.get("/rules", response_model=list[RuleInfo], tags=["rules"])
def list_rules() -> list[RuleInfo]:
    return catalogue()


# -- investigations -----------------------------------------------------------
@router.post("/investigations", response_model=Investigation, status_code=201, tags=["investigations"], responses=ERR)
def create_investigation(body: InvestigationCreate) -> Investigation:
    return investigations.create(body)


@router.get("/investigations", response_model=list[InvestigationListItem], tags=["investigations"])
def list_investigations() -> list[InvestigationListItem]:
    return investigations.list_items()


@router.get("/investigations/{inv_id}", response_model=Investigation, tags=["investigations"], responses=ERR)
def get_investigation(inv_id: str) -> Investigation:
    return investigations.get(inv_id)


@router.post("/investigations/{inv_id}/resolve", response_model=Investigation, tags=["investigations"], responses=ERR)
def resolve_investigation(inv_id: str) -> Investigation:
    return investigations.resolve(inv_id)


@router.delete("/investigations/{inv_id}", status_code=204, tags=["investigations"], responses=ERR)
def delete_investigation(inv_id: str) -> Response:
    investigations.delete(inv_id)
    return Response(status_code=204)


@router.post("/investigations/{inv_id}/capture", response_model=Investigation, tags=["capture"], responses=ERR)
async def upload_capture(inv_id: str, request: Request, file: UploadFile = File(...)) -> Investigation:
    """Upload a .pcap/.pcapng file. It is parsed in memory and never written to disk."""
    limit = get_settings().max_upload_bytes
    investigations.get(inv_id)  # 404 early
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > limit + 64 * 1024:
        raise CaptureError("file_too_large", f"Capture exceeds the {limit // (1024 * 1024)} MB limit.")
    chunks, size = [], 0
    while True:
        chunk = await file.read(256 * 1024)
        if not chunk:
            break
        size += len(chunk)
        if size > limit:
            raise CaptureError("file_too_large", f"Capture exceeds the {limit // (1024 * 1024)} MB limit.")
        chunks.append(chunk)
    data = b"".join(chunks)
    chunks.clear()
    return investigations.attach_capture(inv_id, data, file.filename)


@router.get("/investigations/{inv_id}/packets", response_model=PacketPage, tags=["capture"], responses=ERR)
def list_packets(
    inv_id: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    protocol: Optional[str] = Query(None, max_length=16),
    ip: Optional[str] = Query(None, max_length=64, description="Matches source or destination address"),
    port: Optional[int] = Query(None, ge=0, le=65535, description="Matches source or destination port"),
    flag: Optional[str] = Query(None, max_length=4, description="TCP flag, e.g. SYN, RST"),
    marker: Optional[str] = Query(None, max_length=32, description="reset, retransmission, dns_unanswered, dns_error, syn_no_reply"),
    q: Optional[str] = Query(None, max_length=100, description="Free-text search"),
    dns_name: Optional[str] = Query(None, max_length=253),
) -> dict:
    return investigations.query_packets(inv_id, offset, limit, protocol=protocol, ip=ip, port=port, flag=flag,
                                        marker=marker, q=q, dns_name=dns_name)


@router.get("/investigations/{inv_id}/packets/{index}", response_model=PacketDetail, tags=["capture"], responses=ERR)
def get_packet(inv_id: str, index: int) -> PacketDetail:
    return investigations.packet_detail(inv_id, index)


# -- reports -------------------------------------------------------------------
@router.get("/investigations/{inv_id}/report", response_model=Report, tags=["reports"], responses=ERR)
def get_report(inv_id: str) -> Report:
    return reports.build_report(investigations.get(inv_id))


@router.get("/investigations/{inv_id}/report.json", tags=["reports"], responses=ERR)
def export_json(inv_id: str) -> Response:
    report = reports.build_report(investigations.get(inv_id))
    body = json.dumps(json.loads(report.model_dump_json()), indent=2)
    return Response(body, media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="linkguard-{inv_id}.json"'})


@router.get("/investigations/{inv_id}/report.csv", tags=["reports"], responses=ERR)
def export_csv(inv_id: str) -> Response:
    report = reports.build_report(investigations.get(inv_id))
    return Response(reports.to_csv(report), media_type="text/csv",
                    headers={"Content-Disposition": f'attachment; filename="linkguard-{inv_id}.csv"'})
