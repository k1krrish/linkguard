import csv
import io
import json
import pathlib

import pytest

from app.schemas.models import Investigation, Report
from app.services import diagnostics
from app.services import fixtures as F

FIX = pathlib.Path(__file__).parent / "fixtures"


def upload(client, inv_id, data, name="x.pcap"):
    return client.post(f"/api/investigations/{inv_id}/capture", files={"file": (name, data, "application/octet-stream")})


def new_pcap_inv(client):
    r = client.post("/api/investigations", json={"source": "pcap", "symptom": "dns_resolution_failure"})
    assert r.status_code == 201
    return r.json()


# -- health / docs -------------------------------------------------------------------
def test_health_and_openapi(client):
    h = client.get("/api/health").json()
    assert h["status"] == "ok" and h["limits"]["max_upload_mb"] == 10
    paths = client.get("/openapi.json").json()["paths"]
    for p in ["/api/checks/dns", "/api/checks/tcp", "/api/checks/http", "/api/investigations/{inv_id}/capture",
              "/api/investigations/{inv_id}/report.csv", "/api/samples", "/api/rules"]:
        assert p in paths


# -- live check endpoints -----------------------------------------------------------------
def test_dns_endpoint_schema(client, monkeypatch):
    monkeypatch.setattr(diagnostics, "_getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("198.51.100.9", 0))])
    r = client.post("/api/checks/dns", json={"target": "example.com"})
    assert r.status_code == 200
    j = r.json()
    assert {"check", "target", "status", "started_at", "elapsed_ms", "message", "details", "simulated"} <= set(j)
    assert j["status"] == "success" and j["simulated"] is False and j["details"]["addresses"] == ["198.51.100.9"]


@pytest.mark.parametrize("path,body", [
    ("/api/checks/dns", {"target": "localhost"}),
    ("/api/checks/dns", {"target": "10.0.0.1"}),
    ("/api/checks/tcp", {"target": "127.0.0.1", "port": 80}),
    ("/api/checks/tcp", {"target": "example.com", "port": 3306}),
    ("/api/checks/tcp", {"target": "169.254.169.254", "port": 80}),
    ("/api/checks/http", {"url": "http://127.0.0.1:8000/api/health"}),
    ("/api/checks/http", {"url": "file:///etc/passwd"}),
    ("/api/checks/http", {"url": "http://[::1]/"}),
])
def test_ssrf_rejected_with_400(client, path, body):
    r = client.post(path, json=body)
    assert r.status_code == 400 and r.json()["error"]["code"] in ("target_rejected", "port_rejected")


@pytest.mark.parametrize("path,body", [
    ("/api/checks/dns", {}), ("/api/checks/dns", {"target": ""}), ("/api/checks/dns", {"target": "a.com", "timeout": 999}),
    ("/api/checks/tcp", {"target": "a.com", "port": 70000}), ("/api/checks/tcp", {"target": "a.com"}),
    ("/api/checks/http", {"url": "x", "method": "DELETE"}),
])
def test_invalid_payload_422(client, path, body):
    r = client.post(path, json=body)
    assert r.status_code == 422 and r.json()["error"]["code"] == "invalid_request"


def test_tcp_endpoint_local_with_explicit_override(client, monkeypatch):
    import socket, threading
    srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
    threading.Thread(target=lambda: srv.accept(), daemon=True).start()
    monkeypatch.setenv("LINKGUARD_ALLOW_PRIVATE_TARGETS", "1")
    r = client.post("/api/checks/tcp", json={"target": "127.0.0.1", "port": srv.getsockname()[1], "timeout": 2})
    assert r.status_code == 200 and r.json()["status"] == "success"
    srv.close()


# -- samples / investigations --------------------------------------------------------------------
def test_samples_list_and_load_all(client):
    samples = client.get("/api/samples").json()
    assert {s["id"] for s in samples} >= {"dns-unanswered", "tcp-refused", "http-503", "insufficient"}
    assert all(s["simulated"] for s in samples)
    for s in samples:
        r = client.post(f"/api/samples/{s['id']}/load")
        assert r.status_code == 201
        inv = Investigation.model_validate(r.json())
        assert inv.simulated and inv.title.startswith("[SIMULATED]") and inv.findings
        assert all(c.simulated for c in inv.checks)


def test_unknown_sample_404(client):
    r = client.post("/api/samples/nope/load")
    assert r.status_code == 404 and r.json()["error"]["code"] == "not_found"


def test_sample_expected_findings(client):
    def ids(sid):
        j = client.post(f"/api/samples/{sid}/load").json()
        return {(f["rule_id"], f["status"]) for f in j["findings"]}
    assert ("DNS-001", "issue") in ids("dns-unanswered")
    assert ("TCP-001", "issue") in ids("tcp-refused")
    assert ("LIVE-HTTP-001", "issue") in ids("http-503")
    insuff = ids("insufficient")
    assert ("EVID-001", "inconclusive") in insuff and not any(s == "issue" for _, s in insuff)


def test_create_live_investigation_validates_target(client):
    assert client.post("/api/investigations", json={"source": "live"}).status_code == 400
    assert client.post("/api/investigations", json={"source": "live", "target": "127.0.0.1"}).status_code == 400
    r = client.post("/api/investigations", json={"source": "live", "target": "example.com", "live": {"tcp_ports": [6379]}})
    assert r.status_code == 400 and r.json()["error"]["code"] == "port_rejected"
    r = client.post("/api/investigations", json={"source": "live", "target": "example.com", "live": {"dns": False, "tcp_ports": [], "http": False}})
    assert r.json()["error"]["code"] == "no_checks_selected"


def test_create_live_investigation_runs_real_checks(client, monkeypatch):
    # a globally routable address is needed: the SSRF guard (correctly) blocks documentation ranges for TCP
    monkeypatch.setattr(diagnostics, "_getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))])
    monkeypatch.setattr(diagnostics.socket, "create_connection", lambda *a, **k: (_ for _ in ()).throw(ConnectionRefusedError()))
    r = client.post("/api/investigations", json={"source": "live", "target": "example.com", "symptom": "connection_failure",
                                                   "live": {"dns": True, "tcp_ports": [443], "http": False, "timeout": 2}})
    assert r.status_code == 201
    inv = Investigation.model_validate(r.json())
    assert [c.check for c in inv.checks] == ["dns", "tcp"] and not any(c.simulated for c in inv.checks)
    statuses = {f.rule_id: f.status for f in inv.findings}
    assert statuses["LIVE-DNS-001"] == "ok" and statuses["LIVE-TCP-001"] == "issue"
    assert inv.status == "completed"


def test_list_get_delete(client):
    a = client.post("/api/samples/tcp-refused/load").json()
    client.post("/api/samples/insufficient/load")
    items = client.get("/api/investigations").json()
    assert len(items) == 2 and {"issue_count", "ok_count", "simulated", "packet_total"} <= set(items[0])
    assert client.get(f"/api/investigations/{a['id']}").status_code == 200
    assert client.delete(f"/api/investigations/{a['id']}").status_code == 204
    assert client.get(f"/api/investigations/{a['id']}").status_code == 404
    assert client.delete(f"/api/investigations/{a['id']}").status_code == 404


# -- capture upload ----------------------------------------------------------------------------------
def test_upload_pcap_flow(client):
    inv = new_pcap_inv(client)
    assert inv["status"] == "awaiting_capture" and "Upload a PCAP" in inv["next_actions"][0]
    r = upload(client, inv["id"], (FIX / "dns_unanswered.pcap").read_bytes(), "dns_unanswered.pcap")
    assert r.status_code == 200
    j = Investigation.model_validate(r.json())
    assert j.status == "completed" and j.capture and j.capture.total_packets == 9 and not j.capture.simulated
    assert any(f.rule_id == "DNS-001" and f.status == "issue" for f in j.findings)


def test_upload_pcapng(client):
    inv = new_pcap_inv(client)
    r = upload(client, inv["id"], (FIX / "tcp_refused.pcapng").read_bytes(), "t.pcapng")
    assert r.status_code == 200 and r.json()["capture"]["file_format"] == "pcapng"


def test_upload_filename_sanitized(client):
    inv = new_pcap_inv(client)
    r = upload(client, inv["id"], (FIX / "dns_answered.pcap").read_bytes(), "..\\..\\etc/passwd.pcap")
    assert r.json()["capture"]["filename"] == "passwd.pcap"


@pytest.mark.parametrize("fname", ["malformed.pcap", "empty.pcap"])
def test_upload_bad_files_400(client, fname):
    inv = new_pcap_inv(client)
    r = upload(client, inv["id"], (FIX / fname).read_bytes(), fname)
    # empty.pcap is a valid header with zero packets -> accepted; malformed is rejected
    if fname == "malformed.pcap":
        assert r.status_code == 400 and r.json()["error"]["code"] == "not_a_capture"
    else:
        assert r.status_code == 200 and r.json()["capture"]["total_packets"] == 0
        assert any(f["rule_id"] == "EVID-001" for f in r.json()["findings"])


def test_failed_upload_leaves_investigation_unchanged(client):
    inv = new_pcap_inv(client)
    upload(client, inv["id"], b"garbage garbage garbage", "x.pcap")
    after = client.get(f"/api/investigations/{inv['id']}").json()
    assert after["capture"] is None and after["status"] == "awaiting_capture"


def test_truncated_upload_warns(client):
    inv = new_pcap_inv(client)
    j = upload(client, inv["id"], (FIX / "truncated.pcap").read_bytes()).json()
    assert any("truncated" in w for w in j["capture"]["warnings"])


def test_oversized_upload_413(client, monkeypatch):
    monkeypatch.setenv("LINKGUARD_MAX_UPLOAD_MB", "1")
    inv = new_pcap_inv(client)
    r = upload(client, inv["id"], b"\xd4\xc3\xb2\xa1" + b"\0" * (2 * 1024 * 1024))
    assert r.status_code == 413 and r.json()["error"]["code"] == "file_too_large"


def test_upload_unknown_investigation_404(client):
    assert upload(client, "missing", b"x" * 40).status_code == 404


def test_cannot_upload_into_sample(client):
    inv = client.post("/api/samples/tcp-refused/load").json()
    r = upload(client, inv["id"], (FIX / "dns_answered.pcap").read_bytes())
    assert r.status_code == 400 and r.json()["error"]["code"] == "sample_locked"


def test_live_plus_pcap_becomes_both(client, monkeypatch):
    monkeypatch.setattr(diagnostics, "_getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("198.51.100.9", 0))])
    inv = client.post("/api/investigations", json={"source": "both", "target": "example.com",
                      "live": {"dns": True, "tcp_ports": [], "http": False}}).json()
    assert inv["status"] == "awaiting_capture" and inv["source"] == "both"
    j = upload(client, inv["id"], (FIX / "dns_answered.pcap").read_bytes()).json()
    assert j["status"] == "completed" and j["source"] == "both" and j["checks"] and j["capture"]


# -- packet explorer ------------------------------------------------------------------------------------
@pytest.fixture
def inv_id(client):
    return client.post("/api/samples/tcp-refused/load").json()["id"]


def pk(client, inv_id, **params):
    r = client.get(f"/api/investigations/{inv_id}/packets", params=params)
    assert r.status_code == 200
    return r.json()


def test_packets_paging_and_schema(client, inv_id):
    page = pk(client, inv_id, limit=4)
    assert page["total"] == 9 and len(page["items"]) == 4 and page["items"][0]["index"] == 1
    assert "layers" not in page["items"][0] and "dns" not in page["items"][0]
    assert pk(client, inv_id, offset=8, limit=4)["items"][0]["index"] == 9


def test_packet_filters(client, inv_id):
    assert pk(client, inv_id, protocol="dns")["total"] == 2
    assert pk(client, inv_id, flag="RST")["total"] == 1
    assert pk(client, inv_id, port=8081)["total"] == 2
    assert pk(client, inv_id, ip="198.51.100.20")["total"] == 7
    assert pk(client, inv_id, marker="reset")["total"] == 1
    assert pk(client, inv_id, dns_name="service.example")["total"] == 2
    assert pk(client, inv_id, q="8081", protocol="tcp")["total"] == 2
    assert pk(client, inv_id, q="zzzz-no-match")["total"] == 0


def test_packet_filter_validation(client, inv_id):
    assert client.get(f"/api/investigations/{inv_id}/packets", params={"limit": 9999}).status_code == 422
    assert client.get(f"/api/investigations/{inv_id}/packets", params={"port": "abc"}).status_code == 422


def test_packet_detail(client, inv_id):
    d = client.get(f"/api/investigations/{inv_id}/packets/4").json()
    assert sorted(d["tcp_flags"].split(",")) == ["ACK", "RST"] and d["layers"] and "reset" in d["markers"]
    assert client.get(f"/api/investigations/{inv_id}/packets/99").status_code == 404
    assert client.get(f"/api/investigations/{inv_id}/packets/0").status_code == 404


def test_packets_empty_without_capture(client):
    inv = client.post("/api/samples/http-503/load").json()
    assert pk(client, inv["id"])["total"] == 0


# -- reports ----------------------------------------------------------------------------------------------
def test_report_uses_real_data(client):
    inv = client.post("/api/samples/dns-unanswered/load").json()
    rep = Report.model_validate(client.get(f"/api/investigations/{inv['id']}/report").json())
    assert rep.simulated and "SIMULATED" in rep.summary
    assert rep.packet_evidence and rep.packet_evidence.dns_unanswered == 1 and rep.packet_evidence.total_packets == 9
    assert [f.rule_id for f in rep.findings] == [f["rule_id"] for f in inv["findings"]]
    assert rep.test_outcomes and rep.limitations and rep.next_steps and rep.evidence_index


def test_report_json_export(client):
    inv = client.post("/api/samples/http-503/load").json()
    r = client.get(f"/api/investigations/{inv['id']}/report.json")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    assert json.loads(r.text)["investigation_id"] == inv["id"]


def test_report_csv_export(client):
    inv = client.post("/api/samples/tcp-refused/load").json()
    r = client.get(f"/api/investigations/{inv['id']}/report.csv")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert {x["section"] for x in rows} >= {"report", "capture", "finding", "evidence", "next_step"}
    assert any(x["id"] == "TCP-001" for x in rows)


def test_csv_neutralizes_formula_injection(client):
    from app.services.reports import _cell
    assert _cell("=HYPERLINK(\"x\")").startswith("'=") and _cell("@SUM(A1)").startswith("'@") and _cell("ok") == "ok"
    inv = new_pcap_inv(client)
    upload(client, inv["id"], (FIX / "dns_answered.pcap").read_bytes(), "=cmd.pcap")
    csv_text = client.get(f"/api/investigations/{inv['id']}/report.csv").text
    assert ",=cmd.pcap" not in csv_text and "'=cmd.pcap" in csv_text


def test_report_404(client):
    assert client.get("/api/investigations/zzz/report").status_code == 404
    assert client.get("/api/investigations/zzz/report.csv").status_code == 404


def test_report_for_pending_investigation_is_honest(client):
    inv = new_pcap_inv(client)
    rep = client.get(f"/api/investigations/{inv['id']}/report").json()
    assert "No evidence has been attached" in rep["summary"] and not rep["simulated"]


def test_rules_catalogue(client):
    rules = client.get("/api/rules").json()
    assert len(rules) >= 10 and all(r["does_not_prove"] for r in rules)


def test_store_is_bounded(client, monkeypatch):
    from app.config import Settings
    import app.services.investigations as inv_mod
    monkeypatch.setattr(inv_mod, "get_settings", lambda: Settings(max_investigations=3))
    for _ in range(5):
        client.post("/api/samples/insufficient/load")
    assert len(client.get("/api/investigations").json()) == 3


def test_tcp_connect_blocked_when_name_resolves_to_documentation_range(client, monkeypatch):
    monkeypatch.setattr(diagnostics, "_getaddrinfo", lambda *a, **k: [(2, 1, 6, "", ("198.51.100.9", 0))])
    r = client.post("/api/checks/tcp", json={"target": "example.com", "port": 443})
    assert r.status_code == 400
