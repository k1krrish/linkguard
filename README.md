# LinkGuard 2.0 — Network Incident Detective

[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-19.0+-61DAFB?style=flat-square&logo=react)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5+-3178C6?style=flat-square&logo=typescript)](https://www.typescriptlang.org)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-3.4+-38B2AC?style=flat-square&logo=tailwind-css)](https://tailwindcss.com)
[![Scapy](https://img.shields.io/badge/Scapy-2.5+-FF6F00?style=flat-square)](https://scapy.net)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python)](https://www.python.org)

**Evidence-Based Network Troubleshooting Across DNS, TCP/IP, and Packet Traces.**  
*A Computer Networks (CSE3003) Project.*

LinkGuard investigates application-layer network symptoms (e.g., DNS lookup timeouts, TCP connection resets, HTTP 503 server failures) using **real-time diagnostic network probes** and **in-memory PCAP/PCAPNG packet dissection**. It evaluates observations against **transparent diagnostic rules** to produce structured, evidence-based diagnostic reports with explicit boundary limitations.

---

## Guiding Principles: Honesty in Network Forensics

1. **Observations Over Claims**: A failed probe is an observation from one specific vantage point, never an assertion that "the target server is offline".
2. **Absence is Not Proof**: Packets not observed in a capture are never reported as "did not occur" (the capture might be filtered, truncated, or taken on a different segment).
3. **Transparent Boundaries**: Every diagnostic finding documents what was observed, what it **does not prove**, alternative explanations, and the recommended next test.
4. **No Speculative Percentages**: When evidence is insufficient, the system reports **inconclusive** rather than generating synthetic confidence scores.

---

## System Architecture

```mermaid
flowchart TD
    subgraph Frontend ["Frontend Terminal (React 19 + TypeScript + Vite)"]
        UI["Incident Operations Dashboard"]
        OV["Incident Overview Dashboard"]
        INV["Investigation Workbench"]
        PKT["Interactive Packet Explorer"]
        REP["Diagnostic Report Generator"]
        RUL["Diagnostic Rules Index"]
        SL["Library of Solved Issues"]
        API_CLIENT["Type-Safe REST Client (fetch + timeout)"]
    end

    subgraph Backend ["Backend Engine (FastAPI + Python 3.10+)"]
        ROUTER["REST API Router (/api/*)"]
        SSRF["SSRF Defensive Guard (RFC 1918 / Loopback)"]
        DIAG["Live Diagnostics (DNS / TCP / HTTP)"]
        PCAP_DISSECT["In-Memory PCAP Dissector (Scapy)"]
        RULE_ENG["10-Rule Diagnostic Inference Engine"]
        MEM_STORE["In-Memory Ephemeral Store"]
        REP_GEN["Report Serializer (JSON / CSV / Formula-Safe)"]
    end

    UI --> API_CLIENT
    API_CLIENT -->|HTTP / JSON / Multipart| ROUTER
    ROUTER --> SSRF
    SSRF --> DIAG
    SSRF --> PCAP_DISSECT
    DIAG --> RULE_ENG
    PCAP_DISSECT --> RULE_ENG
    RULE_ENG --> MEM_STORE
    MEM_STORE --> REP_GEN
```

### Data Flow & Component Breakdown

1. **Live Diagnostics Layer**:
   - **DNS Resolution**: Queries system resolver for `A` and `AAAA` records, capturing resolution latency and socket exceptions.
   - **TCP Handshake Probe**: Attempts non-blocking TCP three-way handshake across user-specified ports (e.g., 443, 80, 22, 53) with microsecond precision.
   - **HTTP/HTTPS Checker**: Issues HTTP requests without following redirects (preventing SSRF redirection loops), validating status codes, response headers, and TLS handshake protocols.

2. **Packet Analysis Pipeline (Scapy)**:
   - **In-Memory Streaming**: PCAP/PCAPNG byte payloads are parsed directly in RAM via `scapy.utils.PcapReader` — zero capture files are persisted to disk.
   - **DNS Query/Response Transaction Matching**: Matches queries and replies by transaction ID (`id`), calculating round-trip response times and flagging unanswered queries.
   - **TCP Flow Reconstruction**: Groups packets by bidirectional 4-tuple `(src_ip, src_port, dst_ip, dst_port)`. Tracks `SYN`, `ACK`, `FIN`, and `RST` sequences, detecting resets and retransmissions.

3. **Diagnostic Rule Engine**:
   - Evaluates normalized evidence against 10 formal rules grounded in transport and application-layer RFCs.
   - Outputs findings categorized into `issue`, `inconclusive`, and `ok`, complete with limitation statements and next-step testing guides.

4. **Resolution Workflow & Library of Solved Issues**:
   - Incidents can be verified and resolved with 1-click.
   - Solved incidents are moved from the active dashboard to the persistent **Library of Solved Issues**, dynamically updating KPI counters.
   - Solved issues retain complete audit histories and can be reopened at any time.

---

## Diagnostic Rule Catalog

| Rule ID | Title | Target Protocol | Trigger Condition |
|---|---|---|---|
| `LIVE-DNS-001` | DNS Resolution Timeout | DNS (Live) | System resolver returned resolution failure or lookup timeout |
| `LIVE-TCP-001` | TCP Connection Refused | TCP (Live) | TCP SYN probe received RST packet or connection refused error |
| `LIVE-TCP-002` | TCP Connection Timed Out | TCP (Live) | TCP SYN packet elicited no response within configured timeout window |
| `LIVE-HTTP-001` | Server Error (5xx Status) | HTTP/HTTPS (Live) | HTTP server returned status code in the 500–599 range |
| `LIVE-HTTP-002` | Client Error (4xx Status) | HTTP/HTTPS (Live) | HTTP server returned status code in the 400–499 range |
| `PCAP-DNS-001` | DNS Queries Unanswered | DNS (PCAP) | DNS query frames observed with no matching transaction ID response |
| `PCAP-TCP-001` | TCP Connection Refused | TCP (PCAP) | Outgoing TCP SYN immediately answered by an incoming RST frame |
| `PCAP-TCP-002` | TCP Mid-Stream Reset | TCP (PCAP) | TCP RST frame observed after handshake completion |
| `PCAP-TCP-003` | TCP Retransmissions | TCP (PCAP) | Duplicate TCP sequence numbers with identical payload lengths detected |
| `PCAP-GEN-001` | Insufficient Evidence | General (PCAP) | Capture file contains fewer than 2 packets or zero protocol frames |

---

## Security & Defense-in-Depth

LinkGuard was engineered with strict safety mechanisms for safe educational and defensive use:

- **SSRF Defensive Guard (`validation.py`)**:
  - Rejects localhost (`127.0.0.0/8`, `::1`), private networks (RFC 1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`), and multicast addresses.
  - Rejects internal domain suffixes (`.localhost`, `.local`, `.internal`, `.lan`, `.corp`).
  - Blocks embedded user credentials in target URLs (`http://user:pass@host`).
  - Limits TCP target ports to an explicit allow-list.
- **Zero Disk Persistence**: Uploaded capture files are parsed strictly in memory and discarded immediately after session disposal.
- **Formula Injection Mitigation**: Exported CSV reports sanitize formulas starting with `=`, `+`, `-`, or `@` to prevent spreadsheet execution.

---

## Project Structure

```
linkguard/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   └── routes.py            # REST endpoints (checks, investigations, samples, reports)
│   │   ├── rules/
│   │   │   ├── base.py              # Abstract Rule definition & schema
│   │   │   ├── engine.py            # Rule catalog & evaluation pipeline
│   │   │   ├── live_rules.py        # Live probe diagnostic rules
│   │   │   └── pcap_rules.py        # PCAP packet analysis rules
│   │   ├── schemas/
│   │   │   └── models.py            # Pydantic v2 domain models
│   │   ├── services/
│   │   │   ├── diagnostics.py       # Live DNS, TCP, and HTTP probe execution
│   │   │   ├── evidence.py          # Evidence normalization layer
│   │   │   ├── fixtures.py          # Synthetic PCAP fixture generation
│   │   │   ├── investigations.py    # Investigation session lifecycle & in-memory store
│   │   │   ├── pcap.py              # Scapy PCAP/PCAPNG packet dissector
│   │   │   ├── reports.py           # Executive report generation & CSV export
│   │   │   ├── samples.py           # 16 reference simulation incident profiles
│   │   │   └── validation.py        # SSRF security guard & IP validation
│   │   ├── config.py                # Environment configuration
│   │   └── main.py                  # FastAPI application entry point & CORS
│   ├── scripts/
│   │   └── generate_fixtures.py     # Script to generate test PCAP captures
│   ├── tests/                       # Pytest test suite (unit, API, rules, pcap)
│   ├── pytest.ini                   # Pytest configuration
│   └── requirements.txt             # Backend dependencies
├── frontend/
│   ├── public/                      # Static assets & favicons
│   ├── src/
│   │   ├── components/
│   │   │   ├── domain.tsx           # Findings, probe telemetry, packet & traffic charts
│   │   │   └── ui.tsx               # High-density UI panels, badges, reticles, stats
│   │   ├── pages/
│   │   │   ├── InvestigationDetails.tsx # Live telemetry, findings, and resolution
│   │   │   ├── NewInvestigation.tsx     # 3-way probe builder & drag-and-drop PCAP
│   │   │   ├── Overview.tsx             # Main dashboard, KPI meters & Solved Library
│   │   │   ├── PacketExplorer.tsx       # Searchable packet dissector & hex layer viewer
│   │   │   ├── Reports.tsx              # Diagnostic report preview & JSON/CSV exports
│   │   │   └── Rules.tsx                # Formal diagnostic rule catalog
│   │   ├── api.ts                   # Type-safe backend API integration client
│   │   ├── context.tsx              # Global state management for incidents
│   │   ├── index.css                # Forensic UI styles & scanline accents
│   │   ├── lib.ts                   # Utility functions & formatting helpers
│   │   ├── main.tsx                 # React entry point
│   │   └── types.ts                 # TypeScript type definitions
│   ├── index.html                   # HTML template with Google Fonts (Orbitron/Rajdhani)
│   ├── package.json                 # Frontend dependencies
│   ├── tailwind.config.js           # Design tokens & color palette
│   └── vite.config.ts               # Vite configuration & proxy
├── docs/
│   ├── architecture.md              # Deep architectural overview & data flow
│   ├── test-plan.md                 # Verification test plan & edge cases
│   └── viva-preparation.md          # Comprehensive Q&A for academic reviews
├── .env.example                     # Example environment variables
├── .gitignore                       # Git ignore rules
└── README.md                        # Documentation
```

---

## Quickstart Guide

### Prerequisites
- **Python**: Version `3.10` or higher
- **Node.js**: Version `18` or higher
- **Git**

---

### 1. Backend Setup

```bash
cd backend

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
# Linux / macOS:
# source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start backend server
uvicorn app.main:app --port 8000 --reload
```

- **Backend API**: [http://127.0.0.1:8000](http://127.0.0.1:8000)
- **Interactive Swagger Docs**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **Health Check Endpoint**: [http://127.0.0.1:8000/api/health](http://127.0.0.1:8000/api/health)

---

### 2. Frontend Setup

Open a second terminal:

```bash
cd frontend

# Install Node dependencies
npm install

# Start development server
npm run dev
```

- **Frontend Dashboard**: [http://localhost:5173](http://localhost:5173)

---

### 3. Production & Cloud Deployment (Docker)

LinkGuard includes a multi-stage `Dockerfile` that packages both the React frontend build and the FastAPI backend engine into a single, unified container:

#### Run with Docker Compose
```bash
docker compose up --build -d
```
Access the unified application at [http://localhost:8000](http://localhost:8000).

#### Deploy to Cloud (Render / Railway / Fly.io / VPS)
- **Render**: Connect your GitHub repository and select **Web Service** using `Dockerfile` (or use the included `render.yaml`).
- **Railway**: Click **Deploy from GitHub repo** — Railway automatically detects the root `Dockerfile`.
- **Fly.io**: Run `fly launch` and deploy with standard port 8000 routing.

---

### 4. Running Automated Tests

#### Backend Test Suite (Pytest)
```bash
cd backend
pytest -v
```

#### Frontend Typecheck & Build
```bash
cd frontend
npm run build
```

---

## API Reference Summary

| Endpoint | Method | Description |
|---|---|---|
| `/api/health` | `GET` | System health, engine version, upload limits, SSRF state |
| `/api/rules` | `GET` | List all 10 diagnostic rules with criteria and limitations |
| `/api/samples` | `GET` | List available reference simulation scenarios |
| `/api/samples/{id}/load` | `POST` | Load reference simulation incident into active dashboard |
| `/api/checks/dns` | `POST` | Execute live DNS resolution probe against public domain |
| `/api/checks/tcp` | `POST` | Execute live TCP handshake connect probe against target port |
| `/api/checks/http` | `POST` | Execute live HTTP/HTTPS status probe against target URL |
| `/api/investigations` | `GET` | Retrieve list of active and resolved investigations |
| `/api/investigations` | `POST` | Create a new diagnostic investigation session |
| `/api/investigations/{id}` | `GET` | Retrieve investigation findings, timeline, and checks |
| `/api/investigations/{id}/resolve`| `POST` | Toggle resolution status (moves between Active and Solved Library) |
| `/api/investigations/{id}/capture`| `POST` | Upload and dissect PCAP/PCAPNG capture in memory |
| `/api/investigations/{id}/packets`| `GET` | Retrieve paginated packet frames with protocol filtering |
| `/api/investigations/{id}/report` | `GET` | Retrieve executive report summary and findings |

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details. Built for educational and forensic demonstration.
