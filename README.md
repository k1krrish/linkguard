# LinkGuard 2.0 — Network Incident Detective

<div align="center">

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Render-00F0FF?style=for-the-badge&logo=render&logoColor=white)](https://linkguard-de1c.onrender.com/#/)
[![Interactive Swagger](https://img.shields.io/badge/Swagger-API%20Docs-85EA2D?style=for-the-badge&logo=swagger&logoColor=black)](https://linkguard-de1c.onrender.com/docs)
[![Health Status](https://img.shields.io/badge/Engine%20Health-Active-00FF88?style=for-the-badge&logo=statuspage&logoColor=black)](https://linkguard-de1c.onrender.com/api/health)
[![GitHub Repo](https://img.shields.io/badge/GitHub-Repository-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/k1krrish/linkguard)

<br/>

[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-19.0+-61DAFB?style=flat-square&logo=react)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5+-3178C6?style=flat-square&logo=typescript)](https://www.typescriptlang.org)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-3.4+-38B2AC?style=flat-square&logo=tailwind-css)](https://tailwindcss.com)
[![Scapy](https://img.shields.io/badge/Scapy-2.5+-FF6F00?style=flat-square)](https://scapy.net)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python)](https://www.python.org)
[![Docker](https://img.shields.io/badge/Docker-Multi--Stage-2496ED?style=flat-square&logo=docker)](https://www.docker.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)

<p align="center">
  <strong>Evidence-Based Network Troubleshooting Across DNS, TCP/IP, and Packet Traces.</strong><br/>
  <em>A Computer Networks (CSE3003) Project</em>
</p>

</div>

---

> 🚀 **Live Production Cloud Deployment**: [https://linkguard-de1c.onrender.com/#/](https://linkguard-de1c.onrender.com/#/)  
> 📖 **Interactive Swagger REST Documentation**: [https://linkguard-de1c.onrender.com/docs](https://linkguard-de1c.onrender.com/docs)  
> 🩺 **Live Engine Health Telemetry**: [https://linkguard-de1c.onrender.com/api/health](https://linkguard-de1c.onrender.com/api/health)  
> 🎓 **Academic Viva Preparation & 50-Question Bank**: [`docs/viva-preparation.md`](docs/viva-preparation.md)

---

## Table of Contents

- [Overview & Philosophy](#overview--philosophy)
- [Key Features](#key-features)
- [System Architecture](#system-architecture)
- [Diagnostic Rule Catalog](#diagnostic-rule-catalog)
- [Live Cloud Deployment](#live-cloud-deployment)
- [Local Quickstart](#local-quickstart)
  - [Prerequisites](#prerequisites)
  - [Backend Setup](#1-backend-setup)
  - [Frontend Setup](#2-frontend-setup)
  - [Running with Docker Compose](#3-running-with-docker-compose)
- [Testing & Quality Assurance](#testing--quality-assurance)
- [REST API Specifications](#rest-api-specifications)
- [Defense-in-Depth Security](#defense-in-depth-security)
- [Project Structure](#project-structure)
- [Academic Context](#academic-context)
- [License](#license)

---

## Overview & Philosophy

**LinkGuard** is a forensic network diagnostic platform engineered to triage application and transport-layer incidents without speculative claims. In real-world enterprise environments, troubleshooting network outages frequently suffers from imprecise finger-pointing: is the server down, is DNS timing out, is a firewall silently dropping SYN packets, or did a proxy return a 503 gateway error?

LinkGuard pairs **active multi-vector network probes** with **in-memory PCAP/PCAPNG packet dissection (via Scapy)**. Observations are evaluated against **10 transparent, RFC-grounded diagnostic rules** to deliver deterministic, evidence-backed reports with explicit forensic boundary limits.

### The Four Tenets of Network Forensics

1. **Observations Over Claims**: A failed network probe is strictly an observation from a single client vantage point — never an unverified claim that *"the target server is down"*.
2. **Absence is Not Proof**: Packets not observed in a packet capture are never reported as *"did not occur"*; captures can be truncated, filtered, or taken on a different network segment.
3. **Transparent Boundaries**: Every diagnostic finding explicitly documents what was observed, what it **does not prove**, alternative explanations (firewalls, asymmetric routing), and recommended next steps.
4. **No Speculative Percentages**: When evidence is incomplete or ambiguous, the engine outputs **inconclusive** rather than generating hallucinated confidence percentages.

---

## Key Features

### 🔍 Triple-Vector Active Diagnostics
- **DNS Resolution Engine**: Resolves `A` and `AAAA` records via system resolvers, measuring exact resolution latencies down to the millisecond and categorizing socket failure exceptions (`NXDOMAIN`, resolver timeout, refused).
- **TCP Three-Way Handshake Connect Probe**: Performs non-blocking socket handshakes across target ports (e.g., 443, 80, 22, 53) with microsecond precision, distinguishing between immediate resets (`RST`), silence (`ETIMEDOUT`), and successful handshakes.
- **HTTP/HTTPS Status & TLS Inspector**: Executes non-redirecting HTTP requests to isolate root-cause response codes (4xx client errors vs. 5xx server failures) without following redirection loops.

### 📦 In-Memory PCAP/PCAPNG Dissection (Zero Disk Persistence)
- **High-Performance Streaming**: Byte buffers are dissected directly in RAM via `scapy.utils.PcapReader`. Uploaded `.pcap` and `.pcapng` files are never persisted to disk, safeguarding confidentiality.
- **DNS Transaction ID Matching**: Correlates DNS request frames with corresponding responses using 16-bit transaction IDs (`id`), computing round-trip response times and flagging orphaned or unanswered requests.
- **TCP 4-Tuple Flow Reconstruction**: Reconstructs transport flows by bidirectional `(src_ip, src_port, dst_ip, dst_port)` tuples. Monitors `SYN`, `ACK`, `FIN`, and `RST` sequences to detect mid-stream resets, dropped handshakes, and retransmissions.

### 🧠 10-Rule Diagnostic Inference Engine
- Evaluates synthesized telemetry against deterministic rules mapped to standard RFCs.
- Categorizes findings into three unambiguous states:
  - 🔴 **`issue`**: Clear evidence of transport or application-layer failure.
  - 🟡 **`inconclusive`**: Ambiguous observations requiring additional capture data or vantage points.
  - 🟢 **`ok`**: Expected healthy protocol interaction confirmed.
- Generates actionable next-step testing guides and boundary statements for every finding.

### 🔬 Interactive Wireshark-Grade Packet Explorer
- High-density packet table with protocol-aware color coding (DNS, TCP, HTTP, ICMP, ARP).
- Live substring search, protocol filtering, and bidirectional direction toggle.
- Dual-pane payload viewer with full protocol header dissection and formatted byte/hex representations.

### 🏛️ Library of Solved Issues & Incident Audit Trail
- 1-click incident verification and remediation workflow.
- Solved incidents transition to the **Library of Solved Issues**, dynamically updating dashboard KPI gauges and incident resolution ratios.
- Full audit history retention with bidirectional state restoration (active ↔ resolved).

### 🧪 Pre-Configured Reference Simulation Scenarios
- 1-click test scenarios for rapid demonstration:
  1. **DNS Queries Dropped**: Unanswered DNS UDP frames simulating upstream resolver outages.
  2. **TCP Port Refused**: TCP SYN probe eliciting an immediate RST packet from a closed daemon.
  3. **HTTP 503 Web Failure**: Upstream gateway failure with healthy underlying TCP transport.

---

## System Architecture

```mermaid
flowchart TD
    subgraph Client ["Client Layer (React 19 + TypeScript + Vite)"]
        UI["Incident Dashboard"]
        INV["Investigation Workbench"]
        PKT["Packet Explorer & Hex Inspector"]
        REP["Diagnostic Report Generator"]
        SOL["Library of Solved Issues"]
        API_CLIENT["Type-Safe REST Client (/api)"]
    end

    subgraph Edge ["Cloud / Edge Deployment (Render)"]
        PROXY["Unified Docker Container (Port 8000)"]
    end

    subgraph Engine ["Backend Forensic Engine (FastAPI + Python 3.10+)"]
        ROUTER["REST API Router (/api/*)"]
        SSRF["SSRF Defense Guard (RFC 1918 / Loopback)"]
        DIAG["Active Diagnostic Probes (DNS / TCP / HTTP)"]
        DISSECT["In-Memory PCAP Dissector (Scapy)"]
        RULES["10-Rule Inference Engine"]
        MEM["Ephemeral In-Memory Incident Store"]
        EXPORTER["Report Generator (JSON / Safe-CSV)"]
    end

    Client -->|HTTPS / REST / Multipart| PROXY
    PROXY --> ROUTER
    ROUTER --> SSRF
    SSRF --> DIAG
    SSRF --> DISSECT
    DIAG --> RULES
    DISSECT --> RULES
    RULES --> MEM
    MEM --> EXPORTER
    EXPORTER --> Client
```

---

## Diagnostic Rule Catalog

| Rule ID | Title | Protocol / Layer | Trigger Condition | RFC Reference | Forensic Classification |
|---|---|---|---|---|---|
| `LIVE-DNS-001` | DNS Resolution Timeout | DNS (Application) | System resolver returned resolution failure or lookup timeout | RFC 1035 | 🔴 Issue / 🟡 Inconclusive |
| `LIVE-TCP-001` | TCP Connection Refused | TCP (Transport) | TCP SYN probe received RST packet or connection refused error | RFC 793 / 9293 | 🔴 Issue |
| `LIVE-TCP-002` | TCP Connection Timed Out | TCP (Transport) | TCP SYN packet elicited no response within configured timeout | RFC 793 / 9293 | 🟡 Inconclusive |
| `LIVE-HTTP-001` | Server Error (5xx Status) | HTTP (Application) | Server returned HTTP status code in the 500–599 range | RFC 9110 | 🔴 Issue |
| `LIVE-HTTP-002` | Client Error (4xx Status) | HTTP (Application) | Server returned HTTP status code in the 400–499 range | RFC 9110 | 🔴 Issue |
| `PCAP-DNS-001` | DNS Queries Unanswered | DNS (Packet Trace) | DNS query frames observed with no matching transaction ID response | RFC 1035 | 🔴 Issue |
| `PCAP-TCP-001` | TCP Connection Refused | TCP (Packet Trace) | Outgoing TCP SYN immediately answered by an incoming RST frame | RFC 793 / 9293 | 🔴 Issue |
| `PCAP-TCP-002` | TCP Mid-Stream Reset | TCP (Packet Trace) | TCP RST frame observed after successful three-way handshake | RFC 793 / 9293 | 🔴 Issue |
| `PCAP-TCP-003` | TCP Retransmissions | TCP (Packet Trace) | Duplicate TCP sequence numbers with identical payload lengths detected | RFC 793 / 9293 | 🟡 Inconclusive |
| `PCAP-GEN-001` | Insufficient Evidence | General (Capture) | Capture file contains fewer than 2 packets or zero protocol frames | N/A | 🟡 Inconclusive |

---

## Live Cloud Deployment

LinkGuard is deployed in production on **Render** as a unified, production-hardened container service:

- **Web Application**: [https://linkguard-de1c.onrender.com/#/](https://linkguard-de1c.onrender.com/#/)
- **Swagger REST API**: [https://linkguard-de1c.onrender.com/docs](https://linkguard-de1c.onrender.com/docs)
- **Health Telemetry**: [https://linkguard-de1c.onrender.com/api/health](https://linkguard-de1c.onrender.com/api/health)

### Cloud Architecture Highlights
- **Single Multi-Stage Dockerfile**: Builds the React 19 SPA with Vite, copies static assets into the Python backend runtime, and serves both the API endpoints (`/api/*`) and SPA routing from a unified Uvicorn server on port 8000.
- **Zero CORS Friction**: Because both frontend and backend share the same origin in production, cross-origin request issues and latency overhead are eliminated.
- **Auto-Deploy CI/CD**: Pushes to the `main` branch on GitHub automatically trigger build and deployment cycles on Render.

---

## Local Quickstart

### Prerequisites
- **Python**: Version `3.10` or higher
- **Node.js**: Version `18` or higher
- **Git**

---

### 1. Backend Setup

```bash
# Clone repository
git clone https://github.com/k1krrish/linkguard.git
cd linkguard/backend

# Create and activate virtual environment
python -m venv .venv

# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
# Linux / macOS:
source .venv/bin/activate

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

Open a second terminal window:

```bash
cd linkguard/frontend

# Install dependencies
npm install

# Start Vite development server
npm run dev
```

- **Frontend Application**: [http://localhost:5173](http://localhost:5173)

---

### 3. Running with Docker Compose

Launch the entire stack with a single command:

```bash
docker compose up --build -d
```

Access the unified application locally at [http://localhost:8000](http://localhost:8000).

---

## Testing & Quality Assurance

LinkGuard includes an extensive test suite covering SSRF defense, live probe parsing, PCAP frame dissection, rule inference, and report serialization:

### Backend Test Suite (Pytest)
```bash
cd backend
python -m pytest -v
```
*Includes 190+ unit, integration, and security assertion tests.*

### Frontend Verification (TypeScript & Build)
```bash
cd frontend
npm run build
```
*Validates type safety across all React components and packages production assets.*

---

## REST API Specifications

| Method | Endpoint | Description | Request Payload / Params |
|---|---|---|---|
| `GET` | `/api/health` | Engine version, status, max upload limits, SSRF state | None |
| `GET` | `/api/rules` | Complete index of 10 diagnostic rules with logic and limits | None |
| `GET` | `/api/samples` | List of reference simulation scenarios | None |
| `POST` | `/api/samples/{id}/load` | Load a reference simulation incident into active store | URL path parameter |
| `POST` | `/api/checks/dns` | Execute real-time DNS lookup probe | `{"target": "example.com", "timeout": 5.0}` |
| `POST` | `/api/checks/tcp` | Execute non-blocking TCP handshake connect probe | `{"target": "example.com", "port": 443, "timeout": 5.0}` |
| `POST` | `/api/checks/http` | Execute non-redirecting HTTP status check probe | `{"url": "https://example.com", "method": "GET"}` |
| `GET` | `/api/investigations` | Retrieve all active and resolved investigation sessions | None |
| `POST` | `/api/investigations` | Initialize a new forensic investigation session | `CreatePayload` (symptom, live probes config) |
| `GET` | `/api/investigations/{id}` | Retrieve investigation findings, timeline, and checks | URL path parameter |
| `POST` | `/api/investigations/{id}/resolve` | Toggle resolution status (moves between Active & Solved) | URL path parameter |
| `POST` | `/api/investigations/{id}/capture` | Upload and dissect PCAP/PCAPNG capture in RAM | Multipart file upload (`.pcap`, `.pcapng`) |
| `GET` | `/api/investigations/{id}/packets` | Paginated packet frames with protocol and query filters | `?page=1&limit=50&protocol=dns&search=query` |
| `GET` | `/api/investigations/{id}/report` | Retrieve executive report summary and structured findings | URL path parameter |

---

## Defense-in-Depth Security

LinkGuard is designed for safe educational, diagnostic, and laboratory usage with rigorous security boundaries:

- **Server-Side Request Forgery (SSRF) Guard (`validation.py`)**:
  - Automatically rejects loopback addresses (`127.0.0.0/8`, `::1`), private networks (RFC 1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), carrier-grade NAT (`100.64.0.0/10`), link-local addresses (`169.254.0.0/16`), and multicast subnets.
  - Rejects internal DNS suffix queries (`.localhost`, `.local`, `.internal`, `.lan`, `.corp`).
  - Blocks embedded user authentication credentials in probe URLs (`http://admin:secret@target`).
  - Limits TCP target ports to an explicit whitelist of safe diagnostic ports.
- **Zero Disk Persistence**: Uploaded capture payloads are parsed strictly in memory and discarded upon session recycling.
- **CSV Formula Injection Mitigation**: Exported diagnostic spreadsheets sanitize cells starting with `=`, `+`, `-`, or `@` to prevent execution in spreadsheet software.

---

## Project Structure

```
linkguard/
├── .github/                         # GitHub repository configuration
├── backend/                         # FastAPI Diagnostic Engine
│   ├── app/
│   │   ├── api/
│   │   │   └── routes.py            # REST API endpoints & route handlers
│   │   ├── rules/
│   │   │   ├── base.py              # Abstract Rule interface & evaluation models
│   │   │   ├── engine.py            # Rule evaluation orchestrator
│   │   │   ├── live_rules.py        # Live network probe diagnostic rules
│   │   │   └── pcap_rules.py        # PCAP packet analysis diagnostic rules
│   │   ├── schemas/
│   │   │   └── models.py            # Pydantic domain models & schemas
│   │   ├── services/
│   │   │   ├── diagnostics.py       # Live DNS, TCP, and HTTP probe execution
│   │   │   ├── evidence.py          # Telemetry & evidence normalization
│   │   │   ├── fixtures.py          # Synthetic PCAP fixture generation
│   │   │   ├── investigations.py    # Investigation session lifecycle management
│   │   │   ├── pcap.py              # In-memory Scapy PCAP/PCAPNG dissector
│   │   │   ├── reports.py           # Executive report generation & CSV export
│   │   │   ├── samples.py           # Reference simulation incident scenarios
│   │   │   └── validation.py        # SSRF defense & input sanitization
│   │   ├── config.py                # Environment configuration & CORS origins
│   │   └── main.py                  # FastAPI entry point & SPA static mounting
│   ├── scripts/
│   │   └── generate_fixtures.py     # Test fixture generation utility
│   ├── tests/                       # Pytest test suite (190+ tests)
│   ├── pytest.ini                   # Pytest configuration
│   └── requirements.txt             # Backend Python dependencies
├── frontend/                        # React 19 SPA
│   ├── public/                      # Static assets & web manifest
│   ├── src/
│   │   ├── components/
│   │   │   ├── domain.tsx           # Telemetry cards, charts, and findings
│   │   │   └── ui.tsx               # Forensic HUD panels, badges, and meters
│   │   ├── pages/
│   │   │   ├── InvestigationDetails.tsx # Live triage, findings, and resolution
│   │   │   ├── NewInvestigation.tsx     # Probe builder & drag-and-drop PCAP
│   │   │   ├── Overview.tsx             # Main dashboard, KPIs & Solved Library
│   │   │   ├── PacketExplorer.tsx       # Searchable packet dissector & hex viewer
│   │   │   ├── Reports.tsx              # Diagnostic report preview & CSV export
│   │   │   └── Rules.tsx                # Formal diagnostic rule catalog
│   │   ├── api.ts                   # Type-safe API client
│   │   ├── context.tsx              # React context & incident state management
│   │   ├── index.css                # Forensic UI styling & themes
│   │   ├── lib.ts                   # Helper functions & formatting utilities
│   │   ├── main.tsx                 # React application entry point
│   │   └── types.ts                 # TypeScript type declarations
│   ├── index.html                   # HTML template
│   ├── package.json                 # Frontend dependencies
│   ├── tailwind.config.js           # Tailwind CSS styling configuration
│   └── vite.config.ts               # Vite build configuration & dev proxy
├── docs/                            # Academic & Architectural Documentation
│   ├── architecture.md              # In-depth architectural design document
│   ├── test-plan.md                 # Test plan, edge cases, and verification
│   └── viva-preparation.md          # 50-Question Viva & Interview preparation
├── Dockerfile                       # Multi-stage production container build
├── docker-compose.yml               # Local container orchestration
├── .env.example                     # Environment configuration template
├── .gitignore                       # Git ignore rules
└── README.md                        # Master documentation
```

---

## Academic Context

LinkGuard was designed and implemented for the **Computer Networks (CSE3003)** curriculum. It bridges theoretical protocol models (OSI and TCP/IP stack layers) with practical network forensics:

- **Layer 7 (Application)**: DNS lookup failure semantics (RFC 1035), HTTP status taxonomy (RFC 9110), TLS handshake protocol.
- **Layer 4 (Transport)**: TCP state transitions (RFC 793, RFC 9293), sequence number mechanics, window dynamics, retransmissions, and three-way handshake anomalies.
- **Layer 3 (Network)**: IPv4/IPv6 packet structure, RFC 1918 private address boundaries, ICMP error propagation.

For comprehensive viva preparation, detailed explanations of all network terms, and answers to 50 faculty review questions, consult [`docs/viva-preparation.md`](docs/viva-preparation.md).

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for complete details. Developed for forensic demonstration and educational research.
