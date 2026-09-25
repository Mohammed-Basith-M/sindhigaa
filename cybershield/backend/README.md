# CyberShield Backend - PCAP Threat Intelligence Engine

The CyberShield backend is a modular, high-throughput network packet dissection and threat intelligence service.

## Key Architecture Features
- **Zero-Dependency Native Dissection**: Built-in binary parser (`analyzer/pcap_parser.py`) supports classic `.pcap` (both little and big endian microsecond/nanosecond) and modern `.pcapng` (Section Header & Enhanced Packet Blocks) using Python standard library `struct` and `socket`.
- **Dual Runtime Compatibility**: 
  - Runs natively with Python 3 standard library (`http.server`, `sqlite3`, `socket`, `struct`) — zero external `pip` packages required.
  - Automatically elevates to full Flask + `flask_cors` + Scapy if installed.
- **Dynamic Port Selection**: Defaults to port `5000` (configurable via `BACKEND_PORT` or `FLASK_PORT`), with automatic socket conflict resolution to avoid port collision.

---

## Quick Start (Zero Dependencies)

Run directly using Python 3 without installing any third-party packages:
```bash
cd cybershield/backend
python3 app.py
```
Output:
```text
[*] CyberShield PCAP Analyzer Backend listening on http://0.0.0.0:5000
```

---

## Production / Virtual Environment Setup (Optional)

```bash
cd cybershield/backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Service health status check |
| `POST` | `/upload` | Upload `.pcap` or `.pcapng` file (max 50 MB) for live analysis |
| `GET` | `/demo` | Generate sample synthetic reconnaissance scenario |
| `GET` | `/stats` | Aggregate SOC dashboard metrics |
| `GET` | `/history` | Search and filter previous analysis records |
| `GET` | `/results/<analysis_id>` | Retrieve full telemetry and XAI dossier |
| `DELETE` | `/history/<analysis_id>` | Remove record from persistent audit ledger |
| `GET` | `/api/sample-pcaps` | Enumerate pre-synthesized test captures |
| `POST` | `/api/analyze-sample` | Analyze server-side sample capture |
| `GET` | `/api/download-sample/<filename>` | Download raw test capture binary |

---

## Testing & CLI Analysis

### 1. Dissect a PCAP from Terminal
```bash
python3 analyzer/run_analysis.py ../../tests/test_files/port_scan.pcap
```

### 2. Run Complete Automated Test Suite (10 Test Cases)
```bash
python3 ../../tests/run_tests.py
```
