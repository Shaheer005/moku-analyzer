# moku-analyzer

A vulnerability analyzer service built for the [moku](https://github.com/Raysh454/moku) platform. This service receives scan requests from moku's Go client, runs vulnerability analysis using a pluggable adapter system, and returns structured results.

Built with Python + FastAPI as part of a Final Year Project at DHA Suffa University.

---

## What This Does

Moku crawls websites and monitors for changes. When it finds a page, it sends it here for vulnerability analysis. This service:

1. Receives a scan request (URL or HTML) from moku
2. Runs it through a selected vulnerability scanner (adapter)
3. Returns structured vulnerability findings back to moku

The key design is the **Adapter Pattern** — any vulnerability scanner can be plugged in without changing the core system.

---

## Architecture

```
moku (Go client)
      │
      ▼  HTTP
┌─────────────────────────────────┐
│         moku-analyzer           │
│         (this service)          │
│                                 │
│  POST /scan                     │
│  GET  /scan/{id}                │
│  GET  /health                   │
│  GET  /adapters                 │
│                                 │
│  ┌──────────────────────────┐   │
│  │     Adapter Registry     │   │
│  │  builtin | nuclei | nikto│   │
│  │  shodan  | virustotal    │   │
│  │  zap     | mock          │   │
│  └──────────────────────────┘   │
└─────────────────────────────────┘
```

---

## Project Structure

```
moku-analyzer/
├── main.py                        # FastAPI app entry point, adapter registration
├── run.py                         # Server startup script
├── requirements.txt               # Python dependencies
├── .env                           # API keys (never committed to Git)
├── .gitignore
│
├── app/
│   ├── api/
│   │   └── routes.py              # API endpoints (POST /scan, GET /scan/{id}, etc.)
│   │
│   ├── core/
│   │   ├── job_store.py           # Thread-safe in-memory job storage
│   │   └── runner.py              # Background job executor
│   │
│   ├── models/
│   │   └── schemas.py             # Pydantic models (ScanRequest, ScanResult, Vulnerability)
│   │
│   └── adapters/
│       ├── base.py                # Abstract BaseAdapter class
│       ├── registry.py            # Adapter registry
│       ├── builtin_adapter.py     # Moku's own analyzer (Phase 2)
│       ├── nuclei_adapter.py      # Nuclei CLI wrapper
│       ├── nikto_adapter.py       # Nikto CLI wrapper
│       ├── shodan_adapter.py      # Shodan API integration
│       ├── virustotal_adapter.py  # VirusTotal API integration
│       ├── zap_adapter.py         # OWASP ZAP wrapper
│       └── mock_adapter.py        # Mock adapter for testing
│
└── tests/                         # Test scripts used during development
```

---

## Requirements

- Python 3.11+
- pip
- For Nuclei adapter: [Nuclei](https://github.com/projectdiscovery/nuclei/releases) installed and in PATH
- For Nikto adapter: [Nikto](https://github.com/sullo/nikto) installed and in PATH
- For ZAP adapter: [OWASP ZAP](https://www.zaproxy.org/download/) installed
- For Shodan adapter: Free Shodan API key from [shodan.io](https://shodan.io)
- For VirusTotal adapter: Free VirusTotal API key from [virustotal.com](https://virustotal.com)

---

## Setup & Installation

**Step 1 — Clone the repo:**
```bash
git clone https://github.com/Shaheer005/moku-analyzer.git
cd moku-analyzer
```

**Step 2 — Create a virtual environment:**
```bash
python -m venv .venv
```

**Step 3 — Activate the virtual environment:**

Windows:
```bash
.venv\Scripts\activate
```

Mac/Linux:
```bash
source .venv/bin/activate
```

**Step 4 — Install dependencies:**
```bash
pip install -r requirements.txt
```

**Step 5 — Create your `.env` file:**
```bash
cp .env.example .env
```
Or create `.env` manually in the project root:
```
SHODAN_API_KEY=your_shodan_key_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here
```

**Step 6 — Run the server:**
```bash
python run.py
```

Server starts at `http://127.0.0.1:8080`

---

## API Endpoints

### GET /health
Check if the service is running and see registered adapters.

```bash
curl http://127.0.0.1:8080/health
```

Response:
```json
{
  "status": "ok",
  "adapters": ["builtin", "nuclei", "nikto", "shodan", "virustotal", "zap", "mock"]
}
```

---

### GET /adapters
Get list of available vulnerability analyzers to show in UI.

```bash
curl http://127.0.0.1:8080/adapters
```

Response:
```json
{
  "adapters": [
    {"name": "builtin", "description": "Moku built-in vulnerability analyzer"},
    {"name": "nuclei", "description": "Template-based scanner by ProjectDiscovery"},
    {"name": "shodan", "description": "Passive recon using Shodan internet scan database"},
    {"name": "virustotal", "description": "URL reputation check against 90+ security vendors"}
  ]
}
```

---

### POST /scan
Submit a new scan job. Returns a `job_id` immediately — the scan runs in the background.

```bash
curl -X POST http://127.0.0.1:8080/scan \
  -H "Content-Type: application/json" \
  -d '{"method":"url","url":"http://target.com","adapter":"nuclei"}'
```

Request body:
```json
{
  "method": "url",
  "url": "http://target.com",
  "adapter": "nuclei"
}
```

| Field | Required | Description |
|---|---|---|
| method | yes | `"url"` or `"html"` |
| url | if method=url | Target URL to scan |
| html | if method=html | Raw HTML string to scan |
| adapter | no | Which scanner to use (default: `"builtin"`) |

Response:
```json
{
  "job_id": "e37f2592-0042-4279-9329-c084e6ec9377"
}
```

---

### GET /scan/{job_id}
Poll for scan results. Keep calling until `status` is `done` or `failed`.

```bash
curl http://127.0.0.1:8080/scan/e37f2592-0042-4279-9329-c084e6ec9377
```

Response when done:
```json
{
  "id": "e37f2592-0042-4279-9329-c084e6ec9377",
  "status": "done",
  "vulnerabilities": [
    {
      "type": "CVE-2023-48795",
      "severity": "critical",
      "description": "Terrapin SSH vulnerability",
      "evidence": "scanme.nmap.org:22",
      "location": "scanme.nmap.org"
    }
  ]
}
```

Possible status values:
| Status | Meaning |
|---|---|
| `pending` | Job created, not started yet |
| `running` | Scan in progress |
| `done` | Scan complete, results ready |
| `failed` | Scan failed, check `error` field |

---

## Available Adapters

| Adapter | Type | Requires | Description |
|---|---|---|---|
| `builtin` | Built-in | Nothing | Moku's own analyzer — XSS, SQLi, headers (Phase 2) |
| `nuclei` | CLI tool | Nuclei installed | Template-based scanner, 9000+ vulnerability templates |
| `nikto` | CLI tool | Nikto installed | Web server misconfiguration scanner |
| `shodan` | API | SHODAN_API_KEY | Passive recon — open ports, services, known CVEs |
| `virustotal` | API | VIRUSTOTAL_API_KEY | URL reputation — checks against 90+ security vendors |
| `zap` | CLI tool | ZAP installed | OWASP ZAP active web vulnerability scanner |
| `mock` | Test only | Nothing | Returns hardcoded findings — for development/testing |

---

## How to Add a New Adapter

Any vulnerability scanner can be added in 3 steps:

**Step 1 — Create the adapter file** `app/adapters/myscanner_adapter.py`:
```python
from app.adapters.base import BaseAdapter
from app.models.schemas import Vulnerability, Severity
from typing import List

class MyScannerAdapter(BaseAdapter):
    name = "myscanner"
    description = "My custom scanner"

    def scan_url(self, url: str) -> List[Vulnerability]:
        # run your scanner here
        return []

    def scan_html(self, html: str, source_url: str = "") -> List[Vulnerability]:
        # run your scanner on HTML here
        return []
```

**Step 2 — Register it in `main.py`:**
```python
from app.adapters.myscanner_adapter import MyScannerAdapter
registry.register(MyScannerAdapter())
```

**Step 3 — It works immediately.** No other changes needed.

---

## Development

**Run with auto-reload** (for development — note: clears in-memory jobs on restart):
```bash
python -m uvicorn main:app --reload --port 8080
```

**Run stable** (for testing — jobs persist):
```bash
python run.py
```

**Interactive API docs** (Swagger UI):
```
http://127.0.0.1:8080/docs
```

---

## Phase Roadmap

| Phase | Deadline | Status |
|---|---|---|
| Phase 1 — API contract, async job engine, plugin adapter system | April 2026 | ✅ Complete |
| Phase 2 — Built-in vulnerability analyzer (XSS, SQLi, headers, open redirect) | May 2026 | 🔄 In progress |

---

## Related

- [moku](https://github.com/Raysh454/moku) — the main platform this service integrates with
- [Nuclei](https://github.com/projectdiscovery/nuclei) — fast vulnerability scanner
- [Nikto](https://github.com/sullo/nikto) — web server scanner
- [OWASP ZAP](https://www.zaproxy.org) — web application security scanner
- [Shodan](https://shodan.io) — internet-wide scan database
- [VirusTotal](https://virustotal.com) — malware and URL reputation service
