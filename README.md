<img width="1376" height="768" alt="Gemini_Generated_Image_sx241bsx241bsx24" src="https://github.com/user-attachments/assets/ef0f77b0-2949-4c5b-96e9-1a564f175d7e" />


ARISE is a professional-grade, state-driven **External Attack Surface Monitoring (EASM)** toolkit. It converts target domain lists into fully structured exposure maps by executing an 18-module reconnaissance, fingerprinting, and vulnerability prioritization pipeline. Features WAF-aware scanning, EPSS-prioritized vulnerability mapping, cloud misconfiguration detection (AWS/GCP/Azure), API security testing, and real-time visualization via a Flask dashboard.

---

## Key Features

* **State-Driven Workflow**: Centralized manifest-driven state management (`manifest.json` per scan) records results across all modules
* **18-Module Pipeline**: Asset discovery through cloud exposure detection with automated risk scoring
* **Cloud Exposure Detection**: AWS, GCP, Azure misconfiguration scanning with weighted scoring model (`base_weight × exploitability × exposure`)
* **API Security Testing**: Swagger/OpenAPI auto-discovery (autoswagger) + stateful REST API fuzzing (RESTler)
* **Tech Stack Detection**: httpx-powered technology fingerprinting with visual wordcloud
* **6-Domain Risk Model**: Composite scoring across Vulnerability (35), Credential (25), Infrastructure (20), SSL/Domain (10), Attack Surface (10), and Cloud Exposure (40) — clamped to 0–100
* **Real-time Dashboard**: 10-tab Flask UI with Overview, Assets, Vulns, CVEs, API, Cloud, Ports, Dirs, Changes, Pipeline views
* **Knowledge Transfer**: Built-in KT document at `/kt` for onboarding and architecture reference

---

## Tools & Dependencies

### Reconnaissance
| Tool | Purpose |
|------|---------|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Passive subdomain discovery from multiple sources |
| [puredns](https://github.com/d3mondev/puredns) | DNS brute-force with massdns backend |
| [massdns](https://github.com/blechschmidt/massdns) | High-performance DNS stub resolver |
| [dnsx](https://github.com/projectdiscovery/dnsx) | DNS toolkit — A, AAAA, CNAME resolution |
| [haktrails](https://github.com/hakluke/haktrails) | SecurityTrails API wrapper |
| [httpx](https://github.com/projectdiscovery/httpx) | HTTP probing, tech detection, response capture |
| [naabu](https://github.com/projectdiscovery/naabu) | Fast SYN/CONNECT port scanner |
| [nmap](https://nmap.org/) | Service version fingerprinting (-sV) |

### Crawling & Discovery
| Tool | Purpose |
|------|---------|
| [katana](https://github.com/projectdiscovery/katana) | Active web crawler with JS rendering |
| [gospider](https://github.com/jaeles-project/gospider) | Go-based web spider |
| [gau](https://github.com/lc/gau) | Passive URL fetcher (Wayback Machine, Common Crawl, OTX) |
| [dirsearch](https://github.com/maurosoria/dirsearch) | Directory and file brute-forcer |
| [ffuf](https://github.com/ffuf/ffuf) | Fast web fuzzer for dirs, params, vhosts |
| [gf](https://github.com/tomnomnom/gf) | Grep pattern matcher for params, secrets, URLs |

### Vulnerability Testing
| Tool | Purpose |
|------|---------|
| [nuclei](https://github.com/projectdiscovery/nuclei) | Template-based vulnerability scanner (CVEs, misconfigs) |
| [dalfox](https://github.com/hahwul/dalfox) | XSS scanner and validator |
| [sqlmap](https://github.com/sqlmapproject/sqlmap) | SQL injection detection and exploitation |
| [trufflehog](https://github.com/trufflesecurity/trufflehog) | Secret and credential scanner |
| [wafw00f](https://github.com/EnableSecurity/wafw00f) | WAF fingerprinting and identification |

### API Security
| Tool | Purpose |
|------|---------|
| [autoswagger](https://github.com/AresS31/autoswagger) | Swagger/OpenAPI spec auto-discovery |
| [RESTler](https://github.com/microsoft/restler-fuzzer) | Microsoft's stateful REST API fuzzer |

### Platform
| Component | Purpose |
|-----------|---------|
| Python 3 + Flask | Orchestrator, dashboard, API server |
| Bash | Pipeline scripting (easm-pipeline.sh) |
| Go toolchain | Required for subfinder, httpx, nuclei, katana, etc. |

---

## Pipeline Modules

| # | Module | Description |
|---|--------|-------------|
| 01 | Asset Discovery | Passive subdomain enumeration (subfinder, haktrails) |
| 02 | Subdomain Enumeration | DNS brute-force with permutation (puredns) |
| 03 | DNS Resolution | Bulk resolution, CDN vs origin classification (dnsx) |
| 04 | HTTP Discovery | HTTP probing + tech stack detection (httpx) |
| 05 | WAF Detection | 3-tier WAF fingerprinting (wafw00f → nuclei → httpx) |
| 06 | Web Crawling | Active + passive URL harvesting (katana, gospider, gau) |
| 07 | Header Analysis | Security header grading (HSTS, CSP, X-Frame-Options) |
| 08 | Service Fingerprinting | Nmap version detection for non-HTTP services |
| 09 | Directory Discovery | WAF-aware directory brute-forcing (dirsearch, ffuf) |
| 10 | Secret Scanning | API keys, tokens, credentials in JS/endpoints (trufflehog) |
| 11 | Parameter Fuzzing | URL parameter discovery for injection gating |
| 12 | Nuclei Scanning | Template-driven vulnerability checks |
| 13 | XSS Testing | Reflected/DOM XSS validation (dalfox) |
| 14 | SQLi Testing | SQL injection detection (sqlmap) |
| 15 | LFI Testing | Local File Inclusion path traversal checks |
| 16 | API Security | Swagger discovery + REST API fuzzing (autoswagger, RESTler) |
| 17 | Cloud Exposure | AWS/GCP/Azure misconfiguration detection with weighted scoring |
| 18 | Reporting | Aggregate results, compute final risk scores |

---

## Folder Structure

```text
ARISE/
├── arise.py                    # Main orchestrator (scan + dashboard launcher)
├── dashboard.py                # Flask dashboard server (20+ API endpoints)
├── easm-pipeline.sh            # 18-module scanning pipeline (~3500 lines)
├── setup.sh                    # Debian/Ubuntu dependency installer
├── requirements.txt            # Python dependencies
├── hosts.txt                   # Target domain list
├── templates/
│   ├── dashboard.html          # Main dashboard UI
│   └── kt.html                 # Knowledge Transfer document
├── cloud-templates/            # Custom nuclei templates for cloud detection
│   ├── cloud-metadata-exposure.yaml
│   ├── debug-endpoints.yaml
│   ├── public-object-storage.yaml
│   └── terraform-state-exposure.yaml
├── lists/                      # Wordlists & DNS resolver lists
├── scope/                      # Target scope configurations
└── scans/                      # Isolated scan output directories
    └── {domain}-{DDMMYY}-{HHMM}/
        ├── manifest.json       # Central scan state
        ├── logs/               # Per-module execution logs
        └── [01-18]_*/          # Module output folders
```

---

## Quick Start

### 1. Install Dependencies
```bash
# Debian/Ubuntu
bash setup.sh
```

### 2. Configure Targets
```text
# hosts.txt — one domain per line
example.com
target.org
```

### 3. Run ARISE
```bash
# Full scan + dashboard
python3 arise.py

# Dashboard only (browse previous scans)
python3 arise.py --dashboard-only

# Scan only (no web UI)
python3 arise.py --no-dashboard
```

Dashboard: [http://localhost:5000](http://localhost:5000) | KT Document: [http://localhost:5000/kt](http://localhost:5000/kt)

---

## CLI Options

```bash
python3 arise.py --hosts targets.txt          # Custom target file
python3 arise.py --skip waf_detection         # Skip specific modules
python3 arise.py --dashboard-port 8080        # Custom dashboard port
python3 arise.py --dry-run                    # Preview execution order
python3 arise.py --env PORT_SCAN_MODE=fast    # Tuning via env vars
python3 arise.py --env NAABU_RATE=5000        # Port scan rate limit
```

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT_SCAN_MODE` | `fast` | `fast` = top 1000 ports, `full` = all 65535 |
| `NAABU_RATE` | `1000` | Packets/sec for port scanning |
| `APISEC_AUTH_TOKEN_CMD` | (empty) | Shell command to get API auth token for RESTler |
| `APISEC_AUTH_REFRESH_SEC` | `300` | Token refresh interval in seconds |

---

## License & Disclaimer
This tool is built for authorized security assessments and threat modeling. Ensure proper authorization exists before scanning any target infrastructure.
