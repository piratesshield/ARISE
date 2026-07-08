<img width="1376" height="768" alt="Gemini_Generated_Image_sx241bsx241bsx24" src="https://github.com/user-attachments/assets/ef0f77b0-2949-4c5b-96e9-1a564f175d7e" />


ARISE is a professional-grade, state-driven **External Attack Surface Monitoring (EASM)** prototype. It converts standard target lists into a fully structured exposure map by executing a complete 14-module reconnaissance, finger-printing, and vulnerability prioritization pipeline. It features WAF-aware scanning, EPSS-prioritized vulnerability mapping, and real-time visualization via a Flask-based interactive dashboard.

---

## 🌟 Key Features

* **State-Driven Workflow**: Centralized manifest-driven state management (`manifest.json` per scan target) records results from all modules sequentially.
* **14-Module Recon Pipeline**: 
  1. **Asset Discovery**: Multi-source asset discovery mapping root domains and IP spaces.
  2. **Subdomain Enumeration**: Permutated and active brute forcing combined with passive checks.
  3. **DNS Resolution**: Fast resolution with origin vs. CDN classification.
  4. **HTTP Discovery**: Service confirmation and active port scanning.
  5. **WAF Detection**: Active detection baseline setup to prevent target blocking.
  6. **Header Analysis**: Technology and cookie security posture grading.
  7. **Service Fingerprinting**: Version identification for non-HTTP services.
  8. **Directory Discovery**: WAF-aware batched file and path brute forcing.
  9. **Web Crawling**: Historical and active URL/endpoint harvesting.
  10. **Secret Scanning**: Scans harvested JS files and endpoints for sensitive exposures.
  11. **Parameter Fuzzing**: Param detection for vulnerability gating.
  12. **Nuclei Scanning**: Template-driven vulnerability checks.
  13. **XSS Testing**: Dedicated cross-site scripting validation.
  14. **Reporting**: Aggregation of logs, statistics, and structured JSON output.
* **Real-time Dashboard**: Flask-based visualization showing scan status, resolved hosts, vulnerabilities, and open ports.

---

## 📂 Folder Structure

```text
zero-EASM/
├── scans/                                    # All isolated target scans
│   ├── target-DDMMYY-HHMM/                  # Timestamped scan folder
│   │   ├── manifest.json                    # Central scan metadata & results state
│   │   ├── logs/                            # Per-module execution logs
│   │   └── [01_asset_discovery to 14_reporting]/ # Sequential module output folders
├── scope/                                   # Target scope lists and configurations
├── lists/                                   # Wordlists & DNS resolver lists
├── templates/                               # HTML layouts for dashboard visualization
├── logs/                                    # General orchestrator logs
├── arise.py                                 # Main controller & dashboard orchestrator
├── easm-pipeline.sh                         # Core shell scanning pipeline
├── setup.sh                                 # Linux (Debian/Ubuntu) dependency installer
├── requirements.txt                         # Python dependencies manifest
```

---

## ⚙️ One-Time Setup

> [!NOTE]
> The setup script is designed for Debian/Ubuntu-based Linux environments.

### 1. Run the Setup Script
The script updates APT packages, installs core utility/build packages, compiles MassDNS from source, downloads wordlists, and installs Go tools:
```bash
bash setup.sh
```

### 2. Install Dependencies

```bash
Follow the instrctions at requirements.txt
```
---

## 🚀 Running ARISE

### 1. Define Targets
Add target domains to [hosts.txt](file:///Users/apple/Documents/backup/zero-EASM/ARISE/hosts.txt) (one domain per line). Lines starting with `#` are ignored:
```text
# Targets
example.com
target.org
```

### 2. Start Scanning & Dashboard
Launch the unified orchestration script. This starts the Flask web dashboard and runs the scanner against targets sequentially:
```bash
python3 arise.py
```
* **Dashboard URL**: [http://localhost:5000](http://localhost:5000)
* **Real-time Progress**: The UI automatically parses scan folders and displays real-time execution metrics.

---

## 🛠️ CLI Options & Orchestration

The orchestration script [arise.py](file:///Users/apple/Documents/backup/zero-EASM/ARISE/arise.py) supports fine-tuning commands to adapt to network environments and scan scopes:

* **Scan Only (No Dashboard)**:
  ```bash
  python3 arise.py --no-dashboard
  ```
* **Dashboard Only (Browse previous scans)**:
  ```bash
  python3 arise.py --dashboard-only
  ```
* **Custom Targets List**:
  ```bash
  python3 arise.py --hosts my_targets.txt
  ```
* **Skip Specific Modules**:
  ```bash
  python3 arise.py --skip waf_detection --skip param_fuzzing
  ```
* **Pass Tuning Options to Scanner**:
  ```bash
  python3 arise.py --env PORT_SCAN_MODE=fast --env NAABU_RATE=5000
  ```
* **Dry Run (Preview Execution Order)**:
  ```bash
  python3 arise.py --dry-run
  ```
* **Change Dashboard Port**:
  ```bash
  python3 arise.py --dashboard-port 8080
  ```
* **Get Full Help**:
  ```bash
  python3 arise.py --help
  ```

---

## 🛡️ Scan Pipeline Tuning Parameters
The pipeline supports the following environment variables for tuning speed and coverage (pass via `--env`):
* `PORT_SCAN_MODE`: Set port scanning speeds (`fast` or `full`).
* `NAABU_RATE`: Naabu packet sending rate limit (default: `1000`).

---

## 📝 License & Disclaimer
This tool is built for authorized security assessments and threat modeling. Ensure proper authorization exists before scanning any target infrastructure.
