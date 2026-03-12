# SecOps Command Center

A real-time security operations dashboard that pulls live CVE intelligence from the NVD API, checks IPs against threat intelligence feeds, maps vulnerabilities to an asset inventory, and generates prioritized remediation reports.

![Python](https://img.shields.io/badge/Python-3.9+-blue?style=flat-square)
![Flask](https://img.shields.io/badge/Flask-2.3+-green?style=flat-square)
![NVD API](https://img.shields.io/badge/NVD-API%20v2-red?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## Features

- **Live CVE feed** — pulls real vulnerabilities from the NVD API v2
- **CVSS v3 scoring** — parses and displays base scores and severity ratings
- **Asset mapping** — maps CVEs to affected assets based on services running
- **Risk prioritization** — scores CVEs by CVSS + asset criticality to build a remediation queue
- **IOC checking** — checks IPs against AbuseIPDB or local threat intelligence
- **Executive report** — generates a standalone HTML report at `/report`
- **REST API** — `/api/cves`, `/api/iocs`, `/api/summary` endpoints
- **Auto-refresh** — dashboard refreshes every 5 minutes with latest data

---

## How It Works
```
NVD API → CVE Feed → Asset Mapper → Risk Scorer → Prioritized Queue
                                                         ↓
AbuseIPDB / Local Intel → IOC Checker → Threat Dashboard + Report
```

1. Fetches recent CVEs from NVD API (last 30 days)
2. Maps each CVE to assets in your inventory based on running services
3. Scores CVEs by CVSS v3 + asset criticality multiplier
4. Checks IPs against threat intelligence feeds
5. Renders live dashboard and generates executive report

---

## Project Structure
```
secops-center/
├── server.py                  # Flask app — dashboard, API, report
├── requirements.txt
├── README.md
├── modules/
│   ├── __init__.py
│   ├── nvd_feed.py            # NVD API v2 client — live CVE data
│   ├── ioc_checker.py         # AbuseIPDB + local threat intel
│   ├── threat_scorer.py       # CVSS scoring + asset mapping
│   └── report.py              # HTML report generator
└── data/
    └── assets.json            # Asset inventory
```

---

## Quick Start

**Install dependencies:**
```bash
pip install flask requests
```

**Run the dashboard:**
```bash
python3 server.py
```

**Open in browser:**

| URL | Description |
|---|---|
| `http://127.0.0.1:5000/` | Live SOC dashboard |
| `http://127.0.0.1:5000/report` | Executive HTML report |
| `http://127.0.0.1:5000/api/cves` | CVE data as JSON |
| `http://127.0.0.1:5000/api/iocs` | IOC results as JSON |
| `http://127.0.0.1:5000/api/summary` | Summary stats as JSON |

---

## Asset Inventory

Edit `data/assets.json` to match your environment:
```json
{
  "assets": [
    {
      "id": "srv-001",
      "name": "Web Server",
      "ip": "192.168.1.10",
      "os": "Ubuntu 22.04",
      "services": ["nginx", "openssl", "php"],
      "criticality": "HIGH",
      "department": "IT"
    }
  ]
}
```

Supported services for CVE mapping: `nginx`, `openssl`, `mysql`, `openssh`, `php`, `exchange`, `iis`, `smb`, `rdp`, `docker`, `snmp`

---

## AbuseIPDB Integration

To enable live IP threat intelligence, set your AbuseIPDB API key:
```bash
export ABUSEIPDB_KEY="your_api_key_here"
python3 server.py
```

Without a key the tool falls back to a built-in local threat intelligence database. Get a free API key at [abuseipdb.com](https://www.abuseipdb.com).

---

## Risk Prioritization

CVEs are scored using:
```
Priority Score = min((CVSS Base Score × Asset Criticality Multiplier) + (Affected Asset Count × 0.5), 10.0)
```

| Asset Criticality | Multiplier |
|---|---|
| CRITICAL | 1.5× |
| HIGH | 1.2× |
| MEDIUM | 1.0× |
| LOW | 0.8× |

---

## Requirements

- Python 3.9+
- Flask
- requests
- Internet connection for NVD API (falls back to sample data if unavailable)

---

## Author

**George Skhirtladze** — IT Specialist & Security Analyst  
[GitHub](https://github.com/Toshi-hub834) · [LinkedIn](https://www.linkedin.com/in/george-skhirtladze-04b726272) · [Portfolio](https://toshi-hub834.github.io)
```

Save as `README.md` then create `requirements.txt`:
```
flask>=2.3.0
requests>=2.31.0