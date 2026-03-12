"""
IOC Checker Module
Checks IPs against AbuseIPDB threat intelligence.
Falls back to local IOC list if API key not configured.
"""

import requests
import json
import os
from typing import Dict, List


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
API_KEY = os.environ.get("ABUSEIPDB_KEY", "")

# Built-in known malicious IPs for demo
KNOWN_MALICIOUS = {
    "45.33.32.156":  {"reason": "Known SSH brute force source",      "confidence": 95, "category": "Brute Force"},
    "10.0.0.55":     {"reason": "Nikto scanner activity detected",    "confidence": 80, "category": "Web Scanner"},
    "172.16.0.22":   {"reason": "SQL injection attempts detected",    "confidence": 90, "category": "SQL Injection"},
    "192.168.1.50":  {"reason": "HTTP brute force attempts",         "confidence": 75, "category": "Brute Force"},
    "185.220.101.1": {"reason": "Tor exit node — anonymization",     "confidence": 99, "category": "Tor"},
    "194.165.16.11": {"reason": "Known ransomware C2 server",        "confidence": 98, "category": "C2/Malware"},
    "91.108.4.1":    {"reason": "Telegram-based C2 infrastructure",  "confidence": 85, "category": "C2/Malware"},
}


class IOCChecker:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose

    def check_ip(self, ip: str) -> Dict:
        """Check single IP against AbuseIPDB or local list."""
        # Try AbuseIPDB first if key available
        if API_KEY:
            return self._check_abuseipdb(ip)
        return self._check_local(ip)

    def check_multiple(self, ips: List[str]) -> List[Dict]:
        """Check multiple IPs."""
        results = []
        for ip in ips:
            result = self.check_ip(ip)
            results.append(result)
        return results

    def _check_abuseipdb(self, ip: str) -> Dict:
        """Query AbuseIPDB API."""
        try:
            headers = {"Key": API_KEY, "Accept": "application/json"}
            params  = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
            resp    = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=10)
            resp.raise_for_status()
            data    = resp.json().get("data", {})
            return {
                "ip":           ip,
                "malicious":    data.get("abuseConfidenceScore", 0) > 25,
                "confidence":   data.get("abuseConfidenceScore", 0),
                "country":      data.get("countryCode", "N/A"),
                "isp":          data.get("isp", "N/A"),
                "reports":      data.get("totalReports", 0),
                "category":     "AbuseIPDB",
                "reason":       f"{data.get('totalReports', 0)} abuse reports",
                "source":       "AbuseIPDB"
            }
        except Exception as e:
            if self.verbose:
                print(f"[IOC] AbuseIPDB error for {ip}: {e}")
            return self._check_local(ip)

    def _check_local(self, ip: str) -> Dict:
        """Check against local known malicious IP list."""
        if ip in KNOWN_MALICIOUS:
            entry = KNOWN_MALICIOUS[ip]
            return {
                "ip":         ip,
                "malicious":  True,
                "confidence": entry["confidence"],
                "country":    "N/A",
                "isp":        "N/A",
                "reports":    0,
                "category":   entry["category"],
                "reason":     entry["reason"],
                "source":     "Local Threat Intel"
            }
        return {
            "ip":         ip,
            "malicious":  False,
            "confidence": 0,
            "country":    "N/A",
            "isp":        "N/A",
            "reports":    0,
            "category":   "Clean",
            "reason":     "No threat intelligence found",
            "source":     "Local Threat Intel"
        }