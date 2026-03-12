"""
Threat Scorer Module
Maps CVEs to assets and generates prioritized remediation queue.
"""

import json
from typing import List, Dict


# Keyword mapping: service name → related CVE keywords
SERVICE_CVE_MAP = {
    "nginx":    ["nginx", "http", "web"],
    "openssl":  ["openssl", "ssl", "tls", "heartbleed"],
    "mysql":    ["mysql", "mariadb", "sql"],
    "openssh":  ["openssh", "ssh"],
    "php":      ["php"],
    "exchange": ["exchange", "microsoft", "outlook"],
    "iis":      ["iis", "microsoft", "http"],
    "smb":      ["smb", "samba", "windows"],
    "rdp":      ["rdp", "remote desktop", "windows"],
    "docker":   ["docker", "container", "runc"],
    "snmp":     ["snmp", "cisco"],
    "ssh":      ["ssh", "openssh"],
}

CRITICALITY_MULTIPLIER = {
    "CRITICAL": 1.5,
    "HIGH":     1.2,
    "MEDIUM":   1.0,
    "LOW":      0.8,
}


class ThreatScorer:

    def map_cves_to_assets(self, cves: List[Dict], assets: List[Dict]) -> List[Dict]:
        """Map CVEs to affected assets based on service keywords."""
        mapped = []
        for cve in cves:
            affected = []
            desc = cve.get("description", "").lower()
            cve_id = cve.get("id", "").lower()

            for asset in assets:
                for service in asset.get("services", []):
                    keywords = SERVICE_CVE_MAP.get(service, [service])
                    if any(kw in desc or kw in cve_id for kw in keywords):
                        affected.append(asset)
                        break

            mapped.append({**cve, "affected_assets": affected})

        return mapped

    def prioritize(self, mapped_cves: List[Dict]) -> List[Dict]:
        """Score and sort CVEs by risk priority."""
        scored = []
        for cve in mapped_cves:
            base_score = cve.get("score") or 0
            assets     = cve.get("affected_assets", [])

            # Asset criticality boost
            max_criticality = "LOW"
            for asset in assets:
                c = asset.get("criticality", "LOW")
                if CRITICALITY_MULTIPLIER.get(c, 0) > CRITICALITY_MULTIPLIER.get(max_criticality, 0):
                    max_criticality = c

            multiplier    = CRITICALITY_MULTIPLIER.get(max_criticality, 1.0)
            asset_count   = len(assets)
            priority_score = min(base_score * multiplier + (asset_count * 0.5), 10.0)
            priority_score = round(priority_score, 2)

            scored.append({
                **cve,
                "priority_score": priority_score,
                "max_criticality": max_criticality,
                "asset_count": asset_count,
                "remediation": self._get_remediation(cve),
            })

        scored.sort(key=lambda x: x["priority_score"], reverse=True)
        return scored

    def _get_remediation(self, cve: Dict) -> str:
        desc  = cve.get("description", "").lower()
        score = cve.get("score", 0) or 0

        if "openssl" in desc or "ssl" in desc or "tls" in desc:
            return "Update OpenSSL to latest version. Check TLS configuration."
        if "ssh" in desc:
            return "Update OpenSSH. Enforce key-based auth. Disable root login."
        if "sql" in desc or "mysql" in desc:
            return "Apply database patches. Use parameterized queries. Restrict DB access."
        if "nginx" in desc or "apache" in desc:
            return "Update web server. Review configuration. Enable WAF."
        if "smb" in desc or "rdp" in desc:
            return "Apply Windows patches. Disable SMBv1. Restrict RDP access."
        if "docker" in desc or "container" in desc:
            return "Update container runtime. Review image security. Apply least privilege."
        if score >= 9.0:
            return "CRITICAL: Patch immediately. Isolate affected systems if patch unavailable."
        if score >= 7.0:
            return "HIGH: Schedule patching within 7 days. Monitor for exploitation."
        if score >= 4.0:
            return "MEDIUM: Schedule patching within 30 days."
        return "LOW: Include in next maintenance window."

    def generate_summary(self, prioritized: List[Dict]) -> Dict:
        """Generate summary statistics."""
        total    = len(prioritized)
        critical = sum(1 for c in prioritized if (c.get("score") or 0) >= 9.0)
        high     = sum(1 for c in prioritized if 7.0 <= (c.get("score") or 0) < 9.0)
        medium   = sum(1 for c in prioritized if 4.0 <= (c.get("score") or 0) < 7.0)
        low      = sum(1 for c in prioritized if (c.get("score") or 0) < 4.0)
        affected_assets = set()
        for c in prioritized:
            for a in c.get("affected_assets", []):
                affected_assets.add(a["id"])

        return {
            "total_cves":      total,
            "critical":        critical,
            "high":            high,
            "medium":          medium,
            "low":             low,
            "affected_assets": len(affected_assets),
            "risk_score":      round(sum((c.get("score") or 0) for c in prioritized) / total, 2) if total else 0,
        }