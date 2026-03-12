"""
Report Generator
Generates executive HTML report from SecOps analysis.
"""

from datetime import datetime
from typing import Dict, List


SEVERITY_COLORS = {
    "CRITICAL": "#c0152a",
    "HIGH":     "#e05c00",
    "MEDIUM":   "#c9943a",
    "LOW":      "#4a9a6a",
    "UNKNOWN":  "#666",
}


class ReportGenerator:

    def generate(self, summary: Dict, prioritized: List[Dict],
                 ioc_results: List[Dict], assets: List[Dict],
                 output: str = "secops_report.html"):

        generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cve_rows  = self._cve_rows(prioritized[:20])
        ioc_rows  = self._ioc_rows(ioc_results)
        asset_rows = self._asset_rows(assets)

        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"/>
<title>SecOps Report — {generated}</title>
<style>
  :root {{
    --bg:#0a0305; --bg2:#0f0408; --bg3:#140608;
    --red:#c0152a; --gold:#c9943a; --bone:#e8dcc8; --bone-dim:#9a8f7e;
    --border:rgba(192,21,42,0.25); --green:#4a9a6a; --orange:#e05c00;
  }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ background:var(--bg); color:var(--bone-dim); font-family:'Courier New',monospace; font-size:13px; }}
  header {{ background:var(--bg2); border-bottom:2px solid var(--red); padding:24px 40px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:12px; }}
  header h1 {{ color:var(--bone); font-size:22px; letter-spacing:4px; }}
  .meta {{ font-size:11px; color:var(--bone-dim); }}
  .meta span {{ color:var(--gold); }}
  .container {{ padding:32px 40px; }}
  .summary-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-bottom:32px; }}
  .card {{ background:var(--bg2); border:1px solid var(--border); padding:20px; text-align:center; }}
  .card .num {{ font-size:40px; font-weight:bold; line-height:1; }}
  .card .label {{ font-size:9px; letter-spacing:2px; margin-top:4px; opacity:0.7; }}
  .c-red {{ color:var(--red); }} .c-orange {{ color:var(--orange); }}
  .c-gold {{ color:var(--gold); }} .c-green {{ color:var(--green); }} .c-bone {{ color:var(--bone); }}
  .panel {{ background:var(--bg2); border:1px solid var(--border); padding:24px; margin-bottom:24px; }}
  .panel h2 {{ color:var(--gold); font-size:10px; letter-spacing:3px; margin-bottom:16px; padding-bottom:10px; border-bottom:1px solid var(--border); }}
  table {{ width:100%; border-collapse:collapse; }}
  th {{ color:var(--gold); font-size:9px; letter-spacing:2px; padding:8px 12px; text-align:left; border-bottom:1px solid var(--border); }}
  td {{ padding:8px 12px; border-bottom:1px solid rgba(192,21,42,0.06); font-size:11px; word-break:break-word; }}
  tr:hover td {{ background:rgba(192,21,42,0.04); }}
  .badge {{ display:inline-block; padding:2px 8px; font-size:9px; letter-spacing:1px; border:1px solid; }}
  .risk-bar {{ background:var(--bg3); height:4px; margin-top:4px; }}
  .risk-fill {{ height:4px; }}
  footer {{ border-top:1px solid var(--border); padding:20px 40px; font-size:10px; color:rgba(154,143,126,0.3); letter-spacing:2px; }}
</style>
</head><body>
<header>
  <h1>⬡ SECOPS COMMAND CENTER</h1>
  <div class="meta">Generated: <span>{generated}</span> &nbsp;|&nbsp; CVEs Analyzed: <span>{summary.get('total_cves',0)}</span> &nbsp;|&nbsp; Assets: <span>{len(assets)}</span></div>
</header>
<div class="container">
  <div class="summary-grid">
    <div class="card"><div class="num c-red">{summary.get('critical',0)}</div><div class="label">CRITICAL CVEs</div></div>
    <div class="card"><div class="num c-orange">{summary.get('high',0)}</div><div class="label">HIGH CVEs</div></div>
    <div class="card"><div class="num c-gold">{summary.get('medium',0)}</div><div class="label">MEDIUM CVEs</div></div>
    <div class="card"><div class="num c-green">{summary.get('low',0)}</div><div class="label">LOW CVEs</div></div>
    <div class="card"><div class="num c-bone">{summary.get('affected_assets',0)}</div><div class="label">AFFECTED ASSETS</div></div>
    <div class="card"><div class="num c-gold">{summary.get('risk_score',0)}</div><div class="label">AVG CVSS SCORE</div></div>
  </div>

  <div class="panel">
    <h2>PRIORITIZED CVE REMEDIATION QUEUE</h2>
    <table>
      <tr><th>CVE ID</th><th>SEVERITY</th><th>SCORE</th><th>PRIORITY</th><th>AFFECTED ASSETS</th><th>REMEDIATION</th></tr>
      {cve_rows}
    </table>
  </div>

  <div class="panel">
    <h2>IOC / THREAT INTELLIGENCE</h2>
    <table>
      <tr><th>IP ADDRESS</th><th>STATUS</th><th>CONFIDENCE</th><th>CATEGORY</th><th>REASON</th><th>SOURCE</th></tr>
      {ioc_rows}
    </table>
  </div>

  <div class="panel">
    <h2>ASSET INVENTORY</h2>
    <table>
      <tr><th>ID</th><th>NAME</th><th>IP</th><th>OS</th><th>CRITICALITY</th><th>SERVICES</th></tr>
      {asset_rows}
    </table>
  </div>
</div>
<footer>SecOps Command Center &nbsp;|&nbsp; github.com/Toshi-hub834 &nbsp;|&nbsp; George Skhirtladze</footer>
</body></html>"""

        with open(output, "w") as f:
            f.write(html)
        print(f"[+] Report saved to {output}")

    def _severity_badge(self, severity: str) -> str:
        color = SEVERITY_COLORS.get(severity, "#666")
        return f'<span class="badge" style="color:{color};border-color:{color}">{severity}</span>'

    def _cve_rows(self, cves: List[Dict]) -> str:
        rows = ""
        for c in cves:
            score    = c.get("score") or 0
            severity = c.get("severity", "UNKNOWN")
            priority = c.get("priority_score", 0)
            assets   = ", ".join(a["name"] for a in c.get("affected_assets", [])) or "—"
            rem      = c.get("remediation", "—")[:80]
            pct      = min(int(priority * 10), 100)
            color    = SEVERITY_COLORS.get(severity, "#666")
            rows += f"""<tr>
  <td style="color:var(--bone)">{c['id']}</td>
  <td>{self._severity_badge(severity)}</td>
  <td style="color:{color}">{score}</td>
  <td>
    {priority}
    <div class="risk-bar"><div class="risk-fill" style="width:{pct}%;background:{color}"></div></div>
  </td>
  <td style="color:var(--gold)">{assets}</td>
  <td>{rem}</td>
</tr>"""
        return rows

    def _ioc_rows(self, iocs: List[Dict]) -> str:
        rows = ""
        for i in iocs:
            status = '<span style="color:var(--red)">⚠ MALICIOUS</span>' if i.get("malicious") else '<span style="color:var(--green)">✓ CLEAN</span>'
            conf   = i.get("confidence", 0)
            rows += f"""<tr>
  <td style="color:var(--bone)">{i['ip']}</td>
  <td>{status}</td>
  <td style="color:var(--gold)">{conf}%</td>
  <td>{i.get('category','—')}</td>
  <td>{i.get('reason','—')}</td>
  <td style="opacity:0.6">{i.get('source','—')}</td>
</tr>"""
        return rows

    def _asset_rows(self, assets: List[Dict]) -> str:
        rows = ""
        colors = {"CRITICAL": "var(--red)", "HIGH": "var(--orange)", "MEDIUM": "var(--gold)", "LOW": "var(--green)"}
        for a in assets:
            crit  = a.get("criticality", "LOW")
            color = colors.get(crit, "var(--bone-dim)")
            svcs  = ", ".join(a.get("services", []))
            rows += f"""<tr>
  <td style="opacity:0.6">{a['id']}</td>
  <td style="color:var(--bone)">{a['name']}</td>
  <td style="color:var(--gold)">{a['ip']}</td>
  <td>{a.get('os','—')}</td>
  <td style="color:{color}">{crit}</td>
  <td style="opacity:0.7">{svcs}</td>
</tr>"""
        return rows