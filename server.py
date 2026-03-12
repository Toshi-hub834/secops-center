#!/usr/bin/env python3
"""
SecOps Command Center
Author: George Skhirtladze
Real-time security operations dashboard — CVE intelligence,
IOC checking, asset mapping, and threat prioritization.
"""

import json
import os
from flask import Flask, render_template_string, jsonify
from modules.nvd_feed import NVDFeed
from modules.ioc_checker import IOCChecker
from modules.threat_scorer import ThreatScorer
from modules.report import ReportGenerator
from datetime import datetime


app = Flask(__name__)


SAMPLE_IPS = [
    "45.33.32.156",
    "10.0.0.55",
    "172.16.0.22",
    "192.168.1.50",
    "185.220.101.1",
    "194.165.16.11",
    "8.8.8.8",
    "1.1.1.1",
]

def load_assets():
    with open("data/assets.json") as f:
        return json.load(f)["assets"]

def run_analysis():
    """Run full SecOps analysis pipeline."""
    print("[*] Running SecOps analysis pipeline...")


    print("[+] Fetching CVEs from NVD...")
    nvd    = NVDFeed(verbose=True)
    cves   = nvd.fetch_recent(days=30, limit=20)
    print(f"    Got {len(cves)} CVEs")


    assets = load_assets()
    print(f"[+] Loaded {len(assets)} assets")


    scorer   = ThreatScorer()
    mapped   = scorer.map_cves_to_assets(cves, assets)
    priority = scorer.prioritize(mapped)
    summary  = scorer.generate_summary(priority)

   
    print("[+] Checking IOCs...")
    checker = IOCChecker()
    iocs    = checker.check_multiple(SAMPLE_IPS)
    malicious = sum(1 for i in iocs if i["malicious"])
    print(f"    {malicious}/{len(iocs)} IPs flagged as malicious")

    return summary, priority, iocs, assets


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"/>
<meta http-equiv="refresh" content="300">
<title>SecOps Command Center</title>
<link href="https://fonts.googleapis.com/css2?family=Cinzel:wght@400;700;900&family=Share+Tech+Mono&display=swap" rel="stylesheet"/>
<style>
  :root {
    --bg:#0a0305; --bg2:#0f0408; --bg3:#140608;
    --red:#c0152a; --red-bright:#e8192f; --red-dim:#7a0d1a;
    --gold:#c9943a; --gold-dim:#8a6020;
    --bone:#e8dcc8; --bone-dim:#9a8f7e;
    --border:rgba(192,21,42,0.25);
    --green:#4a9a6a; --orange:#e05c00;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:var(--bg); color:var(--bone-dim); font-family:'Share Tech Mono',monospace; font-size:12px; }
  header { background:var(--bg2); border-bottom:2px solid var(--red); padding:16px 32px; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px; position:sticky; top:0; z-index:100; }
  .logo { font-family:'Cinzel',serif; color:var(--bone); font-size:18px; letter-spacing:4px; }
  .logo span { color:var(--red); }
  .header-meta { font-size:10px; color:var(--bone-dim); display:flex; gap:20px; flex-wrap:wrap; }
  .header-meta b { color:var(--gold); }
  .container { padding:24px 32px; }
  .summary-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:8px; margin-bottom:24px; }
  .card { background:var(--bg2); border:1px solid var(--border); padding:16px; text-align:center; transition:border-color 0.3s; }
  .card:hover { border-color:var(--red); }
  .card .num { font-family:'Cinzel',serif; font-size:36px; font-weight:900; line-height:1; }
  .card .label { font-size:8px; letter-spacing:2px; margin-top:4px; opacity:0.6; }
  .c-red { color:var(--red); } .c-orange { color:var(--orange); }
  .c-gold { color:var(--gold); } .c-green { color:var(--green); } .c-bone { color:var(--bone); }
  .grid-2 { display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-bottom:16px; }
  @media(max-width:900px) { .grid-2 { grid-template-columns:1fr; } }
  .panel { background:var(--bg2); border:1px solid var(--border); margin-bottom:16px; }
  .panel-header { padding:12px 20px; border-bottom:1px solid var(--border); display:flex; justify-content:space-between; align-items:center; }
  .panel-title { color:var(--gold); font-size:9px; letter-spacing:3px; }
  .panel-count { color:var(--bone-dim); font-size:9px; }
  .panel-body { padding:16px 20px; overflow-x:auto; }
  table { width:100%; border-collapse:collapse; }
  th { color:var(--gold); font-size:8px; letter-spacing:2px; padding:6px 10px; text-align:left; border-bottom:1px solid var(--border); white-space:nowrap; }
  td { padding:6px 10px; border-bottom:1px solid rgba(192,21,42,0.05); font-size:11px; }
  tr:hover td { background:rgba(192,21,42,0.04); }
  .badge { display:inline-block; padding:1px 6px; font-size:8px; letter-spacing:1px; border:1px solid; }
  .risk-bar { background:var(--bg3); height:3px; margin-top:3px; width:60px; }
  .risk-fill { height:3px; }
  .ioc-mal { color:var(--red); } .ioc-clean { color:var(--green); }
  .refresh-note { font-size:9px; color:rgba(154,143,126,0.3); }
  footer { border-top:1px solid var(--border); padding:16px 32px; font-size:9px; color:rgba(154,143,126,0.2); letter-spacing:2px; display:flex; justify-content:space-between; }
</style>
</head><body>
<header>
  <div class="logo">SECOPS <span>⬡</span> COMMAND CENTER</div>
  <div class="header-meta">
    <span>Generated: <b>{{ generated }}</b></span>
    <span>CVEs: <b>{{ summary.total_cves }}</b></span>
    <span>Assets: <b>{{ asset_count }}</b></span>
    <span>Malicious IPs: <b style="color:var(--red)">{{ malicious_count }}</b></span>
    <span class="refresh-note">Auto-refresh: 5min</span>
  </div>
</header>

<div class="container">
  <div class="summary-grid">
    <div class="card"><div class="num c-red">{{ summary.critical }}</div><div class="label">CRITICAL</div></div>
    <div class="card"><div class="num c-orange">{{ summary.high }}</div><div class="label">HIGH</div></div>
    <div class="card"><div class="num c-gold">{{ summary.medium }}</div><div class="label">MEDIUM</div></div>
    <div class="card"><div class="num c-green">{{ summary.low }}</div><div class="label">LOW</div></div>
    <div class="card"><div class="num c-bone">{{ summary.affected_assets }}</div><div class="label">AFFECTED ASSETS</div></div>
    <div class="card"><div class="num c-gold">{{ summary.risk_score }}</div><div class="label">AVG CVSS</div></div>
    <div class="card"><div class="num c-red">{{ malicious_count }}</div><div class="label">MALICIOUS IPs</div></div>
  </div>

  <div class="panel">
    <div class="panel-header">
      <span class="panel-title">PRIORITIZED CVE REMEDIATION QUEUE</span>
      <span class="panel-count">{{ cves|length }} CVEs</span>
    </div>
    <div class="panel-body">
      <table>
        <tr><th>CVE ID</th><th>SEVERITY</th><th>CVSS</th><th>PRIORITY</th><th>AFFECTED ASSETS</th><th>REMEDIATION</th></tr>
        {% for c in cves %}
        {% set color = {'CRITICAL':'#c0152a','HIGH':'#e05c00','MEDIUM':'#c9943a','LOW':'#4a9a6a'}.get(c.severity, '#666') %}
        <tr>
          <td style="color:var(--bone)">{{ c.id }}</td>
          <td><span class="badge" style="color:{{ color }};border-color:{{ color }}">{{ c.severity }}</span></td>
          <td style="color:{{ color }}">{{ c.score or 'N/A' }}</td>
          <td>
            {{ c.priority_score }}
            <div class="risk-bar"><div class="risk-fill" style="width:{{ [c.priority_score * 10, 100]|min }}%;background:{{ color }}"></div></div>
          </td>
          <td style="color:var(--gold)">{{ c.affected_assets|map(attribute='name')|join(', ') or '—' }}</td>
          <td style="opacity:0.7">{{ c.remediation[:70] }}...</td>
        </tr>
        {% endfor %}
      </table>
    </div>
  </div>

  <div class="grid-2">
    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">IOC / THREAT INTELLIGENCE</span>
        <span class="panel-count">{{ iocs|length }} IPs checked</span>
      </div>
      <div class="panel-body">
        <table>
          <tr><th>IP</th><th>STATUS</th><th>CONFIDENCE</th><th>CATEGORY</th></tr>
          {% for i in iocs %}
          <tr>
            <td style="color:var(--bone)">{{ i.ip }}</td>
            <td>{% if i.malicious %}<span class="ioc-mal">⚠ MALICIOUS</span>{% else %}<span class="ioc-clean">✓ CLEAN</span>{% endif %}</td>
            <td style="color:var(--gold)">{{ i.confidence }}%</td>
            <td>{{ i.category }}</td>
          </tr>
          {% endfor %}
        </table>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <span class="panel-title">ASSET INVENTORY</span>
        <span class="panel-count">{{ assets|length }} assets</span>
      </div>
      <div class="panel-body">
        <table>
          <tr><th>NAME</th><th>IP</th><th>CRITICALITY</th><th>OS</th></tr>
          {% for a in assets %}
          {% set color = {'CRITICAL':'#c0152a','HIGH':'#e05c00','MEDIUM':'#c9943a','LOW':'#4a9a6a'}.get(a.criticality, '#666') %}
          <tr>
            <td style="color:var(--bone)">{{ a.name }}</td>
            <td style="color:var(--gold)">{{ a.ip }}</td>
            <td style="color:{{ color }}">{{ a.criticality }}</td>
            <td>{{ a.os }}</td>
          </tr>
          {% endfor %}
        </table>
      </div>
    </div>
  </div>
</div>
<footer>
  <span>SECOPS COMMAND CENTER &nbsp;|&nbsp; github.com/Toshi-hub834</span>
  <span>George Skhirtladze &nbsp;|&nbsp; toshi-hub834.github.io</span>
</footer>
</body></html>"""


@app.route("/")
def dashboard():
    summary, priority, iocs, assets = run_analysis()
    malicious_count = sum(1 for i in iocs if i["malicious"])
    return render_template_string(
        DASHBOARD_HTML,
        summary=summary,
        cves=priority,
        iocs=iocs,
        assets=assets,
        asset_count=len(assets),
        malicious_count=malicious_count,
        generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )


@app.route("/api/cves")
def api_cves():
    nvd  = NVDFeed()
    cves = nvd.fetch_recent(days=30, limit=20)
    return jsonify(cves)


@app.route("/api/iocs")
def api_iocs():
    checker = IOCChecker()
    results = checker.check_multiple(SAMPLE_IPS)
    return jsonify(results)


@app.route("/api/summary")
def api_summary():
    summary, priority, iocs, assets = run_analysis()
    return jsonify(summary)


@app.route("/report")
def report():
    summary, priority, iocs, assets = run_analysis()
    reporter = ReportGenerator()
    reporter.generate(summary, priority, iocs, assets, output="secops_report.html")
    with open("secops_report.html") as f:
        return f.read()


if __name__ == "__main__":
    print("\n[*] SecOps Command Center")
    print("[*] github.com/Toshi-hub834")
    print("[*] Running on http://127.0.0.1:5000\n")
    app.run(debug=True, port=5000)