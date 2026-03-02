from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
import html as html_mod
from collections import Counter

from .nmap_parser import Host
from .findings import Finding
from .vulns import VulnMatch


SEV_WEIGHTS = {"critical": 40, "high": 10, "medium": 3, "low": 1, "info": 0}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True)
class Report:
    generated_at_utc: str
    host_count: int
    up_hosts: int
    open_service_count: int
    findings: list[Finding]
    hosts: list[Host]
    vuln_matches: list[VulnMatch] = field(default_factory=list)
    severity_counts: dict[str, int] = field(default_factory=dict)
    risk_score: int = 0               # 0-100 weighted risk score
    risk_level: str = "info"          # critical/high/medium/low/info
    category_counts: dict[str, int] = field(default_factory=dict)
    top_cves: list[str] = field(default_factory=list)


def _compute_risk(severity_counts: dict[str, int]) -> tuple[int, str]:
    """Return (score 0-100, level) from severity counts."""
    raw = sum(SEV_WEIGHTS.get(s, 0) * c for s, c in severity_counts.items())
    score = min(raw, 100)
    if score >= 80:
        return score, "critical"
    if score >= 50:
        return score, "high"
    if score >= 25:
        return score, "medium"
    if score >= 5:
        return score, "low"
    return score, "info"


def build_report(hosts: list[Host], findings: list[Finding],
                 vuln_matches: list[VulnMatch] | None = None) -> Report:
    up_hosts = sum(1 for h in hosts if h.status == "up")
    open_svcs = sum(1 for h in hosts for s in h.services if s.state == "open")
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")

    all_items = list(findings)
    if vuln_matches:
        for vm in vuln_matches:
            all_items.append(Finding(
                host=vm.host,
                severity=vm.severity,
                title=vm.title,
                detail=vm.description,
                recommendation=vm.recommendation,
                port=vm.port,
                protocol=vm.protocol,
                category="vuln",
                cves=vm.cves,
                vuln_id=vm.vuln_id,
            ))

    # Count severities
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_items:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    risk_score, risk_level = _compute_risk(counts)

    # Category counts
    cat_counts = dict(Counter(f.category or "other" for f in all_items))

    # Collect unique CVEs across all findings
    all_cves: list[str] = []
    seen_cves: set[str] = set()
    for f in all_items:
        for cve in f.cves:
            if cve not in seen_cves:
                seen_cves.add(cve)
                all_cves.append(cve)

    return Report(
        generated_at_utc=ts,
        host_count=len(hosts),
        up_hosts=up_hosts,
        open_service_count=open_svcs,
        findings=all_items,
        hosts=hosts,
        vuln_matches=vuln_matches or [],
        severity_counts=counts,
        risk_score=risk_score,
        risk_level=risk_level,
        category_counts=cat_counts,
        top_cves=all_cves[:20],
    )


def render_markdown(r: Report) -> str:
    sorted_findings = sorted(r.findings, key=lambda f: (SEV_ORDER.get(f.severity, 9), f.host, f.port or -1))

    lines: list[str] = []
    lines.append("# Network Audit Report")
    lines.append("")

    # ── Executive Summary ──
    lines.append("## Executive Summary")
    lines.append("")
    total = len(r.findings)
    crit = r.severity_counts.get("critical", 0)
    high = r.severity_counts.get("high", 0)
    lines.append(f"A network scan of **{r.host_count}** host(s) (**{r.up_hosts}** up) "
                 f"identified **{r.open_service_count}** open service(s) and produced "
                 f"**{total}** finding(s).")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|---|---|")
    lines.append(f"| **Overall Risk Score** | **{r.risk_score}/100 ({r.risk_level.upper()})** |")
    lines.append(f"| Hosts scanned | {r.host_count} ({r.up_hosts} up) |")
    lines.append(f"| Open services | {r.open_service_count} |")
    lines.append(f"| Total findings | {total} |")
    lines.append(f"| Report generated (UTC) | {r.generated_at_utc} |")
    lines.append("")
    if crit + high > 0:
        lines.append(f"> **Action required:** {crit} critical and {high} high severity "
                     f"finding(s) need prompt remediation.")
        lines.append("")

    # ── Severity Breakdown ──
    lines.append("## Severity Breakdown")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---:|")
    for sev in ("critical", "high", "medium", "low", "info"):
        cnt = r.severity_counts.get(sev, 0)
        marker = " :red_circle:" if sev == "critical" and cnt > 0 else ""
        lines.append(f"| {sev.upper()} | {cnt}{marker} |")
    lines.append("")

    # ── Category Breakdown ──
    if r.category_counts:
        lines.append("## Findings by Category")
        lines.append("")
        lines.append("| Category | Count |")
        lines.append("|---|---:|")
        for cat, cnt in sorted(r.category_counts.items(), key=lambda x: -x[1]):
            lines.append(f"| {cat} | {cnt} |")
        lines.append("")

    # ── CVE References ──
    if r.top_cves:
        lines.append("## CVE References")
        lines.append("")
        for cve in r.top_cves:
            lines.append(f"- [{cve}](https://nvd.nist.gov/vuln/detail/{cve})")
        lines.append("")

    # ── Vulnerability matches ──
    if r.vuln_matches:
        lines.append("## Known Vulnerability Matches")
        lines.append("")
        lines.append("| ID | Severity | Host | Port | Product | Title | CVEs |")
        lines.append("|---|---|---|---|---|---|---|")
        for vm in sorted(r.vuln_matches, key=lambda v: (SEV_ORDER.get(v.severity, 9), v.host)):
            cve_str = ", ".join(f"[{c}](https://nvd.nist.gov/vuln/detail/{c})" for c in vm.cves) if vm.cves else "—"
            lines.append(f"| {vm.vuln_id} | **{vm.severity.upper()}** | `{vm.host}` | "
                         f"{vm.protocol}/{vm.port} | {vm.product} {vm.version} | "
                         f"{vm.title} | {cve_str} |")
        lines.append("")
        # Detailed vulnerability descriptions
        for vm in sorted(r.vuln_matches, key=lambda v: (SEV_ORDER.get(v.severity, 9), v.host)):
            lines.append(f"### [{vm.vuln_id}] {vm.severity.upper()} — {vm.title}")
            lines.append(f"- **Host:** `{vm.host}` **Port:** `{vm.protocol}/{vm.port}`")
            lines.append(f"- **Product:** {vm.product} {vm.version}")
            if vm.cves:
                cve_links = ", ".join(f"[{c}](https://nvd.nist.gov/vuln/detail/{c})" for c in vm.cves)
                lines.append(f"- **CVEs:** {cve_links}")
            lines.append(f"- {vm.description}")
            lines.append(f"- **Recommendation:** {vm.recommendation}")
            lines.append("")

    # ── All Findings ──
    lines.append("## All Findings (sorted by severity)")
    lines.append("")
    if not sorted_findings:
        lines.append("_No findings from current rule set._")
    else:
        for f in sorted_findings:
            port_str = f"{f.protocol}/{f.port}" if f.port and f.protocol else "n/a"
            category_str = f" [{f.category}]" if f.category else ""
            cve_str = ""
            if f.cves:
                cve_links = ", ".join(f"[{c}](https://nvd.nist.gov/vuln/detail/{c})" for c in f.cves)
                cve_str = f"\n- **CVEs:** {cve_links}"
            lines.append(f"### {f.severity.upper()}{category_str} — {f.title}")
            lines.append(f"- **Host:** `{f.host}`")
            lines.append(f"- **Port:** `{port_str}`")
            lines.append(f"- **Detail:** {f.detail}")
            lines.append(f"- **Recommendation:** {f.recommendation}{cve_str}")
            lines.append("")

    # ── Host / Service Inventory ──
    lines.append("## Host / Service Inventory")
    lines.append("")
    for h in sorted(r.hosts, key=lambda x: x.address):
        open_svcs = [s for s in h.services if s.state == "open"]
        if h.status != "up" or not open_svcs:
            continue
        host_line = f"### {h.address}"
        if h.hostname:
            host_line += f" ({h.hostname})"
        if h.os_matches:
            best_os = h.os_matches[0]
            host_line += f" — OS: {best_os.name} ({best_os.accuracy}%)"
        lines.append(host_line)
        lines.append("")

        # Host metadata
        meta_parts: list[str] = []
        if h.mac_address:
            mac_str = f"MAC: `{h.mac_address}`"
            if h.mac_vendor:
                mac_str += f" ({h.mac_vendor})"
            meta_parts.append(mac_str)
        if h.uptime_seconds is not None:
            days = h.uptime_seconds // 86400
            hours = (h.uptime_seconds % 86400) // 3600
            meta_parts.append(f"Uptime: {days}d {hours}h")
        if h.distance_hops is not None:
            meta_parts.append(f"Hops: {h.distance_hops}")
        if meta_parts:
            lines.append(f"- {' | '.join(meta_parts)}")
            lines.append("")

        # Service table
        lines.append("| Port | Service | Product/Version | CPE |")
        lines.append("|---|---|---|---|")
        for s in sorted(open_svcs, key=lambda x: (x.protocol, x.port)):
            name = s.name or "unknown"
            ver = " ".join([x for x in [s.product, s.version, s.extrainfo] if x]) or "—"
            cpe_str = s.cpe[0] if s.cpe else "—"
            lines.append(f"| `{s.protocol}/{s.port}` | **{name}** | {ver} | `{cpe_str}` |")
        lines.append("")

    # ── Remediation Priority ──
    crit_high = [f for f in sorted_findings if f.severity in ("critical", "high")]
    if crit_high:
        lines.append("## Remediation Priority")
        lines.append("")
        lines.append("The following items should be addressed first:")
        lines.append("")
        lines.append("| # | Severity | Finding | Host | Port |")
        lines.append("|---:|---|---|---|---|")
        for i, f in enumerate(crit_high, 1):
            port_str = f"{f.protocol}/{f.port}" if f.port and f.protocol else "—"
            lines.append(f"| {i} | **{f.severity.upper()}** | {f.title} | `{f.host}` | {port_str} |")
        lines.append("")

    return "\n".join(lines)


def render_html(r: Report) -> str:
    """Render a self-contained, rich HTML report with dashboard, charts, and interactivity."""
    sorted_findings = sorted(r.findings, key=lambda f: (SEV_ORDER.get(f.severity, 9), f.host, f.port or -1))

    sev_colors = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#d97706",
        "low": "#2563eb",
        "info": "#6b7280",
    }
    sev_bg = {
        "critical": "#fef2f2",
        "high": "#fff7ed",
        "medium": "#fffbeb",
        "low": "#eff6ff",
        "info": "#f9fafb",
    }

    def esc(text: str) -> str:
        return html_mod.escape(str(text))

    # ── Risk gauge color ──
    risk_color = sev_colors.get(r.risk_level, "#6b7280")

    # ── SVG donut chart ──
    def _svg_donut(counts: dict[str, int], size: int = 180) -> str:
        total = sum(counts.values())
        if total == 0:
            return ""
        cx, cy, radius = size // 2, size // 2, 60
        circumference = 2 * 3.14159 * radius
        offset = 0
        arcs: list[str] = []
        for sev in ("critical", "high", "medium", "low", "info"):
            cnt = counts.get(sev, 0)
            if cnt == 0:
                continue
            frac = cnt / total
            dash = frac * circumference
            gap = circumference - dash
            color = sev_colors.get(sev, "#6b7280")
            arcs.append(
                f'<circle cx="{cx}" cy="{cy}" r="{radius}" fill="none" '
                f'stroke="{color}" stroke-width="24" '
                f'stroke-dasharray="{dash:.1f} {gap:.1f}" '
                f'stroke-dashoffset="{-offset:.1f}" />'
            )
            offset += dash
        return (
            f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" '
            f'style="transform:rotate(-90deg)">{chr(10).join(arcs)}</svg>'
        )

    parts: list[str] = []
    parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Network Audit Report — {esc(r.generated_at_utc)}</title>
<style>
  :root {{
    --bg: #f1f5f9; --surface: #ffffff; --text: #1e293b; --text2: #475569;
    --text3: #64748b; --border: #e2e8f0; --hover: #f8fafc;
  }}
  [data-theme="dark"] {{
    --bg: #0f172a; --surface: #1e293b; --text: #f1f5f9; --text2: #cbd5e1;
    --text3: #94a3b8; --border: #334155; --hover: #1e293b;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif;
         background: var(--bg); color: var(--text); line-height: 1.6; }}
  a {{ color: #3b82f6; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}

  /* Layout */
  .layout {{ display: flex; min-height: 100vh; }}
  .sidebar {{ width: 240px; background: var(--surface); border-right: 1px solid var(--border);
              padding: 1.5rem 0; position: fixed; top: 0; left: 0; bottom: 0; overflow-y: auto;
              z-index: 10; }}
  .sidebar .logo {{ padding: 0 1.25rem 1.25rem; font-weight: 700; font-size: 1rem;
                    color: var(--text); border-bottom: 1px solid var(--border); }}
  .sidebar nav {{ padding: 1rem 0; }}
  .sidebar nav a {{ display: block; padding: 0.4rem 1.25rem; color: var(--text2);
                    font-size: 0.85rem; transition: background 0.15s; }}
  .sidebar nav a:hover {{ background: var(--hover); color: var(--text); text-decoration: none; }}
  .sidebar nav a.active {{ color: #3b82f6; font-weight: 600; border-left: 3px solid #3b82f6;
                           padding-left: calc(1.25rem - 3px); }}
  .main {{ margin-left: 240px; flex: 1; padding: 2rem 2.5rem; max-width: 1100px; }}

  /* Header */
  .header {{ display: flex; justify-content: space-between; align-items: center;
             margin-bottom: 2rem; flex-wrap: wrap; gap: 1rem; }}
  .header h1 {{ font-size: 1.5rem; color: var(--text); }}
  .header-controls {{ display: flex; gap: 0.75rem; align-items: center; }}
  .header-controls select, .header-controls button {{
    padding: 0.4rem 0.8rem; border: 1px solid var(--border); border-radius: 6px;
    background: var(--surface); color: var(--text); font-size: 0.85rem; cursor: pointer;
  }}
  .meta-line {{ color: var(--text3); font-size: 0.85rem; margin-bottom: 1.5rem; }}

  /* Section */
  .section {{ margin-bottom: 2.5rem; scroll-margin-top: 1rem; }}
  .section h2 {{ font-size: 1.2rem; color: var(--text); margin-bottom: 1rem;
                 padding-bottom: 0.5rem; border-bottom: 2px solid var(--border); }}

  /* Risk gauge */
  .risk-banner {{ background: var(--surface); border-radius: 12px; padding: 1.5rem 2rem;
                  box-shadow: 0 1px 4px rgba(0,0,0,0.06); display: flex;
                  align-items: center; gap: 2rem; margin-bottom: 2rem; border-left: 5px solid; }}
  .risk-banner .score {{ font-size: 3rem; font-weight: 800; line-height: 1; }}
  .risk-banner .score-label {{ font-size: 0.8rem; color: var(--text3); text-transform: uppercase;
                               letter-spacing: 0.05em; }}
  .risk-banner .desc {{ flex: 1; }}
  .risk-banner .desc p {{ color: var(--text2); font-size: 0.95rem; margin-top: 0.3rem; }}

  /* Dashboard */
  .dashboard {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
                gap: 0.75rem; margin-bottom: 2rem; }}
  .card {{ background: var(--surface); border-radius: 10px; padding: 1rem 1.2rem;
           box-shadow: 0 1px 3px rgba(0,0,0,0.06); text-align: center;
           border-top: 4px solid; transition: transform 0.15s; cursor: default; }}
  .card:hover {{ transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.1); }}
  .card .count {{ font-size: 1.8rem; font-weight: 700; }}
  .card .label {{ font-size: 0.75rem; color: var(--text3); text-transform: uppercase;
                  letter-spacing: 0.05em; }}

  /* Chart row */
  .chart-row {{ display: flex; gap: 2rem; flex-wrap: wrap; align-items: flex-start; margin-bottom: 2rem; }}
  .chart-box {{ background: var(--surface); border-radius: 10px; padding: 1.5rem;
                box-shadow: 0 1px 3px rgba(0,0,0,0.06); flex: 1; min-width: 240px; }}
  .chart-box h3 {{ font-size: 0.95rem; color: var(--text); margin-bottom: 1rem; }}
  .bar-chart {{ display: flex; flex-direction: column; gap: 0.5rem; }}
  .bar-row {{ display: flex; align-items: center; gap: 0.5rem; }}
  .bar-row .bar-label {{ font-size: 0.8rem; color: var(--text2); width: 70px; text-align: right; }}
  .bar-row .bar-track {{ flex: 1; height: 22px; background: var(--bg); border-radius: 4px; overflow: hidden; }}
  .bar-row .bar-fill {{ height: 100%; border-radius: 4px; transition: width 0.5s ease; min-width: 2px;
                        display: flex; align-items: center; padding-left: 6px; }}
  .bar-row .bar-fill span {{ font-size: 0.7rem; color: white; font-weight: 600; }}
  .donut-wrap {{ display: flex; flex-direction: column; align-items: center; gap: 0.75rem; }}
  .donut-legend {{ display: flex; flex-wrap: wrap; gap: 0.5rem 1rem; justify-content: center; }}
  .donut-legend span {{ font-size: 0.8rem; color: var(--text2); display: flex;
                        align-items: center; gap: 4px; }}
  .donut-legend .dot {{ width: 10px; height: 10px; border-radius: 50%; display: inline-block; }}

  /* Tables */
  table {{ width: 100%; border-collapse: collapse; margin: 0.75rem 0; font-size: 0.9rem; }}
  th, td {{ padding: 0.55rem 0.75rem; text-align: left; border-bottom: 1px solid var(--border); }}
  th {{ background: var(--bg); font-weight: 600; font-size: 0.8rem; text-transform: uppercase;
        color: var(--text3); letter-spacing: 0.03em; position: sticky; top: 0; }}
  tr:hover {{ background: var(--hover); }}

  /* Findings */
  .finding {{ background: var(--surface); border-radius: 10px; padding: 1rem 1.25rem;
              margin-bottom: 0.6rem; box-shadow: 0 1px 3px rgba(0,0,0,0.06);
              border-left: 4px solid; cursor: pointer; transition: box-shadow 0.15s; }}
  .finding:hover {{ box-shadow: 0 3px 10px rgba(0,0,0,0.1); }}
  .finding-header {{ display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }}
  .sev-badge {{ display: inline-block; padding: 2px 10px; border-radius: 4px; color: white;
                font-size: 0.7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.03em; }}
  .cat-badge {{ display: inline-block; padding: 1px 8px; border-radius: 3px; font-size: 0.7rem;
                color: var(--text3); border: 1px solid var(--border); }}
  .finding .ftitle {{ font-weight: 600; font-size: 0.95rem; }}
  .finding .fmeta {{ color: var(--text3); font-size: 0.8rem; margin-top: 0.15rem; }}
  .finding-body {{ display: none; margin-top: 0.75rem; padding-top: 0.75rem;
                   border-top: 1px solid var(--border); }}
  .finding-body.open {{ display: block; }}
  .finding .detail {{ color: var(--text2); font-size: 0.9rem; margin-bottom: 0.4rem; }}
  .finding .rec {{ color: #059669; font-size: 0.88rem; }}
  [data-theme="dark"] .finding .rec {{ color: #34d399; }}
  .finding .cves {{ margin-top: 0.3rem; }}
  .finding .cves a {{ font-size: 0.82rem; color: #7c3aed; margin-right: 0.5rem; }}
  [data-theme="dark"] .finding .cves a {{ color: #a78bfa; }}

  /* Host cards */
  .host-card {{ background: var(--surface); border-radius: 10px; padding: 1.25rem 1.5rem;
                margin-bottom: 0.75rem; box-shadow: 0 1px 3px rgba(0,0,0,0.06); }}
  .host-card .addr {{ font-weight: 700; font-size: 1rem; display: flex;
                      align-items: center; gap: 0.5rem; }}
  .host-card .host-meta {{ color: var(--text3); font-size: 0.82rem; margin: 0.3rem 0 0.75rem; }}

  /* Print */
  @media print {{
    .sidebar, .header-controls {{ display: none !important; }}
    .main {{ margin-left: 0; padding: 0; }}
    .finding-body {{ display: block !important; }}
    body {{ background: white; }}
  }}
  /* Mobile */
  @media (max-width: 768px) {{
    .sidebar {{ display: none; }}
    .main {{ margin-left: 0; padding: 1rem; }}
    .chart-row {{ flex-direction: column; }}
  }}
</style>
</head>
<body>
""")

    # ── Sidebar Navigation ──
    parts.append("""<div class="layout">
<aside class="sidebar">
  <div class="logo">Net Audit Report</div>
  <nav>
    <a href="#executive-summary" class="active">Executive Summary</a>
    <a href="#severity-dashboard">Severity Dashboard</a>""")
    if r.vuln_matches:
        parts.append('    <a href="#vuln-matches">Vulnerability Matches</a>')
    parts.append("""    <a href="#all-findings">All Findings</a>
    <a href="#host-inventory">Host Inventory</a>""")
    crit_high = [f for f in sorted_findings if f.severity in ("critical", "high")]
    if crit_high:
        parts.append('    <a href="#remediation">Remediation Priority</a>')
    if r.top_cves:
        parts.append('    <a href="#cve-references">CVE References</a>')
    parts.append("  </nav>\n</aside>")

    # ── Main Content ──
    parts.append('<div class="main">')

    # Header
    parts.append('<div class="header">')
    parts.append(f'<h1>Network Audit Report</h1>')
    parts.append("""<div class="header-controls">
  <select id="sev-filter" onchange="filterFindings()">
    <option value="all">All severities</option>
    <option value="critical">Critical</option>
    <option value="high">High</option>
    <option value="medium">Medium</option>
    <option value="low">Low</option>
    <option value="info">Info</option>
  </select>
  <button onclick="toggleTheme()">Toggle Dark Mode</button>
  <button onclick="window.print()">Print / PDF</button>
</div></div>""")
    parts.append(f'<div class="meta-line">Generated: {esc(r.generated_at_utc)} &middot; '
                 f'Hosts: {r.host_count} (up: {r.up_hosts}) &middot; '
                 f'Open services: {r.open_service_count} &middot; '
                 f'Total findings: {len(r.findings)}</div>')

    # ── Executive Summary / Risk Banner ──
    total = len(r.findings)
    crit = r.severity_counts.get("critical", 0)
    high = r.severity_counts.get("high", 0)

    desc_parts = []
    if crit > 0:
        desc_parts.append(f"{crit} critical")
    if high > 0:
        desc_parts.append(f"{high} high")
    action = ""
    if desc_parts:
        action = f"<strong>Immediate action required:</strong> {' and '.join(desc_parts)} severity finding(s) detected."
    else:
        action = "No critical or high severity findings detected."

    parts.append(f'<div id="executive-summary" class="section">')
    parts.append(f'<div class="risk-banner" style="border-left-color:{risk_color}">')
    parts.append(f'<div><div class="score" style="color:{risk_color}">{r.risk_score}</div>'
                 f'<div class="score-label">Risk Score / 100</div></div>')
    parts.append(f'<div class="desc"><strong style="text-transform:uppercase;color:{risk_color}">'
                 f'{esc(r.risk_level)} Risk</strong>'
                 f'<p>Scanned {r.host_count} host(s), {r.up_hosts} responded. '
                 f'Discovered {r.open_service_count} open service(s) and {total} finding(s). '
                 f'{action}</p></div>')

    # Donut chart
    donut_svg = _svg_donut(r.severity_counts)
    if donut_svg:
        parts.append(f'<div class="donut-wrap">{donut_svg}')
        parts.append('<div class="donut-legend">')
        for sev in ("critical", "high", "medium", "low", "info"):
            cnt = r.severity_counts.get(sev, 0)
            if cnt > 0:
                parts.append(f'<span><span class="dot" style="background:{sev_colors[sev]}"></span>'
                             f'{sev.upper()} ({cnt})</span>')
        parts.append('</div></div>')
    parts.append('</div></div>')

    # ── Severity Dashboard Cards ──
    parts.append('<div id="severity-dashboard" class="section">')
    parts.append('<h2>Severity Dashboard</h2>')
    parts.append('<div class="dashboard">')
    for sev in ("critical", "high", "medium", "low", "info"):
        count = r.severity_counts.get(sev, 0)
        color = sev_colors.get(sev, "#6b7280")
        parts.append(f'<div class="card" style="border-top-color:{color}" '
                     f'onclick="document.getElementById(\'sev-filter\').value=\'{sev}\';filterFindings()">')
        parts.append(f'<div class="count" style="color:{color}">{count}</div>')
        parts.append(f'<div class="label">{sev}</div></div>')
    parts.append("</div>")

    # ── Category bar chart ──
    if r.category_counts:
        max_cat = max(r.category_counts.values()) if r.category_counts else 1
        cat_colors = {
            "port": "#3b82f6", "service": "#8b5cf6", "ssl": "#06b6d4",
            "vuln": "#dc2626", "compliance": "#f59e0b", "suspicious": "#ef4444",
            "info": "#6b7280", "management": "#ea580c", "database": "#d946ef",
            "encryption": "#14b8a6", "auth": "#f97316", "network": "#0ea5e9",
            "os": "#a855f7", "other": "#94a3b8", "web": "#10b981",
        }
        parts.append('<div class="chart-row"><div class="chart-box"><h3>Findings by Category</h3>')
        parts.append('<div class="bar-chart">')
        for cat, cnt in sorted(r.category_counts.items(), key=lambda x: -x[1]):
            pct = (cnt / max_cat) * 100
            color = cat_colors.get(cat, "#94a3b8")
            parts.append(
                f'<div class="bar-row">'
                f'<div class="bar-label">{esc(cat)}</div>'
                f'<div class="bar-track"><div class="bar-fill" style="width:{pct:.0f}%;background:{color}">'
                f'<span>{cnt}</span></div></div></div>'
            )
        parts.append('</div></div>')

        # Hosts-at-risk mini table
        host_finding_counts: dict[str, dict[str, int]] = {}
        for f in r.findings:
            if f.host not in host_finding_counts:
                host_finding_counts[f.host] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
            host_finding_counts[f.host][f.severity] = host_finding_counts[f.host].get(f.severity, 0) + 1
        if host_finding_counts:
            parts.append('<div class="chart-box"><h3>Findings per Host</h3>')
            parts.append('<table><thead><tr><th>Host</th><th>Crit</th><th>High</th>'
                         '<th>Med</th><th>Low</th><th>Info</th><th>Total</th></tr></thead><tbody>')
            for host, sc in sorted(host_finding_counts.items(),
                                    key=lambda x: -(x[1].get("critical", 0) * 100 + x[1].get("high", 0) * 10)):
                t = sum(sc.values())
                parts.append(f'<tr><td><code>{esc(host)}</code></td>')
                for s in ("critical", "high", "medium", "low", "info"):
                    v = sc.get(s, 0)
                    style = f' style="color:{sev_colors[s]};font-weight:700"' if v > 0 else ""
                    parts.append(f'<td{style}>{v}</td>')
                parts.append(f'<td><strong>{t}</strong></td></tr>')
            parts.append('</tbody></table></div>')
        parts.append('</div>')

    parts.append("</div>")  # end section

    # ── Vulnerability Matches ──
    if r.vuln_matches:
        parts.append('<div id="vuln-matches" class="section">')
        parts.append('<h2>Known Vulnerability Matches</h2>')
        parts.append('<table><thead><tr><th>ID</th><th>Severity</th><th>Host</th>'
                     '<th>Port</th><th>Product</th><th>Title</th><th>CVEs</th></tr></thead><tbody>')
        for vm in sorted(r.vuln_matches, key=lambda v: (SEV_ORDER.get(v.severity, 9), v.host)):
            color = sev_colors.get(vm.severity, "#6b7280")
            cve_links = ", ".join(
                f'<a href="https://nvd.nist.gov/vuln/detail/{esc(c)}" target="_blank">{esc(c)}</a>'
                for c in vm.cves
            ) if vm.cves else "—"
            parts.append(
                f'<tr><td><code>{esc(vm.vuln_id)}</code></td>'
                f'<td><span class="sev-badge" style="background:{color}">{esc(vm.severity.upper())}</span></td>'
                f'<td><code>{esc(vm.host)}</code></td><td>{esc(vm.protocol)}/{vm.port}</td>'
                f'<td>{esc(vm.product)} {esc(vm.version)}</td>'
                f'<td>{esc(vm.title)}</td><td>{cve_links}</td></tr>'
            )
        parts.append('</tbody></table></div>')

    # ── All Findings ──
    parts.append('<div id="all-findings" class="section">')
    parts.append('<h2>All Findings</h2>')

    if not sorted_findings:
        parts.append('<p style="color:var(--text3)"><em>No findings from current rule set.</em></p>')
    else:
        for f in sorted_findings:
            color = sev_colors.get(f.severity, "#6b7280")
            bg = sev_bg.get(f.severity, "#f9fafb")
            port_str = f"{f.protocol}/{f.port}" if f.port and f.protocol else "n/a"
            cat_html = f'<span class="cat-badge">{esc(f.category)}</span>' if f.category else ""
            cve_html = ""
            if f.cves:
                links = " ".join(
                    f'<a href="https://nvd.nist.gov/vuln/detail/{esc(c)}" target="_blank">{esc(c)}</a>'
                    for c in f.cves
                )
                cve_html = f'<div class="cves">{links}</div>'
            parts.append(
                f'<div class="finding" data-sev="{f.severity}" data-cat="{f.category or ""}" '
                f'style="border-left-color:{color}" onclick="toggleBody(this)">'
                f'<div class="finding-header">'
                f'<span class="sev-badge" style="background:{color}">{esc(f.severity)}</span>'
                f'{cat_html}'
                f'<span class="ftitle">{esc(f.title)}</span></div>'
                f'<div class="fmeta">{esc(f.host)} &middot; {esc(port_str)}</div>'
                f'<div class="finding-body">'
                f'<div class="detail">{esc(f.detail)}</div>'
                f'<div class="rec">Recommendation: {esc(f.recommendation)}</div>'
                f'{cve_html}</div></div>'
            )

    parts.append("</div>")

    # ── Host Inventory ──
    parts.append('<div id="host-inventory" class="section">')
    parts.append('<h2>Host / Service Inventory</h2>')
    for h in sorted(r.hosts, key=lambda x: x.address):
        open_svcs = [s for s in h.services if s.state == "open"]
        if h.status != "up" or not open_svcs:
            continue
        host_label = esc(h.address)
        if h.hostname:
            host_label += f" ({esc(h.hostname)})"
        os_str = ""
        if h.os_matches:
            os_str = f" &mdash; {esc(h.os_matches[0].name)}"

        # Host metadata
        meta_parts: list[str] = []
        if h.mac_address:
            mac = f"MAC: <code>{esc(h.mac_address)}</code>"
            if h.mac_vendor:
                mac += f" ({esc(h.mac_vendor)})"
            meta_parts.append(mac)
        if h.uptime_seconds is not None:
            d = h.uptime_seconds // 86400
            hrs = (h.uptime_seconds % 86400) // 3600
            meta_parts.append(f"Uptime: {d}d {hrs}h")
        if h.distance_hops is not None:
            meta_parts.append(f"Hops: {h.distance_hops}")
        meta_html = " &middot; ".join(meta_parts) if meta_parts else ""

        parts.append(f'<div class="host-card">')
        parts.append(f'<div class="addr">{host_label}{os_str}</div>')
        if meta_html:
            parts.append(f'<div class="host-meta">{meta_html}</div>')

        # Service table
        parts.append('<table><thead><tr><th>Port</th><th>Service</th>'
                     '<th>Product / Version</th><th>CPE</th></tr></thead><tbody>')
        for s in sorted(open_svcs, key=lambda x: (x.protocol, x.port)):
            name = esc(s.name or "unknown")
            ver = " ".join([x for x in [s.product, s.version, s.extrainfo] if x])
            ver = esc(ver) if ver else "—"
            cpe = f"<code>{esc(s.cpe[0])}</code>" if s.cpe else "—"
            parts.append(
                f'<tr><td><code>{esc(s.protocol)}/{s.port}</code></td>'
                f'<td><strong>{name}</strong></td><td>{ver}</td><td>{cpe}</td></tr>'
            )
        parts.append('</tbody></table></div>')
    parts.append("</div>")

    # ── Remediation Priority ──
    if crit_high:
        parts.append('<div id="remediation" class="section">')
        parts.append('<h2>Remediation Priority</h2>')
        parts.append('<p style="color:var(--text2);margin-bottom:0.75rem">'
                     'Address these items first, sorted by severity.</p>')
        parts.append('<table><thead><tr><th>#</th><th>Severity</th><th>Finding</th>'
                     '<th>Host</th><th>Port</th><th>Recommendation</th></tr></thead><tbody>')
        for i, f in enumerate(crit_high, 1):
            color = sev_colors.get(f.severity, "#6b7280")
            port_str = f"{f.protocol}/{f.port}" if f.port and f.protocol else "—"
            parts.append(
                f'<tr><td>{i}</td>'
                f'<td><span class="sev-badge" style="background:{color}">{esc(f.severity.upper())}</span></td>'
                f'<td>{esc(f.title)}</td>'
                f'<td><code>{esc(f.host)}</code></td>'
                f'<td>{esc(port_str)}</td>'
                f'<td style="font-size:0.85rem;color:var(--text2)">{esc(f.recommendation)}</td></tr>'
            )
        parts.append('</tbody></table></div>')

    # ── CVE References ──
    if r.top_cves:
        parts.append('<div id="cve-references" class="section">')
        parts.append('<h2>CVE References</h2>')
        parts.append('<table><thead><tr><th>CVE ID</th><th>NVD Link</th></tr></thead><tbody>')
        for cve in r.top_cves:
            url = f"https://nvd.nist.gov/vuln/detail/{esc(cve)}"
            parts.append(f'<tr><td><code>{esc(cve)}</code></td>'
                         f'<td><a href="{url}" target="_blank">{url}</a></td></tr>')
        parts.append('</tbody></table></div>')

    # ── Footer ──
    parts.append(f'<div style="margin-top:3rem;padding-top:1rem;border-top:1px solid var(--border);'
                 f'color:var(--text3);font-size:0.8rem">'
                 f'Report generated by <strong>net-audit-report</strong> on {esc(r.generated_at_utc)}.'
                 f'</div>')

    # Close main + layout
    parts.append("</div></div>")

    # ── JavaScript ──
    parts.append("""
<script>
function filterFindings() {
  var sel = document.getElementById('sev-filter').value;
  document.querySelectorAll('.finding').forEach(function(el) {
    el.style.display = (sel === 'all' || el.dataset.sev === sel) ? '' : 'none';
  });
}
function toggleBody(el) {
  var body = el.querySelector('.finding-body');
  if (body) body.classList.toggle('open');
}
function toggleTheme() {
  var html = document.documentElement;
  html.setAttribute('data-theme', html.getAttribute('data-theme') === 'dark' ? '' : 'dark');
}
// Sidebar active link tracking
(function() {
  var links = document.querySelectorAll('.sidebar nav a');
  var sections = [];
  links.forEach(function(a) {
    var id = a.getAttribute('href').slice(1);
    var el = document.getElementById(id);
    if (el) sections.push({link: a, el: el});
  });
  window.addEventListener('scroll', function() {
    var scrollY = window.scrollY + 100;
    var active = sections[0];
    for (var i = 0; i < sections.length; i++) {
      if (sections[i].el.offsetTop <= scrollY) active = sections[i];
    }
    links.forEach(function(a) { a.classList.remove('active'); });
    if (active) active.link.classList.add('active');
  });
})();
</script>
</body></html>""")

    return "\n".join(parts)


def flatten_findings_for_csv(findings: list[Finding],
                             report: Report | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    risk_score = report.risk_score if report else ""
    risk_level = report.risk_level if report else ""
    for f in findings:
        rows.append(
            {
                "host": f.host,
                "severity": f.severity,
                "title": f.title,
                "category": f.category or "",
                "detail": f.detail,
                "recommendation": f.recommendation,
                "protocol": f.protocol or "",
                "port": f.port or "",
                "cves": ",".join(f.cves) if f.cves else "",
                "vuln_id": f.vuln_id or "",
                "risk_score": risk_score,
                "risk_level": risk_level,
            }
        )
    return rows
