from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
import html as html_mod

from .nmap_parser import Host
from .findings import Finding
from .vulns import VulnMatch


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

    return Report(
        generated_at_utc=ts,
        host_count=len(hosts),
        up_hosts=up_hosts,
        open_service_count=open_svcs,
        findings=all_items,
        hosts=hosts,
        vuln_matches=vuln_matches or [],
        severity_counts=counts,
    )


def render_markdown(r: Report) -> str:
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(r.findings, key=lambda f: (sev_order.get(f.severity, 9), f.host, f.port or -1))

    lines: list[str] = []
    lines.append("# Network Audit Report (from Nmap XML)")
    lines.append("")
    lines.append(f"- Generated (UTC): **{r.generated_at_utc}**")
    lines.append(f"- Hosts in file: **{r.host_count}** (up: **{r.up_hosts}**)")
    lines.append(f"- Open services (count): **{r.open_service_count}**")
    lines.append("")

    # Findings summary
    lines.append("## Findings Summary")
    lines.append(f"- Critical: **{r.severity_counts.get('critical', 0)}**")
    lines.append(f"- High: **{r.severity_counts.get('high', 0)}**")
    lines.append(f"- Medium: **{r.severity_counts.get('medium', 0)}**")
    lines.append(f"- Low: **{r.severity_counts.get('low', 0)}**")
    lines.append(f"- Info: **{r.severity_counts.get('info', 0)}**")
    lines.append("")

    # Vulnerability matches
    if r.vuln_matches:
        lines.append("## Known Vulnerability Matches")
        for vm in sorted(r.vuln_matches, key=lambda v: (sev_order.get(v.severity, 9), v.host)):
            cve_str = ", ".join(vm.cves) if vm.cves else "N/A"
            lines.append(f"### [{vm.vuln_id}] {vm.severity.upper()} — {vm.title}")
            lines.append(f"- Host: `{vm.host}` Port: `{vm.protocol}/{vm.port}`")
            lines.append(f"- Product: {vm.product} {vm.version}")
            lines.append(f"- CVEs: {cve_str}")
            lines.append(f"- {vm.description}")
            lines.append(f"- **Recommendation:** {vm.recommendation}")
            lines.append("")

    lines.append("## All Findings (sorted by severity)")
    if not sorted_findings:
        lines.append("_No findings from current rule set._")
    else:
        for f in sorted_findings:
            port_str = f"{f.protocol}/{f.port}" if f.port and f.protocol else "n/a"
            category_str = f" [{f.category}]" if f.category else ""
            cve_str = ""
            if f.cves:
                cve_str = f"\n- CVEs: {', '.join(f.cves)}"
            lines.append(f"### {f.severity.upper()}{category_str} — {f.title}")
            lines.append(f"- Host: `{f.host}`")
            lines.append(f"- Port: `{port_str}`")
            lines.append(f"- Detail: {f.detail}")
            lines.append(f"- Recommendation: {f.recommendation}{cve_str}")
            lines.append("")

    # Inventory section
    lines.append("## Host / Service Inventory (open only)")
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

        if h.mac_address:
            lines.append(f"- MAC: `{h.mac_address}`" + (f" ({h.mac_vendor})" if h.mac_vendor else ""))

        for s in sorted(open_svcs, key=lambda x: (x.protocol, x.port)):
            name = s.name or "unknown"
            ver = " ".join([x for x in [s.product, s.version, s.extrainfo] if x])
            ver = f" — {ver}" if ver else ""
            cpe_str = ""
            if s.cpe:
                cpe_str = f" `{s.cpe[0]}`"
            lines.append(f"- `{s.protocol}/{s.port}` **{name}**{ver}{cpe_str}")
        lines.append("")

    return "\n".join(lines)


def render_html(r: Report) -> str:
    """Render a self-contained HTML report with severity dashboard."""
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(r.findings, key=lambda f: (sev_order.get(f.severity, 9), f.host, f.port or -1))

    sev_colors = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#d97706",
        "low": "#2563eb",
        "info": "#6b7280",
    }

    def esc(text: str) -> str:
        return html_mod.escape(str(text))

    parts: list[str] = []
    parts.append("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Network Audit Report</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: #f8fafc; color: #1e293b; line-height: 1.6; padding: 2rem; }
  .container { max-width: 1200px; margin: 0 auto; }
  h1 { font-size: 1.8rem; margin-bottom: 1rem; color: #0f172a; }
  h2 { font-size: 1.4rem; margin: 2rem 0 1rem; color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 0.5rem; }
  h3 { font-size: 1.1rem; margin: 1.5rem 0 0.5rem; }
  .meta { color: #64748b; margin-bottom: 2rem; }
  .dashboard { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }
  .card { background: white; border-radius: 8px; padding: 1.2rem 1.5rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1);
          min-width: 140px; text-align: center; border-top: 4px solid; }
  .card .count { font-size: 2rem; font-weight: 700; }
  .card .label { font-size: 0.85rem; color: #64748b; text-transform: uppercase; }
  .finding { background: white; border-radius: 8px; padding: 1rem 1.5rem; margin-bottom: 0.75rem;
             box-shadow: 0 1px 3px rgba(0,0,0,0.08); border-left: 4px solid; }
  .finding .sev-badge { display: inline-block; padding: 2px 10px; border-radius: 4px; color: white;
                        font-size: 0.75rem; font-weight: 700; text-transform: uppercase; margin-right: 0.5rem; }
  .finding .title { font-weight: 600; }
  .finding .detail { color: #475569; margin: 0.3rem 0; font-size: 0.95rem; }
  .finding .rec { color: #059669; font-size: 0.9rem; }
  .finding .cves { color: #7c3aed; font-size: 0.85rem; }
  .host-card { background: white; border-radius: 8px; padding: 1rem 1.5rem; margin-bottom: 0.75rem;
               box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
  .host-card .addr { font-weight: 600; font-size: 1.05rem; }
  .host-card .svc { color: #475569; font-size: 0.9rem; padding: 2px 0; }
  .svc code { background: #f1f5f9; padding: 1px 6px; border-radius: 3px; font-size: 0.85rem; }
  table { width: 100%; border-collapse: collapse; margin: 1rem 0; }
  th, td { padding: 0.5rem 0.75rem; text-align: left; border-bottom: 1px solid #e2e8f0; }
  th { background: #f1f5f9; font-weight: 600; font-size: 0.85rem; text-transform: uppercase; color: #64748b; }
  .filter-bar { margin-bottom: 1rem; }
  .filter-bar select { padding: 0.4rem 0.8rem; border: 1px solid #cbd5e1; border-radius: 4px; font-size: 0.9rem; }
</style>
</head>
<body>
<div class="container">
""")

    parts.append(f"<h1>Network Audit Report</h1>")
    parts.append(f'<p class="meta">Generated: {esc(r.generated_at_utc)} | '
                 f'Hosts: {r.host_count} (up: {r.up_hosts}) | '
                 f'Open services: {r.open_service_count}</p>')

    # Dashboard cards
    parts.append('<div class="dashboard">')
    for sev in ("critical", "high", "medium", "low", "info"):
        count = r.severity_counts.get(sev, 0)
        color = sev_colors.get(sev, "#6b7280")
        parts.append(f'<div class="card" style="border-top-color:{color}">')
        parts.append(f'<div class="count" style="color:{color}">{count}</div>')
        parts.append(f'<div class="label">{sev}</div></div>')
    parts.append("</div>")

    # Vulnerability matches
    if r.vuln_matches:
        parts.append("<h2>Known Vulnerability Matches</h2>")
        parts.append("<table><thead><tr><th>ID</th><th>Severity</th><th>Host</th>"
                     "<th>Port</th><th>Product</th><th>Title</th><th>CVEs</th></tr></thead><tbody>")
        for vm in sorted(r.vuln_matches, key=lambda v: (sev_order.get(v.severity, 9), v.host)):
            color = sev_colors.get(vm.severity, "#6b7280")
            cves = ", ".join(vm.cves) if vm.cves else "—"
            parts.append(f'<tr><td>{esc(vm.vuln_id)}</td>'
                         f'<td><span style="color:{color};font-weight:700">{esc(vm.severity.upper())}</span></td>'
                         f'<td>{esc(vm.host)}</td><td>{esc(vm.protocol)}/{vm.port}</td>'
                         f'<td>{esc(vm.product)} {esc(vm.version)}</td>'
                         f'<td>{esc(vm.title)}</td><td>{esc(cves)}</td></tr>')
        parts.append("</tbody></table>")

    # Findings
    parts.append("<h2>All Findings</h2>")
    parts.append('<div class="filter-bar"><label>Filter: <select id="sev-filter" onchange="filterFindings()">')
    parts.append('<option value="all">All severities</option>')
    for sev in ("critical", "high", "medium", "low", "info"):
        parts.append(f'<option value="{sev}">{sev.upper()}</option>')
    parts.append("</select></label></div>")

    for f in sorted_findings:
        color = sev_colors.get(f.severity, "#6b7280")
        port_str = f"{f.protocol}/{f.port}" if f.port and f.protocol else "n/a"
        cat_str = f" [{esc(f.category)}]" if f.category else ""
        cve_line = ""
        if f.cves:
            cve_line = f'<div class="cves">CVEs: {esc(", ".join(f.cves))}</div>'
        parts.append(f'<div class="finding" data-sev="{f.severity}" style="border-left-color:{color}">')
        parts.append(f'<span class="sev-badge" style="background:{color}">{esc(f.severity)}</span>')
        parts.append(f'<span class="title">{esc(f.title)}{cat_str}</span>')
        parts.append(f'<div class="detail">{esc(f.host)} — {esc(port_str)} — {esc(f.detail)}</div>')
        parts.append(f'<div class="rec">Recommendation: {esc(f.recommendation)}</div>')
        parts.append(f'{cve_line}</div>')

    # Host inventory
    parts.append("<h2>Host / Service Inventory</h2>")
    for h in sorted(r.hosts, key=lambda x: x.address):
        open_svcs = [s for s in h.services if s.state == "open"]
        if h.status != "up" or not open_svcs:
            continue
        host_label = esc(h.address)
        if h.hostname:
            host_label += f" ({esc(h.hostname)})"
        os_str = ""
        if h.os_matches:
            os_str = f" — OS: {esc(h.os_matches[0].name)}"

        parts.append(f'<div class="host-card">')
        parts.append(f'<div class="addr">{host_label}{os_str}</div>')
        for s in sorted(open_svcs, key=lambda x: (x.protocol, x.port)):
            name = esc(s.name or "unknown")
            ver = " ".join([x for x in [s.product, s.version, s.extrainfo] if x])
            ver = f" — {esc(ver)}" if ver else ""
            parts.append(f'<div class="svc"><code>{esc(s.protocol)}/{s.port}</code> <strong>{name}</strong>{ver}</div>')
        parts.append("</div>")

    # Filter script
    parts.append("""
<script>
function filterFindings() {
  var sel = document.getElementById('sev-filter').value;
  document.querySelectorAll('.finding').forEach(function(el) {
    el.style.display = (sel === 'all' || el.dataset.sev === sel) ? '' : 'none';
  });
}
</script>
</div></body></html>""")

    return "\n".join(parts)


def flatten_findings_for_csv(findings: list[Finding]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
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
            }
        )
    return rows
