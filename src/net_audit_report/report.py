from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .nmap_parser import Host
from .findings import Finding


@dataclass(frozen=True)
class Report:
    generated_at_utc: str
    host_count: int
    up_hosts: int
    open_service_count: int
    findings: list[Finding]
    hosts: list[Host]


def build_report(hosts: list[Host], findings: list[Finding]) -> Report:
    up_hosts = sum(1 for h in hosts if h.status == "up")
    open_svcs = sum(1 for h in hosts for s in h.services if s.state == "open")
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return Report(
        generated_at_utc=ts,
        host_count=len(hosts),
        up_hosts=up_hosts,
        open_service_count=open_svcs,
        findings=findings,
        hosts=hosts,
    )


def render_markdown(r: Report) -> str:
    sev_order = {"high": 0, "medium": 1, "low": 2}
    sorted_findings = sorted(r.findings, key=lambda f: (sev_order.get(f.severity, 9), f.host, f.port or -1))

    lines: list[str] = []
    lines.append("# Network Audit Report (from Nmap XML)")
    lines.append("")
    lines.append(f"- Generated (UTC): **{r.generated_at_utc}**")
    lines.append(f"- Hosts in file: **{r.host_count}** (up: **{r.up_hosts}**)")
    lines.append(f"- Open services (count): **{r.open_service_count}**")
    lines.append("")

    # Findings summary
    counts: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for f in r.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    lines.append("## Findings Summary")
    lines.append(f"- High: **{counts.get('high', 0)}**")
    lines.append(f"- Medium: **{counts.get('medium', 0)}**")
    lines.append(f"- Low: **{counts.get('low', 0)}**")
    lines.append("")

    lines.append("## Findings (sorted by severity)")
    if not sorted_findings:
        lines.append("_No findings from current rule set._")
    else:
        for f in sorted_findings:
            port_str = f"{f.protocol}/{f.port}" if f.port and f.protocol else "n/a"
            lines.append(f"### {f.severity.upper()} — {f.title}")
            lines.append(f"- Host: `{f.host}`")
            lines.append(f"- Port: `{port_str}`")
            lines.append(f"- Detail: {f.detail}")
            lines.append(f"- Recommendation: {f.recommendation}")
            lines.append("")

    # Inventory section
    lines.append("## Host / Service Inventory (open only)")
    for h in sorted(r.hosts, key=lambda x: x.address):
        open_svcs = [s for s in h.services if s.state == "open"]
        if h.status != "up" or not open_svcs:
            continue
        lines.append(f"### {h.address}" + (f" ({h.hostname})" if h.hostname else ""))
        for s in sorted(open_svcs, key=lambda x: (x.protocol, x.port)):
            name = s.name or "unknown"
            ver = " ".join([x for x in [s.product, s.version, s.extrainfo] if x])
            ver = f" — {ver}" if ver else ""
            lines.append(f"- `{s.protocol}/{s.port}` **{name}**{ver}")
        lines.append("")

    return "\n".join(lines)


def flatten_findings_for_csv(findings: list[Finding]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for f in findings:
        rows.append(
            {
                "host": f.host,
                "severity": f.severity,
                "title": f.title,
                "detail": f.detail,
                "recommendation": f.recommendation,
                "protocol": f.protocol or "",
                "port": f.port or "",
            }
        )
    return rows
