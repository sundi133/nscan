"""
Scan diff/comparison module.

Compares two Nmap XML scans to identify:
- New hosts that appeared
- Hosts that disappeared
- New ports/services that opened
- Ports/services that closed
- Version changes on existing services

Useful for tracking network changes over time and detecting drift.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .nmap_parser import Host, Service


@dataclass(frozen=True)
class DiffEntry:
    change_type: str  # "new_host", "removed_host", "new_port", "closed_port", "version_change", "state_change"
    severity: str  # "critical", "high", "medium", "low", "info"
    host: str
    detail: str
    port: Optional[int] = None
    protocol: Optional[str] = None
    old_value: Optional[str] = None
    new_value: Optional[str] = None


@dataclass
class ScanDiff:
    baseline_host_count: int
    current_host_count: int
    new_hosts: list[str]
    removed_hosts: list[str]
    entries: list[DiffEntry]
    summary: dict[str, int] = field(default_factory=dict)


def compare_scans(baseline: list[Host], current: list[Host]) -> ScanDiff:
    """Compare two sets of parsed Nmap hosts and return differences."""
    entries: list[DiffEntry] = []

    baseline_map = {h.address: h for h in baseline if h.status == "up"}
    current_map = {h.address: h for h in current if h.status == "up"}

    baseline_addrs = set(baseline_map.keys())
    current_addrs = set(current_map.keys())

    new_hosts = sorted(current_addrs - baseline_addrs)
    removed_hosts = sorted(baseline_addrs - current_addrs)

    # New hosts
    for addr in new_hosts:
        host = current_map[addr]
        open_ports = [s for s in host.services if s.state == "open"]
        port_list = ", ".join(f"{s.protocol}/{s.port}" for s in sorted(open_ports, key=lambda x: x.port))
        entries.append(DiffEntry(
            change_type="new_host",
            severity="high",
            host=addr,
            detail=f"New host detected: {addr}"
                   + (f" ({host.hostname})" if host.hostname else "")
                   + (f" with open ports: {port_list}" if port_list else ""),
        ))

    # Removed hosts
    for addr in removed_hosts:
        entries.append(DiffEntry(
            change_type="removed_host",
            severity="info",
            host=addr,
            detail=f"Host no longer detected: {addr}",
        ))

    # Compare services on hosts present in both scans
    for addr in sorted(baseline_addrs & current_addrs):
        old_host = baseline_map[addr]
        new_host = current_map[addr]

        old_svcs = {(s.port, s.protocol): s for s in old_host.services}
        new_svcs = {(s.port, s.protocol): s for s in new_host.services}

        old_keys = set(old_svcs.keys())
        new_keys = set(new_svcs.keys())

        # New ports
        for key in sorted(new_keys - old_keys):
            svc = new_svcs[key]
            if svc.state != "open":
                continue
            entries.append(DiffEntry(
                change_type="new_port",
                severity="high",
                host=addr,
                detail=(
                    f"New open port: {svc.protocol}/{svc.port} "
                    f"({svc.name or 'unknown'}"
                    + (f" - {svc.product} {svc.version or ''}" if svc.product else "")
                    + ")"
                ),
                port=svc.port,
                protocol=svc.protocol,
                new_value=f"{svc.name or ''} {svc.product or ''} {svc.version or ''}".strip(),
            ))

        # Closed ports
        for key in sorted(old_keys - new_keys):
            svc = old_svcs[key]
            if svc.state != "open":
                continue
            entries.append(DiffEntry(
                change_type="closed_port",
                severity="info",
                host=addr,
                detail=f"Port closed: {svc.protocol}/{svc.port} ({svc.name or 'unknown'})",
                port=svc.port,
                protocol=svc.protocol,
                old_value=f"{svc.name or ''} {svc.product or ''} {svc.version or ''}".strip(),
            ))

        # Changed services
        for key in sorted(old_keys & new_keys):
            old_svc = old_svcs[key]
            new_svc = new_svcs[key]

            # State change (open -> closed or vice versa)
            if old_svc.state != new_svc.state:
                if new_svc.state == "open":
                    sev = "high"
                else:
                    sev = "info"
                entries.append(DiffEntry(
                    change_type="state_change",
                    severity=sev,
                    host=addr,
                    detail=f"Port {new_svc.protocol}/{new_svc.port} state changed: {old_svc.state} -> {new_svc.state}",
                    port=new_svc.port,
                    protocol=new_svc.protocol,
                    old_value=old_svc.state,
                    new_value=new_svc.state,
                ))

            # Version change
            old_ver = f"{old_svc.product or ''} {old_svc.version or ''}".strip()
            new_ver = f"{new_svc.product or ''} {new_svc.version or ''}".strip()
            if old_ver != new_ver and (old_ver or new_ver):
                entries.append(DiffEntry(
                    change_type="version_change",
                    severity="medium",
                    host=addr,
                    detail=(
                        f"Service version changed on {new_svc.protocol}/{new_svc.port}: "
                        f"'{old_ver or '(none)'}' -> '{new_ver or '(none)'}'"
                    ),
                    port=new_svc.port,
                    protocol=new_svc.protocol,
                    old_value=old_ver,
                    new_value=new_ver,
                ))

    # Build summary counts
    summary: dict[str, int] = {}
    for e in entries:
        summary[e.change_type] = summary.get(e.change_type, 0) + 1

    return ScanDiff(
        baseline_host_count=len(baseline_map),
        current_host_count=len(current_map),
        new_hosts=new_hosts,
        removed_hosts=removed_hosts,
        entries=entries,
        summary=summary,
    )


def render_diff_markdown(diff: ScanDiff) -> str:
    """Render scan diff as Markdown."""
    lines: list[str] = []
    lines.append("# Scan Comparison Report")
    lines.append("")
    lines.append(f"- Baseline hosts (up): **{diff.baseline_host_count}**")
    lines.append(f"- Current hosts (up): **{diff.current_host_count}**")
    lines.append(f"- New hosts: **{len(diff.new_hosts)}**")
    lines.append(f"- Removed hosts: **{len(diff.removed_hosts)}**")
    lines.append("")

    if diff.summary:
        lines.append("## Change Summary")
        for change_type, count in sorted(diff.summary.items()):
            lines.append(f"- {change_type}: **{count}**")
        lines.append("")

    if not diff.entries:
        lines.append("_No changes detected between scans._")
        return "\n".join(lines)

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_entries = sorted(diff.entries, key=lambda e: (sev_order.get(e.severity, 9), e.host, e.port or 0))

    lines.append("## Changes (sorted by severity)")
    for e in sorted_entries:
        icon = {"critical": "!!!", "high": "!!", "medium": "!", "low": "~", "info": "i"}.get(e.severity, "")
        port_str = f" `{e.protocol}/{e.port}`" if e.port else ""
        lines.append(f"- **[{e.severity.upper()}]** `{e.host}`{port_str} — {e.detail}")

    lines.append("")
    return "\n".join(lines)
