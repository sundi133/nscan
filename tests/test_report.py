from __future__ import annotations

from net_audit_report.nmap_parser import Host, Service
from net_audit_report.findings import Finding, generate_findings
from net_audit_report.report import build_report, render_markdown, flatten_findings_for_csv


def _sample_hosts() -> list[Host]:
    return [
        Host(
            address="192.168.1.10",
            hostname="web-server",
            status="up",
            services=[
                Service(port=22, protocol="tcp", state="open", name="ssh", product="OpenSSH", version="8.9"),
                Service(port=80, protocol="tcp", state="open", name="http", product="nginx", version="1.24.0"),
            ],
        )
    ]


def test_build_report():
    hosts = _sample_hosts()
    findings = generate_findings(hosts)
    report = build_report(hosts, findings)
    assert report.host_count == 1
    assert report.up_hosts == 1
    assert report.open_service_count == 2
    assert len(report.findings) > 0


def test_render_markdown():
    hosts = _sample_hosts()
    findings = generate_findings(hosts)
    report = build_report(hosts, findings)
    md = render_markdown(report)
    assert "# Network Audit Report" in md
    assert "192.168.1.10" in md
    assert "## Findings Summary" in md


def test_flatten_findings_for_csv():
    findings = [
        Finding(
            host="10.0.0.1",
            severity="high",
            title="Test",
            detail="detail",
            recommendation="rec",
            port=22,
            protocol="tcp",
        )
    ]
    rows = flatten_findings_for_csv(findings)
    assert len(rows) == 1
    assert rows[0]["host"] == "10.0.0.1"
    assert rows[0]["severity"] == "high"
