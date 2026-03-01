from __future__ import annotations

from net_audit_report.nmap_parser import Host, Service
from net_audit_report.findings import Finding, generate_findings
from net_audit_report.vulns import VulnMatch
from net_audit_report.report import build_report, render_markdown, render_html, flatten_findings_for_csv


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


def test_build_report_with_vulns():
    hosts = _sample_hosts()
    findings = generate_findings(hosts)
    vulns = [VulnMatch(
        host="192.168.1.10", port=22, protocol="tcp",
        product="OpenSSH", version="8.9",
        vuln_id="NAR-005", severity="medium",
        title="OpenSSH moderately outdated",
        description="OpenSSH 8.0-8.8 should be updated.",
        recommendation="Upgrade to 9.x+.",
        cves=[],
    )]
    report = build_report(hosts, findings, vulns)
    # Vuln findings should be merged into total findings
    assert report.severity_counts.get("medium", 0) >= 1
    assert len(report.vuln_matches) == 1


def test_render_markdown():
    hosts = _sample_hosts()
    findings = generate_findings(hosts)
    report = build_report(hosts, findings)
    md = render_markdown(report)
    assert "# Network Audit Report" in md
    assert "192.168.1.10" in md
    assert "## Findings Summary" in md
    assert "Critical:" in md


def test_render_html():
    hosts = _sample_hosts()
    findings = generate_findings(hosts)
    report = build_report(hosts, findings)
    html = render_html(report)
    assert "<!DOCTYPE html>" in html
    assert "Network Audit Report" in html
    assert "192.168.1.10" in html
    assert "filterFindings" in html  # JavaScript filter
    assert "dashboard" in html


def test_render_html_with_vulns():
    hosts = _sample_hosts()
    findings = generate_findings(hosts)
    vulns = [VulnMatch(
        host="192.168.1.10", port=22, protocol="tcp",
        product="OpenSSH", version="8.9",
        vuln_id="NAR-005", severity="medium",
        title="OpenSSH outdated",
        description="OpenSSH 8.9 should be updated.",
        recommendation="Upgrade.",
        cves=["CVE-2024-6387"],
    )]
    report = build_report(hosts, findings, vulns)
    html = render_html(report)
    assert "NAR-005" in html
    assert "CVE-2024-6387" in html


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
            category="port",
            cves=["CVE-2024-1234"],
            vuln_id="NAR-001",
        )
    ]
    rows = flatten_findings_for_csv(findings)
    assert len(rows) == 1
    assert rows[0]["host"] == "10.0.0.1"
    assert rows[0]["severity"] == "high"
    assert rows[0]["category"] == "port"
    assert "CVE-2024-1234" in rows[0]["cves"]
    assert rows[0]["vuln_id"] == "NAR-001"


def test_severity_counts():
    hosts = _sample_hosts()
    findings = [
        Finding(host="10.0.0.1", severity="critical", title="A", detail="d", recommendation="r"),
        Finding(host="10.0.0.1", severity="high", title="B", detail="d", recommendation="r"),
        Finding(host="10.0.0.1", severity="high", title="C", detail="d", recommendation="r"),
        Finding(host="10.0.0.1", severity="low", title="D", detail="d", recommendation="r"),
    ]
    report = build_report(hosts, findings)
    assert report.severity_counts["critical"] == 1
    assert report.severity_counts["high"] == 2
    assert report.severity_counts["low"] == 1
