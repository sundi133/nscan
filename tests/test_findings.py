from __future__ import annotations

from net_audit_report.nmap_parser import Host, Service
from net_audit_report.findings import generate_findings


def _make_host(port: int, name: str | None = None, state: str = "open") -> Host:
    return Host(
        address="10.0.0.1",
        hostname=None,
        status="up",
        services=[Service(port=port, protocol="tcp", state=state, name=name)],
    )


def test_risky_port_finding():
    host = _make_host(3389, "ms-wbt-server")
    findings = generate_findings([host])
    titles = [f.title for f in findings]
    assert "RDP exposed" in titles


def test_insecure_service_finding():
    host = _make_host(8080, "http")
    findings = generate_findings([host])
    titles = [f.title for f in findings]
    assert "HTTP service detected" in titles


def test_closed_port_no_finding():
    host = _make_host(23, "telnet", state="closed")
    findings = generate_findings([host])
    assert len(findings) == 0


def test_down_host_no_finding():
    host = Host(
        address="10.0.0.2",
        hostname=None,
        status="down",
        services=[Service(port=21, protocol="tcp", state="open", name="ftp")],
    )
    findings = generate_findings([host])
    assert len(findings) == 0
