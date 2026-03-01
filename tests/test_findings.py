from __future__ import annotations

from net_audit_report.nmap_parser import Host, Service
from net_audit_report.findings import generate_findings


def _make_host(port: int, name: str | None = None, state: str = "open",
               product: str | None = None) -> Host:
    return Host(
        address="10.0.0.1",
        hostname=None,
        status="up",
        services=[Service(port=port, protocol="tcp", state=state,
                          name=name, product=product)],
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


def test_suspicious_port():
    host = _make_host(4444, "unknown")
    findings = generate_findings([host])
    titles = [f.title for f in findings]
    assert any("Suspicious port" in t or "Metasploit" in t for t in titles)


def test_finding_has_category():
    host = _make_host(3389, "ms-wbt-server")
    findings = generate_findings([host])
    rdp_finding = next(f for f in findings if f.title == "RDP exposed")
    assert rdp_finding.category == "port"


def test_multiple_risky_ports():
    host = Host(
        address="10.0.0.1",
        hostname=None,
        status="up",
        services=[
            Service(port=21, protocol="tcp", state="open", name="ftp"),
            Service(port=23, protocol="tcp", state="open", name="telnet"),
            Service(port=3389, protocol="tcp", state="open", name="ms-wbt-server"),
        ],
    )
    findings = generate_findings([host])
    titles = [f.title for f in findings]
    assert "FTP exposed" in titles
    assert "Telnet exposed" in titles
    assert "RDP exposed" in titles


def test_version_banner_finding():
    host = _make_host(8080, "http", product="nginx")
    findings = generate_findings([host])
    titles = [f.title for f in findings]
    assert "Service version/banner identified" in titles
