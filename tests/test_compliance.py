from __future__ import annotations

from net_audit_report.nmap_parser import Host, Service
from net_audit_report.compliance import check_compliance


def _make_host(services: list[Service], os_name: str | None = None) -> Host:
    from net_audit_report.nmap_parser import OSMatch
    os_matches = []
    if os_name:
        os_matches = [OSMatch(name=os_name, accuracy=90)]
    return Host(
        address="10.0.0.1",
        hostname=None,
        status="up",
        services=services,
        os_matches=os_matches,
    )


def test_management_exposure():
    host = _make_host([
        Service(port=22, protocol="tcp", state="open", name="ssh"),
        Service(port=3389, protocol="tcp", state="open", name="ms-wbt-server"),
    ])
    findings = check_compliance([host])
    titles = [f.title for f in findings]
    assert any("Management service exposed" in t and "SSH" in t for t in titles)
    assert any("Management service exposed" in t and "RDP" in t for t in titles)


def test_database_exposure():
    host = _make_host([
        Service(port=3306, protocol="tcp", state="open", name="mysql"),
        Service(port=27017, protocol="tcp", state="open", name="mongodb"),
    ])
    findings = check_compliance([host])
    titles = [f.title for f in findings]
    assert any("Database exposed" in t and "MySQL" in t for t in titles)
    assert any("Database exposed" in t and "MongoDB" in t for t in titles)
    # Database findings should be critical
    db_findings = [f for f in findings if "Database exposed" in f.title]
    assert all(f.severity == "critical" for f in db_findings)


def test_unencrypted_service():
    host = _make_host([
        Service(port=21, protocol="tcp", state="open", name="ftp"),
        Service(port=23, protocol="tcp", state="open", name="telnet"),
    ])
    findings = check_compliance([host])
    titles = [f.title for f in findings]
    assert any("Unencrypted service: FTP" in t for t in titles)
    assert any("Unencrypted service: Telnet" in t for t in titles)


def test_http_with_https_no_critical():
    host = _make_host([
        Service(port=80, protocol="tcp", state="open", name="http"),
        Service(port=443, protocol="tcp", state="open", name="https", tunnel="ssl"),
    ])
    findings = check_compliance([host])
    http_findings = [f for f in findings if f.port == 80 and "Unencrypted" in f.title]
    # Should be medium (not high) since HTTPS is also available
    for f in http_findings:
        assert f.severity == "medium"


def test_default_cred_risk():
    host = _make_host([
        Service(port=6379, protocol="tcp", state="open", name="redis"),
        Service(port=11211, protocol="tcp", state="open", name="memcached"),
    ])
    findings = check_compliance([host])
    titles = [f.title for f in findings]
    assert any("Default credentials risk" in t and "redis" in t for t in titles)
    assert any("Default credentials risk" in t and "memcached" in t for t in titles)


def test_eol_os_detected():
    host = _make_host(
        [Service(port=22, protocol="tcp", state="open", name="ssh")],
        os_name="Windows Server 2008 R2",
    )
    findings = check_compliance([host])
    titles = [f.title for f in findings]
    assert any("End-of-life OS" in t for t in titles)


def test_eol_os_ubuntu():
    host = _make_host(
        [Service(port=22, protocol="tcp", state="open", name="ssh")],
        os_name="Ubuntu 14.04",
    )
    findings = check_compliance([host])
    eol = [f for f in findings if "End-of-life OS" in f.title]
    assert len(eol) >= 1
    assert eol[0].severity == "critical"


def test_excessive_ports():
    services = [
        Service(port=1000 + i, protocol="tcp", state="open", name=f"svc{i}")
        for i in range(25)
    ]
    host = _make_host(services)
    findings = check_compliance([host])
    assert any("Excessive open ports" in f.title for f in findings)


def test_snmp_exposed():
    host = _make_host([
        Service(port=161, protocol="udp", state="open", name="snmp"),
    ])
    findings = check_compliance([host])
    titles = [f.title for f in findings]
    assert any("SNMP" in t for t in titles)


def test_ipmi_exposed():
    host = _make_host([
        Service(port=623, protocol="udp", state="open", name="ipmi"),
    ])
    findings = check_compliance([host])
    titles = [f.title for f in findings]
    assert any("IPMI" in t for t in titles)
    ipmi_finding = next(f for f in findings if "IPMI" in f.title)
    assert ipmi_finding.severity == "critical"


def test_down_host_no_compliance():
    host = Host(
        address="10.0.0.2",
        hostname=None,
        status="down",
        services=[Service(port=3306, protocol="tcp", state="open", name="mysql")],
    )
    findings = check_compliance([host])
    assert len(findings) == 0
