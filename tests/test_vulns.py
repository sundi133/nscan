from __future__ import annotations

from pathlib import Path
from net_audit_report.nmap_parser import Host, Service, ScriptResult, parse_nmap_xml
from net_audit_report.vulns import match_known_vulns, extract_nse_vulns


SAMPLE_XML = Path(__file__).parent.parent / "samples" / "sample_nmap.xml"


def test_match_apache_path_traversal():
    host = Host(
        address="10.0.0.1",
        hostname=None,
        status="up",
        services=[
            Service(port=443, protocol="tcp", state="open",
                    name="https", product="Apache httpd", version="2.4.49"),
        ],
    )
    matches = match_known_vulns([host])
    assert len(matches) >= 1
    vuln_ids = [m.vuln_id for m in matches]
    assert "NAR-001" in vuln_ids
    apache_match = next(m for m in matches if m.vuln_id == "NAR-001")
    assert "CVE-2021-41773" in apache_match.cves


def test_match_openssh_outdated():
    host = Host(
        address="10.0.0.2",
        hostname=None,
        status="up",
        services=[
            Service(port=22, protocol="tcp", state="open",
                    name="ssh", product="OpenSSH", version="7.2"),
        ],
    )
    matches = match_known_vulns([host])
    assert len(matches) >= 1
    assert any("OpenSSH" in m.title for m in matches)


def test_match_mysql_eol():
    host = Host(
        address="10.0.0.3",
        hostname=None,
        status="up",
        services=[
            Service(port=3306, protocol="tcp", state="open",
                    name="mysql", product="MySQL", version="5.5.62"),
        ],
    )
    matches = match_known_vulns([host])
    assert len(matches) >= 1
    assert any("MySQL" in m.title for m in matches)


def test_match_redis_outdated():
    host = Host(
        address="10.0.0.4",
        hostname=None,
        status="up",
        services=[
            Service(port=6379, protocol="tcp", state="open",
                    name="redis", product="Redis", version="4.0.9"),
        ],
    )
    matches = match_known_vulns([host])
    assert len(matches) >= 1
    assert any("Redis" in m.title for m in matches)


def test_match_samba_critical():
    host = Host(
        address="10.0.0.5",
        hostname=None,
        status="up",
        services=[
            Service(port=445, protocol="tcp", state="open",
                    name="microsoft-ds", product="Samba", version="3.6.25"),
        ],
    )
    matches = match_known_vulns([host])
    assert len(matches) >= 1
    samba_match = next(m for m in matches if "Samba" in m.title)
    assert samba_match.severity == "critical"


def test_no_match_current_version():
    host = Host(
        address="10.0.0.6",
        hostname=None,
        status="up",
        services=[
            Service(port=22, protocol="tcp", state="open",
                    name="ssh", product="OpenSSH", version="9.9"),
        ],
    )
    matches = match_known_vulns([host])
    assert len(matches) == 0


def test_extract_nse_vulns_eternalblue():
    hosts = parse_nmap_xml(str(SAMPLE_XML))
    nse_matches = extract_nse_vulns(hosts)
    assert len(nse_matches) >= 1
    # Should find EternalBlue from the SMB vuln script
    assert any("ms17-010" in m.vuln_id.lower() or "ms17-010" in m.title.lower()
               for m in nse_matches)


def test_extract_nse_vulns_has_cves():
    hosts = parse_nmap_xml(str(SAMPLE_XML))
    nse_matches = extract_nse_vulns(hosts)
    eternalblue = [m for m in nse_matches if "ms17-010" in m.vuln_id.lower()]
    assert len(eternalblue) >= 1
    # Should have extracted CVEs from the script output
    all_cves = []
    for m in eternalblue:
        all_cves.extend(m.cves)
    assert "CVE-2017-0143" in all_cves


def test_match_from_sample_xml():
    """Full integration: parse sample XML and find known vulns."""
    hosts = parse_nmap_xml(str(SAMPLE_XML))
    matches = match_known_vulns(hosts)
    # Should find: Apache 2.4.49, OpenSSH 7.2, MySQL 5.5, Redis 4.x,
    # Samba 3.x, IIS 7.5, OpenSSH 8.9, Tomcat 7.x, OpenSSH 9.7
    assert len(matches) >= 5
    products = {m.product for m in matches}
    assert "Apache httpd" in products
    assert "MySQL" in products
    assert "Samba" in products
