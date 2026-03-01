from __future__ import annotations

from pathlib import Path
from net_audit_report.nmap_parser import parse_nmap_xml


SAMPLE_XML = Path(__file__).parent.parent / "samples" / "sample_nmap.xml"


def test_parse_sample():
    hosts = parse_nmap_xml(str(SAMPLE_XML))
    assert len(hosts) >= 1
    assert hosts[0].address == "192.168.1.10"
    assert hosts[0].hostname == "example-host"
    assert hosts[0].status == "up"


def test_services_parsed():
    hosts = parse_nmap_xml(str(SAMPLE_XML))
    svcs = hosts[0].services
    assert len(svcs) == 2
    ports = {s.port for s in svcs}
    assert ports == {22, 80}


def test_service_details():
    hosts = parse_nmap_xml(str(SAMPLE_XML))
    ssh = next(s for s in hosts[0].services if s.port == 22)
    assert ssh.name == "ssh"
    assert ssh.product == "OpenSSH"
    assert ssh.version == "8.9"
    assert ssh.state == "open"
    assert ssh.protocol == "tcp"
