from __future__ import annotations

from pathlib import Path
from net_audit_report.nmap_parser import parse_nmap_xml, extract_cves_from_scripts


SAMPLE_XML = Path(__file__).parent.parent / "samples" / "sample_nmap.xml"


def test_parse_sample():
    hosts = parse_nmap_xml(str(SAMPLE_XML))
    up_hosts = [h for h in hosts if h.status == "up"]
    assert len(up_hosts) == 4
    assert hosts[0].address == "192.168.1.10"
    assert hosts[0].hostname == "example-host"
    assert hosts[0].status == "up"


def test_services_parsed():
    hosts = parse_nmap_xml(str(SAMPLE_XML))
    svcs = hosts[0].services
    assert len(svcs) == 3  # ssh, http, https
    ports = {s.port for s in svcs}
    assert ports == {22, 80, 443}


def test_service_details():
    hosts = parse_nmap_xml(str(SAMPLE_XML))
    ssh = next(s for s in hosts[0].services if s.port == 22)
    assert ssh.name == "ssh"
    assert ssh.product == "OpenSSH"
    assert ssh.version == "8.9"
    assert ssh.state == "open"
    assert ssh.protocol == "tcp"


def test_mac_address_parsed():
    hosts = parse_nmap_xml(str(SAMPLE_XML))
    assert hosts[0].mac_address == "AA:BB:CC:DD:EE:01"
    assert hosts[0].mac_vendor == "Dell"


def test_os_detection_parsed():
    hosts = parse_nmap_xml(str(SAMPLE_XML))
    assert len(hosts[0].os_matches) == 1
    assert "Linux 5.4" in hosts[0].os_matches[0].name
    assert hosts[0].os_matches[0].accuracy == 95
    assert hosts[0].os_matches[0].os_family == "Linux"


def test_cpe_parsed():
    hosts = parse_nmap_xml(str(SAMPLE_XML))
    ssh = next(s for s in hosts[0].services if s.port == 22)
    assert len(ssh.cpe) == 1
    assert "openssh" in ssh.cpe[0]


def test_nse_scripts_parsed():
    hosts = parse_nmap_xml(str(SAMPLE_XML))
    https_svc = next(s for s in hosts[0].services if s.port == 443)
    assert len(https_svc.scripts) == 2
    script_ids = {s.script_id for s in https_svc.scripts}
    assert "ssl-enum-ciphers" in script_ids
    assert "ssl-cert" in script_ids


def test_ssl_cert_elements():
    hosts = parse_nmap_xml(str(SAMPLE_XML))
    https_svc = next(s for s in hosts[0].services if s.port == 443)
    cert_script = next(s for s in https_svc.scripts if s.script_id == "ssl-cert")
    assert cert_script.elements.get("subject.commonName") == "example-host"
    assert cert_script.elements.get("issuer.commonName") == "Example CA"


def test_host_scripts_parsed():
    hosts = parse_nmap_xml(str(SAMPLE_XML))
    legacy = next(h for h in hosts if h.address == "192.168.1.30")
    assert len(legacy.host_scripts) >= 1
    assert legacy.host_scripts[0].script_id == "smb-vuln-ms17-010"


def test_extract_cves_from_scripts():
    hosts = parse_nmap_xml(str(SAMPLE_XML))
    legacy = next(h for h in hosts if h.address == "192.168.1.30")
    cves = extract_cves_from_scripts(legacy.host_scripts)
    assert "CVE-2017-0143" in cves
    assert "CVE-2017-0144" in cves


def test_down_host_parsed():
    hosts = parse_nmap_xml(str(SAMPLE_XML))
    down = next(h for h in hosts if h.address == "192.168.1.99")
    assert down.status == "down"


def test_uptime_parsed():
    hosts = parse_nmap_xml(str(SAMPLE_XML))
    assert hosts[0].uptime_seconds == 864000
