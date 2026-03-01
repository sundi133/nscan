from __future__ import annotations

from pathlib import Path
from net_audit_report.nmap_parser import Host, Service, parse_nmap_xml
from net_audit_report.diff import compare_scans, render_diff_markdown


SAMPLE_XML = Path(__file__).parent.parent / "samples" / "sample_nmap.xml"
BASELINE_XML = Path(__file__).parent.parent / "samples" / "baseline_nmap.xml"


def test_new_host_detected():
    baseline = [Host(address="10.0.0.1", hostname=None, status="up", services=[])]
    current = [
        Host(address="10.0.0.1", hostname=None, status="up", services=[]),
        Host(address="10.0.0.2", hostname=None, status="up",
             services=[Service(port=22, protocol="tcp", state="open", name="ssh")]),
    ]
    diff = compare_scans(baseline, current)
    assert "10.0.0.2" in diff.new_hosts
    assert len(diff.removed_hosts) == 0


def test_removed_host_detected():
    baseline = [
        Host(address="10.0.0.1", hostname=None, status="up", services=[]),
        Host(address="10.0.0.2", hostname=None, status="up", services=[]),
    ]
    current = [Host(address="10.0.0.1", hostname=None, status="up", services=[])]
    diff = compare_scans(baseline, current)
    assert "10.0.0.2" in diff.removed_hosts
    assert len(diff.new_hosts) == 0


def test_new_port_detected():
    baseline = [Host(
        address="10.0.0.1", hostname=None, status="up",
        services=[Service(port=22, protocol="tcp", state="open", name="ssh")],
    )]
    current = [Host(
        address="10.0.0.1", hostname=None, status="up",
        services=[
            Service(port=22, protocol="tcp", state="open", name="ssh"),
            Service(port=80, protocol="tcp", state="open", name="http"),
        ],
    )]
    diff = compare_scans(baseline, current)
    new_port_entries = [e for e in diff.entries if e.change_type == "new_port"]
    assert len(new_port_entries) == 1
    assert new_port_entries[0].port == 80


def test_closed_port_detected():
    baseline = [Host(
        address="10.0.0.1", hostname=None, status="up",
        services=[
            Service(port=22, protocol="tcp", state="open", name="ssh"),
            Service(port=80, protocol="tcp", state="open", name="http"),
        ],
    )]
    current = [Host(
        address="10.0.0.1", hostname=None, status="up",
        services=[Service(port=22, protocol="tcp", state="open", name="ssh")],
    )]
    diff = compare_scans(baseline, current)
    closed_entries = [e for e in diff.entries if e.change_type == "closed_port"]
    assert len(closed_entries) == 1
    assert closed_entries[0].port == 80


def test_version_change_detected():
    baseline = [Host(
        address="10.0.0.1", hostname=None, status="up",
        services=[Service(port=22, protocol="tcp", state="open", name="ssh",
                          product="OpenSSH", version="8.2")],
    )]
    current = [Host(
        address="10.0.0.1", hostname=None, status="up",
        services=[Service(port=22, protocol="tcp", state="open", name="ssh",
                          product="OpenSSH", version="9.0")],
    )]
    diff = compare_scans(baseline, current)
    version_entries = [e for e in diff.entries if e.change_type == "version_change"]
    assert len(version_entries) == 1
    assert version_entries[0].old_value == "OpenSSH 8.2"
    assert version_entries[0].new_value == "OpenSSH 9.0"


def test_no_changes():
    hosts = [Host(
        address="10.0.0.1", hostname=None, status="up",
        services=[Service(port=22, protocol="tcp", state="open", name="ssh")],
    )]
    diff = compare_scans(hosts, hosts)
    assert len(diff.entries) == 0
    assert len(diff.new_hosts) == 0
    assert len(diff.removed_hosts) == 0


def test_render_diff_markdown():
    baseline = [Host(address="10.0.0.1", hostname=None, status="up", services=[])]
    current = [
        Host(address="10.0.0.1", hostname=None, status="up", services=[]),
        Host(address="10.0.0.2", hostname="new-server", status="up",
             services=[Service(port=22, protocol="tcp", state="open", name="ssh")]),
    ]
    diff = compare_scans(baseline, current)
    md = render_diff_markdown(diff)
    assert "# Scan Comparison Report" in md
    assert "10.0.0.2" in md
    assert "New host" in md or "new_host" in md


def test_diff_with_sample_files():
    """Integration test comparing baseline and current sample XMLs."""
    baseline = parse_nmap_xml(str(BASELINE_XML))
    current = parse_nmap_xml(str(SAMPLE_XML))
    diff = compare_scans(baseline, current)

    # 192.168.1.50 is in baseline but not in current => removed
    assert "192.168.1.50" in diff.removed_hosts

    # 192.168.1.20, .30, .40 are in current but not baseline => new
    assert "192.168.1.20" in diff.new_hosts
    assert "192.168.1.30" in diff.new_hosts

    # 192.168.1.10 is in both — should detect version change (nginx 1.18 -> 1.24)
    version_changes = [e for e in diff.entries if e.change_type == "version_change"]
    assert len(version_changes) >= 1


def test_diff_summary():
    baseline = [Host(address="10.0.0.1", hostname=None, status="up", services=[])]
    current = [
        Host(address="10.0.0.1", hostname=None, status="up", services=[]),
        Host(address="10.0.0.2", hostname=None, status="up", services=[]),
    ]
    diff = compare_scans(baseline, current)
    assert diff.summary.get("new_host", 0) == 1
