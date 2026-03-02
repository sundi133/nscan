"""Tests for the Nuclei scanner integration."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from net_audit_report.nmap_parser import Host, Service
from net_audit_report.nuclei_scanner import (
    _derive_targets_from_hosts,
    _parse_nuclei_jsonl,
    build_nuclei_command,
    NucleiConfig,
)


def _sample_hosts() -> list[Host]:
    return [
        Host(
            address="192.168.1.10",
            hostname="web-server",
            status="up",
            services=[
                Service(port=22, protocol="tcp", state="open", name="ssh",
                        product="OpenSSH", version="8.9"),
                Service(port=80, protocol="tcp", state="open", name="http",
                        product="nginx", version="1.24.0"),
                Service(port=443, protocol="tcp", state="open", name="https",
                        product="nginx", version="1.24.0", tunnel="ssl"),
                Service(port=3306, protocol="tcp", state="open", name="mysql",
                        product="MySQL", version="8.0"),
            ],
        ),
        Host(
            address="192.168.1.20",
            hostname=None,
            status="down",
            services=[],
        ),
    ]


def test_derive_targets_from_hosts():
    hosts = _sample_hosts()
    targets = _derive_targets_from_hosts(hosts)

    # Should include HTTP/HTTPS URLs and bare host
    assert "http://web-server:80" in targets
    assert "https://web-server:443" in targets
    assert "web-server" in targets
    # MySQL is non-HTTP
    assert "web-server:3306" in targets
    # SSH is non-HTTP
    assert "web-server:22" in targets
    # Down host should not be included
    assert "192.168.1.20" not in targets


def test_derive_targets_uses_hostname():
    hosts = [
        Host(
            address="10.0.0.1",
            hostname="myhost.example.com",
            status="up",
            services=[
                Service(port=80, protocol="tcp", state="open", name="http"),
            ],
        ),
    ]
    targets = _derive_targets_from_hosts(hosts)
    assert "http://myhost.example.com:80" in targets
    assert "myhost.example.com" in targets


def test_derive_targets_falls_back_to_ip():
    hosts = [
        Host(
            address="10.0.0.1",
            hostname=None,
            status="up",
            services=[
                Service(port=443, protocol="tcp", state="open", name="https", tunnel="ssl"),
            ],
        ),
    ]
    targets = _derive_targets_from_hosts(hosts)
    assert "https://10.0.0.1:443" in targets


def test_derive_targets_empty_hosts():
    targets = _derive_targets_from_hosts([])
    assert targets == []


def test_parse_nuclei_jsonl():
    """Test parsing Nuclei JSONL output."""
    items = [
        {
            "template-id": "tech-detect",
            "info": {
                "name": "Nginx Version Detected",
                "severity": "info",
                "description": "Nginx version was detected.",
                "tags": ["tech"],
            },
            "host": "http://192.168.1.10:80",
            "matched-at": "http://192.168.1.10:80",
            "port": 80,
        },
        {
            "template-id": "CVE-2021-41773",
            "info": {
                "name": "Apache Path Traversal",
                "severity": "critical",
                "description": "Apache HTTP Server path traversal.",
                "remediation": "Upgrade Apache to 2.4.51 or later.",
                "tags": ["cve", "apache"],
                "classification": {
                    "cve-id": ["CVE-2021-41773"],
                },
                "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
            },
            "host": "http://192.168.1.10:80",
            "matched-at": "http://192.168.1.10:80/icons/.%2e/etc/passwd",
            "port": 80,
        },
        {
            "template-id": "exposed-panels:grafana-login",
            "info": {
                "name": "Grafana Login Panel",
                "severity": "medium",
                "description": "Grafana login panel was detected.",
                "tags": ["panel", "grafana"],
            },
            "host": "http://192.168.1.10:3000",
            "matched-at": "http://192.168.1.10:3000/login",
        },
    ]

    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        for item in items:
            f.write(json.dumps(item) + "\n")
        tmp_path = f.name

    try:
        findings = _parse_nuclei_jsonl(tmp_path)
        assert len(findings) == 3

        # First: info severity
        assert findings[0].severity == "info"
        assert "[Nuclei]" in findings[0].title
        assert findings[0].port == 80

        # Second: critical with CVE
        crit = findings[1]
        assert crit.severity == "critical"
        assert "CVE-2021-41773" in crit.cves
        assert crit.category == "vuln"
        assert crit.vuln_id == "CVE-2021-41773"
        assert "Upgrade Apache" in crit.recommendation

        # Third: medium with panel tag
        panel = findings[2]
        assert panel.severity == "medium"
        assert "Grafana" in panel.title
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_parse_nuclei_jsonl_empty():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        tmp_path = f.name

    try:
        findings = _parse_nuclei_jsonl(tmp_path)
        assert findings == []
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_parse_nuclei_jsonl_malformed():
    """Malformed lines should be skipped without error."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write("not valid json\n")
        f.write('{"template-id": "test", "info": {"name": "Test", "severity": "low"}, "host": "1.2.3.4"}\n')
        f.write("\n")
        tmp_path = f.name

    try:
        findings = _parse_nuclei_jsonl(tmp_path)
        assert len(findings) == 1
        assert findings[0].severity == "low"
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_parse_nuclei_cve_string():
    """CVE as a string instead of list should be handled."""
    item = {
        "template-id": "CVE-2024-1234",
        "info": {
            "name": "Test CVE",
            "severity": "high",
            "classification": {"cve-id": "CVE-2024-1234"},
        },
        "host": "10.0.0.1",
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        f.write(json.dumps(item) + "\n")
        tmp_path = f.name

    try:
        findings = _parse_nuclei_jsonl(tmp_path)
        assert len(findings) == 1
        assert findings[0].cves == ["CVE-2024-1234"]
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_build_nuclei_command():
    config = NucleiConfig(
        targets=["http://example.com"],
        severity="critical,high",
        tags="cve",
        rate_limit=100,
        concurrency=10,
    )
    cmd = build_nuclei_command(config, "/tmp/out.jsonl", "/tmp/targets.txt")

    assert "nuclei" in cmd
    assert "-l" in cmd
    assert "/tmp/targets.txt" in cmd
    assert "-o" in cmd
    assert "/tmp/out.jsonl" in cmd
    assert "-severity" in cmd
    idx = cmd.index("-severity")
    assert cmd[idx + 1] == "critical,high"
    assert "-tags" in cmd
    assert "-rate-limit" in cmd


def test_build_nuclei_command_minimal():
    config = NucleiConfig(targets=["http://example.com"])
    cmd = build_nuclei_command(config, "/tmp/out.jsonl", "/tmp/targets.txt")

    assert "nuclei" in cmd
    assert "-tags" not in cmd
    assert "-exclude-tags" not in cmd
    assert "-t" not in cmd  # no custom templates
