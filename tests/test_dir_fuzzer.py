"""Tests for directory fuzzing module."""
from __future__ import annotations

from net_audit_report.nmap_parser import Host, Service
from net_audit_report.dir_fuzzer import (
    _derive_web_targets,
    _analyze_fuzz_hits,
    _BUILTIN_PATHS,
    FuzzHit,
)


def _sample_hosts() -> list[Host]:
    return [
        Host(
            address="10.0.0.1",
            hostname="web.example.com",
            status="up",
            services=[
                Service(port=80, protocol="tcp", state="open", name="http"),
                Service(port=443, protocol="tcp", state="open", name="https", tunnel="ssl"),
                Service(port=22, protocol="tcp", state="open", name="ssh"),
                Service(port=3306, protocol="tcp", state="open", name="mysql"),
            ],
        ),
        Host(address="10.0.0.2", hostname=None, status="down", services=[]),
    ]


def test_derive_web_targets():
    hosts = _sample_hosts()
    targets = _derive_web_targets(hosts)
    assert "http://web.example.com:80" in targets
    assert "https://web.example.com:443" in targets
    # SSH/MySQL should NOT be in web targets
    assert not any(":22" in t for t in targets)
    assert not any(":3306" in t for t in targets)
    # Down host should not appear
    assert not any("10.0.0.2" in t for t in targets)


def test_derive_web_targets_common_ports():
    hosts = [Host(
        address="10.0.0.5", hostname=None, status="up",
        services=[
            Service(port=8080, protocol="tcp", state="open", name="http-proxy"),
            Service(port=8443, protocol="tcp", state="open", name="unknown"),
        ],
    )]
    targets = _derive_web_targets(hosts)
    assert "http://10.0.0.5:8080" in targets
    assert "https://10.0.0.5:8443" in targets


def test_builtin_paths_not_empty():
    assert len(_BUILTIN_PATHS) > 50


def test_analyze_fuzz_hits_sensitive_file():
    hits = [
        FuzzHit(url="http://example.com/.env", status_code=200,
                content_length=512, words=30, lines=10),
    ]
    findings = _analyze_fuzz_hits("http://example.com", hits)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "Sensitive file" in findings[0].title


def test_analyze_fuzz_hits_admin_panel():
    hits = [
        FuzzHit(url="http://example.com/admin", status_code=200,
                content_length=4096, words=200, lines=50),
    ]
    findings = _analyze_fuzz_hits("http://example.com", hits)
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert "Admin panel" in findings[0].title


def test_analyze_fuzz_hits_debug_endpoint():
    hits = [
        FuzzHit(url="http://example.com/phpinfo.php", status_code=200,
                content_length=80000, words=5000, lines=800),
    ]
    findings = _analyze_fuzz_hits("http://example.com", hits)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "Debug" in findings[0].title or "info" in findings[0].title.lower()


def test_analyze_fuzz_hits_api_docs():
    hits = [
        FuzzHit(url="http://example.com/swagger", status_code=200,
                content_length=1024, words=100, lines=20),
    ]
    findings = _analyze_fuzz_hits("http://example.com", hits)
    assert len(findings) == 1
    assert "API documentation" in findings[0].title


def test_analyze_fuzz_hits_backup():
    hits = [
        FuzzHit(url="http://example.com/backup.sql", status_code=200,
                content_length=500000, words=10000, lines=5000),
    ]
    findings = _analyze_fuzz_hits("http://example.com", hits)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "Backup" in findings[0].title or "dump" in findings[0].title.lower()


def test_analyze_fuzz_hits_403():
    hits = [
        FuzzHit(url="http://example.com/secret", status_code=403,
                content_length=200, words=20, lines=5),
    ]
    findings = _analyze_fuzz_hits("http://example.com", hits)
    assert len(findings) == 1
    assert findings[0].severity == "info"
    assert "Restricted" in findings[0].title


def test_analyze_fuzz_hits_redirect():
    hits = [
        FuzzHit(url="http://example.com/old", status_code=301,
                content_length=0, redirect_location="https://example.com/new"),
    ]
    findings = _analyze_fuzz_hits("http://example.com", hits)
    assert len(findings) == 1
    assert "https://example.com/new" in findings[0].detail


def test_analyze_fuzz_hits_empty():
    findings = _analyze_fuzz_hits("http://example.com", [])
    assert findings == []
