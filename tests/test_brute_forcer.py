"""Tests for credential brute-force module."""
from __future__ import annotations

from net_audit_report.nmap_parser import Host, Service
from net_audit_report.brute_forcer import (
    _derive_brute_targets,
    _analyze_credential_hits,
    DEFAULT_CREDS,
    CredentialHit,
)


def _sample_hosts() -> list[Host]:
    return [
        Host(
            address="10.0.0.1",
            hostname="db-server",
            status="up",
            services=[
                Service(port=22, protocol="tcp", state="open", name="ssh"),
                Service(port=3306, protocol="tcp", state="open", name="mysql"),
                Service(port=6379, protocol="tcp", state="open", name="redis"),
                Service(port=80, protocol="tcp", state="open", name="http"),
            ],
        ),
        Host(address="10.0.0.2", hostname=None, status="down", services=[]),
    ]


def test_derive_brute_targets():
    hosts = _sample_hosts()
    targets = _derive_brute_targets(hosts)
    # Should include ssh, mysql, redis, http
    svc_keys = [t[3] for t in targets]
    assert "ssh" in svc_keys
    assert "mysql" in svc_keys
    assert "redis" in svc_keys
    assert "http" in svc_keys


def test_derive_brute_targets_skips_down():
    hosts = [Host(address="10.0.0.2", hostname=None, status="down",
                  services=[Service(port=22, protocol="tcp", state="open", name="ssh")])]
    targets = _derive_brute_targets(hosts)
    assert targets == []


def test_derive_brute_targets_skips_unknown():
    hosts = [Host(
        address="10.0.0.1", hostname=None, status="up",
        services=[Service(port=9999, protocol="tcp", state="open", name="unknown-svc")],
    )]
    targets = _derive_brute_targets(hosts)
    assert targets == []


def test_default_creds_not_empty():
    assert len(DEFAULT_CREDS) >= 10
    for svc, creds in DEFAULT_CREDS.items():
        assert len(creds) > 0, f"No default creds for {svc}"


def test_analyze_credential_hits_no_auth():
    hits = [CredentialHit(
        host="10.0.0.1", port=6379, protocol="tcp",
        service="redis", username="", password="",
        source="hydra",
    )]
    findings = _analyze_credential_hits(hits)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert "No authentication" in findings[0].title


def test_analyze_credential_hits_anonymous():
    hits = [CredentialHit(
        host="10.0.0.1", port=21, protocol="tcp",
        service="ftp", username="anonymous", password="",
        source="hydra",
    )]
    findings = _analyze_credential_hits(hits)
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "Anonymous" in findings[0].title or "guest" in findings[0].title.lower()


def test_analyze_credential_hits_default_creds():
    hits = [CredentialHit(
        host="10.0.0.1", port=22, protocol="tcp",
        service="ssh", username="root", password="toor",
        source="hydra",
    )]
    findings = _analyze_credential_hits(hits)
    assert len(findings) == 1
    assert findings[0].severity == "critical"
    assert "Default credentials" in findings[0].title


def test_analyze_credential_hits_password_masked():
    """Passwords should be masked in findings detail."""
    hits = [CredentialHit(
        host="10.0.0.1", port=22, protocol="tcp",
        service="ssh", username="admin", password="secretpass",
        source="hydra",
    )]
    findings = _analyze_credential_hits(hits)
    assert len(findings) == 1
    # Full password should NOT appear
    assert "secretpass" not in findings[0].detail
    # Masked version should appear
    assert "s********s" in findings[0].detail or "s" in findings[0].detail


def test_analyze_credential_hits_empty():
    findings = _analyze_credential_hits([])
    assert findings == []
