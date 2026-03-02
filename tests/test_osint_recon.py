"""Tests for OSINT reconnaissance module."""
from __future__ import annotations

from net_audit_report.nmap_parser import Host, Service
from net_audit_report.osint_recon import (
    _derive_targets,
    _derive_web_urls,
    _analyze_whois,
    _analyze_http_headers,
    WhoisInfo,
    HttpHeaderInfo,
    _EXPECTED_HEADERS,
)


def _sample_hosts() -> list[Host]:
    return [
        Host(
            address="93.184.216.34",
            hostname="example.com",
            status="up",
            services=[
                Service(port=80, protocol="tcp", state="open", name="http"),
                Service(port=443, protocol="tcp", state="open", name="https", tunnel="ssl"),
            ],
        ),
    ]


def test_derive_targets():
    hosts = _sample_hosts()
    targets = _derive_targets(hosts)
    assert "example.com" in targets


def test_derive_targets_from_explicit():
    targets = _derive_targets([], explicit_targets=["target.com"])
    assert "target.com" in targets


def test_derive_targets_skips_ips():
    targets = _derive_targets([], explicit_targets=["192.168.1.1", "10.0.0.0/24"])
    assert len(targets) == 0


def test_derive_web_urls():
    hosts = _sample_hosts()
    urls = _derive_web_urls(hosts)
    assert "http://example.com:80" in urls
    assert "https://example.com:443" in urls


def test_analyze_whois():
    whois = WhoisInfo(
        registrar="MarkMonitor",
        creation_date="1995-08-14",
        expiry_date="2025-08-13",
        name_servers=["a.iana-servers.net", "b.iana-servers.net"],
        org="Internet Corporation for Assigned Names and Numbers",
        country="US",
    )
    findings = _analyze_whois("example.com", whois)
    assert len(findings) >= 1
    assert any("registration" in f.title.lower() for f in findings)
    assert any("name server" in f.title.lower() for f in findings)


def test_analyze_whois_empty():
    whois = WhoisInfo()
    findings = _analyze_whois("example.com", whois)
    # No expiry → no registration finding
    assert not any("registration" in f.title.lower() for f in findings)


def test_analyze_http_headers_missing_security():
    info = HttpHeaderInfo(
        url="https://example.com:443",
        status_code=200,
        headers={"content-type": "text/html"},
        missing_security_headers=list(_EXPECTED_HEADERS.keys()),
    )
    findings = _analyze_http_headers(info)
    # Should flag missing HSTS, CSP, X-Content-Type-Options, etc.
    titles = [f.title for f in findings]
    assert any("HSTS" in t for t in titles)
    assert any("Content-Security-Policy" in t for t in titles)


def test_analyze_http_headers_info_leakage():
    info = HttpHeaderInfo(
        url="https://example.com:443",
        status_code=200,
        server="Apache/2.4.49 (Ubuntu)",
        x_powered_by="PHP/7.4.3",
        headers={
            "server": "Apache/2.4.49 (Ubuntu)",
            "x-powered-by": "PHP/7.4.3",
            "content-type": "text/html",
            # Include all expected headers so we only get leak findings
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "content-security-policy": "default-src 'self'",
            "x-xss-protection": "1; mode=block",
            "referrer-policy": "strict-origin",
            "permissions-policy": "geolocation=()",
        },
        missing_security_headers=[],
    )
    findings = _analyze_http_headers(info)
    titles = [f.title for f in findings]
    assert any("server" in t.lower() for t in titles)
    assert any("x-powered-by" in t.lower() for t in titles)


def test_analyze_http_headers_insecure_cookie():
    info = HttpHeaderInfo(
        url="https://example.com:443",
        status_code=200,
        headers={
            "set-cookie": "session=abc123; Path=/",
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "content-security-policy": "default-src 'self'",
            "x-xss-protection": "1",
            "referrer-policy": "strict-origin",
            "permissions-policy": "geolocation=()",
        },
        missing_security_headers=[],
    )
    findings = _analyze_http_headers(info)
    titles = [f.title for f in findings]
    assert any("Secure" in t for t in titles)
    assert any("HttpOnly" in t for t in titles)


def test_analyze_http_headers_hsts_not_flagged_for_http():
    """HSTS should not be flagged for plain HTTP URLs."""
    info = HttpHeaderInfo(
        url="http://example.com:80",
        status_code=200,
        headers={},
        missing_security_headers=["strict-transport-security"],
    )
    findings = _analyze_http_headers(info)
    titles = [f.title for f in findings]
    assert not any("HSTS" in t for t in titles)


def test_analyze_http_headers_empty():
    info = HttpHeaderInfo(
        url="https://example.com:443",
        status_code=200,
        headers={
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "content-security-policy": "default-src 'self'",
            "x-xss-protection": "1; mode=block",
            "referrer-policy": "strict-origin",
            "permissions-policy": "geolocation=()",
        },
        missing_security_headers=[],
    )
    findings = _analyze_http_headers(info)
    # No leakage headers, all security headers present, no cookies
    assert len(findings) == 0
