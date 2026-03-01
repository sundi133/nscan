from __future__ import annotations

from net_audit_report.nmap_parser import Host, Service, ScriptResult
from net_audit_report.ssl_analyzer import analyze_ssl_findings


def _make_ssl_host(scripts: list[ScriptResult]) -> Host:
    return Host(
        address="10.0.0.1",
        hostname=None,
        status="up",
        services=[
            Service(port=443, protocol="tcp", state="open",
                    name="https", tunnel="ssl", scripts=scripts),
        ],
    )


def test_weak_protocol_detected():
    scripts = [ScriptResult(
        script_id="ssl-enum-ciphers",
        output="SSLv3: ciphers: TLS_RSA_WITH_AES_128_CBC_SHA\nTLSv1.2: ciphers: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    )]
    host = _make_ssl_host(scripts)
    findings = analyze_ssl_findings([host])
    titles = [f.title for f in findings]
    assert any("SSLv3" in t for t in titles)


def test_weak_cipher_detected():
    scripts = [ScriptResult(
        script_id="ssl-enum-ciphers",
        output="TLSv1.2: ciphers: TLS_RSA_WITH_RC4_128_SHA - weak",
    )]
    host = _make_ssl_host(scripts)
    findings = analyze_ssl_findings([host])
    titles = [f.title for f in findings]
    assert any("RC4" in t for t in titles)


def test_self_signed_cert():
    scripts = [ScriptResult(
        script_id="ssl-cert",
        output="Subject: CN=mysite",
        elements={
            "subject.commonName": "mysite",
            "issuer.commonName": "mysite",
            "validity.notAfter": "2028-01-01T00:00:00",
            "pubkey.bits": "2048",
        },
    )]
    host = _make_ssl_host(scripts)
    findings = analyze_ssl_findings([host])
    titles = [f.title for f in findings]
    assert "Self-signed certificate" in titles


def test_weak_key_size():
    scripts = [ScriptResult(
        script_id="ssl-cert",
        output="Subject: CN=mysite",
        elements={
            "subject.commonName": "mysite",
            "issuer.commonName": "Real CA",
            "pubkey.bits": "1024",
        },
    )]
    host = _make_ssl_host(scripts)
    findings = analyze_ssl_findings([host])
    assert any("1024" in f.title for f in findings)


def test_weak_signature():
    scripts = [ScriptResult(
        script_id="ssl-cert",
        output="Subject: CN=mysite",
        elements={
            "subject.commonName": "mysite",
            "issuer.commonName": "Real CA",
            "sig_algo": "sha1WithRSAEncryption",
        },
    )]
    host = _make_ssl_host(scripts)
    findings = analyze_ssl_findings([host])
    assert any("sha1" in f.title.lower() for f in findings)


def test_heartbleed_detected():
    scripts = [ScriptResult(
        script_id="ssl-heartbleed",
        output="VULNERABLE: Heartbleed (CVE-2014-0160)",
    )]
    host = _make_ssl_host(scripts)
    findings = analyze_ssl_findings([host])
    assert any("Heartbleed" in f.title for f in findings)
    heartbleed = next(f for f in findings if "Heartbleed" in f.title)
    assert heartbleed.severity == "critical"
    assert "CVE-2014-0160" in heartbleed.cves


def test_poodle_detected():
    scripts = [ScriptResult(
        script_id="ssl-poodle",
        output="VULNERABLE: POODLE SSLv3",
    )]
    host = _make_ssl_host(scripts)
    findings = analyze_ssl_findings([host])
    assert any("POODLE" in f.title for f in findings)


def test_no_findings_for_good_config():
    scripts = [ScriptResult(
        script_id="ssl-enum-ciphers",
        output="TLSv1.2: ciphers: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\nTLSv1.3: ciphers: TLS_AES_256_GCM_SHA384\ncipher preference: server",
    )]
    host = _make_ssl_host(scripts)
    findings = analyze_ssl_findings([host])
    # Should not flag any critical/high issues
    critical_high = [f for f in findings if f.severity in ("critical", "high")]
    assert len(critical_high) == 0


def test_ssl_findings_from_sample():
    """Integration test with sample XML."""
    from pathlib import Path
    from net_audit_report.nmap_parser import parse_nmap_xml

    hosts = parse_nmap_xml(str(Path(__file__).parent.parent / "samples" / "sample_nmap.xml"))
    findings = analyze_ssl_findings(hosts)
    # Should find weak TLSv1.0 and RC4 on 192.168.1.10:443
    assert len(findings) >= 1
    hosts_with_findings = {f.host for f in findings}
    assert "192.168.1.10" in hosts_with_findings
