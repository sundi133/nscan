"""Tests for DNS reconnaissance module."""
from __future__ import annotations

from net_audit_report.nmap_parser import Host, Service
from net_audit_report.dns_recon import (
    _derive_domains,
    _analyze_dns_records,
    DnsRecord,
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


def test_derive_domains_from_hosts():
    hosts = _sample_hosts()
    domains = _derive_domains(hosts)
    assert "example.com" in domains


def test_derive_domains_from_targets():
    domains = _derive_domains([], targets=["target.com", "other.io"])
    assert "target.com" in domains
    assert "other.io" in domains


def test_derive_domains_skips_ips():
    domains = _derive_domains([], targets=["192.168.1.0/24", "10.0.0.1"])
    assert len(domains) == 0


def test_derive_domains_skips_no_dot():
    hosts = [Host(address="10.0.0.1", hostname="localhost", status="up", services=[])]
    domains = _derive_domains(hosts)
    # "localhost" has no dot, should be skipped
    assert "localhost" not in domains


def test_analyze_dns_records_missing_spf():
    records = [
        DnsRecord(name="example.com", record_type="MX", value="mail.example.com"),
        DnsRecord(name="example.com", record_type="NS", value="ns1.example.com"),
    ]
    findings = _analyze_dns_records("example.com", records)
    titles = [f.title for f in findings]
    assert any("SPF" in t for t in titles)
    assert any("DMARC" in t for t in titles)


def test_analyze_dns_records_has_spf_dmarc():
    records = [
        DnsRecord(name="example.com", record_type="MX", value="mail.example.com"),
        DnsRecord(name="example.com", record_type="TXT", value="v=spf1 include:_spf.google.com ~all"),
        DnsRecord(name="_dmarc.example.com", record_type="TXT", value="v=DMARC1; p=reject"),
    ]
    findings = _analyze_dns_records("example.com", records)
    titles = [f.title for f in findings]
    # Should NOT flag missing SPF/DMARC
    assert not any("No SPF" in t for t in titles)
    assert not any("No DMARC" in t for t in titles)


def test_analyze_dns_records_permissive_spf():
    records = [
        DnsRecord(name="example.com", record_type="MX", value="mail.example.com"),
        DnsRecord(name="example.com", record_type="TXT", value="v=spf1 +all"),
    ]
    findings = _analyze_dns_records("example.com", records)
    titles = [f.title for f in findings]
    assert any("Permissive SPF" in t for t in titles)


def test_analyze_dns_records_nameservers():
    records = [
        DnsRecord(name="example.com", record_type="NS", value="ns1.example.com"),
        DnsRecord(name="example.com", record_type="NS", value="ns2.example.com"),
    ]
    findings = _analyze_dns_records("example.com", records)
    assert any("nameserver" in f.title.lower() for f in findings)


def test_analyze_dns_records_no_mx_no_email_warnings():
    """If no MX records, SPF/DMARC warnings should not fire."""
    records = [
        DnsRecord(name="example.com", record_type="A", value="93.184.216.34"),
    ]
    findings = _analyze_dns_records("example.com", records)
    titles = [f.title for f in findings]
    assert not any("No SPF" in t for t in titles)
    assert not any("No DMARC" in t for t in titles)
