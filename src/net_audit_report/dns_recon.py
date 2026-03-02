"""
DNS reconnaissance and subdomain enumeration.

Performs DNS lookups, record enumeration, and integrates with subfinder
for passive subdomain discovery.  Results are converted into Finding
objects for the unified report.

IMPORTANT: Only enumerate targets you own or have explicit written
authorization to test.
"""
from __future__ import annotations

import json
import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .findings import Finding
from .nmap_parser import Host


# ── DNS record types we query natively ──────────────────────────────────────

_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "PTR"]

# Security-relevant TXT record patterns
_SECURITY_TXT_PATTERNS = {
    "v=spf1": ("SPF record", "info"),
    "v=DMARC1": ("DMARC record", "info"),
    "v=DKIM1": ("DKIM record", "info"),
}
_MISSING_EMAIL_SECURITY: list[tuple[str, str, str, str]] = [
    ("spf", "v=spf1", "medium", "No SPF record found"),
    ("dmarc", "_dmarc", "medium", "No DMARC record found"),
]


@dataclass
class DnsRecord:
    """A single DNS record."""
    name: str
    record_type: str
    value: str
    ttl: Optional[int] = None


@dataclass
class DnsReconResult:
    """Result of DNS reconnaissance."""
    target: str
    records: list[DnsRecord]
    subdomains: list[str]
    findings: list[Finding]
    duration_seconds: float
    subfinder_used: bool = False


def check_subfinder_installed() -> tuple[bool, str]:
    """Check if subfinder is installed."""
    path = shutil.which("subfinder")
    if not path:
        return False, "subfinder not found in PATH. Install: go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    try:
        result = subprocess.run(
            ["subfinder", "-version"],
            capture_output=True, text=True, timeout=10,
        )
        output = (result.stdout + result.stderr).strip()
        version_line = output.split("\n")[0] if output else "subfinder (unknown version)"
        return True, version_line
    except (subprocess.TimeoutExpired, OSError) as e:
        return False, f"subfinder found but error: {e}"


def check_dig_installed() -> bool:
    """Check if dig is available for DNS queries."""
    return shutil.which("dig") is not None


def _query_dns_dig(domain: str) -> list[DnsRecord]:
    """Use dig to query DNS records."""
    records: list[DnsRecord] = []
    for rtype in _RECORD_TYPES:
        try:
            result = subprocess.run(
                ["dig", "+noall", "+answer", "+ttlid", domain, rtype],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.strip().splitlines():
                parts = line.split()
                if len(parts) >= 5:
                    name = parts[0].rstrip(".")
                    try:
                        ttl = int(parts[1])
                    except ValueError:
                        ttl = None
                    rec_type = parts[3]
                    value = " ".join(parts[4:])
                    records.append(DnsRecord(
                        name=name, record_type=rec_type,
                        value=value.rstrip("."), ttl=ttl,
                    ))
        except (subprocess.TimeoutExpired, OSError):
            continue

    # Also check _dmarc
    try:
        result = subprocess.run(
            ["dig", "+noall", "+answer", f"_dmarc.{domain}", "TXT"],
            capture_output=True, text=True, timeout=10,
        )
        for line in result.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) >= 5:
                name = parts[0].rstrip(".")
                value = " ".join(parts[4:])
                records.append(DnsRecord(
                    name=name, record_type="TXT", value=value,
                ))
    except (subprocess.TimeoutExpired, OSError):
        pass

    return records


def _query_dns_socket(domain: str) -> list[DnsRecord]:
    """Fallback: use socket for basic A/AAAA lookups when dig is unavailable."""
    records: list[DnsRecord] = []
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(domain, None):
            addr = sockaddr[0]
            rtype = "A" if family == socket.AF_INET else "AAAA"
            records.append(DnsRecord(name=domain, record_type=rtype, value=addr))
    except socket.gaierror:
        pass
    return records


def _run_subfinder(domain: str, timeout: int = 300) -> list[str]:
    """Run subfinder for passive subdomain enumeration."""
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", prefix="subfinder_", delete=False,
    )
    tmp.close()

    try:
        subprocess.run(
            ["subfinder", "-d", domain, "-silent", "-o", tmp.name],
            capture_output=True, text=True, timeout=timeout,
        )
        content = Path(tmp.name).read_text(encoding="utf-8", errors="replace")
        subs = [s.strip() for s in content.splitlines() if s.strip()]
        return sorted(set(subs))
    except (subprocess.TimeoutExpired, OSError):
        return []
    finally:
        Path(tmp.name).unlink(missing_ok=True)


def _analyze_dns_records(domain: str, records: list[DnsRecord]) -> list[Finding]:
    """Generate security findings from DNS records."""
    findings: list[Finding] = []
    txt_values = " ".join(r.value for r in records if r.record_type == "TXT")

    # Check for missing email security records
    has_mx = any(r.record_type == "MX" for r in records)
    if has_mx:
        if "v=spf1" not in txt_values:
            findings.append(Finding(
                host=domain, severity="medium",
                title="No SPF record found",
                detail=f"{domain} has MX records but no SPF record to prevent email spoofing.",
                recommendation="Add an SPF TXT record (e.g., v=spf1 include:_spf.google.com ~all).",
                category="dns",
            ))
        if "v=DMARC1" not in txt_values and not any(
            r.name.startswith("_dmarc") and "v=DMARC1" in r.value for r in records
        ):
            findings.append(Finding(
                host=domain, severity="medium",
                title="No DMARC record found",
                detail=f"{domain} has MX records but no DMARC policy to prevent email spoofing.",
                recommendation="Add a DMARC TXT record at _dmarc.{domain} (e.g., v=DMARC1; p=reject).",
                category="dns",
            ))

    # Check for SPF configuration issues
    for r in records:
        if r.record_type == "TXT" and "v=spf1" in r.value:
            if "+all" in r.value:
                findings.append(Finding(
                    host=domain, severity="high",
                    title="Permissive SPF record (+all)",
                    detail=f"{domain} SPF record uses +all which allows any server to send email.",
                    recommendation="Change +all to ~all or -all to restrict email senders.",
                    category="dns",
                ))
            if r.value.count("include:") > 10:
                findings.append(Finding(
                    host=domain, severity="low",
                    title="SPF record has many includes",
                    detail=f"{domain} SPF record has many includes, risking DNS lookup limit (10 max).",
                    recommendation="Consolidate SPF includes to stay within the 10-lookup limit.",
                    category="dns",
                ))

    # Zone transfer check (informational — actual zone transfer
    # requires dig axfr which we don't run for safety)
    ns_records = [r for r in records if r.record_type == "NS"]
    if ns_records:
        findings.append(Finding(
            host=domain, severity="info",
            title=f"DNS nameservers identified ({len(ns_records)})",
            detail=f"{domain} nameservers: {', '.join(r.value for r in ns_records)}",
            recommendation="Ensure zone transfers (AXFR) are restricted to authorized secondaries.",
            category="dns",
        ))

    # Check for wildcard DNS
    # (detected if an unlikely subdomain resolves)

    # Informational: record summary
    rec_types = sorted(set(r.record_type for r in records))
    findings.append(Finding(
        host=domain, severity="info",
        title=f"DNS records enumerated ({len(records)} records)",
        detail=f"{domain} has {len(records)} DNS records of types: {', '.join(rec_types)}.",
        recommendation="Review DNS records for accuracy and remove stale entries.",
        category="dns",
    ))

    return findings


def _derive_domains(hosts: list[Host], targets: list[str] | None = None) -> list[str]:
    """Extract unique domains from hosts and explicit targets."""
    domains: set[str] = set()
    for h in hosts:
        if h.hostname and "." in h.hostname:
            domains.add(h.hostname)
    if targets:
        for t in targets:
            t = t.strip()
            # Skip IPs and CIDR notation
            if t.replace(".", "").replace("/", "").replace(":", "").isdigit():
                continue
            if "/" in t:
                continue
            domains.add(t)
    return sorted(domains)


def run_dns_recon(targets: list[str],
                  hosts: list[Host] | None = None,
                  use_subfinder: bool = True,
                  timeout: int = 300) -> list[DnsReconResult]:
    """Run DNS reconnaissance on targets.

    IMPORTANT: Only enumerate targets you own or have explicit authorization to test.
    """
    domains = _derive_domains(hosts or [], targets)
    if not domains:
        return []

    has_dig = check_dig_installed()
    has_subfinder_bin = False
    if use_subfinder:
        has_subfinder_bin, _ = check_subfinder_installed()

    results: list[DnsReconResult] = []

    for domain in domains:
        start = time.monotonic()

        # DNS record enumeration
        if has_dig:
            records = _query_dns_dig(domain)
        else:
            records = _query_dns_socket(domain)

        # Subdomain enumeration
        subdomains: list[str] = []
        subfinder_used = False
        if has_subfinder_bin and use_subfinder:
            subdomains = _run_subfinder(domain, timeout=timeout)
            subfinder_used = True

        # Analyze findings
        findings = _analyze_dns_records(domain, records)

        # Subdomain findings
        if subdomains:
            findings.append(Finding(
                host=domain, severity="info",
                title=f"Subdomains discovered ({len(subdomains)})",
                detail=f"Passive enumeration found {len(subdomains)} subdomain(s): "
                       f"{', '.join(subdomains[:20])}"
                       + (f" ... and {len(subdomains) - 20} more" if len(subdomains) > 20 else ""),
                recommendation="Review discovered subdomains for forgotten or unauthorized services.",
                category="dns",
            ))
            # Check for potentially interesting subdomains
            interesting = [s for s in subdomains if any(
                k in s.lower() for k in
                ["admin", "staging", "dev", "test", "internal", "vpn",
                 "api", "jenkins", "gitlab", "jira", "confluence",
                 "grafana", "kibana", "elastic", "mongo", "redis",
                 "backup", "old", "legacy", "debug", "phpmyadmin"]
            )]
            if interesting:
                findings.append(Finding(
                    host=domain, severity="medium",
                    title=f"Interesting subdomains found ({len(interesting)})",
                    detail=f"Subdomains suggesting internal/dev services: {', '.join(interesting[:15])}",
                    recommendation="Verify these subdomains are intentionally public and properly secured.",
                    category="dns",
                ))

        elapsed = time.monotonic() - start
        results.append(DnsReconResult(
            target=domain,
            records=records,
            subdomains=subdomains,
            findings=findings,
            duration_seconds=round(elapsed, 2),
            subfinder_used=subfinder_used,
        ))

    return results
