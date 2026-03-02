"""
OSINT (Open Source Intelligence) reconnaissance.

Performs passive reconnaissance using whois, DNS, HTTP headers, and
public data sources.  No active exploitation — only publicly available
information is queried.

IMPORTANT: Only perform reconnaissance on targets you own or have
explicit written authorization to assess.
"""
from __future__ import annotations

import json
import re
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse
from urllib.request import urlopen, Request
from urllib.error import URLError

from .findings import Finding
from .nmap_parser import Host


@dataclass
class WhoisInfo:
    """Parsed whois information."""
    registrar: str = ""
    creation_date: str = ""
    expiry_date: str = ""
    name_servers: list[str] = field(default_factory=list)
    org: str = ""
    country: str = ""
    raw: str = ""


@dataclass
class HttpHeaderInfo:
    """Security-relevant HTTP headers from a target."""
    url: str
    status_code: int = 0
    server: str = ""
    x_powered_by: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    missing_security_headers: list[str] = field(default_factory=list)


@dataclass
class OsintResult:
    """Result of OSINT reconnaissance."""
    target: str
    whois: Optional[WhoisInfo] = None
    http_headers: list[HttpHeaderInfo] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    duration_seconds: float = 0.0


# Security headers that should be present
_EXPECTED_HEADERS = {
    "strict-transport-security": ("HSTS", "high",
        "Add Strict-Transport-Security header (e.g., max-age=31536000; includeSubDomains)."),
    "x-content-type-options": ("X-Content-Type-Options", "medium",
        "Add X-Content-Type-Options: nosniff header."),
    "x-frame-options": ("X-Frame-Options", "medium",
        "Add X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors."),
    "content-security-policy": ("Content-Security-Policy", "medium",
        "Implement a Content-Security-Policy header."),
    "x-xss-protection": ("X-XSS-Protection", "low",
        "Add X-XSS-Protection: 1; mode=block (legacy but still useful)."),
    "referrer-policy": ("Referrer-Policy", "low",
        "Add Referrer-Policy: strict-origin-when-cross-origin."),
    "permissions-policy": ("Permissions-Policy", "low",
        "Add Permissions-Policy header to restrict browser features."),
}

# Headers that leak information
_LEAK_HEADERS = {
    "server": "Server header reveals software/version",
    "x-powered-by": "X-Powered-By header reveals technology stack",
    "x-aspnet-version": "X-AspNet-Version header reveals .NET version",
    "x-aspnetmvc-version": "X-AspNetMvc-Version header reveals MVC version",
}


def check_whois_installed() -> bool:
    """Check if whois CLI is available."""
    return shutil.which("whois") is not None


def _run_whois(domain: str) -> Optional[WhoisInfo]:
    """Run whois lookup on a domain."""
    if not check_whois_installed():
        return None

    try:
        result = subprocess.run(
            ["whois", domain],
            capture_output=True, text=True, timeout=30,
        )
        raw = result.stdout
        if not raw or "No match" in raw:
            return None

        info = WhoisInfo(raw=raw)

        # Parse common fields
        for line in raw.splitlines():
            line_lower = line.lower().strip()

            if line_lower.startswith("registrar:"):
                info.registrar = line.split(":", 1)[1].strip()
            elif "creation date" in line_lower or "created:" in line_lower:
                info.creation_date = line.split(":", 1)[1].strip()
            elif "expiry date" in line_lower or "expiration date" in line_lower or "expire" in line_lower:
                info.expiry_date = line.split(":", 1)[1].strip()
            elif line_lower.startswith("name server:") or line_lower.startswith("nserver:"):
                ns = line.split(":", 1)[1].strip().lower()
                if ns and ns not in info.name_servers:
                    info.name_servers.append(ns)
            elif line_lower.startswith("org:") or line_lower.startswith("registrant organization:"):
                info.org = line.split(":", 1)[1].strip()
            elif line_lower.startswith("country:") or line_lower.startswith("registrant country:"):
                if not info.country:
                    info.country = line.split(":", 1)[1].strip()

        return info
    except (subprocess.TimeoutExpired, OSError):
        return None


def _check_http_headers(url: str, timeout: int = 10) -> Optional[HttpHeaderInfo]:
    """Fetch HTTP headers and analyze security posture."""
    try:
        req = Request(url, method="HEAD")
        req.add_header("User-Agent", "net-audit-report/1.0 (security-scanner)")

        with urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            status_code = resp.status

        info = HttpHeaderInfo(
            url=url,
            status_code=status_code,
            server=headers.get("server", ""),
            x_powered_by=headers.get("x-powered-by", ""),
            headers=headers,
        )

        # Check for missing security headers
        for header_key in _EXPECTED_HEADERS:
            if header_key not in headers:
                info.missing_security_headers.append(header_key)

        return info
    except (URLError, OSError, ValueError):
        return None


def _derive_targets(hosts: list[Host],
                    explicit_targets: list[str] | None = None) -> list[str]:
    """Extract domain names for OSINT."""
    domains: set[str] = set()
    for h in hosts:
        if h.hostname and "." in h.hostname:
            # Get the base domain (last two parts)
            domains.add(h.hostname)
    if explicit_targets:
        for t in explicit_targets:
            t = t.strip()
            if t.replace(".", "").replace("/", "").replace(":", "").isdigit():
                continue
            if "/" in t:
                continue
            domains.add(t)
    return sorted(domains)


def _derive_web_urls(hosts: list[Host]) -> list[str]:
    """Extract HTTP/HTTPS URLs from discovered services."""
    urls: list[str] = []
    seen: set[str] = set()
    for h in hosts:
        if h.status != "up":
            continue
        addr = h.hostname or h.address
        for svc in h.services:
            if svc.state != "open":
                continue
            url = None
            if svc.tunnel == "ssl" or svc.name in ("https", "ssl/http"):
                url = f"https://{addr}:{svc.port}"
            elif svc.name in ("http", "http-proxy", "http-alt"):
                url = f"http://{addr}:{svc.port}"
            elif svc.port in (443, 8443):
                url = f"https://{addr}:{svc.port}"
            elif svc.port in (80, 8080, 8000):
                url = f"http://{addr}:{svc.port}"
            if url and url not in seen:
                seen.add(url)
                urls.append(url)
    return urls


def _analyze_whois(domain: str, whois: WhoisInfo) -> list[Finding]:
    """Generate findings from whois data."""
    findings: list[Finding] = []

    # Domain expiry check
    if whois.expiry_date:
        findings.append(Finding(
            host=domain, severity="info",
            title=f"Domain registration info",
            detail=(f"Registrar: {whois.registrar or 'unknown'}, "
                    f"Created: {whois.creation_date or 'unknown'}, "
                    f"Expires: {whois.expiry_date}, "
                    f"Org: {whois.org or 'unknown'}, "
                    f"Country: {whois.country or 'unknown'}"),
            recommendation="Ensure domain registration is up to date and auto-renew is enabled.",
            category="osint",
        ))

    # Name servers
    if whois.name_servers:
        findings.append(Finding(
            host=domain, severity="info",
            title=f"Name servers ({len(whois.name_servers)})",
            detail=f"Name servers: {', '.join(whois.name_servers)}",
            recommendation="Ensure nameservers are geographically distributed and properly configured.",
            category="osint",
        ))

    return findings


def _analyze_http_headers(info: HttpHeaderInfo) -> list[Finding]:
    """Generate findings from HTTP header analysis."""
    findings: list[Finding] = []

    # Missing security headers
    for header_key in info.missing_security_headers:
        name, severity, recommendation = _EXPECTED_HEADERS[header_key]
        # Only flag HSTS as high for HTTPS
        if header_key == "strict-transport-security" and not info.url.startswith("https"):
            continue
        findings.append(Finding(
            host=info.url, severity=severity,
            title=f"Missing security header: {name}",
            detail=f"{info.url} does not set the {name} header.",
            recommendation=recommendation,
            category="web",
        ))

    # Information leakage headers
    for header_key, desc in _LEAK_HEADERS.items():
        value = info.headers.get(header_key, "")
        if value:
            findings.append(Finding(
                host=info.url, severity="low",
                title=f"Information leakage: {header_key}",
                detail=f"{info.url} {desc}: {value}",
                recommendation=f"Remove or obfuscate the {header_key} header.",
                category="web",
            ))

    # Check for insecure cookies
    set_cookie = info.headers.get("set-cookie", "")
    if set_cookie:
        cookie_lower = set_cookie.lower()
        if "secure" not in cookie_lower and info.url.startswith("https"):
            findings.append(Finding(
                host=info.url, severity="medium",
                title="Cookie missing Secure flag",
                detail=f"{info.url} sets cookies without the Secure attribute over HTTPS.",
                recommendation="Add the Secure flag to all cookies served over HTTPS.",
                category="web",
            ))
        if "httponly" not in cookie_lower:
            findings.append(Finding(
                host=info.url, severity="medium",
                title="Cookie missing HttpOnly flag",
                detail=f"{info.url} sets cookies without the HttpOnly attribute.",
                recommendation="Add the HttpOnly flag to session cookies to prevent XSS-based theft.",
                category="web",
            ))

    return findings


def run_osint(hosts: list[Host],
              targets: list[str] | None = None,
              check_headers: bool = True,
              check_whois_data: bool = True,
              timeout: int = 30) -> list[OsintResult]:
    """Run OSINT reconnaissance on targets.

    IMPORTANT: Only assess targets you own or have explicit authorization to test.
    """
    domains = _derive_targets(hosts, targets)
    web_urls = _derive_web_urls(hosts) if check_headers else []

    if not domains and not web_urls:
        return []

    results: list[OsintResult] = []

    for domain in domains:
        start = time.monotonic()
        all_findings: list[Finding] = []
        whois_info = None

        # Whois lookup
        if check_whois_data:
            whois_info = _run_whois(domain)
            if whois_info:
                all_findings.extend(_analyze_whois(domain, whois_info))

        elapsed = time.monotonic() - start
        results.append(OsintResult(
            target=domain,
            whois=whois_info,
            findings=all_findings,
            duration_seconds=round(elapsed, 2),
        ))

    # HTTP header checks (grouped by URL, not domain)
    if check_headers and web_urls:
        header_findings: list[Finding] = []
        header_infos: list[HttpHeaderInfo] = []
        start = time.monotonic()

        for url in web_urls:
            info = _check_http_headers(url, timeout=timeout)
            if info:
                header_infos.append(info)
                header_findings.extend(_analyze_http_headers(info))

        elapsed = time.monotonic() - start

        if header_findings:
            # Add to first result or create new one
            target_label = web_urls[0] if web_urls else "web"
            results.append(OsintResult(
                target=target_label,
                http_headers=header_infos,
                findings=header_findings,
                duration_seconds=round(elapsed, 2),
            ))

    return results
