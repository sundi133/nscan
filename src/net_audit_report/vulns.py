"""
Known vulnerable version database and CVE correlation.

This module matches service product/version strings from Nmap output against
a curated database of known-vulnerable versions. It does NOT perform any
active exploitation — only passive version-based matching from scan results
you already collected on authorized systems.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
import re

from .nmap_parser import Host, Service, extract_cves_from_scripts


@dataclass(frozen=True)
class VulnMatch:
    host: str
    port: int
    protocol: str
    product: str
    version: str
    vuln_id: str
    severity: str  # "critical" | "high" | "medium" | "low"
    title: str
    description: str
    recommendation: str
    cves: list[str]


# Curated list of known-vulnerable version ranges.
# Format: (product_regex, version_regex, vuln_id, severity, title, description, recommendation, cves)
# These are well-known, publicly-disclosed vulnerabilities.
KNOWN_VULNS: list[tuple[str, str, str, str, str, str, str, list[str]]] = [
    # Apache HTTP Server
    (
        r"Apache httpd",
        r"^2\.4\.(49|50)$",
        "NAR-001",
        "critical",
        "Apache HTTP Server Path Traversal",
        "Apache 2.4.49/2.4.50 is vulnerable to path traversal and possible RCE via mod_cgi.",
        "Upgrade Apache to 2.4.51+ immediately.",
        ["CVE-2021-41773", "CVE-2021-42013"],
    ),
    (
        r"Apache httpd",
        r"^2\.4\.([1-9]|[1-3][0-9]|4[0-8])$",
        "NAR-002",
        "high",
        "Apache HTTP Server outdated",
        "Apache version is significantly outdated and may be vulnerable to multiple known CVEs.",
        "Upgrade to latest Apache 2.4.x release.",
        [],
    ),
    # OpenSSH
    (
        r"OpenSSH",
        r"^[1-6]\.",
        "NAR-003",
        "critical",
        "OpenSSH severely outdated",
        "OpenSSH versions before 7.0 have multiple critical vulnerabilities including auth bypass.",
        "Upgrade OpenSSH to 9.x+ immediately.",
        [],
    ),
    (
        r"OpenSSH",
        r"^7\.[0-3]",
        "NAR-004",
        "high",
        "OpenSSH outdated (7.x early)",
        "OpenSSH 7.0-7.3 has known vulnerabilities including user enumeration.",
        "Upgrade to OpenSSH 9.x+.",
        ["CVE-2016-6210"],
    ),
    (
        r"OpenSSH",
        r"^8\.[0-8]",
        "NAR-005",
        "medium",
        "OpenSSH moderately outdated",
        "OpenSSH 8.0-8.8 should be updated for latest security fixes.",
        "Upgrade to OpenSSH 9.x+.",
        [],
    ),
    (
        r"OpenSSH",
        r"^9\.[0-7]",
        "NAR-006",
        "high",
        "OpenSSH regreSSHion vulnerability",
        "OpenSSH before 9.8 may be vulnerable to CVE-2024-6387 (regreSSHion) race condition.",
        "Upgrade to OpenSSH 9.8+ immediately.",
        ["CVE-2024-6387"],
    ),
    # nginx
    (
        r"nginx",
        r"^1\.(([0-9]|1[0-9])\.|2[0-2]\.)",
        "NAR-007",
        "high",
        "nginx outdated",
        "nginx version is outdated and may be vulnerable to HTTP request smuggling and other issues.",
        "Upgrade to latest nginx stable release.",
        [],
    ),
    # Microsoft IIS
    (
        r"Microsoft IIS httpd",
        r"^[5-7]\.",
        "NAR-008",
        "critical",
        "IIS severely outdated",
        "IIS 5.x-7.x is end-of-life and has critical unpatched vulnerabilities.",
        "Migrate to IIS 10+ on supported Windows Server.",
        [],
    ),
    # ProFTPD
    (
        r"ProFTPD",
        r"^1\.3\.[0-5]",
        "NAR-009",
        "critical",
        "ProFTPD vulnerable version",
        "ProFTPD 1.3.0-1.3.5 has known RCE vulnerabilities.",
        "Upgrade ProFTPD or switch to SFTP; disable if unused.",
        ["CVE-2015-3306"],
    ),
    # vsftpd
    (
        r"vsftpd",
        r"^2\.3\.4$",
        "NAR-010",
        "critical",
        "vsftpd backdoor version",
        "vsftpd 2.3.4 contains a known backdoor (compromised source tarball).",
        "Upgrade vsftpd immediately; verify binary integrity.",
        ["CVE-2011-2523"],
    ),
    # MySQL
    (
        r"MySQL",
        r"^5\.[0-5]\.",
        "NAR-011",
        "critical",
        "MySQL severely outdated",
        "MySQL 5.0-5.5 is end-of-life with unpatched vulnerabilities.",
        "Upgrade to MySQL 8.x+ or migrate to MariaDB.",
        [],
    ),
    # PostgreSQL
    (
        r"PostgreSQL",
        r"^(9\.[0-5]|[1-8]\.)",
        "NAR-012",
        "high",
        "PostgreSQL outdated",
        "PostgreSQL version is out of support and may have unpatched security issues.",
        "Upgrade to a supported PostgreSQL version (15+).",
        [],
    ),
    # Microsoft SQL Server
    (
        r"Microsoft SQL Server",
        r"^(2000|2005|2008|2012)",
        "NAR-013",
        "critical",
        "SQL Server end-of-life",
        "SQL Server 2000-2012 are end-of-life with no security patches.",
        "Migrate to SQL Server 2019+ or Azure SQL.",
        [],
    ),
    # Redis
    (
        r"Redis",
        r"^[1-5]\.",
        "NAR-014",
        "high",
        "Redis outdated",
        "Redis versions before 6.0 lack ACL support and have known vulnerabilities.",
        "Upgrade to Redis 7.x+; enable AUTH and ACLs.",
        [],
    ),
    # Samba
    (
        r"Samba",
        r"^[1-3]\.",
        "NAR-015",
        "critical",
        "Samba severely outdated",
        "Samba 1.x-3.x has critical vulnerabilities including EternalBlue-related issues.",
        "Upgrade to Samba 4.x+; disable SMBv1.",
        ["CVE-2017-7494"],
    ),
    (
        r"Samba",
        r"^4\.[0-9]\.",
        "NAR-016",
        "high",
        "Samba outdated",
        "Samba 4.0-4.9 is outdated and has known vulnerabilities.",
        "Upgrade to latest Samba 4.x release.",
        [],
    ),
    # Exim
    (
        r"Exim",
        r"^4\.([0-8]|9[0-3])",
        "NAR-017",
        "critical",
        "Exim mail server critical vulnerabilities",
        "Exim versions before 4.94 have multiple critical RCE vulnerabilities.",
        "Upgrade Exim to 4.96+ immediately.",
        ["CVE-2019-10149"],
    ),
    # Postfix (outdated)
    (
        r"Postfix",
        r"^[12]\.",
        "NAR-018",
        "high",
        "Postfix severely outdated",
        "Postfix 1.x-2.x is significantly outdated.",
        "Upgrade to Postfix 3.x+.",
        [],
    ),
    # OpenSSL (via banner)
    (
        r"OpenSSL",
        r"^(0\.|1\.0\.[01])",
        "NAR-019",
        "critical",
        "OpenSSL Heartbleed-era version",
        "OpenSSL before 1.0.2 is vulnerable to Heartbleed and other critical issues.",
        "Upgrade OpenSSL to 3.x+.",
        ["CVE-2014-0160"],
    ),
    # Elasticsearch
    (
        r"Elasticsearch",
        r"^[1-6]\.",
        "NAR-020",
        "high",
        "Elasticsearch outdated",
        "Elasticsearch 1.x-6.x has known vulnerabilities and may lack security features.",
        "Upgrade to Elasticsearch 8.x+ with security enabled by default.",
        [],
    ),
    # MongoDB
    (
        r"MongoDB",
        r"^[1-3]\.",
        "NAR-021",
        "critical",
        "MongoDB outdated and likely insecure",
        "MongoDB 1.x-3.x is outdated; early versions had no auth by default.",
        "Upgrade to MongoDB 6.x+; enforce authentication and TLS.",
        [],
    ),
    # Tomcat
    (
        r"Apache Tomcat",
        r"^[1-7]\.",
        "NAR-022",
        "high",
        "Apache Tomcat outdated",
        "Tomcat versions before 8.x are end-of-life with known vulnerabilities.",
        "Upgrade to Tomcat 10.x+.",
        [],
    ),
    (
        r"Apache Tomcat",
        r"^8\.[05]\.",
        "NAR-023",
        "medium",
        "Apache Tomcat nearing end-of-life",
        "Tomcat 8.x is nearing end-of-life.",
        "Plan migration to Tomcat 10.x+.",
        [],
    ),
    # PHP
    (
        r"PHP",
        r"^[1-7]\.",
        "NAR-024",
        "high",
        "PHP outdated",
        "PHP versions before 8.0 are end-of-life.",
        "Upgrade to PHP 8.2+.",
        [],
    ),
    # Jenkins
    (
        r"Jetty",
        r".*",
        "NAR-025",
        "medium",
        "Jetty/Jenkins detected",
        "Jetty (often backing Jenkins) exposed on network. Verify access controls.",
        "Restrict to internal network; enforce authentication; keep updated.",
        [],
    ),
]


def match_known_vulns(hosts: list[Host]) -> list[VulnMatch]:
    """Match service versions against known vulnerable version database."""
    matches: list[VulnMatch] = []

    for host in hosts:
        if host.status != "up":
            continue

        for svc in host.services:
            if svc.state != "open":
                continue
            if not svc.product:
                continue

            for (prod_re, ver_re, vuln_id, severity, title,
                 desc, rec, cves) in KNOWN_VULNS:
                if not re.search(prod_re, svc.product, re.IGNORECASE):
                    continue
                ver = svc.version or ""
                if not re.search(ver_re, ver):
                    continue

                # Merge CVEs from the database with any from NSE scripts
                script_cves = extract_cves_from_scripts(svc.scripts)
                all_cves = sorted(set(cves + script_cves))

                matches.append(VulnMatch(
                    host=host.address,
                    port=svc.port,
                    protocol=svc.protocol,
                    product=svc.product,
                    version=ver,
                    vuln_id=vuln_id,
                    severity=severity,
                    title=title,
                    description=desc,
                    recommendation=rec,
                    cves=all_cves,
                ))

    return matches


def extract_nse_vulns(hosts: list[Host]) -> list[VulnMatch]:
    """Extract vulnerability findings from NSE vuln scripts (--script vuln)."""
    matches: list[VulnMatch] = []

    vuln_scripts = {
        "vulners", "vulscan", "vuln", "http-vuln-cve2017-5638",
        "http-vuln-cve2014-3704", "http-vuln-cve2011-3192",
        "smb-vuln-ms17-010", "smb-vuln-ms08-067", "smb-vuln-cve-2017-7494",
        "ssl-heartbleed", "ssl-poodle", "ssl-dh-params", "ssl-ccs-injection",
        "http-shellshock", "http-vuln-cve2014-2126", "http-vuln-cve2014-2127",
        "http-vuln-cve2014-2128", "http-vuln-cve2014-2129",
    }

    for host in hosts:
        if host.status != "up":
            continue

        # Check host-level scripts
        for script in host.host_scripts:
            if not _is_vuln_script(script, vuln_scripts):
                continue
            cves = extract_cves_from_scripts([script])
            if _script_indicates_vulnerable(script):
                matches.append(VulnMatch(
                    host=host.address,
                    port=0,
                    protocol="",
                    product="",
                    version="",
                    vuln_id=f"NSE-{script.script_id}",
                    severity=_nse_severity(script),
                    title=f"NSE: {script.script_id}",
                    description=script.output.strip()[:500],
                    recommendation="Investigate and remediate the vulnerability identified by the NSE script.",
                    cves=cves,
                ))

        # Check port-level scripts
        for svc in host.services:
            if svc.state != "open":
                continue
            for script in svc.scripts:
                if not _is_vuln_script(script, vuln_scripts):
                    continue
                cves = extract_cves_from_scripts([script])
                if _script_indicates_vulnerable(script):
                    matches.append(VulnMatch(
                        host=host.address,
                        port=svc.port,
                        protocol=svc.protocol,
                        product=svc.product or "",
                        version=svc.version or "",
                        vuln_id=f"NSE-{script.script_id}",
                        severity=_nse_severity(script),
                        title=f"NSE: {script.script_id}",
                        description=script.output.strip()[:500],
                        recommendation="Investigate and remediate the vulnerability identified by the NSE script.",
                        cves=cves,
                    ))

    return matches


def _is_vuln_script(script: ScriptResult, vuln_scripts: set[str]) -> bool:
    """Check if a script is a vulnerability-related NSE script."""
    sid = script.script_id.lower()
    if sid in vuln_scripts:
        return True
    if "vuln" in sid or "cve" in sid:
        return True
    return False


def _script_indicates_vulnerable(script: ScriptResult) -> bool:
    """Heuristic: does the script output indicate a vulnerability was found?"""
    output_lower = script.output.lower()
    # NSE vuln scripts typically report "VULNERABLE" when they find something
    if "vulnerable" in output_lower:
        return True
    if "state: vulnerable" in output_lower:
        return True
    # CVE references usually mean a finding
    if re.search(r'CVE-\d{4}-\d{4,}', script.output):
        return True
    return False


def _nse_severity(script: ScriptResult) -> str:
    """Estimate severity from NSE script output."""
    output_lower = script.output.lower()
    sid_lower = script.script_id.lower()

    # Heartbleed, EternalBlue, Shellshock => critical
    critical_indicators = ["heartbleed", "ms17-010", "ms08-067", "shellshock", "eternalblue"]
    if any(ind in sid_lower or ind in output_lower for ind in critical_indicators):
        return "critical"

    # Poodle, CCS injection => high
    high_indicators = ["poodle", "ccs-injection", "drown"]
    if any(ind in sid_lower or ind in output_lower for ind in high_indicators):
        return "high"

    return "high"  # Default for confirmed vulns
