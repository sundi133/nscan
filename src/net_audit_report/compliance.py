"""
Configuration compliance checker.

Validates network/service configuration against security best practices
and common compliance frameworks (CIS benchmarks, NIST guidelines).
Analyzes data from Nmap XML output only — no active probing.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .nmap_parser import Host, Service
from .findings import Finding


@dataclass(frozen=True)
class ComplianceRule:
    rule_id: str
    title: str
    description: str
    severity: str
    category: str  # "network", "auth", "encryption", "management", "database", "web"
    recommendation: str


# Management ports that should NOT be exposed to untrusted networks
MANAGEMENT_PORTS = {
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    5900: "VNC",
    5901: "VNC",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    8291: "MikroTik Winbox",
    161: "SNMP",
    162: "SNMP-Trap",
    10000: "Webmin",
    2222: "SSH-alt",
    8443: "HTTPS-alt/management",
}

# Database ports
DATABASE_PORTS = {
    1433: "MSSQL",
    1434: "MSSQL-Browser",
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
    27018: "MongoDB",
    6379: "Redis",
    9042: "Cassandra",
    5984: "CouchDB",
    8086: "InfluxDB",
    9200: "Elasticsearch",
    9300: "Elasticsearch-Transport",
    11211: "Memcached",
}

# Ports that should use encryption
SHOULD_BE_ENCRYPTED = {
    21: ("FTP", "Use SFTP (port 22) or FTPS (port 990) instead."),
    23: ("Telnet", "Use SSH instead."),
    80: ("HTTP", "Redirect to HTTPS (443); deploy TLS certificate."),
    110: ("POP3", "Use POP3S (995) with TLS."),
    143: ("IMAP", "Use IMAPS (993) with TLS."),
    389: ("LDAP", "Use LDAPS (636) or STARTTLS."),
    8080: ("HTTP-alt", "Use HTTPS; deploy TLS certificate."),
    69: ("TFTP", "Restrict to management VLAN; consider secure alternatives."),
    161: ("SNMP", "Use SNMPv3 with auth/encryption; restrict community strings."),
    514: ("Syslog", "Use TLS-encrypted syslog (RFC 5425)."),
}

# Default credential services
DEFAULT_CRED_SERVICES = {
    "ftp": "FTP may allow anonymous access. Verify authentication is required.",
    "mongodb": "MongoDB may run without authentication by default. Verify auth is enabled.",
    "redis": "Redis may be running without a password (pre-6.0 default). Verify AUTH is configured.",
    "memcached": "Memcached has no authentication. Restrict access by firewall rules.",
    "elasticsearch": "Elasticsearch may not require authentication (pre-8.0). Verify security is enabled.",
    "couchdb": "CouchDB may be in admin-party mode. Verify authentication is configured.",
}


def check_compliance(hosts: list[Host]) -> list[Finding]:
    """Run all compliance checks against parsed hosts."""
    findings: list[Finding] = []

    for host in hosts:
        if host.status != "up":
            continue

        open_svcs = [s for s in host.services if s.state == "open"]
        open_ports = {s.port for s in open_svcs}

        findings.extend(_check_management_exposure(host, open_svcs))
        findings.extend(_check_database_exposure(host, open_svcs))
        findings.extend(_check_unencrypted_services(host, open_svcs, open_ports))
        findings.extend(_check_default_credentials_risk(host, open_svcs))
        findings.extend(_check_excessive_services(host, open_svcs))
        findings.extend(_check_os_eol(host))
        findings.extend(_check_network_services(host, open_svcs))

    return findings


def _check_management_exposure(host: Host, services: list[Service]) -> list[Finding]:
    findings: list[Finding] = []
    for svc in services:
        if svc.port in MANAGEMENT_PORTS:
            svc_name = MANAGEMENT_PORTS[svc.port]
            findings.append(Finding(
                host=host.address,
                severity="high",
                title=f"Management service exposed: {svc_name}",
                detail=(
                    f"{host.address} exposes {svc_name} on {svc.protocol}/{svc.port}. "
                    f"Management services should be restricted to trusted networks."
                ),
                recommendation=(
                    f"Restrict {svc_name} access via firewall rules to management VLAN/VPN only. "
                    f"Implement MFA where possible."
                ),
                port=svc.port,
                protocol=svc.protocol,
                category="management",
            ))
    return findings


def _check_database_exposure(host: Host, services: list[Service]) -> list[Finding]:
    findings: list[Finding] = []
    for svc in services:
        if svc.port in DATABASE_PORTS:
            db_name = DATABASE_PORTS[svc.port]
            findings.append(Finding(
                host=host.address,
                severity="critical",
                title=f"Database exposed: {db_name}",
                detail=(
                    f"{host.address} exposes {db_name} on {svc.protocol}/{svc.port}. "
                    f"Databases should never be directly accessible from untrusted networks."
                ),
                recommendation=(
                    f"Restrict {db_name} to application subnets only. "
                    f"Enforce strong authentication, TLS encryption, and least-privilege access."
                ),
                port=svc.port,
                protocol=svc.protocol,
                category="database",
            ))
    return findings


def _check_unencrypted_services(host: Host, services: list[Service],
                                 open_ports: set[int]) -> list[Finding]:
    findings: list[Finding] = []
    for svc in services:
        if svc.port in SHOULD_BE_ENCRYPTED:
            svc_name, rec = SHOULD_BE_ENCRYPTED[svc.port]

            # Don't flag HTTP on 80 if HTTPS on 443 is also present (likely redirect)
            if svc.port == 80 and 443 in open_ports:
                if svc.tunnel == "ssl":
                    continue
                findings.append(Finding(
                    host=host.address,
                    severity="medium",
                    title=f"Unencrypted {svc_name} alongside HTTPS",
                    detail=(
                        f"{host.address} runs {svc_name} on {svc.protocol}/{svc.port} "
                        f"alongside HTTPS on 443. Verify HTTP redirects to HTTPS."
                    ),
                    recommendation="Ensure HTTP->HTTPS redirect is in place; set HSTS header.",
                    port=svc.port,
                    protocol=svc.protocol,
                    category="encryption",
                ))
                continue

            # Skip if tunnel is SSL (e.g., FTPS)
            if svc.tunnel == "ssl":
                continue

            findings.append(Finding(
                host=host.address,
                severity="high",
                title=f"Unencrypted service: {svc_name}",
                detail=(
                    f"{host.address} runs {svc_name} on {svc.protocol}/{svc.port} "
                    f"without encryption. Credentials and data may be intercepted."
                ),
                recommendation=rec,
                port=svc.port,
                protocol=svc.protocol,
                category="encryption",
            ))
    return findings


def _check_default_credentials_risk(host: Host, services: list[Service]) -> list[Finding]:
    findings: list[Finding] = []
    for svc in services:
        if svc.name:
            key = svc.name.lower()
            if key in DEFAULT_CRED_SERVICES:
                detail = DEFAULT_CRED_SERVICES[key]
                findings.append(Finding(
                    host=host.address,
                    severity="high",
                    title=f"Default credentials risk: {svc.name}",
                    detail=f"{host.address} {svc.protocol}/{svc.port}: {detail}",
                    recommendation="Enforce authentication; change default credentials; audit access.",
                    port=svc.port,
                    protocol=svc.protocol,
                    category="auth",
                ))
    return findings


def _check_excessive_services(host: Host, services: list[Service]) -> list[Finding]:
    """Flag hosts running an excessive number of services (possible misconfiguration)."""
    findings: list[Finding] = []
    if len(services) > 20:
        findings.append(Finding(
            host=host.address,
            severity="medium",
            title="Excessive open ports detected",
            detail=(
                f"{host.address} has {len(services)} open ports. "
                f"Large attack surface increases risk. Review if all services are needed."
            ),
            recommendation="Audit running services; disable unnecessary ones; apply principle of least functionality.",
            category="network",
        ))
    return findings


def _check_os_eol(host: Host) -> list[Finding]:
    """Flag end-of-life operating systems detected via OS fingerprinting."""
    findings: list[Finding] = []

    eol_patterns = [
        ("Windows XP", "critical", "Windows XP is end-of-life since April 2014."),
        ("Windows Vista", "critical", "Windows Vista is end-of-life since April 2017."),
        ("Windows 7", "high", "Windows 7 is end-of-life since January 2020."),
        ("Windows 8", "high", "Windows 8/8.1 is end-of-life since January 2023."),
        ("Windows Server 2003", "critical", "Windows Server 2003 is end-of-life since July 2015."),
        ("Windows Server 2008", "critical", "Windows Server 2008/R2 is end-of-life since January 2020."),
        ("Windows Server 2012", "high", "Windows Server 2012/R2 is end-of-life since October 2023."),
        ("Ubuntu 14", "critical", "Ubuntu 14.04 is end-of-life."),
        ("Ubuntu 16", "high", "Ubuntu 16.04 standard support ended; verify ESM coverage."),
        ("Ubuntu 18", "high", "Ubuntu 18.04 standard support ended; verify ESM coverage."),
        ("CentOS 6", "critical", "CentOS 6 is end-of-life since November 2020."),
        ("CentOS 7", "high", "CentOS 7 is end-of-life since June 2024."),
        ("CentOS 8", "high", "CentOS 8 is end-of-life since December 2021."),
        ("Debian 8", "critical", "Debian 8 (Jessie) is end-of-life."),
        ("Debian 9", "high", "Debian 9 (Stretch) is end-of-life."),
        ("Debian 10", "medium", "Debian 10 (Buster) LTS ended June 2024."),
    ]

    for os_match in host.os_matches:
        for pattern, severity, detail in eol_patterns:
            if pattern.lower() in os_match.name.lower():
                findings.append(Finding(
                    host=host.address,
                    severity=severity,
                    title=f"End-of-life OS: {os_match.name}",
                    detail=f"{host.address}: {detail} No security patches are available.",
                    recommendation="Migrate to a supported OS version; isolate system if migration is delayed.",
                    category="os",
                ))
                break  # One finding per OS match

    return findings


def _check_network_services(host: Host, services: list[Service]) -> list[Finding]:
    """Check for risky network services (SNMP, NFS, etc.)."""
    findings: list[Finding] = []

    for svc in services:
        name = (svc.name or "").lower()

        # SNMP v1/v2c
        if name == "snmp" or svc.port == 161:
            snmp_detail = "SNMPv1/v2c uses community strings (cleartext). "
            if svc.product and "v3" not in svc.product.lower():
                snmp_detail += f"Detected: {svc.product} {svc.version or ''}."
            findings.append(Finding(
                host=host.address,
                severity="high",
                title="SNMP service exposed",
                detail=f"{host.address} {svc.protocol}/{svc.port}: {snmp_detail}",
                recommendation="Use SNMPv3 with auth+encryption; restrict access; change default community strings.",
                port=svc.port,
                protocol=svc.protocol,
                category="network",
            ))

        # NFS
        if name == "nfs" or svc.port == 2049:
            findings.append(Finding(
                host=host.address,
                severity="high",
                title="NFS service exposed",
                detail=f"{host.address} {svc.protocol}/{svc.port}: NFS shares may be accessible without authentication.",
                recommendation="Restrict NFS exports to specific IPs; use NFSv4 with Kerberos; verify /etc/exports.",
                port=svc.port,
                protocol=svc.protocol,
                category="network",
            ))

        # TFTP
        if name == "tftp" or svc.port == 69:
            findings.append(Finding(
                host=host.address,
                severity="high",
                title="TFTP service exposed",
                detail=f"{host.address} {svc.protocol}/{svc.port}: TFTP has no authentication or encryption.",
                recommendation="Restrict TFTP to management network; replace with SCP/SFTP where possible.",
                port=svc.port,
                protocol=svc.protocol,
                category="network",
            ))

        # LDAP without TLS
        if name == "ldap" and svc.tunnel != "ssl":
            findings.append(Finding(
                host=host.address,
                severity="high",
                title="LDAP without encryption",
                detail=f"{host.address} {svc.protocol}/{svc.port}: LDAP without TLS exposes credentials.",
                recommendation="Enable LDAPS (port 636) or STARTTLS; disable plaintext LDAP.",
                port=svc.port,
                protocol=svc.protocol,
                category="encryption",
            ))

        # IPMI
        if name == "ipmi" or svc.port == 623:
            findings.append(Finding(
                host=host.address,
                severity="critical",
                title="IPMI/BMC exposed",
                detail=f"{host.address} {svc.protocol}/{svc.port}: IPMI is frequently exploitable (password hash disclosure).",
                recommendation="Isolate IPMI on dedicated management VLAN; update firmware; change default credentials.",
                port=svc.port,
                protocol=svc.protocol,
                category="management",
            ))

    return findings
