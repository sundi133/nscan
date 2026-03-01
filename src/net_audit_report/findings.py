from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional
from .nmap_parser import Host, Service


@dataclass(frozen=True)
class Finding:
    host: str
    severity: str  # "critical" | "high" | "medium" | "low" | "info"
    title: str
    detail: str
    recommendation: str
    port: Optional[int] = None
    protocol: Optional[str] = None
    category: Optional[str] = None  # "port", "service", "ssl", "vuln", "compliance", etc.
    cves: list[str] = field(default_factory=list)
    vuln_id: Optional[str] = None


# ─── Port-based policy rules ────────────────────────────────────────────────

RISKY_PORTS: dict[int, tuple[str, str, str]] = {
    21: ("high", "FTP exposed", "Prefer SFTP/FTPS; disable anonymous; restrict by firewall."),
    23: ("high", "Telnet exposed", "Disable Telnet; use SSH; restrict management access."),
    25: ("medium", "SMTP exposed", "Restrict SMTP relay; enforce auth; use STARTTLS."),
    53: ("medium", "DNS exposed", "Ensure not an open resolver; restrict zone transfers."),
    69: ("high", "TFTP exposed", "TFTP has no auth; restrict to management VLAN."),
    111: ("high", "RPCbind exposed", "Restrict RPC services; disable if unused."),
    135: ("high", "MSRPC exposed", "Restrict to trusted subnets; patch regularly."),
    137: ("high", "NetBIOS exposed", "Disable NetBIOS over TCP/IP; restrict by firewall."),
    138: ("high", "NetBIOS exposed", "Disable NetBIOS over TCP/IP; restrict by firewall."),
    139: ("high", "NetBIOS/SMB exposed", "Restrict to trusted subnets; disable SMBv1."),
    445: ("high", "SMB exposed", "Restrict SMB to trusted subnets; disable SMBv1; patch regularly."),
    512: ("high", "rexec exposed", "Disable r-services; use SSH."),
    513: ("high", "rlogin exposed", "Disable r-services; use SSH."),
    514: ("high", "rsh/syslog exposed", "Disable r-services; use SSH; encrypt syslog."),
    623: ("critical", "IPMI exposed", "Isolate IPMI; update firmware; change default creds."),
    1099: ("high", "Java RMI exposed", "Restrict RMI; disable if unused; may allow deserialization attacks."),
    1433: ("high", "MSSQL exposed", "Restrict DB to app subnets; strong auth; patch; audit logins."),
    1521: ("high", "Oracle DB exposed", "Restrict to app subnets; strong auth; patch."),
    2049: ("high", "NFS exposed", "Restrict exports to specific IPs; use NFSv4 with Kerberos."),
    3306: ("high", "MySQL exposed", "Restrict DB to app subnets; least privilege; patch; rotate creds."),
    3389: ("high", "RDP exposed", "Restrict by VPN/firewall; enable NLA/MFA; monitor brute force."),
    4444: ("critical", "Metasploit default port", "Investigate immediately; may indicate compromise."),
    5432: ("high", "PostgreSQL exposed", "Restrict network; enforce TLS; least privilege; patch."),
    5900: ("high", "VNC exposed", "Restrict to admin network; require encryption/auth; prefer VPN."),
    5985: ("high", "WinRM-HTTP exposed", "Restrict to management network; use HTTPS (5986)."),
    6379: ("high", "Redis exposed", "Restrict network; require AUTH; enable TLS."),
    6667: ("medium", "IRC exposed", "Verify legitimate use; may indicate botnet C2."),
    8080: ("medium", "HTTP-alt exposed", "Apply same security as primary HTTP; prefer HTTPS."),
    8443: ("medium", "HTTPS-alt exposed", "Review if management interface; restrict access."),
    9042: ("high", "Cassandra exposed", "Restrict to app subnets; enable authentication."),
    9200: ("high", "Elasticsearch exposed", "Restrict network; enable security features."),
    11211: ("high", "Memcached exposed", "Restrict to local/app network; no auth available."),
    27017: ("high", "MongoDB exposed", "Restrict network; auth enabled; TLS; no public exposure."),
    50000: ("high", "SAP exposed", "Restrict to internal network; patch regularly."),
}

INSECURE_SERVICE_NAMES: dict[str, tuple[str, str, str]] = {
    "ftp": ("high", "Insecure service (FTP)", "Use SFTP/FTPS; disable plaintext auth."),
    "telnet": ("high", "Insecure service (Telnet)", "Use SSH; disable Telnet."),
    "http": ("medium", "HTTP service detected", "Prefer HTTPS; redirect HTTP->HTTPS; set HSTS where appropriate."),
    "finger": ("high", "Finger service exposed", "Disable finger; leaks user information."),
    "rexec": ("high", "rexec exposed", "Disable; use SSH instead."),
    "rlogin": ("high", "rlogin exposed", "Disable; use SSH instead."),
    "rsh": ("high", "rsh exposed", "Disable; use SSH instead."),
}

# Suspicious ports that may indicate compromise or misconfiguration
SUSPICIOUS_PORTS: dict[int, tuple[str, str]] = {
    4444: ("Metasploit default handler", "Common reverse shell port; investigate immediately."),
    5555: ("Android Debug Bridge", "ADB exposed; may allow remote code execution."),
    31337: ("Back Orifice / Elite", "Classic backdoor port; investigate immediately."),
    12345: ("NetBus", "Classic backdoor port; investigate."),
    1234: ("Common reverse shell", "Investigate if this is a legitimate service."),
    9001: ("Tor / common backdoor", "Verify if legitimate; may indicate Tor exit or backdoor."),
}


def generate_findings(hosts: Iterable[Host]) -> list[Finding]:
    """Generate security findings from parsed Nmap hosts."""
    findings: list[Finding] = []

    for h in hosts:
        if h.status != "up":
            continue

        for s in h.services:
            if s.state != "open":
                continue

            # Port-based rules
            if s.port in RISKY_PORTS:
                sev, title, rec = RISKY_PORTS[s.port]
                findings.append(
                    Finding(
                        host=h.address,
                        severity=sev,
                        title=title,
                        detail=f"{h.address} exposes {s.protocol}/{s.port} ({s.name or 'unknown service'}).",
                        recommendation=rec,
                        port=s.port,
                        protocol=s.protocol,
                        category="port",
                    )
                )

            # Suspicious port check
            if s.port in SUSPICIOUS_PORTS:
                title, detail_extra = SUSPICIOUS_PORTS[s.port]
                findings.append(
                    Finding(
                        host=h.address,
                        severity="critical",
                        title=f"Suspicious port: {title}",
                        detail=f"{h.address} {s.protocol}/{s.port}: {detail_extra}",
                        recommendation="Investigate this port immediately; verify it serves a legitimate purpose.",
                        port=s.port,
                        protocol=s.protocol,
                        category="suspicious",
                    )
                )

            # Service-name rules
            if s.name:
                key = s.name.lower()
                if key in INSECURE_SERVICE_NAMES:
                    sev, title, rec = INSECURE_SERVICE_NAMES[key]
                    findings.append(
                        Finding(
                            host=h.address,
                            severity=sev,
                            title=title,
                            detail=f"{h.address} reports service '{s.name}' on {s.protocol}/{s.port}.",
                            recommendation=rec,
                            port=s.port,
                            protocol=s.protocol,
                            category="service",
                        )
                    )

            # Version/banner exposure
            if s.product or s.version:
                findings.append(
                    Finding(
                        host=h.address,
                        severity="low",
                        title="Service version/banner identified",
                        detail=(
                            f"{h.address} {s.protocol}/{s.port} appears to be "
                            f"{(s.product or 'unknown product')} {(s.version or '')}".strip()
                            + "."
                        ),
                        recommendation="Consider minimizing banner disclosure and ensure timely patching.",
                        port=s.port,
                        protocol=s.protocol,
                        category="info",
                    )
                )

    # Deduplicate exact duplicates
    uniq: dict[tuple, Finding] = {}
    for f in findings:
        k = (f.host, f.port, f.protocol, f.title, f.detail)
        uniq[k] = f
    return list(uniq.values())
