from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Optional
from .nmap_parser import Host, Service


@dataclass(frozen=True)
class Finding:
    host: str
    severity: str  # "low" | "medium" | "high"
    title: str
    detail: str
    recommendation: str
    port: Optional[int] = None
    protocol: Optional[str] = None


# Simple policy rules (defensive hardening hints)
RISKY_PORTS: dict[int, tuple[str, str, str]] = {
    21: ("high", "FTP exposed", "Prefer SFTP/FTPS; disable anonymous; restrict by firewall."),
    23: ("high", "Telnet exposed", "Disable Telnet; use SSH; restrict management access."),
    445: ("high", "SMB exposed", "Restrict SMB to trusted subnets; disable SMBv1; patch regularly."),
    3389: ("high", "RDP exposed", "Restrict by VPN/firewall; enable NLA/MFA; monitor brute force."),
    5900: ("medium", "VNC exposed", "Restrict to admin network; require encryption/auth; prefer VPN."),
    1433: ("high", "MSSQL exposed", "Restrict DB to app subnets; strong auth; patch; audit logins."),
    3306: ("high", "MySQL exposed", "Restrict DB to app subnets; least privilege; patch; rotate creds."),
    5432: ("high", "PostgreSQL exposed", "Restrict network; enforce TLS; least privilege; patch."),
    27017: ("high", "MongoDB exposed", "Restrict network; auth enabled; TLS; no public exposure."),
}

INSECURE_SERVICE_NAMES = {
    "ftp": ("high", "Insecure service (FTP)", "Use SFTP/FTPS; disable plaintext auth."),
    "telnet": ("high", "Insecure service (Telnet)", "Use SSH; disable Telnet."),
    "http": ("medium", "HTTP service detected", "Prefer HTTPS; redirect HTTP->HTTPS; set HSTS where appropriate."),
}


def generate_findings(hosts: Iterable[Host]) -> list[Finding]:
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
                    )
                )

            # Service-name rules (best-effort)
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
                        )
                    )

            # Heuristic: exposed version string (can aid attackers); suggest minimizing banner exposure
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
                    )
                )

    # Deduplicate exact duplicates
    uniq: dict[tuple, Finding] = {}
    for f in findings:
        k = (f.host, f.port, f.protocol, f.title, f.detail)
        uniq[k] = f
    return list(uniq.values())
