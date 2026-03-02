"""
Credential brute-force integration.

Wraps Hydra for network service credential testing and includes a
built-in default-credential checker for common services.

IMPORTANT: Only test credentials on targets you own or have explicit
written authorization to test.  Unauthorized credential testing is
illegal.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .findings import Finding
from .nmap_parser import Host


# ── Default credentials to test ─────────────────────────────────────────────
# These are well-known defaults shipped with products.
# Format: service_name → [(user, pass, description)]
DEFAULT_CREDS: dict[str, list[tuple[str, str, str]]] = {
    "ftp": [
        ("anonymous", "", "Anonymous FTP"),
        ("anonymous", "anonymous", "Anonymous FTP"),
        ("ftp", "ftp", "Default FTP"),
        ("admin", "admin", "Common default"),
    ],
    "ssh": [
        ("root", "root", "Root default"),
        ("root", "toor", "Root default"),
        ("admin", "admin", "Common default"),
        ("pi", "raspberry", "Raspberry Pi default"),
        ("ubuntu", "ubuntu", "Ubuntu default"),
    ],
    "mysql": [
        ("root", "", "MySQL no password"),
        ("root", "root", "MySQL default"),
        ("root", "mysql", "MySQL default"),
        ("admin", "admin", "Common default"),
    ],
    "postgresql": [
        ("postgres", "postgres", "PostgreSQL default"),
        ("postgres", "", "PostgreSQL no password"),
        ("admin", "admin", "Common default"),
    ],
    "redis": [
        ("", "", "Redis no auth"),
    ],
    "mongodb": [
        ("", "", "MongoDB no auth"),
        ("admin", "admin", "Common default"),
    ],
    "telnet": [
        ("admin", "admin", "Common default"),
        ("admin", "password", "Common default"),
        ("root", "root", "Root default"),
    ],
    "vnc": [
        ("", "password", "VNC default"),
        ("", "vnc", "VNC default"),
    ],
    "snmp": [
        ("", "public", "Default community string"),
        ("", "private", "Default community string"),
    ],
    "http": [
        ("admin", "admin", "Common default"),
        ("admin", "password", "Common default"),
        ("admin", "1234", "Common default"),
        ("root", "root", "Common default"),
    ],
    "smb": [
        ("guest", "", "Guest account"),
        ("admin", "admin", "Common default"),
        ("administrator", "password", "Common default"),
    ],
    "rdp": [
        ("administrator", "password", "Common default"),
        ("admin", "admin", "Common default"),
    ],
}

# Service name normalization: Nmap service name → our key
_SVC_NORMALIZE: dict[str, str] = {
    "ftp": "ftp",
    "ssh": "ssh",
    "telnet": "telnet",
    "http": "http",
    "https": "http",
    "http-proxy": "http",
    "mysql": "mysql",
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "redis": "redis",
    "mongodb": "mongodb",
    "mongod": "mongodb",
    "vnc": "vnc",
    "ms-wbt-server": "rdp",
    "microsoft-ds": "smb",
    "netbios-ssn": "smb",
    "snmp": "snmp",
}

# Hydra service protocol names
_HYDRA_PROTOS: dict[str, str] = {
    "ssh": "ssh",
    "ftp": "ftp",
    "telnet": "telnet",
    "mysql": "mysql",
    "postgresql": "postgres",
    "vnc": "vnc",
    "rdp": "rdp",
    "smb": "smb",
    "http": "http-get",
    "snmp": "snmp",
}


@dataclass
class CredentialHit:
    """A successful credential match."""
    host: str
    port: int
    protocol: str
    service: str
    username: str
    password: str
    source: str  # "hydra" or "default-check"


@dataclass
class BruteForceResult:
    """Result of credential testing."""
    hits: list[CredentialHit]
    findings: list[Finding]
    duration_seconds: float
    tool_used: str  # "hydra" or "default-check"
    targets_tested: int = 0


def check_hydra_installed() -> tuple[bool, str]:
    """Check if Hydra is installed."""
    path = shutil.which("hydra")
    if not path:
        return False, "hydra not found. Install: apt install hydra / brew install hydra"
    try:
        result = subprocess.run(
            ["hydra", "-h"], capture_output=True, text=True, timeout=10,
        )
        output = (result.stdout + result.stderr).strip()
        # Hydra prints version in first few lines
        for line in output.split("\n")[:3]:
            if "hydra" in line.lower() and ("v" in line.lower() or "version" in line.lower()):
                return True, line.strip()
        return True, "Hydra (version unknown)"
    except (subprocess.TimeoutExpired, OSError) as e:
        return False, f"hydra found but error: {e}"


def _build_hydra_userpass_file(creds: list[tuple[str, str, str]]) -> str:
    """Write user:pass pairs to a temp file for hydra -C flag."""
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", prefix="hydra_creds_", delete=False,
    )
    for user, passwd, _ in creds:
        tmp.write(f"{user}:{passwd}\n")
    tmp.close()
    return tmp.name


def _run_hydra(host: str, port: int, protocol: str,
               creds_file: str, timeout: int = 120) -> list[CredentialHit]:
    """Run Hydra with a colon-separated credentials file."""
    hits: list[CredentialHit] = []

    cmd = [
        "hydra",
        "-C", creds_file,
        "-s", str(port),
        "-t", "4",          # conservative thread count
        "-f",                # stop on first found
        "-o", "/dev/stdout",
        host, protocol,
    ]

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        # Parse hydra output for successful logins
        for line in result.stdout.splitlines():
            line = line.strip()
            # Hydra success line format: [PORT][PROTO] host:IP login:USER password:PASS
            if "login:" in line and "password:" in line:
                user = ""
                passwd = ""
                parts = line.split()
                for p in parts:
                    if p.startswith("login:"):
                        user = p[6:]
                    elif p.startswith("password:"):
                        passwd = p[9:]
                if user or passwd:
                    hits.append(CredentialHit(
                        host=host, port=port, protocol=protocol,
                        service=protocol, username=user, password=passwd,
                        source="hydra",
                    ))
    except (subprocess.TimeoutExpired, OSError):
        pass

    return hits


def _derive_brute_targets(hosts: list[Host]) -> list[tuple[str, int, str, str]]:
    """Extract (host, port, nmap_svc, our_key) tuples for services we can test."""
    targets: list[tuple[str, int, str, str]] = []
    seen: set[tuple[str, int]] = set()

    for h in hosts:
        if h.status != "up":
            continue
        addr = h.hostname or h.address

        for svc in h.services:
            if svc.state != "open":
                continue
            svc_name = (svc.name or "").lower()
            our_key = _SVC_NORMALIZE.get(svc_name)
            if our_key and our_key in DEFAULT_CREDS and (addr, svc.port) not in seen:
                seen.add((addr, svc.port))
                targets.append((addr, svc.port, svc.protocol, our_key))

    return targets


def _analyze_credential_hits(hits: list[CredentialHit]) -> list[Finding]:
    """Convert credential hits to findings."""
    findings: list[Finding] = []

    for hit in hits:
        mask = hit.password
        if len(mask) > 2:
            mask = mask[0] + "*" * (len(mask) - 2) + mask[-1]
        elif mask:
            mask = "*" * len(mask)
        else:
            mask = "(empty)"

        if hit.username == "" and hit.password == "":
            severity = "critical"
            title = f"No authentication on {hit.service}"
            detail = (f"{hit.host}:{hit.port} ({hit.service}) accepts connections "
                      f"without any authentication.")
            recommendation = "Enable authentication immediately."
        elif hit.username in ("anonymous", "guest", ""):
            severity = "high"
            title = f"Anonymous/guest access on {hit.service}"
            detail = (f"{hit.host}:{hit.port} ({hit.service}) allows "
                      f"anonymous/guest login (user: '{hit.username}').")
            recommendation = "Disable anonymous/guest access unless explicitly required."
        else:
            severity = "critical"
            title = f"Default credentials on {hit.service}"
            detail = (f"{hit.host}:{hit.port} ({hit.service}) accepts "
                      f"default credentials (user: '{hit.username}', pass: '{mask}').")
            recommendation = "Change default credentials immediately; enforce strong password policy."

        findings.append(Finding(
            host=hit.host,
            severity=severity,
            title=title,
            detail=detail,
            recommendation=recommendation,
            port=hit.port,
            protocol=hit.protocol,
            category="auth",
        ))

    return findings


def run_brute_force(hosts: list[Host],
                    use_hydra: bool = True,
                    timeout_per_service: int = 120,
                    ) -> BruteForceResult:
    """Test default/common credentials against discovered services.

    IMPORTANT: Only test targets you own or have explicit written
    authorization to test.
    """
    targets = _derive_brute_targets(hosts)
    if not targets:
        return BruteForceResult(
            hits=[], findings=[], duration_seconds=0.0,
            tool_used="none", targets_tested=0,
        )

    has_hydra = False
    if use_hydra:
        has_hydra, _ = check_hydra_installed()

    all_hits: list[CredentialHit] = []
    start = time.monotonic()

    for host, port, proto, svc_key in targets:
        creds = DEFAULT_CREDS.get(svc_key, [])
        if not creds:
            continue

        hydra_proto = _HYDRA_PROTOS.get(svc_key)

        if has_hydra and hydra_proto:
            # Use Hydra for the test
            creds_file = _build_hydra_userpass_file(creds)
            try:
                hits = _run_hydra(
                    host, port, hydra_proto, creds_file,
                    timeout=timeout_per_service,
                )
                all_hits.extend(hits)
            finally:
                Path(creds_file).unlink(missing_ok=True)

    elapsed = time.monotonic() - start
    findings = _analyze_credential_hits(all_hits)

    return BruteForceResult(
        hits=all_hits,
        findings=findings,
        duration_seconds=round(elapsed, 2),
        tool_used="hydra" if has_hydra else "default-check",
        targets_tested=len(targets),
    )
