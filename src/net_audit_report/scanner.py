"""
Nmap scanner wrapper.

Runs Nmap scans via subprocess and captures XML output for analysis.
Requires nmap to be installed on the system.

IMPORTANT: Only scan networks and hosts you own or have explicit written
authorization to test. Unauthorized scanning is illegal in most jurisdictions.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class ScanProfile(Enum):
    """Pre-built scan profiles for common use cases."""
    QUICK = "quick"
    STANDARD = "standard"
    FULL = "full"
    VULN = "vuln"
    SSL = "ssl"
    UDP = "udp"
    STEALTH = "stealth"
    PING = "ping"


# Maps profile names to Nmap arguments
SCAN_PROFILES: dict[ScanProfile, list[str]] = {
    ScanProfile.QUICK: [
        "-sV", "--top-ports", "100", "-T4",
    ],
    ScanProfile.STANDARD: [
        "-sV", "-sC", "-O", "-T3",
    ],
    ScanProfile.FULL: [
        "-sV", "-sC", "-O", "-p-", "-T3",
        "--script", "vuln,ssl-enum-ciphers,ssl-cert,ssl-heartbleed",
    ],
    ScanProfile.VULN: [
        "-sV", "--script", "vuln", "-T3",
    ],
    ScanProfile.SSL: [
        "-sV", "-p", "443,8443,993,995,465,636",
        "--script", "ssl-enum-ciphers,ssl-cert,ssl-heartbleed,ssl-poodle,ssl-dh-params,ssl-ccs-injection",
    ],
    ScanProfile.UDP: [
        "-sU", "-sV", "--top-ports", "100", "-T3",
    ],
    ScanProfile.STEALTH: [
        "-sS", "-sV", "-T2", "--max-retries", "1",
    ],
    ScanProfile.PING: [
        "-sn",
    ],
}


@dataclass
class ScanConfig:
    """Configuration for an Nmap scan."""
    targets: list[str]
    profile: Optional[ScanProfile] = None
    extra_args: list[str] = field(default_factory=list)
    ports: Optional[str] = None
    top_ports: Optional[int] = None
    scripts: Optional[str] = None
    timing: Optional[int] = None  # 0-5
    sudo: bool = False
    output_xml: Optional[str] = None  # If None, uses a temp file
    interface: Optional[str] = None
    exclude: Optional[str] = None
    timeout: int = 3600  # Max seconds for the scan


@dataclass
class ScanResult:
    """Result of an Nmap scan."""
    success: bool
    xml_path: str
    stdout: str
    stderr: str
    return_code: int
    command: list[str]
    duration_seconds: float


def check_nmap_installed() -> tuple[bool, str]:
    """Check if nmap is installed and return version info."""
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        return False, "nmap not found in PATH. Install: https://nmap.org/download.html"

    try:
        result = subprocess.run(
            ["nmap", "--version"],
            capture_output=True, text=True, timeout=10,
        )
        version_line = result.stdout.strip().split("\n")[0] if result.stdout else "unknown"
        return True, version_line
    except (subprocess.TimeoutExpired, OSError) as e:
        return False, f"nmap found but error checking version: {e}"


def build_nmap_command(config: ScanConfig, xml_output_path: str) -> list[str]:
    """Build the nmap command line from a ScanConfig."""
    cmd: list[str] = []

    if config.sudo:
        cmd.append("sudo")

    cmd.append("nmap")

    # Profile args
    if config.profile:
        cmd.extend(SCAN_PROFILES[config.profile])

    # Port specification (overrides profile)
    if config.ports:
        cmd.extend(["-p", config.ports])
    elif config.top_ports:
        cmd.extend(["--top-ports", str(config.top_ports)])

    # Scripts (overrides profile)
    if config.scripts:
        cmd.extend(["--script", config.scripts])

    # Timing (overrides profile)
    if config.timing is not None:
        cmd.extend([f"-T{config.timing}"])

    # Interface
    if config.interface:
        cmd.extend(["-e", config.interface])

    # Exclusions
    if config.exclude:
        cmd.extend(["--exclude", config.exclude])

    # Extra args
    cmd.extend(config.extra_args)

    # XML output
    cmd.extend(["-oX", xml_output_path])

    # Targets
    cmd.extend(config.targets)

    return cmd


def run_scan(config: ScanConfig) -> ScanResult:
    """
    Execute an Nmap scan. Returns ScanResult with the path to the XML output.

    IMPORTANT: Only scan targets you own or have explicit authorization to test.
    """
    import time

    # Determine XML output path
    if config.output_xml:
        xml_path = config.output_xml
        Path(xml_path).parent.mkdir(parents=True, exist_ok=True)
        cleanup_xml = False
    else:
        tmp = tempfile.NamedTemporaryFile(suffix=".xml", prefix="nscan_", delete=False)
        xml_path = tmp.name
        tmp.close()
        cleanup_xml = False  # Caller is responsible for cleanup

    cmd = build_nmap_command(config, xml_path)

    start = time.monotonic()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.timeout,
        )
        elapsed = time.monotonic() - start

        success = result.returncode == 0 and Path(xml_path).exists()

        return ScanResult(
            success=success,
            xml_path=xml_path,
            stdout=result.stdout,
            stderr=result.stderr,
            return_code=result.returncode,
            command=cmd,
            duration_seconds=round(elapsed, 2),
        )

    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - start
        return ScanResult(
            success=False,
            xml_path=xml_path,
            stdout="",
            stderr=f"Scan timed out after {config.timeout} seconds.",
            return_code=-1,
            command=cmd,
            duration_seconds=round(elapsed, 2),
        )
    except OSError as e:
        elapsed = time.monotonic() - start
        return ScanResult(
            success=False,
            xml_path=xml_path,
            stdout="",
            stderr=f"Failed to execute nmap: {e}",
            return_code=-1,
            command=cmd,
            duration_seconds=round(elapsed, 2),
        )


def list_profiles() -> list[dict[str, str]]:
    """Return a list of scan profiles with descriptions."""
    descriptions = {
        ScanProfile.QUICK: "Fast scan of top 100 ports with version detection",
        ScanProfile.STANDARD: "Service version + default scripts + OS detection (all ports scanned by default)",
        ScanProfile.FULL: "Complete scan: all 65535 ports + vuln scripts + SSL analysis + OS detection",
        ScanProfile.VULN: "Version detection + NSE vuln scripts (checks for known vulnerabilities)",
        ScanProfile.SSL: "SSL/TLS focused: cipher suites, certificates, Heartbleed, POODLE, Logjam",
        ScanProfile.UDP: "Top 100 UDP ports (SNMP, DNS, TFTP, etc.) — requires root/sudo",
        ScanProfile.STEALTH: "SYN stealth scan with conservative timing — requires root/sudo",
        ScanProfile.PING: "Host discovery only (no port scan) — identify live hosts",
    }
    return [
        {
            "name": p.value,
            "description": descriptions.get(p, ""),
            "args": " ".join(SCAN_PROFILES[p]),
        }
        for p in ScanProfile
    ]
