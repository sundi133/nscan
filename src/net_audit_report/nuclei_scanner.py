"""
Nuclei scanner integration.

Runs Nuclei vulnerability scans against discovered hosts/services and
converts results into Finding objects for the unified report.

Nuclei (https://github.com/projectdiscovery/nuclei) is an open-source
vulnerability scanner that uses YAML-based templates.

IMPORTANT: Only scan targets you own or have explicit written authorization
to test.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .findings import Finding
from .nmap_parser import Host


# Nuclei severity → our severity
_SEV_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "unknown": "info",
}

# Nuclei template categories we care about most
_TEMPLATE_TAGS = [
    "cve", "misconfig", "exposure", "panel", "default-login",
    "tech", "token", "xss", "sqli", "lfi", "rce", "ssrf",
    "redirect", "disclosure",
]


@dataclass
class NucleiConfig:
    """Configuration for a Nuclei scan."""
    targets: list[str]
    severity: str = "critical,high,medium,low"  # comma-separated
    tags: Optional[str] = None                   # template tags to include
    exclude_tags: Optional[str] = None           # template tags to exclude
    templates: Optional[str] = None              # custom template path
    rate_limit: int = 150                        # max requests/sec
    concurrency: int = 25                        # concurrent templates
    timeout: int = 900                           # max seconds
    extra_args: list[str] = field(default_factory=list)


@dataclass
class NucleiResult:
    """Result of a Nuclei scan."""
    success: bool
    findings: list[Finding]
    json_path: str
    stdout: str
    stderr: str
    return_code: int
    command: list[str]
    duration_seconds: float
    template_count: int = 0


def check_nuclei_installed() -> tuple[bool, str]:
    """Check if nuclei is installed and return version info."""
    nuclei_path = shutil.which("nuclei")
    if not nuclei_path:
        return False, "nuclei not found in PATH. Install: https://docs.projectdiscovery.io/tools/nuclei/install"

    try:
        result = subprocess.run(
            ["nuclei", "-version"],
            capture_output=True, text=True, timeout=10,
        )
        # nuclei outputs version to stderr
        output = (result.stdout + result.stderr).strip()
        version_line = output.split("\n")[0] if output else "nuclei (unknown version)"
        return True, version_line
    except (subprocess.TimeoutExpired, OSError) as e:
        return False, f"nuclei found but error checking version: {e}"


def _build_targets_file(targets: list[str]) -> str:
    """Write targets to a temp file for nuclei -l flag."""
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", prefix="nuclei_targets_", delete=False,
    )
    for t in targets:
        tmp.write(t + "\n")
    tmp.close()
    return tmp.name


def build_nuclei_command(config: NucleiConfig, json_output_path: str,
                         targets_file: str) -> list[str]:
    """Build the nuclei command line."""
    cmd = [
        "nuclei",
        "-l", targets_file,
        "-jsonl",
        "-o", json_output_path,
        "-severity", config.severity,
        "-rate-limit", str(config.rate_limit),
        "-concurrency", str(config.concurrency),
        "-silent",
    ]

    if config.tags:
        cmd.extend(["-tags", config.tags])

    if config.exclude_tags:
        cmd.extend(["-exclude-tags", config.exclude_tags])

    if config.templates:
        cmd.extend(["-t", config.templates])

    cmd.extend(config.extra_args)

    return cmd


def _derive_targets_from_hosts(hosts: list[Host]) -> list[str]:
    """Build target URLs from Nmap host/service data for Nuclei.

    Nuclei works best with URLs, so we construct them from discovered services.
    """
    targets: set[str] = set()

    for h in hosts:
        if h.status != "up":
            continue
        addr = h.hostname or h.address

        for svc in h.services:
            if svc.state != "open":
                continue

            # HTTP/HTTPS services → URLs
            if svc.tunnel == "ssl" or svc.name in ("https", "ssl/http"):
                targets.add(f"https://{addr}:{svc.port}")
            elif svc.name in ("http", "http-proxy", "http-alt"):
                targets.add(f"http://{addr}:{svc.port}")
            elif svc.port in (443, 8443, 993, 995, 465, 636):
                targets.add(f"https://{addr}:{svc.port}")
            elif svc.port in (80, 8080, 8000, 8888, 3000, 5000):
                targets.add(f"http://{addr}:{svc.port}")
            else:
                # Non-HTTP services: add as host:port for network templates
                targets.add(f"{addr}:{svc.port}")

        # Always include the bare host for network-level templates
        targets.add(addr)

    return sorted(targets)


def _parse_nuclei_jsonl(json_path: str) -> list[Finding]:
    """Parse Nuclei JSONL output into Finding objects."""
    findings: list[Finding] = []
    path = Path(json_path)
    if not path.exists() or path.stat().st_size == 0:
        return findings

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = item.get("info", {})
        severity = _SEV_MAP.get(info.get("severity", "").lower(), "info")
        template_id = item.get("template-id", item.get("templateID", "unknown"))
        name = info.get("name", template_id)

        # Host + port extraction
        host = item.get("host", item.get("ip", "unknown"))
        matched_at = item.get("matched-at", "")
        port_val: Optional[int] = item.get("port")

        # Try to extract port from matched-at URL
        if port_val is None and ":" in matched_at:
            try:
                # handle urls like https://host:port/path
                from urllib.parse import urlparse
                parsed = urlparse(matched_at)
                if parsed.port:
                    port_val = parsed.port
            except Exception:
                pass

        # CVEs
        classification = info.get("classification", {})
        cves = classification.get("cve-id") or []
        if isinstance(cves, str):
            cves = [cves]

        # Description
        description = info.get("description", "")
        if not description:
            description = f"Nuclei template {template_id} matched."

        # Recommendation / remediation
        remediation = info.get("remediation", "")
        if not remediation:
            remediation = "Review and remediate according to the finding details."

        # Tags for category
        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]
        category = "nuclei"
        for tag in tags:
            if tag in ("cve", "vuln"):
                category = "vuln"
                break
            if tag in ("misconfig", "config"):
                category = "compliance"
                break
            if tag in ("exposure", "disclosure"):
                category = "info"
                break
            if tag in ("xss", "sqli", "lfi", "rce", "ssrf"):
                category = "vuln"
                break

        # Extract matcher/evidence
        matcher_name = item.get("matcher-name", "")
        extracted = item.get("extracted-results", [])
        detail_parts = [description]
        if matcher_name:
            detail_parts.append(f"Matcher: {matcher_name}")
        if extracted:
            detail_parts.append(f"Extracted: {', '.join(str(e) for e in extracted[:5])}")
        if matched_at:
            detail_parts.append(f"Matched at: {matched_at}")

        detail = " | ".join(detail_parts)

        # References
        references = info.get("reference") or []
        if isinstance(references, str):
            references = [references]
        if references:
            detail += f" | Refs: {', '.join(references[:3])}"

        findings.append(Finding(
            host=host,
            severity=severity,
            title=f"[Nuclei] {name}",
            detail=detail,
            recommendation=remediation,
            port=port_val,
            protocol="tcp",
            category=category,
            cves=cves,
            vuln_id=template_id,
        ))

    return findings


def run_nuclei(config: NucleiConfig) -> NucleiResult:
    """Execute a Nuclei scan. Returns NucleiResult with parsed findings.

    IMPORTANT: Only scan targets you own or have explicit authorization to test.
    """
    # Write targets file
    targets_file = _build_targets_file(config.targets)

    # Output path
    tmp = tempfile.NamedTemporaryFile(
        suffix=".jsonl", prefix="nuclei_", delete=False,
    )
    json_path = tmp.name
    tmp.close()

    cmd = build_nuclei_command(config, json_path, targets_file)

    start = time.monotonic()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.timeout,
        )
        elapsed = time.monotonic() - start

        success = result.returncode == 0
        findings = _parse_nuclei_jsonl(json_path)

        return NucleiResult(
            success=success,
            findings=findings,
            json_path=json_path,
            stdout=result.stdout,
            stderr=result.stderr,
            return_code=result.returncode,
            command=cmd,
            duration_seconds=round(elapsed, 2),
            template_count=len(findings),
        )
    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - start
        findings = _parse_nuclei_jsonl(json_path)
        return NucleiResult(
            success=False,
            findings=findings,
            json_path=json_path,
            stdout="",
            stderr=f"Nuclei scan timed out after {config.timeout} seconds.",
            return_code=-1,
            command=cmd,
            duration_seconds=round(elapsed, 2),
            template_count=len(findings),
        )
    except OSError as e:
        elapsed = time.monotonic() - start
        return NucleiResult(
            success=False,
            findings=[],
            json_path=json_path,
            stdout="",
            stderr=f"Failed to execute nuclei: {e}",
            return_code=-1,
            command=cmd,
            duration_seconds=round(elapsed, 2),
        )
    finally:
        # Clean up targets file
        try:
            Path(targets_file).unlink(missing_ok=True)
        except OSError:
            pass


def run_nuclei_on_hosts(hosts: list[Host],
                        severity: str = "critical,high,medium,low",
                        timeout: int = 900,
                        rate_limit: int = 150,
                        tags: Optional[str] = None,
                        exclude_tags: Optional[str] = None,
                        templates: Optional[str] = None,
                        extra_args: Optional[list[str]] = None,
                        ) -> NucleiResult:
    """Convenience: derive targets from Nmap hosts and run Nuclei.

    IMPORTANT: Only scan targets you own or have explicit authorization to test.
    """
    targets = _derive_targets_from_hosts(hosts)
    if not targets:
        return NucleiResult(
            success=True, findings=[], json_path="", stdout="",
            stderr="No targets derived from host data.", return_code=0,
            command=[], duration_seconds=0.0,
        )

    config = NucleiConfig(
        targets=targets,
        severity=severity,
        tags=tags,
        exclude_tags=exclude_tags,
        templates=templates,
        rate_limit=rate_limit,
        timeout=timeout,
        extra_args=extra_args or [],
    )

    return run_nuclei(config)
