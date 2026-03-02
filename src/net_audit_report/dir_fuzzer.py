"""
Directory and file fuzzing integration.

Wraps ffuf (or gobuster) for HTTP directory/file brute-forcing and
converts results into Finding objects for the unified report.

IMPORTANT: Only fuzz targets you own or have explicit written
authorization to test.
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


# ── Built-in small wordlist for when no wordlist is specified ──
# These are the most common paths that indicate misconfigurations
_BUILTIN_PATHS = [
    "admin", "administrator", "login", "wp-admin", "wp-login.php",
    "phpmyadmin", "pma", "adminer", "console", "dashboard",
    ".env", ".git/config", ".git/HEAD", ".gitignore",
    ".svn/entries", ".DS_Store", ".htaccess", ".htpasswd",
    "web.config", "crossdomain.xml", "robots.txt", "sitemap.xml",
    "server-status", "server-info", "status", "health", "healthz",
    "api", "api/v1", "api/v2", "graphql", "swagger", "swagger.json",
    "swagger-ui", "api-docs", "openapi.json", "docs",
    "backup", "dump", "db", "database", "sql",
    "wp-content", "wp-includes", "wp-json",
    "config", "config.php", "config.json", "config.yml",
    "debug", "trace", "test", "info", "phpinfo.php",
    "elmah.axd", "actuator", "actuator/health", "actuator/env",
    "metrics", "prometheus", ".well-known/security.txt",
    "cgi-bin", "cgi-bin/printenv",
    "jenkins", "gitlab", "jira", "confluence",
    "kibana", "grafana", "nagios", "zabbix",
    "solr", "elasticsearch", "_cat/indices",
    "manager", "manager/html", "host-manager",
]

# Interesting status codes
_INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405, 500}

# Sensitive file extensions
_SENSITIVE_EXTENSIONS = [
    "bak", "old", "orig", "save", "swp", "tmp",
    "sql", "tar.gz", "zip", "rar", "7z",
    "log", "conf", "cfg", "ini", "env",
]


@dataclass
class FuzzHit:
    """A single directory/file fuzzing result."""
    url: str
    status_code: int
    content_length: int
    content_type: str = ""
    redirect_location: str = ""
    words: int = 0
    lines: int = 0


@dataclass
class DirFuzzResult:
    """Result of directory fuzzing."""
    target: str
    hits: list[FuzzHit]
    findings: list[Finding]
    duration_seconds: float
    tool_used: str  # "ffuf", "gobuster", or "builtin"
    total_requests: int = 0


def check_ffuf_installed() -> tuple[bool, str]:
    """Check if ffuf is installed."""
    path = shutil.which("ffuf")
    if not path:
        return False, "ffuf not found. Install: go install github.com/ffuf/ffuf/v2@latest"
    try:
        result = subprocess.run(
            ["ffuf", "-V"], capture_output=True, text=True, timeout=10,
        )
        output = (result.stdout + result.stderr).strip()
        return True, output.split("\n")[0] if output else "ffuf (unknown version)"
    except (subprocess.TimeoutExpired, OSError) as e:
        return False, f"ffuf found but error: {e}"


def check_gobuster_installed() -> tuple[bool, str]:
    """Check if gobuster is installed."""
    path = shutil.which("gobuster")
    if not path:
        return False, "gobuster not found."
    try:
        result = subprocess.run(
            ["gobuster", "version"], capture_output=True, text=True, timeout=10,
        )
        output = (result.stdout + result.stderr).strip()
        return True, output.split("\n")[0] if output else "gobuster (unknown version)"
    except (subprocess.TimeoutExpired, OSError) as e:
        return False, f"gobuster found but error: {e}"


def _build_builtin_wordlist() -> str:
    """Write built-in wordlist to a temp file."""
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", prefix="fuzz_wordlist_", delete=False,
    )
    for p in _BUILTIN_PATHS:
        tmp.write(p + "\n")
    tmp.close()
    return tmp.name


def _run_ffuf(target_url: str, wordlist: str, timeout: int = 300,
              threads: int = 40, extensions: str = "",
              extra_args: list[str] | None = None) -> tuple[list[FuzzHit], str]:
    """Run ffuf and return hits + raw output."""
    tmp = tempfile.NamedTemporaryFile(
        suffix=".json", prefix="ffuf_", delete=False,
    )
    tmp.close()

    # Ensure target URL ends with /FUZZ
    base = target_url.rstrip("/")
    fuzz_url = f"{base}/FUZZ"

    cmd = [
        "ffuf",
        "-u", fuzz_url,
        "-w", wordlist,
        "-o", tmp.name,
        "-of", "json",
        "-t", str(threads),
        "-mc", "200,201,204,301,302,307,308,401,403,405,500",
        "-ac",           # auto-calibrate to filter common responses
        "-s",            # silent
    ]

    if extensions:
        cmd.extend(["-e", extensions])

    if extra_args:
        cmd.extend(extra_args)

    hits: list[FuzzHit] = []
    stderr_out = ""

    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        stderr_out = result.stderr

        # Parse JSON output
        output_path = Path(tmp.name)
        if output_path.exists() and output_path.stat().st_size > 0:
            data = json.loads(output_path.read_text(encoding="utf-8", errors="replace"))
            for r in data.get("results", []):
                hits.append(FuzzHit(
                    url=r.get("url", ""),
                    status_code=r.get("status", 0),
                    content_length=r.get("length", 0),
                    content_type=r.get("content-type", ""),
                    redirect_location=r.get("redirectlocation", ""),
                    words=r.get("words", 0),
                    lines=r.get("lines", 0),
                ))
    except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError):
        pass
    finally:
        Path(tmp.name).unlink(missing_ok=True)

    return hits, stderr_out


def _analyze_fuzz_hits(target: str, hits: list[FuzzHit]) -> list[Finding]:
    """Convert fuzz hits into security findings."""
    findings: list[Finding] = []

    for hit in hits:
        url = hit.url
        path = url.split("/", 3)[-1] if "/" in url else url
        path_lower = path.lower()

        # Determine severity based on what was found
        severity = "info"
        title = f"Path found: /{path} ({hit.status_code})"
        recommendation = "Review if this path should be publicly accessible."

        # Sensitive files
        if any(k in path_lower for k in [".env", ".git", ".svn", ".htpasswd",
                                          ".DS_Store", "web.config"]):
            severity = "high"
            title = f"Sensitive file exposed: /{path}"
            recommendation = "Remove or restrict access to this sensitive file immediately."

        # Admin/management panels
        elif any(k in path_lower for k in ["admin", "phpmyadmin", "adminer",
                                            "console", "manager", "dashboard"]):
            if hit.status_code in (200, 301, 302):
                severity = "medium"
                title = f"Admin panel accessible: /{path}"
                recommendation = "Restrict admin panel access to authorized IPs/VPN."

        # Debug/info endpoints
        elif any(k in path_lower for k in ["phpinfo", "debug", "trace",
                                            "actuator", "server-status",
                                            "server-info", "elmah"]):
            severity = "high" if hit.status_code == 200 else "medium"
            title = f"Debug/info endpoint found: /{path}"
            recommendation = "Disable debug endpoints in production."

        # API documentation
        elif any(k in path_lower for k in ["swagger", "api-docs", "openapi",
                                            "graphql"]):
            severity = "low" if hit.status_code == 200 else "info"
            title = f"API documentation exposed: /{path}"
            recommendation = "Consider restricting API docs to authenticated users."

        # Backup files
        elif any(k in path_lower for k in ["backup", "dump", ".bak",
                                            ".old", ".sql", ".tar", ".zip"]):
            severity = "high" if hit.status_code == 200 else "medium"
            title = f"Backup/dump file found: /{path}"
            recommendation = "Remove backup files from web-accessible directories."

        # 401/403 — existence confirmed but restricted
        elif hit.status_code in (401, 403):
            severity = "info"
            title = f"Restricted path exists: /{path} ({hit.status_code})"
            recommendation = "Ensure access controls are properly configured."

        # 500 — server error
        elif hit.status_code == 500:
            severity = "low"
            title = f"Server error at: /{path} (500)"
            recommendation = "Investigate server errors; may reveal stack traces."

        detail = (f"{target} /{path} → HTTP {hit.status_code} "
                  f"(size: {hit.content_length}b, words: {hit.words})")
        if hit.redirect_location:
            detail += f" → {hit.redirect_location}"

        findings.append(Finding(
            host=target,
            severity=severity,
            title=title,
            detail=detail,
            recommendation=recommendation,
            category="web",
        ))

    return findings


def _derive_web_targets(hosts: list[Host]) -> list[str]:
    """Extract HTTP/HTTPS URLs from discovered services."""
    targets: list[str] = []
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
            elif svc.port in (80, 8080, 8000, 8888, 3000, 5000):
                url = f"http://{addr}:{svc.port}"

            if url and url not in seen:
                seen.add(url)
                targets.append(url)

    return targets


def run_dir_fuzz(hosts: list[Host],
                 wordlist: Optional[str] = None,
                 timeout: int = 300,
                 threads: int = 40,
                 extensions: str = "",
                 extra_args: Optional[list[str]] = None,
                 ) -> list[DirFuzzResult]:
    """Run directory fuzzing against web services discovered by Nmap.

    IMPORTANT: Only fuzz targets you own or have explicit authorization to test.
    """
    web_targets = _derive_web_targets(hosts)
    if not web_targets:
        return []

    # Determine tool and wordlist
    has_ffuf, _ = check_ffuf_installed()
    use_builtin_wl = wordlist is None
    if use_builtin_wl:
        wordlist = _build_builtin_wordlist()

    results: list[DirFuzzResult] = []

    try:
        for target in web_targets:
            start = time.monotonic()

            if has_ffuf:
                hits, _ = _run_ffuf(
                    target, wordlist, timeout=timeout,
                    threads=threads, extensions=extensions,
                    extra_args=extra_args,
                )
                tool_used = "ffuf"
            else:
                # Fallback: no fuzzer available
                hits = []
                tool_used = "none"

            findings = _analyze_fuzz_hits(target, hits)
            elapsed = time.monotonic() - start

            results.append(DirFuzzResult(
                target=target,
                hits=hits,
                findings=findings,
                duration_seconds=round(elapsed, 2),
                tool_used=tool_used,
                total_requests=len(_BUILTIN_PATHS) if use_builtin_wl else 0,
            ))
    finally:
        if use_builtin_wl and wordlist:
            Path(wordlist).unlink(missing_ok=True)

    return results
