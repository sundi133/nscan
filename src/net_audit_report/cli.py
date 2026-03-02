from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .nmap_parser import parse_nmap_xml
from .findings import generate_findings
from .vulns import match_known_vulns, extract_nse_vulns
from .ssl_analyzer import analyze_ssl_findings
from .compliance import check_compliance
from .report import build_report, render_markdown, render_html, flatten_findings_for_csv
from .diff import compare_scans, render_diff_markdown
from .utils import ensure_outdir, write_json, write_csv


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="net-audit-report",
        description=(
            "Network security audit tool. Scan authorized networks with Nmap "
            "and analyze results for vulnerabilities, misconfigurations, and "
            "compliance issues."
        ),
    )
    sub = p.add_subparsers(dest="command")

    # ── scan ──────────────────────────────────────────────────────────────
    scan_p = sub.add_parser(
        "scan",
        help="Run an Nmap scan and automatically analyze results",
        description=(
            "Run an Nmap scan against authorized targets and generate a "
            "security report. Requires nmap installed on the system."
        ),
    )
    scan_p.add_argument("targets", nargs="+",
                        help="Target hosts/networks (e.g. 192.168.1.0/24 scanme.nmap.org)")
    scan_p.add_argument("--profile", "-p",
                        default="standard",
                        choices=["quick", "standard", "full", "vuln", "ssl", "udp", "stealth", "ping"],
                        help="Scan profile (default: standard)")
    scan_p.add_argument("--ports",
                        help="Port specification (e.g. '22,80,443' or '1-1024')")
    scan_p.add_argument("--top-ports", type=int,
                        help="Scan top N most common ports")
    scan_p.add_argument("--scripts",
                        help="NSE scripts to run (e.g. 'vuln,ssl-enum-ciphers')")
    scan_p.add_argument("--timing", "-T", type=int, choices=range(6),
                        help="Timing template 0-5 (higher=faster)")
    scan_p.add_argument("--sudo", action="store_true",
                        help="Run nmap with sudo (needed for SYN/UDP scans)")
    scan_p.add_argument("--interface", "-e",
                        help="Network interface to use")
    scan_p.add_argument("--exclude",
                        help="Hosts to exclude from scan")
    scan_p.add_argument("--timeout", type=int, default=3600,
                        help="Max scan duration in seconds (default: 3600)")
    scan_p.add_argument("--save-xml",
                        help="Save raw Nmap XML to this path")
    scan_p.add_argument("--extra-args", nargs=argparse.REMAINDER, default=[],
                        help="Additional nmap arguments (pass after --)")
    _add_report_args(scan_p)

    # ── analyze ───────────────────────────────────────────────────────────
    analyze_p = sub.add_parser(
        "analyze",
        help="Analyze an existing Nmap XML file",
        description="Analyze a previously collected Nmap XML file for vulnerabilities and issues.",
    )
    analyze_p.add_argument("--input", "-i", required=True,
                           help="Path to Nmap XML file (created with nmap -oX)")
    analyze_p.add_argument("--baseline", "-b",
                           help="Baseline Nmap XML for scan comparison/diff")
    _add_report_args(analyze_p)

    # ── diff ──────────────────────────────────────────────────────────────
    diff_p = sub.add_parser(
        "diff",
        help="Compare two Nmap XML scans",
        description="Compare baseline and current scans to identify changes.",
    )
    diff_p.add_argument("--baseline", required=True,
                        help="Baseline (older) Nmap XML file")
    diff_p.add_argument("--current", required=True,
                        help="Current (newer) Nmap XML file")
    diff_p.add_argument("--outdir", "-o", default="reports",
                        help="Output directory (default: reports)")
    diff_p.add_argument("--format", "-f", nargs="+",
                        default=["md", "json"],
                        choices=["md", "json"],
                        help="Output formats (default: md json)")
    diff_p.add_argument("--quiet", "-q", action="store_true",
                        help="Suppress informational output")

    # ── profiles ──────────────────────────────────────────────────────────
    sub.add_parser(
        "profiles",
        help="List available scan profiles",
        description="Show all built-in scan profiles with their Nmap arguments.",
    )

    return p


def _add_report_args(parser: argparse.ArgumentParser) -> None:
    """Add common report-related arguments to a subparser."""
    parser.add_argument("--outdir", "-o", default="reports",
                        help="Output directory (default: reports)")
    parser.add_argument("--format", "-f", nargs="+",
                        default=["md", "json", "csv", "html"],
                        choices=["md", "json", "csv", "html"],
                        help="Output formats (default: md json csv html)")
    parser.add_argument("--min-severity", "-s",
                        default="low",
                        choices=["critical", "high", "medium", "low", "info"],
                        help="Minimum severity to include (default: low)")
    parser.add_argument("--no-vulns", action="store_true",
                        help="Skip known vulnerability version matching")
    parser.add_argument("--no-ssl", action="store_true",
                        help="Skip SSL/TLS analysis")
    parser.add_argument("--no-compliance", action="store_true",
                        help="Skip compliance checks")
    parser.add_argument("--nuclei", action="store_true",
                        help="Run Nuclei vulnerability scan after Nmap (requires nuclei installed)")
    parser.add_argument("--nuclei-severity",
                        default="critical,high,medium,low",
                        help="Nuclei severity filter (default: critical,high,medium,low)")
    parser.add_argument("--nuclei-tags",
                        help="Nuclei template tags to include (e.g. 'cve,misconfig')")
    parser.add_argument("--nuclei-exclude-tags",
                        help="Nuclei template tags to exclude")
    parser.add_argument("--nuclei-templates",
                        help="Path to custom Nuclei templates")
    parser.add_argument("--nuclei-rate-limit", type=int, default=150,
                        help="Nuclei max requests/sec (default: 150)")
    parser.add_argument("--nuclei-timeout", type=int, default=900,
                        help="Nuclei max scan duration in seconds (default: 900)")
    # DNS recon
    parser.add_argument("--dns", action="store_true",
                        help="Run DNS recon and subdomain enumeration (uses dig + subfinder)")
    parser.add_argument("--no-subfinder", action="store_true",
                        help="Skip subfinder subdomain enumeration during --dns")
    parser.add_argument("--dns-timeout", type=int, default=300,
                        help="DNS/subfinder timeout in seconds (default: 300)")
    # Directory fuzzing
    parser.add_argument("--fuzz", action="store_true",
                        help="Run directory/file fuzzing on web services (uses ffuf)")
    parser.add_argument("--fuzz-wordlist",
                        help="Custom wordlist for fuzzing (default: built-in common paths)")
    parser.add_argument("--fuzz-extensions",
                        default="",
                        help="File extensions to append (e.g. '.php,.bak,.old')")
    parser.add_argument("--fuzz-threads", type=int, default=40,
                        help="Fuzzing threads (default: 40)")
    parser.add_argument("--fuzz-timeout", type=int, default=300,
                        help="Fuzzing timeout per target in seconds (default: 300)")
    # Credential brute-force
    parser.add_argument("--brute", action="store_true",
                        help="Test default/common credentials (uses hydra if available)")
    parser.add_argument("--no-hydra", action="store_true",
                        help="Skip hydra; only test built-in default creds list")
    parser.add_argument("--brute-timeout", type=int, default=120,
                        help="Brute-force timeout per service in seconds (default: 120)")
    # OSINT recon
    parser.add_argument("--osint", action="store_true",
                        help="Run OSINT recon (whois, HTTP security headers)")
    parser.add_argument("--no-whois", action="store_true",
                        help="Skip whois lookups during --osint")
    parser.add_argument("--no-headers", action="store_true",
                        help="Skip HTTP header checks during --osint")
    parser.add_argument("--quiet", "-q", action="store_true",
                        help="Suppress informational output")


def _log(msg: str, quiet: bool) -> None:
    if not quiet:
        print(msg)


SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _run_analysis(xml_path: str, args: argparse.Namespace, outdir: Path) -> int:
    """Core analysis logic shared between scan and analyze commands."""
    quiet = args.quiet
    min_sev = SEV_RANK.get(args.min_severity, 3)

    _log(f"Parsing {xml_path}...", quiet)
    hosts = parse_nmap_xml(xml_path)
    _log(f"  Found {len(hosts)} hosts, {sum(1 for h in hosts if h.status == 'up')} up.", quiet)

    # Generate all findings
    findings = generate_findings(hosts)
    _log(f"  Base findings: {len(findings)}", quiet)

    # Vulnerability matching
    vuln_matches = []
    if not args.no_vulns:
        vuln_matches = match_known_vulns(hosts)
        nse_vulns = extract_nse_vulns(hosts)
        vuln_matches.extend(nse_vulns)
        _log(f"  Vulnerability matches: {len(vuln_matches)}", quiet)

    # SSL/TLS analysis
    if not args.no_ssl:
        ssl_findings = analyze_ssl_findings(hosts)
        findings.extend(ssl_findings)
        _log(f"  SSL/TLS findings: {len(ssl_findings)}", quiet)

    # Compliance checks
    if not args.no_compliance:
        compliance_findings = check_compliance(hosts)
        findings.extend(compliance_findings)
        _log(f"  Compliance findings: {len(compliance_findings)}", quiet)

    # Nuclei scan
    if getattr(args, "nuclei", False):
        from .nuclei_scanner import check_nuclei_installed, run_nuclei_on_hosts

        installed, nuclei_info = check_nuclei_installed()
        if not installed:
            print(f"WARNING: {nuclei_info}", file=sys.stderr)
            print("Skipping Nuclei scan.", file=sys.stderr)
        else:
            _log(f"  Nuclei: {nuclei_info}", quiet)
            _log(f"  Starting Nuclei scan...", quiet)

            nuclei_result = run_nuclei_on_hosts(
                hosts,
                severity=getattr(args, "nuclei_severity", "critical,high,medium,low"),
                timeout=getattr(args, "nuclei_timeout", 900),
                rate_limit=getattr(args, "nuclei_rate_limit", 150),
                tags=getattr(args, "nuclei_tags", None),
                exclude_tags=getattr(args, "nuclei_exclude_tags", None),
                templates=getattr(args, "nuclei_templates", None),
            )

            if nuclei_result.success:
                findings.extend(nuclei_result.findings)
                _log(f"  Nuclei findings: {len(nuclei_result.findings)} "
                     f"({nuclei_result.duration_seconds}s)", quiet)
            else:
                _log(f"  Nuclei scan had issues: {nuclei_result.stderr[:200]}", quiet)
                # Still include any partial findings
                if nuclei_result.findings:
                    findings.extend(nuclei_result.findings)
                    _log(f"  Nuclei partial findings: {len(nuclei_result.findings)}", quiet)

    # DNS recon
    if getattr(args, "dns", False):
        from .dns_recon import run_dns_recon

        _log("  Starting DNS recon...", quiet)
        # Derive explicit targets from scan args if available
        explicit_targets = getattr(args, "targets", None)
        dns_results = run_dns_recon(
            targets=explicit_targets or [],
            hosts=hosts,
            use_subfinder=not getattr(args, "no_subfinder", False),
            timeout=getattr(args, "dns_timeout", 300),
        )
        dns_count = 0
        for dr in dns_results:
            findings.extend(dr.findings)
            dns_count += len(dr.findings)
            if dr.subdomains:
                _log(f"    {dr.target}: {len(dr.subdomains)} subdomains found", quiet)
        _log(f"  DNS findings: {dns_count}", quiet)

    # Directory fuzzing
    if getattr(args, "fuzz", False):
        from .dir_fuzzer import run_dir_fuzz, check_ffuf_installed

        installed, ffuf_info = check_ffuf_installed()
        if not installed:
            print(f"WARNING: {ffuf_info}", file=sys.stderr)
            print("Skipping directory fuzzing.", file=sys.stderr)
        else:
            _log(f"  {ffuf_info}", quiet)
            _log("  Starting directory fuzzing...", quiet)
            fuzz_results = run_dir_fuzz(
                hosts,
                wordlist=getattr(args, "fuzz_wordlist", None),
                timeout=getattr(args, "fuzz_timeout", 300),
                threads=getattr(args, "fuzz_threads", 40),
                extensions=getattr(args, "fuzz_extensions", ""),
            )
            fuzz_count = 0
            for fr in fuzz_results:
                findings.extend(fr.findings)
                fuzz_count += len(fr.findings)
                _log(f"    {fr.target}: {len(fr.hits)} hits ({fr.duration_seconds}s)", quiet)
            _log(f"  Fuzzing findings: {fuzz_count}", quiet)

    # Credential brute-force
    if getattr(args, "brute", False):
        from .brute_forcer import run_brute_force

        _log("  Starting credential testing...", quiet)
        brute_result = run_brute_force(
            hosts,
            use_hydra=not getattr(args, "no_hydra", False),
            timeout_per_service=getattr(args, "brute_timeout", 120),
        )
        findings.extend(brute_result.findings)
        _log(f"  Credential findings: {len(brute_result.findings)} "
             f"({brute_result.targets_tested} services tested, "
             f"{brute_result.duration_seconds}s)", quiet)
        if brute_result.hits:
            _log(f"  WARNING: {len(brute_result.hits)} default credential(s) found!", quiet)

    # OSINT recon
    if getattr(args, "osint", False):
        from .osint_recon import run_osint

        _log("  Starting OSINT recon...", quiet)
        explicit_targets = getattr(args, "targets", None)
        osint_results = run_osint(
            hosts,
            targets=explicit_targets,
            check_headers=not getattr(args, "no_headers", False),
            check_whois_data=not getattr(args, "no_whois", False),
        )
        osint_count = 0
        for osr in osint_results:
            findings.extend(osr.findings)
            osint_count += len(osr.findings)
        _log(f"  OSINT findings: {osint_count}", quiet)

    # Filter by minimum severity
    findings = [f for f in findings if SEV_RANK.get(f.severity, 9) <= min_sev]
    vuln_matches = [v for v in vuln_matches if SEV_RANK.get(v.severity, 9) <= min_sev]

    report = build_report(hosts, findings, vuln_matches)

    _log("", quiet)
    _log(f"  Total findings: {len(report.findings)}", quiet)
    for sev in ("critical", "high", "medium", "low", "info"):
        cnt = report.severity_counts.get(sev, 0)
        if cnt > 0:
            _log(f"    {sev.upper()}: {cnt}", quiet)
    _log("", quiet)

    # Write outputs
    written: list[str] = []
    formats = args.format

    if "md" in formats:
        path = outdir / "report.md"
        path.write_text(render_markdown(report), encoding="utf-8")
        written.append(str(path))

    if "json" in formats:
        path = outdir / "report.json"
        write_json(path, report)
        written.append(str(path))

    if "csv" in formats:
        path = outdir / "report.csv"
        rows = flatten_findings_for_csv(report.findings, report)
        write_csv(
            path, rows,
            fieldnames=["host", "severity", "title", "category", "protocol", "port",
                        "detail", "recommendation", "cves", "vuln_id",
                        "risk_score", "risk_level"],
        )
        written.append(str(path))

    if "html" in formats:
        path = outdir / "report.html"
        path.write_text(render_html(report), encoding="utf-8")
        written.append(str(path))

    for w in written:
        _log(f"Wrote: {w}", quiet)

    return 0


def _run_diff(baseline_path: str, current_path: str, outdir: Path,
              formats: list[str], quiet: bool) -> int:
    """Run scan diff logic."""
    _log(f"Comparing {baseline_path} vs {current_path}...", quiet)

    baseline_hosts = parse_nmap_xml(baseline_path)
    current_hosts = parse_nmap_xml(current_path)
    diff = compare_scans(baseline_hosts, current_hosts)

    written: list[str] = []

    if "md" in formats:
        diff_md_path = outdir / "diff.md"
        diff_md_path.write_text(render_diff_markdown(diff), encoding="utf-8")
        written.append(str(diff_md_path))

    if "json" in formats:
        diff_json_path = outdir / "diff.json"
        write_json(diff_json_path, diff)
        written.append(str(diff_json_path))

    for w in written:
        _log(f"Wrote: {w}", quiet)

    _log(f"\n  Baseline hosts: {diff.baseline_host_count}, Current: {diff.current_host_count}", quiet)
    _log(f"  New hosts: {len(diff.new_hosts)}, Removed: {len(diff.removed_hosts)}", quiet)
    _log(f"  Total changes: {len(diff.entries)}", quiet)

    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Handle the 'scan' subcommand."""
    from .scanner import ScanProfile, ScanConfig, run_scan, check_nmap_installed

    quiet = args.quiet

    # Check nmap is installed
    installed, version_info = check_nmap_installed()
    if not installed:
        print(f"ERROR: {version_info}", file=sys.stderr)
        print("Install nmap: https://nmap.org/download.html", file=sys.stderr)
        return 2
    _log(f"Using {version_info}", quiet)

    # Build scan config
    profile = ScanProfile(args.profile)
    config = ScanConfig(
        targets=args.targets,
        profile=profile,
        ports=args.ports,
        top_ports=args.top_ports,
        scripts=args.scripts,
        timing=args.timing,
        sudo=args.sudo,
        interface=args.interface,
        exclude=args.exclude,
        timeout=args.timeout,
        output_xml=args.save_xml,
        extra_args=args.extra_args if args.extra_args else [],
    )

    _log(f"\nStarting {profile.value} scan against: {', '.join(args.targets)}", quiet)

    # Run the scan
    result = run_scan(config)

    _log(f"  Scan completed in {result.duration_seconds}s (exit code: {result.return_code})", quiet)

    if not result.success:
        print(f"ERROR: Nmap scan failed.", file=sys.stderr)
        if result.stderr:
            print(f"stderr: {result.stderr}", file=sys.stderr)
        print(f"Command: {' '.join(result.command)}", file=sys.stderr)
        return 1

    # Save XML if requested
    if args.save_xml:
        _log(f"  Nmap XML saved: {args.save_xml}", quiet)

    outdir = ensure_outdir(args.outdir)

    # Always save a copy of the raw XML in the output dir
    raw_xml_path = outdir / "scan.xml"
    if result.xml_path != str(raw_xml_path):
        import shutil
        shutil.copy2(result.xml_path, raw_xml_path)
    _log(f"  Raw XML: {raw_xml_path}", quiet)

    _log("", quiet)

    # Run analysis on the scan results
    return _run_analysis(result.xml_path, args, outdir)


def cmd_analyze(args: argparse.Namespace) -> int:
    """Handle the 'analyze' subcommand."""
    in_path = Path(args.input)
    if not in_path.exists():
        print(f"ERROR: input file not found: {in_path}", file=sys.stderr)
        return 2

    outdir = ensure_outdir(args.outdir)
    rc = _run_analysis(str(in_path), args, outdir)

    # Handle baseline diff if requested
    if rc == 0 and args.baseline:
        baseline_path = Path(args.baseline)
        if not baseline_path.exists():
            print(f"ERROR: baseline file not found: {baseline_path}", file=sys.stderr)
            return 2
        rc = _run_diff(str(baseline_path), str(in_path), outdir,
                       args.format, args.quiet)

    return rc


def cmd_diff(args: argparse.Namespace) -> int:
    """Handle the 'diff' subcommand."""
    for label, path in [("baseline", args.baseline), ("current", args.current)]:
        if not Path(path).exists():
            print(f"ERROR: {label} file not found: {path}", file=sys.stderr)
            return 2

    outdir = ensure_outdir(args.outdir)
    return _run_diff(args.baseline, args.current, outdir, args.format, args.quiet)


def cmd_profiles(args: argparse.Namespace) -> int:
    """Handle the 'profiles' subcommand."""
    from .scanner import list_profiles

    print("Available scan profiles:\n")
    for p in list_profiles():
        print(f"  {p['name']:12s}  {p['description']}")
        print(f"  {'':12s}  nmap {p['args']}")
        print()
    return 0


def main(argv: list[str] | None = None) -> int:
    # Backwards compatibility: if --input/-i is used without a subcommand,
    # prepend 'analyze' so the old CLI style still works.
    if argv and any(a in ("--input", "-i") for a in argv):
        first = argv[0] if argv else ""
        if first not in ("scan", "analyze", "diff", "profiles"):
            argv = ["analyze"] + list(argv)

    parser = build_argparser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 0

    handlers = {
        "scan": cmd_scan,
        "analyze": cmd_analyze,
        "diff": cmd_diff,
        "profiles": cmd_profiles,
    }

    handler = handlers.get(args.command)
    if handler:
        return handler(args)

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
