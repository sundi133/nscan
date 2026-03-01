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
            "Defensive network audit tool. Analyzes authorized Nmap XML output "
            "for vulnerabilities, misconfigurations, and compliance issues. "
            "Does NOT perform any scanning."
        ),
    )
    p.add_argument("--input", "-i", required=True,
                   help="Path to Nmap XML file (created with nmap -oX)")
    p.add_argument("--outdir", "-o", default="reports",
                   help="Output directory (default: reports)")
    p.add_argument("--format", "-f", nargs="+",
                   default=["md", "json", "csv", "html"],
                   choices=["md", "json", "csv", "html"],
                   help="Output formats (default: md json csv html)")
    p.add_argument("--baseline", "-b",
                   help="Baseline Nmap XML for scan comparison/diff")
    p.add_argument("--min-severity", "-s",
                   default="low",
                   choices=["critical", "high", "medium", "low", "info"],
                   help="Minimum severity to include in reports (default: low)")
    p.add_argument("--no-vulns", action="store_true",
                   help="Skip known vulnerability version matching")
    p.add_argument("--no-ssl", action="store_true",
                   help="Skip SSL/TLS analysis")
    p.add_argument("--no-compliance", action="store_true",
                   help="Skip compliance checks")
    p.add_argument("--quiet", "-q", action="store_true",
                   help="Suppress informational output")
    return p


def _log(msg: str, quiet: bool) -> None:
    if not quiet:
        print(msg)


SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def main(argv: list[str] | None = None) -> int:
    args = build_argparser().parse_args(argv)

    in_path = Path(args.input)
    if not in_path.exists():
        print(f"ERROR: input file not found: {in_path}", file=sys.stderr)
        return 2

    outdir = ensure_outdir(args.outdir)
    quiet = args.quiet
    min_sev = SEV_RANK.get(args.min_severity, 3)

    _log(f"Parsing {in_path}...", quiet)
    hosts = parse_nmap_xml(str(in_path))
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

    if "md" in args.format:
        path = outdir / "report.md"
        path.write_text(render_markdown(report), encoding="utf-8")
        written.append(str(path))

    if "json" in args.format:
        path = outdir / "report.json"
        write_json(path, report)
        written.append(str(path))

    if "csv" in args.format:
        path = outdir / "report.csv"
        rows = flatten_findings_for_csv(report.findings)
        write_csv(
            path, rows,
            fieldnames=["host", "severity", "title", "category", "protocol", "port",
                        "detail", "recommendation", "cves", "vuln_id"],
        )
        written.append(str(path))

    if "html" in args.format:
        path = outdir / "report.html"
        path.write_text(render_html(report), encoding="utf-8")
        written.append(str(path))

    for w in written:
        _log(f"Wrote: {w}", quiet)

    # Scan diff/comparison
    if args.baseline:
        baseline_path = Path(args.baseline)
        if not baseline_path.exists():
            print(f"ERROR: baseline file not found: {baseline_path}", file=sys.stderr)
            return 2

        _log(f"\nComparing with baseline: {baseline_path}...", quiet)
        baseline_hosts = parse_nmap_xml(str(baseline_path))
        diff = compare_scans(baseline_hosts, hosts)

        diff_md_path = outdir / "diff.md"
        diff_md_path.write_text(render_diff_markdown(diff), encoding="utf-8")
        _log(f"Wrote: {diff_md_path}", quiet)

        diff_json_path = outdir / "diff.json"
        write_json(diff_json_path, diff)
        _log(f"Wrote: {diff_json_path}", quiet)

        _log(f"\n  Baseline hosts: {diff.baseline_host_count}, Current: {diff.current_host_count}", quiet)
        _log(f"  New hosts: {len(diff.new_hosts)}, Removed: {len(diff.removed_hosts)}", quiet)
        _log(f"  Total changes: {len(diff.entries)}", quiet)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
