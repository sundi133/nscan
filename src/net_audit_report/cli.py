from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .nmap_parser import parse_nmap_xml
from .findings import generate_findings
from .report import build_report, render_markdown, flatten_findings_for_csv
from .utils import ensure_outdir, write_json, write_csv


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="net-audit-report",
        description="Defensive analyzer for authorized Nmap XML results (no scanning).",
    )
    p.add_argument("--input", "-i", required=True, help="Path to Nmap XML file created with -oX")
    p.add_argument("--outdir", "-o", default="reports", help="Output directory (default: reports)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_argparser().parse_args(argv)

    in_path = Path(args.input)
    if not in_path.exists():
        print(f"ERROR: input file not found: {in_path}", file=sys.stderr)
        return 2

    outdir = ensure_outdir(args.outdir)

    hosts = parse_nmap_xml(str(in_path))
    findings = generate_findings(hosts)
    report = build_report(hosts, findings)

    # Write outputs
    (outdir / "report.md").write_text(render_markdown(report), encoding="utf-8")
    write_json(outdir / "report.json", report)

    rows = flatten_findings_for_csv(findings)
    write_csv(
        outdir / "report.csv",
        rows,
        fieldnames=["host", "severity", "title", "protocol", "port", "detail", "recommendation"],
    )

    print(f"Wrote: {(outdir / 'report.md')}")
    print(f"Wrote: {(outdir / 'report.json')}")
    print(f"Wrote: {(outdir / 'report.csv')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
