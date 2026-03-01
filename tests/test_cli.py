from __future__ import annotations

import tempfile
from pathlib import Path

from net_audit_report.cli import main


SAMPLE_XML = Path(__file__).parent.parent / "samples" / "sample_nmap.xml"
BASELINE_XML = Path(__file__).parent.parent / "samples" / "baseline_nmap.xml"


def test_cli_generates_all_reports():
    with tempfile.TemporaryDirectory() as tmpdir:
        rc = main(["--input", str(SAMPLE_XML), "--outdir", tmpdir])
        assert rc == 0
        assert (Path(tmpdir) / "report.md").exists()
        assert (Path(tmpdir) / "report.json").exists()
        assert (Path(tmpdir) / "report.csv").exists()
        assert (Path(tmpdir) / "report.html").exists()


def test_cli_missing_input():
    rc = main(["--input", "/nonexistent/file.xml"])
    assert rc == 2


def test_cli_format_selection():
    with tempfile.TemporaryDirectory() as tmpdir:
        rc = main(["--input", str(SAMPLE_XML), "--outdir", tmpdir, "--format", "md", "json"])
        assert rc == 0
        assert (Path(tmpdir) / "report.md").exists()
        assert (Path(tmpdir) / "report.json").exists()
        assert not (Path(tmpdir) / "report.html").exists()
        assert not (Path(tmpdir) / "report.csv").exists()


def test_cli_with_baseline_diff():
    with tempfile.TemporaryDirectory() as tmpdir:
        rc = main([
            "--input", str(SAMPLE_XML),
            "--baseline", str(BASELINE_XML),
            "--outdir", tmpdir,
        ])
        assert rc == 0
        assert (Path(tmpdir) / "diff.md").exists()
        assert (Path(tmpdir) / "diff.json").exists()


def test_cli_min_severity_filter():
    with tempfile.TemporaryDirectory() as tmpdir:
        rc = main([
            "--input", str(SAMPLE_XML),
            "--outdir", tmpdir,
            "--min-severity", "high",
            "--format", "json",
        ])
        assert rc == 0
        import json
        data = json.loads((Path(tmpdir) / "report.json").read_text())
        # All findings should be high or critical
        for f in data.get("findings", []):
            assert f["severity"] in ("critical", "high")


def test_cli_no_vulns_flag():
    with tempfile.TemporaryDirectory() as tmpdir:
        rc = main([
            "--input", str(SAMPLE_XML),
            "--outdir", tmpdir,
            "--no-vulns",
            "--format", "json",
        ])
        assert rc == 0
        import json
        data = json.loads((Path(tmpdir) / "report.json").read_text())
        assert len(data.get("vuln_matches", [])) == 0


def test_cli_quiet_mode():
    with tempfile.TemporaryDirectory() as tmpdir:
        rc = main(["--input", str(SAMPLE_XML), "--outdir", tmpdir, "--quiet"])
        assert rc == 0


def test_cli_html_contains_dashboard():
    with tempfile.TemporaryDirectory() as tmpdir:
        rc = main(["--input", str(SAMPLE_XML), "--outdir", tmpdir, "--format", "html"])
        assert rc == 0
        html = (Path(tmpdir) / "report.html").read_text()
        assert "dashboard" in html
        assert "Network Audit Report" in html


def test_cli_missing_baseline():
    with tempfile.TemporaryDirectory() as tmpdir:
        rc = main([
            "--input", str(SAMPLE_XML),
            "--baseline", "/nonexistent/baseline.xml",
            "--outdir", tmpdir,
        ])
        assert rc == 2
