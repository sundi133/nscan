from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

from net_audit_report.cli import main


SAMPLE_XML = Path(__file__).parent.parent / "samples" / "sample_nmap.xml"
BASELINE_XML = Path(__file__).parent.parent / "samples" / "baseline_nmap.xml"


# ── 'analyze' subcommand ────────────────────────────────────────────────────


def test_analyze_generates_all_reports():
    with tempfile.TemporaryDirectory() as tmpdir:
        rc = main(["analyze", "--input", str(SAMPLE_XML), "--outdir", tmpdir])
        assert rc == 0
        assert (Path(tmpdir) / "report.md").exists()
        assert (Path(tmpdir) / "report.json").exists()
        assert (Path(tmpdir) / "report.csv").exists()
        assert (Path(tmpdir) / "report.html").exists()


def test_analyze_missing_input():
    rc = main(["analyze", "--input", "/nonexistent/file.xml"])
    assert rc == 2


def test_analyze_format_selection():
    with tempfile.TemporaryDirectory() as tmpdir:
        rc = main(["analyze", "--input", str(SAMPLE_XML), "--outdir", tmpdir,
                    "--format", "md", "json"])
        assert rc == 0
        assert (Path(tmpdir) / "report.md").exists()
        assert (Path(tmpdir) / "report.json").exists()
        assert not (Path(tmpdir) / "report.html").exists()
        assert not (Path(tmpdir) / "report.csv").exists()


def test_analyze_with_baseline_diff():
    with tempfile.TemporaryDirectory() as tmpdir:
        rc = main(["analyze",
                    "--input", str(SAMPLE_XML),
                    "--baseline", str(BASELINE_XML),
                    "--outdir", tmpdir])
        assert rc == 0
        assert (Path(tmpdir) / "diff.md").exists()


def test_analyze_min_severity_filter():
    with tempfile.TemporaryDirectory() as tmpdir:
        rc = main(["analyze",
                    "--input", str(SAMPLE_XML),
                    "--outdir", tmpdir,
                    "--min-severity", "high",
                    "--format", "json"])
        assert rc == 0
        data = json.loads((Path(tmpdir) / "report.json").read_text())
        for f in data.get("findings", []):
            assert f["severity"] in ("critical", "high")


def test_analyze_no_vulns_flag():
    with tempfile.TemporaryDirectory() as tmpdir:
        rc = main(["analyze",
                    "--input", str(SAMPLE_XML),
                    "--outdir", tmpdir,
                    "--no-vulns",
                    "--format", "json"])
        assert rc == 0
        data = json.loads((Path(tmpdir) / "report.json").read_text())
        assert len(data.get("vuln_matches", [])) == 0


def test_analyze_quiet_mode():
    with tempfile.TemporaryDirectory() as tmpdir:
        rc = main(["analyze", "--input", str(SAMPLE_XML),
                    "--outdir", tmpdir, "--quiet"])
        assert rc == 0


def test_analyze_html_contains_dashboard():
    with tempfile.TemporaryDirectory() as tmpdir:
        rc = main(["analyze", "--input", str(SAMPLE_XML),
                    "--outdir", tmpdir, "--format", "html"])
        assert rc == 0
        html = (Path(tmpdir) / "report.html").read_text()
        assert "dashboard" in html
        assert "Network Audit Report" in html


def test_analyze_missing_baseline():
    with tempfile.TemporaryDirectory() as tmpdir:
        rc = main(["analyze",
                    "--input", str(SAMPLE_XML),
                    "--baseline", "/nonexistent/baseline.xml",
                    "--outdir", tmpdir])
        assert rc == 2


# ── backwards compatibility (no subcommand, --input flag) ────────────────────


def test_backwards_compat_input_flag():
    """Passing --input without a subcommand should work like 'analyze'."""
    with tempfile.TemporaryDirectory() as tmpdir:
        rc = main(["--input", str(SAMPLE_XML), "--outdir", tmpdir,
                    "--format", "json"])
        assert rc == 0
        assert (Path(tmpdir) / "report.json").exists()


# ── 'diff' subcommand ───────────────────────────────────────────────────────


def test_diff_subcommand():
    with tempfile.TemporaryDirectory() as tmpdir:
        rc = main(["diff",
                    "--baseline", str(BASELINE_XML),
                    "--current", str(SAMPLE_XML),
                    "--outdir", tmpdir])
        assert rc == 0
        assert (Path(tmpdir) / "diff.md").exists()
        assert (Path(tmpdir) / "diff.json").exists()


def test_diff_missing_baseline():
    rc = main(["diff", "--baseline", "/nonexistent.xml",
               "--current", str(SAMPLE_XML)])
    assert rc == 2


def test_diff_missing_current():
    rc = main(["diff", "--baseline", str(BASELINE_XML),
               "--current", "/nonexistent.xml"])
    assert rc == 2


# ── 'profiles' subcommand ───────────────────────────────────────────────────


def test_profiles_subcommand(capsys):
    rc = main(["profiles"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "quick" in out
    assert "full" in out
    assert "vuln" in out
    assert "ssl" in out


# ── 'scan' subcommand (mocked) ──────────────────────────────────────────────


MOCK_XML = """\
<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.0"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_scan_no_nmap(capsys):
    """scan command fails gracefully when nmap is not installed."""
    with patch("net_audit_report.scanner.check_nmap_installed",
               return_value=(False, "nmap not found")):
        rc = main(["scan", "10.0.0.1"])
        assert rc == 2


def test_scan_success_mocked():
    """Full scan->analyze pipeline with mocked nmap."""
    with tempfile.TemporaryDirectory() as tmpdir:
        from net_audit_report.scanner import ScanResult

        mock_result = ScanResult(
            success=True,
            xml_path=str(SAMPLE_XML),  # Use existing sample as scan output
            stdout="Nmap done",
            stderr="",
            return_code=0,
            command=["nmap", "-sV", "10.0.0.1"],
            duration_seconds=5.0,
        )

        with patch("net_audit_report.scanner.check_nmap_installed",
                    return_value=(True, "Nmap 7.94")):
            with patch("net_audit_report.scanner.run_scan", return_value=mock_result):
                rc = main(["scan", "10.0.0.1", "--outdir", tmpdir,
                           "--format", "json", "--quiet"])
                assert rc == 0
                assert (Path(tmpdir) / "report.json").exists()


def test_scan_failure_mocked():
    """Scan fails and reports error."""
    from net_audit_report.scanner import ScanResult

    mock_result = ScanResult(
        success=False,
        xml_path="/tmp/nonexistent.xml",
        stdout="",
        stderr="Failed to resolve host",
        return_code=1,
        command=["nmap", "nonexistent.invalid"],
        duration_seconds=0.5,
    )

    with patch("net_audit_report.scanner.check_nmap_installed",
               return_value=(True, "Nmap 7.94")):
        with patch("net_audit_report.scanner.run_scan", return_value=mock_result):
            rc = main(["scan", "nonexistent.invalid", "--quiet"])
            assert rc == 1


# ── no command shows help ────────────────────────────────────────────────────


def test_no_args_shows_help(capsys):
    rc = main([])
    assert rc == 0
    out = capsys.readouterr().out
    assert "scan" in out or "usage" in out.lower()
