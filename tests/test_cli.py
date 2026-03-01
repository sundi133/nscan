from __future__ import annotations

import tempfile
from pathlib import Path

from net_audit_report.cli import main


SAMPLE_XML = Path(__file__).parent.parent / "samples" / "sample_nmap.xml"


def test_cli_generates_reports():
    with tempfile.TemporaryDirectory() as tmpdir:
        rc = main(["--input", str(SAMPLE_XML), "--outdir", tmpdir])
        assert rc == 0
        assert (Path(tmpdir) / "report.md").exists()
        assert (Path(tmpdir) / "report.json").exists()
        assert (Path(tmpdir) / "report.csv").exists()


def test_cli_missing_input():
    rc = main(["--input", "/nonexistent/file.xml"])
    assert rc == 2
