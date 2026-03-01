# net-audit-report

Defensive tool that converts authorized Nmap XML output into a structured security report.
It does **not** perform scanning. You must provide Nmap XML from an authorized environment.

## Quick start

### 1) Create authorized Nmap XML (you run this yourself)

Example (authorized networks only):

```bash
nmap -sV -oX out.xml 192.168.1.0/24
```

### 2) Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 3) Generate reports

```bash
net-audit-report --input out.xml --outdir reports
```

Outputs:

- `reports/report.md` - Markdown report with findings and inventory
- `reports/report.json` - Machine-readable JSON report
- `reports/report.csv` - CSV of all findings for spreadsheet analysis

## Features

- **Nmap XML parsing** - Extracts hosts, services, versions from `-oX` output
- **Policy-based findings** - Flags risky ports (FTP, Telnet, RDP, SMB, databases), insecure services, and exposed version banners
- **Severity classification** - High / Medium / Low ratings with actionable hardening recommendations
- **Multi-format output** - Markdown, JSON, and CSV reports in one command
- **Extensible rules** - Add your own policy rules in `src/net_audit_report/findings.py`

## Running tests

```bash
pip install pytest
pytest
```

## Project structure

```
net-audit-report/
  README.md
  pyproject.toml
  LICENSE
  .gitignore
  src/
    net_audit_report/
      __init__.py
      cli.py          # CLI entry point
      nmap_parser.py   # Nmap XML parser
      findings.py      # Policy rules and finding generation
      report.py        # Report building and rendering
      utils.py         # File I/O helpers
  tests/
    test_parser.py     # Parser tests
    test_findings.py   # Finding generation tests
    test_report.py     # Report rendering tests
    test_cli.py        # CLI integration tests
  samples/
    sample_nmap.xml    # Example Nmap XML for testing
```

## Notes

- This tool only parses Nmap XML (`-oX`).
- Add your own policy rules in `src/net_audit_report/findings.py`.
- No network scanning is performed by this tool.

## License

MIT
