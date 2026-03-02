# net-audit-report

All-in-one network security audit tool. Scan your authorized networks with Nmap and get
comprehensive vulnerability reports with hardening recommendations.

**Scan + Analyze in one command:**
```bash
net-audit-report scan 192.168.1.0/24 --profile full --outdir reports
```

**Or analyze existing Nmap XML:**
```bash
net-audit-report analyze --input scan.xml --outdir reports
```

> **IMPORTANT:** Only scan networks and hosts you own or have explicit written
> authorization to test. Unauthorized scanning is illegal in most jurisdictions.

## Install

```bash
git clone https://github.com/sundi133/nscan.git
cd nscan
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

**Requires:** Python 3.10+ and [Nmap](https://nmap.org/download.html) installed for scanning.

## Getting started — step by step

Follow these steps to go from zero to your first scan report.

### Step 1: Install prerequisites

You need Python 3.10+ and Nmap. Verify both are installed:

```bash
python3 --version   # must be 3.10 or higher
nmap --version      # must be installed and on PATH
```

If Nmap is not installed:
- **Ubuntu/Debian:** `sudo apt install nmap`
- **macOS:** `brew install nmap`
- **Windows:** Download from [nmap.org](https://nmap.org/download.html)

### Step 2: Clone and install

```bash
git clone https://github.com/sundi133/nscan.git
cd nscan
python3 -m venv .venv
source .venv/bin/activate    # Linux/macOS
# .venv\Scripts\activate     # Windows
pip install -e .
```

### Step 3: Verify the installation

```bash
net-audit-report --help
net-audit-report profiles
```

You should see the list of available scan profiles.

### Step 4: Run your first scan

Pick a target you own or are authorized to scan, then run:

```bash
net-audit-report scan <TARGET> --profile quick --outdir my-first-report
```

Replace `<TARGET>` with an IP, hostname, or CIDR range. Example with Nmap's public test server:

```bash
net-audit-report scan scanme.nmap.org --profile quick --outdir my-first-report
```

This runs a fast scan (top 100 ports) and generates reports in `my-first-report/`.

### Step 5: View the reports

```bash
# Open the HTML report (interactive dashboard with filtering)
open my-first-report/report.html        # macOS
xdg-open my-first-report/report.html    # Linux

# Or read the markdown report in terminal
cat my-first-report/report.md
```

### Step 6: Run a deeper scan

Once you're comfortable, try a more thorough scan:

```bash
# Standard scan — version + scripts + OS detection
net-audit-report scan 192.168.1.0/24 --outdir reports

# Full vulnerability assessment — all 65535 ports + vuln scripts + SSL
net-audit-report scan 192.168.1.0/24 --profile full --outdir reports

# SSL/TLS audit on a web server
net-audit-report scan myapp.example.com --profile ssl --outdir reports

# UDP scan (requires sudo)
net-audit-report scan 192.168.1.0/24 --profile udp --sudo --outdir reports
```

### Step 7: Compare scans over time

Run a baseline scan, then scan again later and diff:

```bash
# Initial scan
net-audit-report scan 192.168.1.0/24 --profile quick --save-xml baseline.xml

# ... time passes, changes are made ...

# Follow-up scan
net-audit-report scan 192.168.1.0/24 --profile quick --save-xml current.xml

# See what changed
net-audit-report diff --baseline baseline.xml --current current.xml --outdir reports
```

### Try it without Nmap (analysis only)

You can test the analysis pipeline using the included sample data — no Nmap needed:

```bash
net-audit-report analyze --input samples/sample_nmap.xml --outdir /tmp/test
cat /tmp/test/report.md
```

## Quick start

### Scan and analyze (one command)

```bash
# Quick scan — top 100 ports with version detection
net-audit-report scan 192.168.1.0/24 --profile quick

# Standard scan — version + scripts + OS detection
net-audit-report scan 192.168.1.0/24

# Full vulnerability assessment — all ports + vuln scripts + SSL
net-audit-report scan 192.168.1.0/24 --profile full

# SSL/TLS focused audit
net-audit-report scan myapp.example.com --profile ssl

# UDP services (requires sudo)
net-audit-report scan 192.168.1.0/24 --profile udp --sudo

# Custom ports and scripts
net-audit-report scan 10.0.0.1 --ports 22,80,443,8080 --scripts vuln,ssl-cert

# Multiple targets
net-audit-report scan 192.168.1.0/24 10.0.0.0/24 dmz.example.com
```

### Analyze existing Nmap XML

```bash
# If you already have Nmap XML from a previous scan
net-audit-report analyze --input scan.xml

# Compare with a baseline
net-audit-report analyze --input current.xml --baseline previous.xml

# Only critical/high findings, HTML only
net-audit-report analyze --input scan.xml --min-severity high --format html
```

### Compare scans

```bash
net-audit-report diff --baseline last_week.xml --current today.xml
```

### List scan profiles

```bash
net-audit-report profiles
```

## Scan profiles

| Profile | Description | Nmap args |
|---------|-------------|-----------|
| `quick` | Top 100 ports, version detection, fast | `-sV --top-ports 100 -T4` |
| `standard` | Version + scripts + OS detection (default) | `-sV -sC -O -T3` |
| `full` | All 65535 ports + vuln scripts + SSL | `-sV -sC -O -p- --script vuln,ssl-*` |
| `vuln` | Version detection + NSE vuln scripts | `-sV --script vuln` |
| `ssl` | SSL/TLS audit (ciphers, certs, vulns) | `-sV -p 443,8443,... --script ssl-*` |
| `udp` | Top 100 UDP ports (requires sudo) | `-sU -sV --top-ports 100` |
| `stealth` | SYN stealth scan, conservative timing | `-sS -sV -T2` |
| `ping` | Host discovery only, no port scan | `-sn` |

## Output files

| File | Description |
|------|-------------|
| `report.html` | Interactive HTML report with severity dashboard and filtering |
| `report.md` | Markdown report for documentation/wikis |
| `report.json` | Machine-readable JSON for automation/CI pipelines |
| `report.csv` | CSV for spreadsheet analysis |
| `scan.xml` | Raw Nmap XML output (when using `scan` command) |
| `diff.md` | Scan comparison report |
| `diff.json` | Scan diff in JSON format |

## What it detects

### Vulnerability detection
- **Known vulnerable versions** — 25+ patterns: Apache path traversal (CVE-2021-41773), OpenSSH regreSSHion (CVE-2024-6387), vsftpd backdoor, Samba EternalBlue, MySQL/Redis/MongoDB EOL, Tomcat, PHP, IIS, Exim, etc.
- **NSE script results** — Parses output from `--script vuln` (EternalBlue, Heartbleed, Shellshock, etc.)
- **CVE extraction** — Automatically extracts CVE identifiers from NSE output
- **Suspicious ports** — Flags common backdoor/C2 ports (4444, 31337, etc.)

### SSL/TLS analysis
- **Weak protocols** — SSLv2, SSLv3, TLSv1.0, TLSv1.1
- **Weak ciphers** — RC4, DES, 3DES, NULL, EXPORT, anonymous
- **Certificate issues** — Self-signed, expired, expiring, weak keys (<2048-bit), SHA1/MD5 signatures
- **Known SSL vulns** — Heartbleed, POODLE, CCS injection, Logjam

### Compliance & configuration
- **Management exposure** — SSH, RDP, VNC, WinRM, IPMI, SNMP, Webmin
- **Database exposure** — MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch, Memcached
- **Unencrypted services** — FTP, Telnet, HTTP, LDAP, POP3, IMAP without TLS
- **Default credential risks** — Services commonly misconfigured without auth
- **OS end-of-life** — Windows XP/7/Server 2008, Ubuntu 14/16/18, CentOS 6/7/8, old Debian
- **Excessive services** — Hosts with >20 open ports

### Scan comparison
- New/removed hosts between scans
- New/closed ports on existing hosts
- Service version changes over time

## CLI reference

```
net-audit-report scan <targets> [options]
  --profile, -p      Scan profile (quick/standard/full/vuln/ssl/udp/stealth/ping)
  --ports            Port specification (e.g. '22,80,443' or '1-1024')
  --top-ports        Scan top N most common ports
  --scripts          NSE scripts (e.g. 'vuln,ssl-cert')
  --timing, -T       Timing template 0-5
  --sudo             Run with sudo (needed for SYN/UDP)
  --interface, -e    Network interface
  --exclude          Hosts to exclude
  --timeout          Max scan duration in seconds (default: 3600)
  --save-xml         Save raw XML to specific path
  --outdir, -o       Output directory (default: reports)
  --format, -f       Output formats: md json csv html
  --min-severity, -s Minimum severity: critical|high|medium|low|info
  --no-vulns         Skip version-based vulnerability matching
  --no-ssl           Skip SSL/TLS analysis
  --no-compliance    Skip compliance checks
  --quiet, -q        Suppress output

net-audit-report analyze --input <file.xml> [options]
  --input, -i        Nmap XML file (required)
  --baseline, -b     Baseline XML for comparison
  (same report options as scan)

net-audit-report diff --baseline <old.xml> --current <new.xml>
  --outdir, -o       Output directory
  --format, -f       Output formats: md json

net-audit-report profiles
  List all available scan profiles
```

## Testing

### Install test dependencies

```bash
pip install -e .
pip install pytest
```

### Run all tests

```bash
# Run all 100+ tests
pytest -v

# Run with short summary
pytest

# Run a specific test file
pytest tests/test_scanner.py -v
pytest tests/test_vulns.py -v
pytest tests/test_ssl.py -v
pytest tests/test_compliance.py -v

# Run a specific test
pytest tests/test_scanner.py::test_build_command_quick_profile -v

# Run tests matching a keyword
pytest -k "ssl" -v
pytest -k "vuln" -v
pytest -k "scan" -v
```

### Test without Nmap installed

All scanner tests use **mocked subprocess calls** so you don't need Nmap installed
to run the test suite. The tests verify:

- Command construction for all profiles
- Scan success/failure/timeout handling
- XML output parsing integration
- CLI subcommand routing
- Backwards compatibility

### Test with real Nmap (manual)

If you have Nmap installed and want to test against real targets:

```bash
# 1. Test against Nmap's public test server
net-audit-report scan scanme.nmap.org --profile quick --outdir /tmp/test-report

# 2. Test against your local machine
net-audit-report scan 127.0.0.1 --profile standard --outdir /tmp/local-report

# 3. Test your home network (if authorized)
net-audit-report scan 192.168.1.0/24 --profile full --outdir /tmp/network-report

# 4. Test SSL on a specific site you own
net-audit-report scan yourdomain.com --profile ssl --outdir /tmp/ssl-report

# 5. Test scan comparison (run twice, then diff)
net-audit-report scan 192.168.1.0/24 --profile quick --save-xml baseline.xml
# ... make changes ...
net-audit-report scan 192.168.1.0/24 --profile quick --save-xml current.xml
net-audit-report diff --baseline baseline.xml --current current.xml

# 6. View the HTML report in your browser
open reports/report.html    # macOS
xdg-open reports/report.html  # Linux
```

### Test the analysis pipeline (no Nmap needed)

```bash
# Use the included sample data
net-audit-report analyze --input samples/sample_nmap.xml --outdir /tmp/test

# Compare samples
net-audit-report analyze --input samples/sample_nmap.xml \
  --baseline samples/baseline_nmap.xml --outdir /tmp/test

# Filter by severity
net-audit-report analyze --input samples/sample_nmap.xml \
  --min-severity critical --format json --outdir /tmp/test

# Check what the tool finds
cat /tmp/test/report.md
```

### Test modules individually

```python
# In a Python shell
from net_audit_report.nmap_parser import parse_nmap_xml
from net_audit_report.findings import generate_findings
from net_audit_report.vulns import match_known_vulns
from net_audit_report.ssl_analyzer import analyze_ssl_findings
from net_audit_report.compliance import check_compliance

hosts = parse_nmap_xml("samples/sample_nmap.xml")
print(f"Hosts: {len(hosts)}")

findings = generate_findings(hosts)
print(f"Findings: {len(findings)}")

vulns = match_known_vulns(hosts)
print(f"Vuln matches: {len(vulns)}")
for v in vulns:
    print(f"  [{v.severity}] {v.host}:{v.port} - {v.title}")
```

## Project structure

```
src/net_audit_report/
  cli.py             # CLI with scan/analyze/diff/profiles subcommands
  scanner.py         # Nmap subprocess wrapper with scan profiles
  nmap_parser.py     # Nmap XML parser (hosts, services, scripts, OS, CPE)
  findings.py        # Policy rules for risky ports/services
  vulns.py           # Known vulnerable version database + NSE vuln extraction
  ssl_analyzer.py    # SSL/TLS configuration analysis
  compliance.py      # Configuration and compliance checks
  diff.py            # Scan comparison/diff engine
  report.py          # Report building (MD, HTML, JSON, CSV)
  utils.py           # File I/O helpers
tests/               # 100+ tests covering all modules
samples/             # Example Nmap XML files for testing
```

## Extending

- Add version rules: edit `KNOWN_VULNS` in `src/net_audit_report/vulns.py`
- Add port rules: edit `RISKY_PORTS` in `src/net_audit_report/findings.py`
- Add compliance rules: edit checks in `src/net_audit_report/compliance.py`
- Add SSL rules: edit analyzers in `src/net_audit_report/ssl_analyzer.py`
- Add scan profiles: edit `SCAN_PROFILES` in `src/net_audit_report/scanner.py`

## License

MIT
