# net-audit-report

Defensive network vulnerability analyzer that converts authorized Nmap XML output into
comprehensive security reports. Identifies known vulnerabilities, misconfigurations,
SSL/TLS issues, and compliance gaps — all from scan data you already collected.

**This tool does NOT perform any network scanning.** You must provide Nmap XML from
authorized scans on systems you own or have written permission to test.

## Quick start

### 1) Run your authorized Nmap scan

```bash
# Basic service version scan
nmap -sV -oX out.xml 192.168.1.0/24

# Full scan with vuln scripts and SSL analysis
nmap -sV -sC --script vuln,ssl-enum-ciphers,ssl-cert -O -oX out.xml 192.168.1.0/24
```

### 2) Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

### 3) Generate reports

```bash
# Full analysis with all outputs
net-audit-report --input out.xml --outdir reports

# Compare with a baseline scan
net-audit-report --input current.xml --baseline previous.xml --outdir reports

# Only critical/high findings, HTML only
net-audit-report --input out.xml --min-severity high --format html

# Skip specific checks
net-audit-report --input out.xml --no-ssl --no-compliance
```

## Output files

| File | Description |
|------|-------------|
| `report.html` | Interactive HTML report with severity dashboard and filtering |
| `report.md` | Markdown report for documentation/wikis |
| `report.json` | Machine-readable JSON for automation/CI pipelines |
| `report.csv` | CSV for spreadsheet analysis |
| `diff.md` | Scan comparison report (when `--baseline` is used) |
| `diff.json` | Scan diff in JSON format |

## Features

### Vulnerability detection
- **Known vulnerable version matching** — Curated database of 25+ known-vulnerable software versions (Apache, OpenSSH, nginx, MySQL, PostgreSQL, Redis, Samba, Tomcat, PHP, etc.) with CVE references
- **NSE script analysis** — Parses Nmap vuln script output (EternalBlue, Heartbleed, Shellshock, etc.)
- **CVE extraction** — Automatically extracts CVE identifiers from NSE script results
- **Suspicious port detection** — Flags common backdoor/C2 ports (4444, 31337, etc.)

### SSL/TLS analysis
- **Weak protocols** — Flags SSLv2, SSLv3, TLSv1.0, TLSv1.1
- **Weak ciphers** — Detects RC4, DES, 3DES, NULL, EXPORT, anonymous ciphers
- **Certificate issues** — Self-signed certs, expired/expiring certs, weak keys (<2048-bit), weak signatures (SHA1/MD5)
- **Known SSL vulns** — Heartbleed, POODLE, CCS injection, Logjam

### Compliance & configuration
- **Management exposure** — Flags SSH, RDP, VNC, WinRM, IPMI, SNMP, Webmin on untrusted networks
- **Database exposure** — Detects exposed MySQL, PostgreSQL, MongoDB, Redis, Elasticsearch, Memcached
- **Unencrypted services** — Flags FTP, Telnet, HTTP, LDAP, POP3, IMAP without TLS
- **Default credential risks** — Warns about services commonly misconfigured without auth
- **OS end-of-life** — Detects Windows XP/7/Server 2008, Ubuntu 14/16/18, CentOS 6/7/8, old Debian
- **Excessive services** — Flags hosts with >20 open ports

### Scan comparison
- **Host diff** — New/removed hosts between scans
- **Port diff** — New/closed ports on existing hosts
- **Version tracking** — Service version changes over time
- **State changes** — Port state transitions (open/closed/filtered)

### Reporting
- **5-level severity** — Critical, High, Medium, Low, Info
- **4 output formats** — HTML (interactive), Markdown, JSON, CSV
- **Severity dashboard** — Visual summary in HTML reports
- **Client-side filtering** — Filter findings by severity in HTML report
- **Category tagging** — Findings tagged by type (port, service, ssl, vuln, compliance, etc.)

## CLI options

```
net-audit-report --help

Options:
  --input, -i        Path to Nmap XML file (required)
  --outdir, -o       Output directory (default: reports)
  --format, -f       Output formats: md json csv html (default: all)
  --baseline, -b     Baseline Nmap XML for scan comparison
  --min-severity, -s Minimum severity: critical|high|medium|low|info
  --no-vulns         Skip known vulnerability matching
  --no-ssl           Skip SSL/TLS analysis
  --no-compliance    Skip compliance checks
  --quiet, -q        Suppress informational output
```

## Recommended Nmap scan commands

```bash
# Quick service scan
nmap -sV -oX quick.xml <target>

# Comprehensive vulnerability assessment
nmap -sV -sC -O --script vuln,ssl-enum-ciphers,ssl-cert,ssl-heartbleed -oX full.xml <target>

# UDP services (SNMP, TFTP, etc.)
sudo nmap -sU -sV --top-ports 100 -oX udp.xml <target>

# Full TCP + common UDP
sudo nmap -sS -sU -sV -sC -O --script vuln -oX combined.xml <target>
```

## Running tests

```bash
pip install pytest
pytest -v
```

## Project structure

```
src/net_audit_report/
  cli.py             # CLI with all options
  nmap_parser.py     # Nmap XML parser (hosts, services, scripts, OS, CPE)
  findings.py        # Policy rules for risky ports/services
  vulns.py           # Known vulnerable version database + NSE vuln extraction
  ssl_analyzer.py    # SSL/TLS configuration analysis
  compliance.py      # Configuration and compliance checks
  diff.py            # Scan comparison/diff engine
  report.py          # Report building (MD, HTML, JSON, CSV)
  utils.py           # File I/O helpers
tests/               # 60+ tests covering all modules
samples/             # Example Nmap XML files
```

## Extending

- Add version rules: edit `KNOWN_VULNS` in `src/net_audit_report/vulns.py`
- Add port rules: edit `RISKY_PORTS` in `src/net_audit_report/findings.py`
- Add compliance rules: edit checks in `src/net_audit_report/compliance.py`
- Add SSL rules: edit analyzers in `src/net_audit_report/ssl_analyzer.py`

## License

MIT
