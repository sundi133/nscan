"""
SSL/TLS configuration analyzer.

Parses ssl-enum-ciphers, ssl-cert, and related NSE script output to identify
weak TLS configurations, expired certificates, and cipher suite issues.
This module only analyzes data already collected from authorized Nmap scans.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
import re
from datetime import datetime

from .nmap_parser import Host, ScriptResult
from .findings import Finding


WEAK_CIPHERS = {
    "RC4", "DES", "3DES", "DES-CBC3", "RC2", "IDEA", "SEED",
    "NULL", "EXPORT", "anon", "ADH", "AECDH",
}

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}

PREFERRED_PROTOCOLS = {"TLSv1.2", "TLSv1.3"}


@dataclass(frozen=True)
class CertInfo:
    subject_cn: Optional[str]
    issuer_cn: Optional[str]
    not_before: Optional[str]
    not_after: Optional[str]
    is_self_signed: bool
    is_expired: bool
    key_bits: Optional[int]
    sig_algo: Optional[str]
    san: list[str]


def analyze_ssl_findings(hosts: list[Host]) -> list[Finding]:
    """Generate findings from SSL/TLS script output."""
    findings: list[Finding] = []

    for host in hosts:
        if host.status != "up":
            continue

        for svc in host.services:
            if svc.state != "open":
                continue

            for script in svc.scripts:
                if script.script_id == "ssl-enum-ciphers":
                    findings.extend(_analyze_ciphers(host.address, svc.port, svc.protocol, script))
                elif script.script_id == "ssl-cert":
                    findings.extend(_analyze_cert(host.address, svc.port, svc.protocol, script))
                elif script.script_id == "ssl-heartbleed":
                    findings.extend(_analyze_heartbleed(host.address, svc.port, svc.protocol, script))
                elif script.script_id == "ssl-poodle":
                    findings.extend(_analyze_poodle(host.address, svc.port, svc.protocol, script))
                elif script.script_id == "ssl-dh-params":
                    findings.extend(_analyze_dh_params(host.address, svc.port, svc.protocol, script))
                elif script.script_id == "ssl-ccs-injection":
                    findings.extend(_analyze_ccs(host.address, svc.port, svc.protocol, script))

    return findings


def _analyze_ciphers(host: str, port: int, proto: str, script: ScriptResult) -> list[Finding]:
    findings: list[Finding] = []
    output = script.output

    # Check for weak protocols
    for weak_proto in WEAK_PROTOCOLS:
        if weak_proto in output:
            findings.append(Finding(
                host=host,
                severity="critical" if weak_proto in ("SSLv2", "SSLv3") else "high",
                title=f"Weak TLS protocol: {weak_proto}",
                detail=f"{host} {proto}/{port} supports {weak_proto}, which is insecure and deprecated.",
                recommendation=f"Disable {weak_proto}; enforce TLSv1.2+ minimum.",
                port=port,
                protocol=proto,
                category="ssl",
            ))

    # Check for weak ciphers
    for cipher in WEAK_CIPHERS:
        if re.search(re.escape(cipher), output, re.IGNORECASE):
            findings.append(Finding(
                host=host,
                severity="high",
                title=f"Weak cipher suite: {cipher}",
                detail=f"{host} {proto}/{port} supports weak cipher involving {cipher}.",
                recommendation=f"Remove {cipher}-based cipher suites; use AES-GCM or ChaCha20-Poly1305.",
                port=port,
                protocol=proto,
                category="ssl",
            ))

    # Check if TLSv1.3 is missing
    if "TLSv1.3" not in output and ("TLSv1.2" in output or "TLSv1.1" in output or "TLSv1.0" in output):
        findings.append(Finding(
            host=host,
            severity="low",
            title="TLSv1.3 not supported",
            detail=f"{host} {proto}/{port} does not appear to support TLSv1.3.",
            recommendation="Enable TLSv1.3 for improved security and performance.",
            port=port,
            protocol=proto,
            category="ssl",
        ))

    # Check for cipher order preference
    if "server cipher order" not in output.lower() and "cipher preference: client" in output.lower():
        findings.append(Finding(
            host=host,
            severity="medium",
            title="No server cipher preference",
            detail=f"{host} {proto}/{port} allows client cipher preference.",
            recommendation="Configure server to enforce its own cipher order.",
            port=port,
            protocol=proto,
            category="ssl",
        ))

    return _dedup_findings(findings)


def _analyze_cert(host: str, port: int, proto: str, script: ScriptResult) -> list[Finding]:
    findings: list[Finding] = []
    output = script.output
    elems = script.elements

    # Check for self-signed cert
    subject = elems.get("subject.commonName", "")
    issuer = elems.get("issuer.commonName", "")
    if subject and issuer and subject == issuer:
        findings.append(Finding(
            host=host,
            severity="high",
            title="Self-signed certificate",
            detail=f"{host} {proto}/{port} uses a self-signed certificate (CN={subject}).",
            recommendation="Replace with a certificate from a trusted CA (e.g., Let's Encrypt).",
            port=port,
            protocol=proto,
            category="ssl",
        ))

    # Check for expiration
    not_after = elems.get("validity.notAfter", "")
    if not_after:
        try:
            # Nmap uses format like "2024-01-15T12:00:00"
            expiry = datetime.fromisoformat(not_after.replace("Z", "+00:00").split("+")[0])
            now = datetime.utcnow()
            if expiry < now:
                findings.append(Finding(
                    host=host,
                    severity="critical",
                    title="SSL certificate expired",
                    detail=f"{host} {proto}/{port} certificate expired on {not_after}.",
                    recommendation="Renew the certificate immediately.",
                    port=port,
                    protocol=proto,
                    category="ssl",
                ))
            elif (expiry - now).days < 30:
                findings.append(Finding(
                    host=host,
                    severity="high",
                    title="SSL certificate expiring soon",
                    detail=f"{host} {proto}/{port} certificate expires on {not_after} ({(expiry - now).days} days).",
                    recommendation="Renew the certificate before expiration.",
                    port=port,
                    protocol=proto,
                    category="ssl",
                ))
        except (ValueError, TypeError):
            pass

    # Check for weak key size
    pubkey_bits = elems.get("pubkey.bits", "")
    if pubkey_bits:
        try:
            bits = int(pubkey_bits)
            if bits < 2048:
                findings.append(Finding(
                    host=host,
                    severity="critical",
                    title=f"Weak certificate key ({bits}-bit)",
                    detail=f"{host} {proto}/{port} uses a {bits}-bit key which is cryptographically weak.",
                    recommendation="Regenerate certificate with at least 2048-bit RSA or 256-bit ECDSA key.",
                    port=port,
                    protocol=proto,
                    category="ssl",
                ))
        except ValueError:
            pass

    # Check for weak signature algorithm
    sig_algo = elems.get("sig_algo", "") or ""
    if "sha1" in sig_algo.lower() or "md5" in sig_algo.lower():
        findings.append(Finding(
            host=host,
            severity="high",
            title=f"Weak certificate signature ({sig_algo})",
            detail=f"{host} {proto}/{port} certificate uses weak signature algorithm: {sig_algo}.",
            recommendation="Regenerate certificate with SHA-256 or stronger signature algorithm.",
            port=port,
            protocol=proto,
            category="ssl",
        ))

    return findings


def _analyze_heartbleed(host: str, port: int, proto: str, script: ScriptResult) -> list[Finding]:
    if "vulnerable" in script.output.lower():
        return [Finding(
            host=host,
            severity="critical",
            title="Heartbleed vulnerability (CVE-2014-0160)",
            detail=f"{host} {proto}/{port} is vulnerable to Heartbleed.",
            recommendation="Upgrade OpenSSL immediately; revoke and reissue certificates; rotate all secrets.",
            port=port,
            protocol=proto,
            category="ssl",
            cves=["CVE-2014-0160"],
        )]
    return []


def _analyze_poodle(host: str, port: int, proto: str, script: ScriptResult) -> list[Finding]:
    if "vulnerable" in script.output.lower():
        return [Finding(
            host=host,
            severity="high",
            title="POODLE vulnerability (CVE-2014-3566)",
            detail=f"{host} {proto}/{port} is vulnerable to POODLE attack via SSLv3.",
            recommendation="Disable SSLv3 entirely; enforce TLSv1.2+ minimum.",
            port=port,
            protocol=proto,
            category="ssl",
            cves=["CVE-2014-3566"],
        )]
    return []


def _analyze_dh_params(host: str, port: int, proto: str, script: ScriptResult) -> list[Finding]:
    findings: list[Finding] = []
    output = script.output.lower()
    if "vulnerable" in output or "weak" in output:
        findings.append(Finding(
            host=host,
            severity="high",
            title="Weak Diffie-Hellman parameters (Logjam)",
            detail=f"{host} {proto}/{port} uses weak DH parameters.",
            recommendation="Use 2048-bit+ DH parameters or switch to ECDHE.",
            port=port,
            protocol=proto,
            category="ssl",
            cves=["CVE-2015-4000"],
        ))
    return findings


def _analyze_ccs(host: str, port: int, proto: str, script: ScriptResult) -> list[Finding]:
    if "vulnerable" in script.output.lower():
        return [Finding(
            host=host,
            severity="high",
            title="CCS Injection vulnerability (CVE-2014-0224)",
            detail=f"{host} {proto}/{port} is vulnerable to OpenSSL CCS injection.",
            recommendation="Upgrade OpenSSL to patched version.",
            port=port,
            protocol=proto,
            category="ssl",
            cves=["CVE-2014-0224"],
        )]
    return []


def _dedup_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    result: list[Finding] = []
    for f in findings:
        key = (f.host, f.port, f.protocol, f.title)
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result
